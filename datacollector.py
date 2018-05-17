import re
import ast
import time
import subprocess
import socket, struct, fcntl
from random import randint

class DataCollector(object):
  def __init__(self, config):
    self.data = {}
    self.updated = {}
    self.config = config
    self.ports = ast.literal_eval(config.get('gateway', 'ports'))

    self.update_oneshot()

  def update_oneshot(self):
    self.data['macs'] = self._update_interface_macs_linux()
    self.update()

  def update(self):
    self.data['ifstat'] = self._update_ifstat_linux()
    self.data['dhcp_leases'] = self._update_dnsmasq_leases()
    self.data['ip'] = self._update_interface_addresses()
    self.data['nameservers'] = [ '195.74.0.47', '195.197.54.100' ]

    if 'latency' not in self.updated or (time.time() - self.updated['latency'] >= 300):
      self.data['latency'] = self._update_latency()
      self.updated['latency'] = time.time()

    if 'host_table' not in self.updated or (time.time() - self.updated['host_table'] >= 120):
      self.data['host_table'] = self._update_iproute2_neighbors_linux()
      self.updated['host_table'] = time.time()

  def _update_ifstat_linux(self):
    ret = {}
    f = open("/proc/net/dev", "r");
    data = f.read()
    f.close()

    lines = re.split("[\r\n]+", data)
    for line in lines[2:]:
      if line.find(":") < 0: continue
      iface, data = line.split(":")
      columns = data.split()

      info                  = {}
      info["rx_bytes"]      = columns[0]
      info["rx_packets"]    = columns[1]
      info["rx_errors"]     = columns[2]
      info["rx_dropped"]    = columns[3]
      info["rx_fifo"]       = columns[4]
      info["rx_frame"]      = columns[5]
      info["rx_compressed"] = columns[6]
      info["rx_multicast"]  = columns[7]

      info["tx_bytes"]      = columns[8]
      info["tx_packets"]    = columns[9]
      info["tx_errors"]     = columns[10]
      info["tx_dropped"]    = columns[11]
      info["tx_fifo"]       = columns[12]
      info["tx_frame"]      = columns[13]
      info["tx_compressed"] = columns[14]
      info["tx_multicast"]  = columns[15]

      ret[iface.lstrip()] = info
    return ret

  def _update_dnsmasq_leases(self):
    leasef = '/tmp/dhcp.leases'
    leases = []
    with open(leasef, 'r') as f:
      for line in f:
        (expiry, mac, ip, name, clientid) = line.split()
        lease = {}
        if name != '*':
          lease['hostname'] = name
        lease['ip'] = ip
        lease['mac'] = mac
        leases.append(lease)
    return leases

  def _get_arp_table_linux(self):
    arp_table = []
    lan_ifs = [ d['ifname'] for d in self.ports if 'lan' in d['name'].lower() ]
    with open('/proc/net/arp') as f:
      header_line = f.readline()
      for line in f:
        (ipaddr, hwtype, flags, hwaddr, mask, iface) = line.split()
	if not iface in lan_ifs:
	  continue
	if flags == '0x0':
	  continue
	arp = {}
	arp['mac'] = hwaddr
	arp['ip'] = ipaddr
	dhcp_hostname = [ d['hostname'] for d in self.data['dhcp_leases'] if 'hostname' in d and d['mac'].lower() == hwaddr ]
	if dhcp_hostname:
	  arp['hostname'] = dhcp_hostname[0]
	arp_table.append(arp)
    return arp_table

  def _update_iproute2_neighbors_linux(self):
    neigh_table = []
    lan_ifs = [ d['ifname'] for d in self.ports if 'lan' in d['name'].lower() ]
    ip = subprocess.Popen(["ip", "-4", "-s", "neigh", "list"], stdout=subprocess.PIPE)

    for line in ip.stdout.readlines():
      fields = line.split()

      if fields[-1] == "REACHABLE" or fields[-1] == "STALE":
        dev_i = fields.index('dev') if 'dev' in fields else None
        lladdr_i = fields.index('lladdr') if 'lladdr' in fields else None
        stats_i = fields.index('used') if 'used' in fields else None

        assert dev_i and lladdr_i and stats_i

        if fields[dev_i + 1] in lan_ifs:
          used,confirmed,updated = [ int(x) for x in fields[stats_i + 1].split('/') ]

          # consider stale neighbor entry as active if it's been used within 2 minutes
          if fields[-1] == "STALE" and used > 120:
            continue
          neigh = {}
          neigh['mac'] = fields[lladdr_i + 1]
          neigh['ip'] = fields[0]
          dhcp_hostname = [ d['hostname'] for d in self.data['dhcp_leases'] if 'hostname' in d and d['mac'].lower() == fields[lladdr_i + 1] ]
          if dhcp_hostname:
            neigh['hostname'] = dhcp_hostname[0]
          neigh_table.append(neigh)
    return neigh_table

  def _get_default_route_linux(self):
    with open("/proc/net/route") as f:
      for line in f:
        fields = line.strip().split()
	if fields[1] != '00000000' or not int(fields[3], 16) & 2:
	  continue

	return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

  def _update_interface_addresses(self):
    ret = {}
    for d in self.ports:
      ( ip, mask ) = self._get_interface_address(d['ifname'])
      if not ip or not mask:
        continue
      if d['name'].lower() == 'wan':
        ret[d['ifname']] = { 'address': ip, 'netmask': mask, 'gateway': self._get_default_route_linux() }
      else:
        ret[d['ifname']] = { 'address': ip, 'netmask': mask }

    return ret

  def _get_interface_address(self, iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = None
    mask = None
    try:
      addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface[:15]))[20:24])
      mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 35099, struct.pack('256s', iface))[20:24])
    except:
      pass
    return [ addr, mask ]

  def _update_interface_macs_linux(self):
    ret = {}
    for d in self.ports:
      ret[d['ifname']] = open('/sys/class/net/%s/address' % d['ifname'],'r').read().strip()
    return ret

  def _update_latency(self):
    stdout = subprocess.Popen(["/bin/ping", "-c1", "-w5", "ping.ubnt.com"], stdout=subprocess.PIPE).stdout.read()
    match = re.search('([\d]*\.[\d]*)/([\d]*\.[\d]*)/([\d]*\.[\d]*)', stdout)
    if not match:
      return None
    ping_min = match.group(1)
    ping_avg = match.group(2)
    ping_max = match.group(3)

    match = re.search('(\d*)% packet loss', stdout)
    if not match:
      return None
    pkt_loss = match.group(1)
    return float(ping_avg)
