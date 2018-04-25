import re
import time
from random import randint

class DataCollector(object):
  def __init__(self):
    self.data = {}

    self.update_oneshot()

  def update_oneshot(self):
    self.data['macs'] = self._update_interface_macs()
    self.update()

  def update(self):
    self.data['ifstat'] = self._update_proc_net_dev()
    # XXX TODO host_table should be ARP entries instead of dhcp leases, and only update host_table every few minutes
    self.data['host_table'] = self._update_dnsmasq_leases()
    self.data['ip'] = self._update_interface_addresses()
    self.data['nameservers'] = [ '195.74.0.47', '195.197.54.100' ]

  def _update_proc_net_dev(self):
    ret = {}
    f = open("/proc/net/dev", "r");
    data = f.read()
    f.close()

    r = re.compile("[:\s]+")
    lines = re.split("[\r\n]+", data)
    for line in lines[2:]:
      columns = r.split(line)
      if len(columns) < 18:
        continue
      info                  = {}
      info["rx_bytes"]      = columns[2]
      info["rx_packets"]    = columns[3]
      info["rx_errors"]     = columns[4]
      info["rx_dropped"]    = columns[5]
      info["rx_fifo"]       = columns[6]
      info["rx_frame"]      = columns[7]
      info["rx_compressed"] = columns[8]
      info["rx_multicast"]  = columns[9]

      info["tx_bytes"]      = columns[10]
      info["tx_packets"]    = columns[11]
      info["tx_errors"]     = columns[12]
      info["tx_dropped"]    = columns[13]
      info["tx_fifo"]       = columns[14]
      info["tx_frame"]      = columns[15]
      info["tx_compressed"] = columns[16]
      info["tx_multicast"]  = columns[17]

      iface                 = columns[1]
      ret[iface] = info
    return ret


  def _update_dnsmasq_leases(self):
    leasef = 'dhcp.leases.example'
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

  def _update_interface_addresses(self):
    # XXX TODO
    return { 'eth0': { 'address': '10.10.10.5', 'netmask': '255.255.248.0', 'gateway': '10.10.10.1' }, 'eth1': { 'address': '192.168.4.1', 'netmask': '255.255.255.0' } }

  def _update_interface_macs(self):
    # XXX TODO
    return { 'eth0': '0a:0a:0a:0a:0a:0b', 'eth1': '0a:0a:0a:0a:0a:0a' }
