# -*- coding: utf-8 -*-
import time
import json
import sys
from Crypto import Random
from random import randint

import zlib
try:
  import snappy
except ImportError:
  pass

from Crypto.Cipher import AES
from struct import pack, unpack

from binascii import a2b_hex

from tlv import UnifiTLV
from tools import mac_string_2_array, ip_string_2_array, netmask_to_cidr, uptime, get_if_table, get_network_table, get_net_stats

MASTER_KEY = "ba86f2bbe107c7c57eb5f2690775c712"

def encode_inform(config, data):
    iv = Random.new().read(16)

    key = MASTER_KEY
    if config.getboolean('gateway', 'is_adopted'):
      key = config.get('gateway', 'key')

    payload = None
    flags = 3
    if 'snappy' in sys.modules:
      payload = snappy.compress(data)
      flags = 5
    else:
      payload = zlib.compress(data)
    pad_len = AES.block_size - (len(payload) % AES.block_size)
    payload += chr(pad_len) * pad_len
    payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).encrypt(payload)
    mac = config.get('gateway','lan_mac')

    encoded_data = 'TNBU'                     # magic
    encoded_data += pack('>I', 1)             # packet version
    encoded_data += pack('BBBBBB', *(mac_string_2_array(mac)))
    encoded_data += pack('>H', flags)         # flags
    encoded_data += iv                        # encryption iv
    encoded_data += pack('>I', 1)             # payload version
    encoded_data += pack('>I', len(payload))  # payload length
    encoded_data += payload

    return encoded_data


def decode_inform(config, encoded_data):
    magic = encoded_data[0:4]
    if magic != 'TNBU':
        raise Exception("Missing magic in response: '{}' instead of 'TNBU'".format(magic))

    # mac = unpack('BBBBBB', encoded_data[8:14])
    # if mac != (0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9):
    #     raise Exception('Mac address changed in response: %s -> %s'%(mac2a((0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9)), mac2a(mac)))

    flags = unpack('>H', encoded_data[14:16])[0]
    iv = encoded_data[16:32]
    version = unpack('>I', encoded_data[32:36])[0]
    payload_len = unpack('>I', encoded_data[36:40])[0]
    payload = encoded_data[40:(40+payload_len)]

    key = MASTER_KEY
    if config.getboolean('gateway', 'is_adopted'):
      key = config.get('gateway', 'key')

    # decrypt if required
    if flags & 0x01:
        payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).decrypt(payload)
        pad_size = ord(payload[-1])
        if pad_size > AES.block_size:
            raise Exception('Response not padded or padding is corrupt')
        payload = payload[:(len(payload) - pad_size)]
    # uncompress if required
    if flags & 0x02:
        payload = zlib.decompress(payload)

    payload_json = json.loads(payload)
    return payload_json


def _create_partial_inform(config,data):
    return json.dumps({
        'hostname': 'UBNT',
        'state': 0,
        'default': 'true',
        'inform_url':  config.get('gateway', 'url'),
        'mac': config.get('gateway', 'lan_mac'),
        'ip': config.get('gateway', 'lan_ip'),
        'model': config.get('gateway', 'device'),
        'model_display': config.get('gateway', 'device_display'),
        'version': config.get('gateway', 'firmware'),
        'uptime': uptime()
    })


def _create_complete_inform(config,data):
     return json.dumps({
         'bootrom_version': 'unknown',
         'cfgversion': config.get('provisioned', 'cfgversion'),
         'config_network_wan': {
             'type': 'dhcp',
         },
         'config_port_table': [ # XXX TODO read from config?
             {
                 'ifname': 'eth0',
                 'name': 'wan'
             },
             {
                 'ifname': 'eth1',
                 'name': 'lan'
             },
             {
                 'ifname': 'eth2',
                 'name': 'LAN2'
             }
         ],
         'connect_request_ip': config.get('gateway', 'lan_ip'),
         'connect_request_port': '36424',
         'default': False,
         'state': 2,
         'discovery_response': False,
         'fw_caps': 3,
         'guest_token': '4C1D46707239C6EB5A2366F505A44A91',
         'has_default_route_distance': True,
         'has_dnsmasq_hostfile_update': False,
         'has_dpi': False,
         'has_eth1': True,
         'has_porta': True,
         'has_ssh_disable': True,
         'has_vti': True,
         'hostname': 'openwrt',
         'inform_url':  config.get('gateway', 'url'),
         'ip': config.get('gateway', 'lan_ip'),
         'isolated': False,
         'locating': False,
         'mac': config.get('gateway', 'lan_mac'),
         'model': config.get('gateway', 'device'),
         'model_display': config.get('gateway', 'device_display'),
         'netmask': '255.255.255.0', # TODO
         'required_version': '4.0.0',
         'selfrun_beacon': True,
         'serial': config.get('gateway', 'lan_mac').replace(':', ''),
         'version': config.get('gateway', 'firmware'),
         'time': int(time.time()),
         'uplink': 'eth0', # TODO
         'uptime': uptime(),
         'pfor-stats': [
             {
                 'id': '596add99e4b0a76e35003e00',
                 'rx_bytes': 0,
                 'rx_packets': 0,
                 'tx_bytes': 0,
                 'tx_packets': 0
             }
         ],
         'speedtest-status': {
         # XXX TODO speedtest (ping?)
             'latency': 9,
             'rundate': int(time.time()),
             'runtime': 6,
             'status_download': 2,
             'status_ping': 2,
             'status_summary': 2,
             'status_upload': 2,
             'xput_download': 385.30819702148,
             'xput_upload': 68.445808410645
         },
         "ddns-status": {
         # XXX TODO dyndns
           "dyndns": [
             {
               "atime": 200,
               "host_name": "dyndns.example.com",
               "ip": "20.1.2.3",
               "mtime": 141,
               "status": "good",
               "warned_min_error_interval": 0,
               "warned_min_interval": 0,
               "wtime": 30
             }
           ]
         },
         'system-stats': {
         ### XXX TODO system-stats (psutil)
           'cpu': randint(0, 20),
           'mem': randint(0, 20),
           'uptime': uptime(),
    #         'cpu': '%s' % psutil.cpu_percent(),
    #         'mem': '%s' % (100 - psutil.virtual_memory()[2]),
    #         'uptime':  '%s' % uptime()
         },
         'routes': [
         # XXX TODO routes
             {
                 'nh': [
                     {
                         'intf': 'eth0',
                         'metric': '1/0',
                         't': 'S>*',
                         'via': '88.114.225.1'
                     }
                 ],
                 'pfx': '0.0.0.0/0'
             },
             {
                 'nh': [
                     {
                         'intf': 'eth1',
                         't': 'C>*'
                     }
                 ],
                 'pfx': '192.168.4.0/24'
             },
         ],
         'network_table': get_network_table(data.data),
         'if_table': get_if_table(data.data),
    })


def create_inform(config,data):
    return _create_partial_inform(config,data) if not config.getboolean('gateway', 'is_adopted') else _create_complete_inform(config,data)


def create_broadcast_message(config, index, version=2, command=6):
    lan_mac = config.get('gateway', 'lan_mac')
    lan_ip = config.get('gateway', 'lan_ip')
    firmware = config.get('gateway', 'firmware')
    device = config.get('gateway', 'device')

    tlv = UnifiTLV()
    tlv.add(1, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(2, bytearray(mac_string_2_array(lan_mac) + ip_string_2_array(lan_ip)))
    tlv.add(3, bytearray('{}.v{}'.format(device, firmware)))
    tlv.add(10, bytearray([ord(c) for c in pack('!I', uptime())]))
    tlv.add(11, bytearray('PFSENSE'))
    tlv.add(12, bytearray(device))
    tlv.add(19, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(18, bytearray([ord(c) for c in pack('!I', index)]))
    tlv.add(21, bytearray(device))
    tlv.add(27, bytearray(firmware))
    tlv.add(22, bytearray(firmware))
    return tlv.get(version=version, command=command)
