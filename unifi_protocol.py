# -*- coding: utf-8 -*-
import time
import json
import sys
import ast
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

def encode_inform(config, data, encryption='CBC'):
    iv = Random.new().read(16)

    key = MASTER_KEY
    if config.getboolean('gateway', 'is_adopted'):
      key = config.get('gateway', 'key')
      if config.getboolean('gateway', 'use_aes_gcm'):
         encryption = 'GCM'
      elif not config.getboolean('gateway', 'use_aes_gcm'):
         encryption = 'CBC'

    payload = None
    flags = 3
    mac = config.get('gateway','lan_mac')

    if encryption == 'GCM':
        flags = flags | 0x01 | 0x08
    elif encryption == 'CBC':
        flags = flags | 0x01

    if 'snappy' in sys.modules:
      payload = snappy.compress(data.encode('ascii'))
      flags = 5
    else:
      payload = zlib.compress(data.encode('ascii'))

    # encode packet
    encoded_data = b'TNBU'                     # magic
    encoded_data += pack('>I', 1)             # packet version
    encoded_data += pack('BBBBBB', *(mac_string_2_array(mac)))
    encoded_data += pack('>H', flags)         # flags
    encoded_data += iv                        # encryption iv
    encoded_data += pack('>I', 1)             # payload version
    #encoded_data += payload

    if encryption == 'GCM':
        # GCM Encryption
        #logger.debug(f'encode_indorm: AES GCM Encrypting packet using key {key} and iv {hexlify(iv)}')
        encoded_data += pack('>I', len(payload)+16)  # payload length
        _aes = AES.new(a2b_hex(key), AES.MODE_GCM, iv)
        _aes.update(encoded_data)
        payload, tag = _aes.encrypt_and_digest(payload)
        payload += tag

    elif encryption == 'CBC':
        pad_len = AES.block_size - (len(payload) % AES.block_size)
        payload += chr(pad_len).encode('ascii') * pad_len
        payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).encrypt(payload)
        encoded_data += pack('>I', len(payload))  # payload length

    encoded_data += payload

    return encoded_data


def decode_inform(config, encoded_data):
    magic = encoded_data[0:4]
    if magic != b'TNBU':
        raise Exception("Missing magic in response: '{}' instead of 'TNBU'".format(magic))

    # mac = unpack('BBBBBB', encoded_data[8:14])
    # if mac != (0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9):
    #     raise Exception('Mac address changed in response: %s -> %s'%(mac2a((0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9)), mac2a(mac)))

    header = encoded_data[:40]
    version = bytes(unpack('>I', encoded_data[4:8]))
    mac = bytes(unpack('BBBBBB', encoded_data[8:14]))
    flags = unpack('>H', encoded_data[14:16])[0]
    iv = encoded_data[16:32]
    payload_ver = unpack('>I', encoded_data[32:36])[0]
    payload_len = unpack('>I', encoded_data[36:40])[0]
    payload = encoded_data[40:(40+payload_len)]

    flag = {
        'encrypted': bool(flags & 0x01),
        'zlibCompressed': bool(flags & 0x02),
        'SnappyCompression': bool(flags & 0x04),
        'encryptedGCM': bool(flags & 0x08),
    }

    key = MASTER_KEY
    if config.getboolean('gateway', 'is_adopted'):
      key = config.get('gateway', 'key')

    # decrypt if required
    if flag['encrypted']:
        if flag['encryptedGCM']:
            tag = payload[-16:]
            payload = payload[:-16]
            _aes = AES.new(a2b_hex(key), AES.MODE_GCM, iv)
            _aes.update(header)
            payload = _aes.decrypt_and_verify(payload, tag)
        else:
            payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).decrypt(payload)
            pad_size = payload[-1]
            if pad_size > AES.block_size:
                raise Exception('Response not padded or padding is corrupt')
            payload = payload[:(len(payload) - pad_size)]
    # uncompress if required
    if flags & 0x02:
        payload = zlib.decompress(payload)

    payload_json = json.loads(payload)
    return payload_json


def _create_partial_inform(config,dc):
    ports = ast.literal_eval(config.get('gateway', 'ports'))
    lan_if = [ d['ifname'] for d in ports if d['type'].lower() == 'lan' ][0]

    return json.dumps({
        'hostname': 'UBNT',
        'state': 0,
        'default': 'true',
        'inform_url':  config.get('gateway', 'url'),
        'mac':  dc.data['macs'][lan_if],
        'ip': dc.data['ip'][lan_if]['address'],
        'model': config.get('gateway', 'device'),
        'model_display': config.get('gateway', 'device_display'),
        'version': config.get('gateway', 'firmware'),
        'uptime': uptime()
    })


def _create_complete_inform(config,dc):
     ports = ast.literal_eval(config.get('gateway', 'ports'))
     lan_if = [ d['ifname'] for d in ports if d['type'].lower() == 'lan' ][0]
     wan_if = [ d['ifname'] for d in ports if d['type'].lower() == 'wan' ][0]

     return json.dumps({
         'bootrom_version': 'unknown',
         'cfgversion': config.get('provisioned', 'cfgversion'),
         'config_network_wan': {
             'type': 'dhcp',
         },
         'config_port_table': ports,
         'connect_request_ip': dc.data['ip'][lan_if]['address'],
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
         'ip': dc.data['ip'][lan_if]['address'],
         'ipv4_active_leases': [],
         'isolated': False,
         'locating': False,
         'mac': dc.data['macs'][lan_if],
         'model': config.get('gateway', 'device'),
         'model_display': config.get('gateway', 'device_display'),
         'netmask': dc.data['ip'][lan_if]['netmask'],
         'required_version': '4.0.0',
         'selfrun_beacon': True,
         'serial': dc.data['macs'][lan_if].replace(':', ''),
         'version': config.get('gateway', 'firmware'),
         'time': int(time.time()),
         'uplink': wan_if,
         'uptime': uptime(),
         'pfor-stats': [],
         'speedtest-status': {
             'latency': int(dc.data['speedtest']['ping']),
             'rundate': dc.data['speedtest']['lastrun'],
             'runtime': 6,
             'status_download': 2,
             'status_ping': 2,
             'status_summary': 2,
             'status_upload': 2,
             'xput_download': dc.data['speedtest']['download'],
             'xput_upload': dc.data['speedtest']['upload']
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
                         'intf': wan_if,
                         'metric': '1/0',
                         't': 'S>*',
                         'via': '%s' % dc.data['ip'][wan_if]['gateway']
                     }
                 ],
                 'pfx': '0.0.0.0/0'
             },
             {
                 'nh': [
                     {
                         'intf': lan_if,
                         't': 'C>*'
                     }
                 ],
                 'pfx': '%s/%s' % (dc.data['ip'][lan_if]['address'], netmask_to_cidr(dc.data['ip'][lan_if]['netmask']))
             },
         ],
         'network_table': get_network_table(dc.data, ports),
         'if_table': get_if_table(dc.data, ports),
    })


def create_inform(config,dc):
    return _create_partial_inform(config,dc) if not config.getboolean('gateway', 'is_adopted') else _create_complete_inform(config,dc)


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
