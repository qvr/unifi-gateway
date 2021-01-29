# -*- coding: utf-8 -*-
import ConfigParser
import argparse
import logging.handlers
import socket
import time
import urllib2

import datacollector

from daemon import Daemon
from unifi_protocol import create_broadcast_message, create_inform, encode_inform, decode_inform

#handler = logging.handlers.SysLogHandler(address='/dev/log')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s [unifi-gateway] : %(levelname)s : %(message)s'))
logger = logging.getLogger('unifi-gateway')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

CONFIG_FILE = 'conf/unifi-gateway.conf'


class UnifiGateway(Daemon):

    def __init__(self, **kwargs):
        self.interval = 10
        self.config = ConfigParser.RawConfigParser()
        self.config.read(CONFIG_FILE)
        self.datacollector = datacollector.DataCollector(self.config)

        Daemon.__init__(self, pidfile=self.config.get('global', 'pid_file'), **kwargs)

    def run(self):
        broadcast_index = 1
        while not self.config.getboolean('gateway', 'is_adopted'):
            if self.config.getboolean('global','disable_broadcast'):
              logger.critical('Not adopted and TLV broadcasting disabled, run set-adopt first')
              return
            self._send_broadcast(broadcast_index)
            time.sleep(self.interval)
            broadcast_index += 1

        while True:
            self.datacollector.update()

            response = self._send_inform(create_inform(self.config,self.datacollector))
            logger.debug('Receive {} from controller'.format(response))
            if response['_type'] == 'noop':
              self.interval = response['interval']
            elif response['_type'] == 'setparam':
              for key, value in response.items():
                  if key == 'mgmt_cfg':
                    self._parse_mgmt_cfg(value)
                  if key not in ['_type', 'server_time_in_utc', 'blocked_sta']:
                      self.config.set('provisioned', key, value)
              self._save_config()
            elif response['_type'] == 'reboot':
              logger.info('Received reboot request from controller')
            elif response['_type'] == 'cmd':
              logger.info('Received CMD request: {}'.format(response['cmd']))
              # speed-test
              # set-locate
              # unset-locate
	    elif response['_type'] == 'upgrade':
	      logger.info('Received upgrade request to version {}'.format(response['version']))
	      if response['version'] != self.config.get('gateway', 'firmware'):
	        self.config.set('gateway', 'previous_firmware', self.config.get('gateway', 'firmware'))
	        self.config.set('gateway', 'firmware', response['version'])
                self._save_config()
		logger.info('New version information stored')
            elif response['_type'] == 'setdefault':
              logger.critical('Controller requested device reset, removing authkey and adopted state')
              self.config.set('gateway', 'is_adopted', False)
              self.config.set('gateway', 'key', None)
              self._save_config()
              break
            elif response['_type'] == 'httperror':
              pass
	    elif response['_type'] == 'urlerror':
	      logger.error('Connection error to controller, retry in 60 seconds: {}'.format(response['msg']))
	      self.interval = 60
            else:
              logger.warn('Unhandled response type')
            time.sleep(self.interval)

    def _send_broadcast(self, broadcast_index):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
        sock.sendto(create_broadcast_message(self.config, broadcast_index), ('233.89.188.1', 10001))

        logger.debug('Send broadcast message #{} from gateway {}'.format(broadcast_index, self.config.get('gateway', 'lan_ip')))

    def quit(self):
        pass

    def set_adopt(self, url, key):
        self.config.set('gateway', 'url', url)
        self.config.set('gateway', 'key', key)
        self._save_config()

        response = self._send_inform(create_inform(self.config,self.datacollector))
        logger.debug('Receive {} from controller'.format(response))
        if response['_type'] == 'httperror':
          if response['code'] == '404':
            logger.info('Controller has received initial inform, Adopt from GUI and re-run this command')
            return
          if response['code'] == '400':
            logger.error('Authentication to controller failed, indicates wrong authkey, device removed from controller?')
            return
	if response['_type'] == 'urlerror':
	  logger.error('Connection error to controller: {}'.format(response['msg']))
	  return

        if response['_type'] == 'setparam':
            if not self.config.getboolean('gateway', 'is_adopted'):
              logger.info('setparam received from controller, device now adopted')
              self.config.set('gateway', 'is_adopted', True)

            for key, value in response.items():
                if key == 'mgmt_cfg':
                  self._parse_mgmt_cfg(value)
                if key not in ['_type', 'server_time_in_utc', 'blocked_sta']:
                    self.config.set('provisioned', key, value)
            self._save_config()

    def _parse_mgmt_cfg(self, data):
        for row in data.split('\n'):
          s = row.split('=')
          if s[0] == 'cfgversion':
            self.config.set('provisioned', 'cfgversion', s[1])
          if s[0] == 'authkey':
            logger.debug('setting new device authkey received in mgmt_cfg')
            self.config.set('provisioned', 'key', s[1])
            self.config.set('gateway', 'key', s[1])
   #####TO Do Self test with CBC or GCM encryption
          if s[0] == 'use_aes_gcm':
            self.config.set('gateway', 'use_aes_gcm', True)
          else:
            self.config.set('gateway', 'use_aes_gcm', False)

    def _send_inform(self, data, encryption='CBC'):
        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/x-binary',
            'User-Agent': 'AirControl Agent v1.0',
            'Expect': '100-continue'         
        }
        url = self.config.get('gateway', 'url')

        request = urllib2.Request(url, encode_inform(self.config, data, encryption=encryption), headers)
        logger.debug('Send inform request to {} : {}'.format(url, data))
        try:
          response = urllib2.urlopen(request)
        except urllib2.HTTPError, e:
          return { '_type': 'httperror', 'code': str(e.code), 'msg': e.msg }
	except urllib2.URLError as e:
	  return { '_type': 'urlerror', 'msg': e.msg }
        return decode_inform(self.config, response.read())

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as config_file:
            self.config.write(config_file)


def restart(args):
    UnifiGateway().restart()


def stop(args):
    UnifiGateway().stop()


def start(args):
    UnifiGateway().start()


def run(args):
    UnifiGateway().run()


def set_adopt(args):
    url, key = None, None
    if UnifiGateway().config.has_option('gateway', 'url'):
      url = UnifiGateway().config.get('gateway', 'url')
    if args.s:
      url = args.s
    assert url

    if UnifiGateway().config.has_option('provisioned', 'key'):
      key = UnifiGateway().config.get('provisioned', 'key')
    if args.k:
      key = args.k

    UnifiGateway().set_adopt(url, key)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_start = subparsers.add_parser('start', help='start unifi gateway daemon')
    parser_start.set_defaults(func=start)

    parser_stop = subparsers.add_parser('stop', help='stop unifi gateway daemon')
    parser_stop.set_defaults(func=stop)

    parser_restart = subparsers.add_parser('restart', help='restart unifi gateway daemon')
    parser_restart.set_defaults(func=restart)

    parser_run = subparsers.add_parser('run', help='run unifi gateway daemon (in foreground)')
    parser_run.set_defaults(func=run)

    parser_adopt = subparsers.add_parser('set-adopt', help='send the adoption request to the controller')
    parser_adopt.add_argument('-s', type=str, help='controller url')
    parser_adopt.add_argument('-k', type=str, help='key')
    parser_adopt.set_defaults(func=set_adopt)

    args = parser.parse_args()
    args.func(args)
