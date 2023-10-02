# Unifi gateway daemon

Forked from https://github.com/stephanlascar/unifi-gateway

The goal of this daemon is to simulate a UGW router to the Unifi controller so your OpenWRT|pfSense|something else router can report stats to the controller.

## How it works now

First change conf/unifi-gateway.conf to yours
```bash
ports (map realif to your real interfaces)
lan_ip = 192.168.4.1
lan_mac = 0a:0a:0a:0a:0a:0a
```

Then adopt the daemon to controller by running:

```bash
python unifi_gateway.py set-adopt -s http://your.controller/inform
```

After first run, adopt from controller and run ``set-adopt`` again.

After the daemon has been adopted, you can start the daemon by running:

```bash
python unifi_gateway.py start
```

(To run in foreground use ``run`` instead of ``start``)

## Hacking it further

This is still in pretty raw state but the basic structure is there:

``unifi_gateway.py`` handles the inform loop and other daemon stuff

``unifi_protocol.py`` does the on-wire formatting and inform template filling

``datacollector.py`` collects the needed data for inform messages and stores it in intermediate format that template fillers then can use. The idea is that this will became modular in the future, so collectors for different platforms (normal linux/OpenWRT/PFSense/etc) could be added easily. For now though the collectors are built-in to the datacollector module.

## Documentation
- https://github.com/jk-5/unifi-inform-protocol
- https://github.com/fxkr/unifi-protocol-reverse-engineering
