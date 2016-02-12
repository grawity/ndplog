#!/usr/bin/env python3
from ipaddress import *
from pprint import pprint
from nullroute.system.ifconfig import *

## main

hosts = [
    ("uk-pf-aukstaiciu9", SshConnector, FreeBsdNeighbourTable),
    ("uk-pf-ausros73", SshConnector, FreeBsdNeighbourTable),
    ("uk-pf-m18-adm", SshConnector, FreeBsdNeighbourTable),
    ("uk-pf-m18-stud", SshConnector, FreeBsdNeighbourTable),
    ("uk-pf-maironio7", SshConnector, FreeBsdNeighbourTable),
    ("uk-pf-utenio2", SshConnector, FreeBsdNeighbourTable),
    #("uk-untangle", SshConnector, LinuxNeighbourTable),
    #("uk-nas1", SshConnector, SolarisNeighbourTable),
]

ip_mac = {}
mac_ip = {}

for host, conn_type, nt_type in hosts:
    nt = nt_type(conn_type("root@%s" % host))
    for item in nt.get_ndp6():
        ip = item["ip"]
        mac = item["mac"]
        if item["ip"].startswith("fe80:"):
            continue
        ip_mac[item["ip"]] = item["mac"]

pprint(ip_mac)
