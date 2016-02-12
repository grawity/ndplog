#!/usr/bin/env python3
from ipaddress import *
from nullroute.system.ifconfig import *
from pprint import pprint
import sqlalchemy as δ
import sqlalchemy.orm
import time

## main

MAX_IPV4_LEN = len("255.255.255.255")
MAX_IPV6_LEN = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
MAX_MAC_LEN = len("ff:ff:ff:ff:ff:ff")

hosts = [
    ("mantas@uk-pf-aukstaiciu9", SshConnector, FreeBsdNeighbourTable),
    ("mantas@uk-pf-ausros73", SshConnector, FreeBsdNeighbourTable),
    ("mantas@uk-pf-m18-adm", SshConnector, FreeBsdNeighbourTable),
    ("mantas@uk-pf-m18-stud", SshConnector, FreeBsdNeighbourTable),
    ("mantas@uk-pf-maironio7", SshConnector, FreeBsdNeighbourTable),
    ("mantas@uk-pf-utenio2", SshConnector, FreeBsdNeighbourTable),
    ("root@uk-untangle", SshConnector, LinuxNeighbourTable),
    #("root@uk-nas1", SshConnector, SolarisNeighbourTable),
]

#δBase = δ.ext.declarative.declarative_base()
#
#class Assoc(δBase):
#    __tablename__ = "arplog"
#
#    id          = δ.Column(δ.Integer, δ.Sequence("arplog_seq"), primary_key=True)
#    ip_addr     = δ.Column(δ.String(MAX_IPV6_LEN), nullable=False)
#    mac_addr    = δ.Column(δ.String(MAX_MAC_LEN), nullable=False)
#    first_seen  = δ.Column(δ.Integer)
#    last_seen   = δ.Column(δ.Integer)

with open("/home/grawity/lib/arplog.conf") as f:
    db_url = f.readline().strip()

δEngine = δ.create_engine(db_url)
δConn = δEngine.connect()

st = δ.sql.text("""
        INSERT INTO arplog (ip_addr, mac_addr, first_seen, last_seen)
        VALUES (:ip_addr, :mac_addr, :now, :now)
        ON DUPLICATE KEY UPDATE last_seen=:now
     """)

for host, conn_type, nt_type in hosts:
    nt = nt_type(conn_type(host))
    for item in nt.get_ndp6():
        ip = item["ip"].split("%")[0]
        mac = item["mac"]
        if ip.startswith("fe80"):
            continue
        print(ip, mac)
        #assoc = Assoc(ip_addr=ip, mac_addr=mac,
        #              first_seen=time.time(), last_seen=time.time())
        bound_st = st.bindparams(ip_addr=ip, mac_addr=mac, now=time.time())
        r = δConn.execute(bound_st)
