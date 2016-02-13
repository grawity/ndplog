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

_connectors = {
    "local": LocalConnector,
    "ssh": SshConnector,
}

_systems = {
    "linux": LinuxNeighbourTable,
    "bsd": FreeBsdNeighbourTable,
    "solaris": SolarisNeighbourTable,
}

db_url = None
hosts = []

with open("/home/grawity/lib/arplog.conf") as f:
    for line in f:
        if line.startswith("#"):
            continue
        k, v = line.strip().split(" = ", 1)
        if k == "db":
            db_url = v
        elif k == "host":
            host_v, conn_v, sys_v, *rest = v.split(", ")
            hosts.append((host_v, _connectors[conn_v], _systems[sys_v]))

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

δEngine = δ.create_engine(db_url)
δConn = δEngine.connect()

st = δ.sql.text("""
        INSERT INTO arplog (ip_addr, mac_addr, first_seen, last_seen)
        VALUES (:ip_addr, :mac_addr, :now, :now)
        ON DUPLICATE KEY UPDATE last_seen=:now
     """)

for host, conn_type, nt_type in hosts:
    print("connecting to", host)
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

print("cleaning up old records")
st = δ.sql.text("""
        DELETE FROM arplog WHERE last_seen < :then
     """)
r = δConn.execute(st.bindparams(then=time.time()-(86400*30*6)))
