#!/usr/bin/env python3
# ndpwatch - poll ARP & ND caches and store to database
# (c) 2016 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (dist/LICENSE.mit)
from nullroute.core import *
from nullroute.system.ifconfig import *
import sqlalchemy as δ
import time

_connectors = {
    "local": LocalConnector,
    "ssh": SshConnector,
}

_systems = {
    "linux": LinuxNeighbourTable,
    "bsd": FreeBsdNeighbourTable,
    "solaris": SolarisNeighbourTable,
}

config = Env.find_config_file("ndpwatch.conf")
db_url = None
hosts = []
max_age_days = 6*30
mode = "all"
verbose = False
n_arp = 0
n_ndp = 0

with open(config, "r") as f:
    for line in f:
        if line.startswith("#"):
            continue
        k, v = line.strip().split(" = ", 1)
        if k == "db":
            db_url = v
        elif k == "host":
            host_v, conn_v, sys_v, *rest = v.split(", ")
            hosts.append((host_v, _connectors[conn_v], _systems[sys_v]))
        elif k == "age":
            max_age_days = int(v)
        elif k == "mode":
            if v in {"ipv4", "ipv6", "all", "both"}:
                mode = v
            else:
                Core.die("config parameter %r has unrecognized value %r" % (k, v))

if not db_url:
    Core.die("database URL not configured")

δEngine = δ.create_engine(db_url)
δConn = δEngine.connect()

st = δ.sql.text("""
        INSERT INTO arplog (ip_addr, mac_addr, first_seen, last_seen)
        VALUES (:ip_addr, :mac_addr, :now, :now)
        ON DUPLICATE KEY UPDATE last_seen=:now
     """)

if mode == "ipv4":
    func = lambda nt: nt.get_arp4()
elif mode == "ipv6":
    func = lambda nt: nt.get_ndp6()
else:
    func = lambda nt: nt.get_all()

for host, conn_type, nt_type in hosts:
    Core.say("connecting to %s" % host)
    try:
        nt = nt_type(conn_type(host))
        now = time.time()
        for item in func(nt):
            ip = item["ip"].split("%")[0]
            mac = item["mac"]
            if ip.startswith("fe80:"):
                continue
            if verbose:
                print("- found", ip, "->", mac)
            if ":" in ip:
                n_ndp += 1
            else:
                n_arp += 1
            bound_st = st.bindparams(ip_addr=ip, mac_addr=mac, now=now)
            r = δConn.execute(bound_st)
    except IOError as e:
        Core.err("connection to %r failed: %r" % (host, e))
    Core.say(" - logged %d ARP entries, %d NDP entries" % (n_arp, n_ndp))

Core.exit_if_errors()

max_age_secs = max_age_days*86400

Core.say("cleaning up old records")
st = δ.sql.text("""
        DELETE FROM arplog WHERE last_seen < :then
     """)
r = δConn.execute(st.bindparams(then=time.time()-max_age_secs))
