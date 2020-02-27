#!/usr/bin/env python3
# ndpwatch - poll ARP & ND caches and store to database
# (c) 2016 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (dist/LICENSE.mit)
import mysql.connector
from nullroute.core import *
from nullroute.system.ifconfig import *
import re
import time

_connectors = {
    "local": LocalConnector,
    "none": NullConnector,
    "ssh": SshConnector,
}

_systems = {
    "linux": LinuxNeighbourTable,
    "bsd": FreeBsdNeighbourTable,
    "solaris": SolarisNeighbourTable,
    "routeros": RouterOsNeighbourTable,
}

config = Env.find_config_file("ndpwatch.conf")
db_url = None
hosts = []
max_age_days = 6*30
mode = "all"
verbose = False

with open(config, "r") as f:
    for line in f:
        if line.startswith("#"):
            continue
        k, v = line.strip().split(" = ", 1)
        if k == "db":
            db_url = v
        elif k == "host":
            v = v.split(",")
            v = [_.strip() for _ in v]
            host_v, conn_v, user_v, pass_v, sys_v, *rest = v
            hosts.append((host_v,
                          _connectors[conn_v],
                          [user_v, pass_v],
                          _systems[sys_v]))
        elif k == "age":
            max_age_days = int(v)
        elif k == "mode":
            if v in {"ipv4", "ipv6", "all", "both"}:
                mode = v
            else:
                Core.die("config parameter %r has unrecognized value %r" % (k, v))

if not db_url:
    Core.die("database URL not configured")

m = re.match(r"^mysql://([^:]+):([^@]+)@([^/]+)/(.+)", db_url)
if not m:
    Core.die("unrecognized database URL %r", db_url)
conn = mysql.connector.connect(host=m.group(3),
                               user=m.group(1),
                               password=m.group(2),
                               database=m.group(4))

if mode == "ipv4":
    func = lambda nt: nt.get_arp4()
elif mode == "ipv6":
    func = lambda nt: nt.get_ndp6()
else:
    func = lambda nt: nt.get_all()

for host, conn_type, user_pass, nt_type in hosts:
    Core.say("connecting to %s" % host)
    n_arp = n_ndp = 0
    try:
        if user_pass[0] != "-":
            if user_pass[1] != "-":
                host = "%s:%s@%s" % (user_pass[0], user_pass[1], host)
            else:
                host = "%s@%s" % (user_pass[0], host)
        nt = nt_type(conn_type(host))
        now = time.time()
        for item in func(nt):
            ip = item["ip"].split("%")[0]
            mac = item["mac"].lower()
            if ip.startswith("fe80:"):
                continue
            if verbose:
                print("- found", ip, "->", mac)
            if ":" in ip:
                n_ndp += 1
            else:
                n_arp += 1
            cursor = conn.cursor()
            cursor.execute("""INSERT INTO arplog (ip_addr, mac_addr, first_seen, last_seen)
                              VALUES (%(ip_addr)s, %(mac_addr)s, %(now)s, %(now)s)
                              ON DUPLICATE KEY UPDATE last_seen=%(now)s""",
                           {"ip_addr": ip, "mac_addr": mac, "now": now})
    except IOError as e:
        Core.err("connection to %r failed: %r" % (host, e))
    Core.say(" - logged %d ARP entries, %d NDP entries" % (n_arp, n_ndp))

Core.exit_if_errors()

max_age_secs = max_age_days*86400

Core.say("cleaning up old records")

cursor = conn.cursor()
cursor.execute("DELETE FROM arplog WHERE last_seen < %(then)s",
               {"then": time.time() - max_age_secs})

conn.close()
Core.fini()
