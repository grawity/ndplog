#!/usr/bin/env python3
# ndpwatch - poll ARP & ND caches and store to database
# (c) 2016 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (dist/LICENSE.mit)
import ipaddress
import json
import mysql.connector
from nullroute.core import Core
import os
import re
import time
import subprocess

def _sh_escape(arg):
    return "'%s'" % arg.replace("'", "'\\''")

def _sh_join(args):
    return " ".join(map(_sh_escape, args))

def _fix_mac(mac):
    return ":".join(["%02x" % int(i, 16) for i in mac.split(":")])

class NeighbourTable():
    def get_all(self):
        yield from self.get_arp4()
        yield from self.get_ndp6()

class _SshNeighbourTable(NeighbourTable):
    def __init__(self, host=None):
        if host and host != "-":
            self.host = host
        else:
            self.host = None

    def _popen(self, args):
        if self.host:
            return subprocess.Popen(["ssh", self.host, _sh_join(args)],
                                    stdout=subprocess.PIPE)
        else:
            return subprocess.Popen(args, stdout=subprocess.PIPE)

class LinuxNeighbourTable(_SshNeighbourTable):
    def _parse_neigh(self, io):
        for line in io:
            line = line.strip().decode("utf-8").split()
            ip = mac = dev = None
            i = 0
            while i < len(line):
                if i == 0:
                    ip = line[i]
                elif line[i] == "dev":
                    dev = line[i+1]
                    i += 1
                elif line[i] == "lladdr":
                    mac = line[i+1]
                    i += 1
                else:
                    pass
                i += 1
            if ip and mac:
                yield {
                    "ip": ip,
                    "mac": mac,
                    "dev": dev,
                }

    def get_arp4(self):
        with self._popen(["ip", "-4", "neigh"]) as proc:
            yield from self._parse_neigh(proc.stdout)
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

    def get_ndp6(self):
        with self._popen(["ip", "-6", "neigh"]) as proc:
            yield from self._parse_neigh(proc.stdout)
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

class LinuxNeighbourTableNew(_SshNeighbourTable):
    def _parse_neigh(self, io):
        data = json.load(io)
        for row in data:
            ip = row.get("dst")
            mac = row.get("lladdr")
            dev = row.get("dev")
            if ip and mac:
                yield {
                    "ip": ip,
                    "mac": mac,
                    "dev": dev,
                }

    def get_arp4(self):
        with self._popen(["ip", "-json", "-4", "neigh"]) as proc:
            yield from self._parse_neigh(proc.stdout)
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

    def get_ndp6(self):
        with self._popen(["ip", "-json", "-6", "neigh"]) as proc:
            yield from self._parse_neigh(proc.stdout)
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

class FreeBsdNeighbourTable(_SshNeighbourTable):
    def get_arp4(self):
        with self._popen(["arp", "-na"]) as proc:
            for line in proc.stdout:
                line = line.strip().decode("utf-8").split()
                if line[3] == "(incomplete)":
                    continue
                assert(line[0] == "?")
                assert(line[2] == "at")
                assert(line[4] == "on")
                yield {
                    "ip": line[1].strip("()"),
                    "mac": line[3],
                    "dev": line[5],
                }
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

    def get_ndp6(self):
        with self._popen(["ndp", "-na"]) as proc:
            for line in proc.stdout:
                line = line.strip().decode("utf-8").split()
                if line[0] != "Neighbor":
                    assert(":" in line[0])
                    yield {
                        "ip": line[0],
                        "mac": line[1],
                        "dev": line[2],
                    }
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

class SolarisNeighbourTable(_SshNeighbourTable):
    def get_arp4(self):
        with self._popen(["arp", "-na"]) as proc:
            header = True
            for line in proc.stdout:
                line = line.strip().decode("utf-8").split()
                if not line:
                    pass
                elif header:
                    if line[0].startswith("-"):
                        header = False
                else:
                    yield {
                        "ip": line[1],
                        "mac": line[3] if ":" in line[3] else line[4],
                        "dev": line[0],
                    }
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

    def get_ndp6(self):
        with self._popen(["netstat", "-npf", "inet6"]) as proc:
            header = True
            for line in proc.stdout:
                line = line.strip().decode("utf-8").split()
                if not line:
                    pass
                elif header:
                    if line[0].startswith("-"):
                        header = False
                else:
                    yield {
                        "ip": line[4],
                        "mac": line[1],
                        "dev": line[0],
                    }
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

class RouterOsNeighbourTable(NeighbourTable):
    def __init__(self, host, username="admin", password=""):
        self.host = host
        self.username = username
        self.password = password

        if "@" in self.host:
            cred, self.host = self.host.rsplit("@", 1)
            if ":" in cred:
                self.username, self.password = cred.split(":", 1)
            else:
                self.username = user

        self.api = self._connect()

    def _connect(self):
        import tikapy

        api = tikapy.TikapySslClient(self.host)
        api.login(self.username, self.password)
        return api

    def get_arp4(self):
        for i in self.api.talk(["/ip/arp/getall"]).values():
            if "mac-address" not in i:
                continue
            yield {
                "ip": i["address"],
                "mac": i["mac-address"],
                "dev": i["interface"],
            }

    def get_ndp6(self):
        for i in self.api.talk(["/ipv6/neighbor/getall"]).values():
            if "mac-address" not in i:
                continue
            yield {
                "ip": i["address"],
                "mac": i["mac-address"],
                "dev": i["interface"],
            }

class SnmpNeighbourTable(NeighbourTable):
    AF_INET = 1
    AF_INET6 = 2

    def __init__(self, host, community="public"):
        self.host = host
        self.community = community
        self._cache = {
            self.AF_INET: [],
            self.AF_INET6: [],
        }

    def _walk(self, mib):
        with self._popen(["snmpbulkwalk", "-v2c",
                          "-c%s" % self.community,
                          "-Onq",
                          self.host, mib]) as proc:
            for line in proc.stdout:
                line = line.strip().decode("utf-8").split()
                oid = line[0].split(".")
                value = line[1]
                yield oid, value
            if proc.wait() != 0:
                raise IOError("command %r returned %r" % (proc.args, proc.returncode))

    def get_all(self, only_af=None):
        if only_af and self._cache[only_af]:
            yield from self._cache[only_af]

        idx2name = {}
        for oid, value in self._walk("IF-MIB::ifName"):
            ifindex = int(oid[12])
            idx2name[ifindex] = value

        for oid, value in self._walk("IP-MIB::ipNetToPhysicalPhysAddress"):
            ifindex = int(oid[11])
            af = int(oid[12])
            if af not in self._cache:
                continue
            addr = bytes([int(c) for c in oid[14:]])
            item = {
                "ip": ipaddress.ip_address(addr),
                "mac": _fix_mac(value),
                "dev": idx2name.get(ifindex, ifindex),
            }
            self._cache[af].append(item)
            if not only_af or only_af == af:
                yield item

    def get_arp4(self):
        yield from self.get_all(only_af=self.AF_INET)

    def get_ndp6(self):
        yield from self.get_all(only_af=self.AF_INET6)

_systems = {
    "linux": LinuxNeighbourTable,
    "bsd": FreeBsdNeighbourTable,
    "solaris": SolarisNeighbourTable,
    "routeros": RouterOsNeighbourTable,
}

config = os.path.expanduser("~/.config/nullroute.eu.org/ndpwatch.conf")
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
            v = [_.strip() for _ in v.split(",")]
            hosts.append(v)
        elif k == "age":
            max_age_days = int(v)

if not db_url:
    Core.die("database URL not configured")

m = re.match(r"^mysql://([^:]+):([^@]+)@([^/]+)/(.+)", db_url)
if not m:
    Core.die("unrecognized database URL %r", db_url)
conn = mysql.connector.connect(host=m.group(3),
                               user=m.group(1),
                               password=m.group(2),
                               database=m.group(4))

for conn_type, host, *conn_args in hosts:
    Core.say("connecting to %s" % host)
    n_arp = n_ndp = 0
    try:
        nt = _systems[conn_type](host, *conn_args)
        now = time.time()
        for item in nt.get_all():
            ip = item["ip"].split("%")[0]
            mac = item["mac"].lower()
            if ip.startswith("fe80:"):
                Core.trace("skipping link-local ip=%r mac=%r", ip, mac)
                continue
            if verbose:
                print("- found", ip, "->", mac)
            if ":" in ip:
                n_ndp += 1
            else:
                n_arp += 1
            cursor = conn.cursor()
            Core.trace("inserting ip=%r mac=%r now=%r", ip, mac, now)
            cursor.execute("""INSERT INTO arplog (ip_addr, mac_addr, first_seen, last_seen)
                              VALUES (%(ip_addr)s, %(mac_addr)s, %(now)s, %(now)s)
                              ON DUPLICATE KEY UPDATE last_seen=%(now)s""",
                           {"ip_addr": ip, "mac_addr": mac, "now": now})
    except IOError as e:
        Core.err("connection to %r failed: %r", host, e)
    Core.say(" - logged %d ARP entries, %d NDP entries" % (n_arp, n_ndp))

conn.commit()
Core.exit_if_errors()

max_age_secs = max_age_days*86400

Core.say("cleaning up old records")

cursor = conn.cursor()
cursor.execute("DELETE FROM arplog WHERE last_seen < %(then)s",
               {"then": time.time() - max_age_secs})

conn.commit()
conn.close()
Core.fini()
