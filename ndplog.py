#!/usr/bin/env python3
# ndplog - poll ARP & ND caches and store to database
# (c) 2016-2021 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License
import argparse
import ipaddress
import json
import os
import re
import time
import sys
import subprocess

try:
    import MySQLdb
except ImportError:
    import mysql.connector as MySQLdb

# Log functions (which should start doing syslog one day)

def log_debug(msg):
    global verbose
    if verbose:
        print(msg)

def log_info(msg):
    print(msg, file=sys.stdout, flush=True)

def log_error(msg):
    print(msg, file=sys.stderr, flush=True)

# String utility functions

def shell_escape(arg):
    return "'%s'" % arg.replace("'", "'\\''")

def shell_join(args):
    return " ".join(map(shell_escape, args))

def canon_mac(mac):
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
            return subprocess.Popen(["ssh", self.host, shell_join(args)],
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
                "mac": canon_mac(value),
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

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--config",
                    default="/etc/ndplog.conf",
                    help="path to the configuration file")
parser.add_argument("-v", "--verbose",
                    action="store_true",
                    help="show more detail about operations")
args = parser.parse_args()

db_url = None
hosts = []
max_age_days = 6*30
verbose = args.verbose

with open(args.config, "r") as f:
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
        else:
            log_error("Unrecognized config key %r" % k)

if not db_url:
    log_error("Database URL not configured")
    exit(2)

m = re.match(r"^mysql://([^:]+):([^@]+)@([^/]+)/(.+)", db_url)
if not m:
    log_error("Unrecognized database URL %r" % db_url)
    exit(2)

conn = MySQLdb.connect(host=m.group(3),
                       user=m.group(1),
                       password=m.group(2),
                       database=m.group(4))

errors = 0
for conn_type, host, *conn_args in hosts:
    log_info("Connecting to %s [%s]" % (conn_type, host))
    n_arp = n_ndp = 0
    try:
        nt = _systems[conn_type](host, *conn_args)
        now = time.time()
        for item in nt.get_all():
            ip = item["ip"].split("%")[0]
            mac = item["mac"].lower()
            if ip.startswith("fe80:"):
                log_debug("Skipping link-local ip=%r mac=%r" % (ip, mac))
                continue
            log_debug("Found %s -> %s" % (ip, mac))
            if ":" in ip:
                n_ndp += 1
            else:
                n_arp += 1
            cursor = conn.cursor()
            log_debug("Inserting ip=%r mac=%r now=%r" % (ip, mac, now))
            cursor.execute("""INSERT INTO arplog (ip_addr, mac_addr, first_seen, last_seen)
                              VALUES (%(ip_addr)s, %(mac_addr)s, %(now)s, %(now)s)
                              ON DUPLICATE KEY UPDATE last_seen=%(now)s""",
                           {"ip_addr": ip, "mac_addr": mac, "now": now})
    except IOError as e:
        log_error("Connection to %r failed: %r" % (host, e))
        errors += 1
    log_info("[%s] Logged %d ARP entries, %d NDP entries" % (host, n_arp, n_ndp))
conn.commit()

if errors:
    log_error("Some hosts couldn't be scanned, exiting without cleanup")
    exit(1)

log_info("Cleaning up records more than %d days old" % max_age_days)
max_age_secs = max_age_days*86400
cursor = conn.cursor()
cursor.execute("DELETE FROM arplog WHERE last_seen < %(then)s",
               {"then": time.time() - max_age_secs})
conn.commit()

log_info("Finished")
conn.close()
