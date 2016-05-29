import ipaddress
import subprocess

def _sh_escape(arg):
    return "'%s'" % arg.replace("'", "'\\''")

def _sh_join(args):
    return " ".join(map(_sh_escape, args))

def _fix_mac(mac):
    return ":".join(["%02x" % int(i, 16) for i in mac.split(":")])

## connector

class Connector(object):
    pass

class NullConnector(Connector):
    def __init__(self, host):
        self.host = host

class LocalConnector(Connector):
    def __init__(self, host=None):
        self.host = host

    def popen(self, args):
        return subprocess.Popen(args, stdout=subprocess.PIPE)

class SshConnector(Connector):
    def __init__(self, host):
        self.host = host

    def popen(self, args):
        return subprocess.Popen(["ssh", "-q", self.host, _sh_join(args)],
                                stdout=subprocess.PIPE)

## neighbour table

class NeighbourTable(object):
    def __init__(self, conn):
        assert(conn.popen)
        self.conn = conn

    def get_all(self):
        yield from self.get_arp4()
        yield from self.get_ndp6()

class LinuxNeighbourTable(NeighbourTable):
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
        with self.conn.popen(["ip", "-4", "neigh"]) as proc:
            yield from self._parse_neigh(proc.stdout)

    def get_ndp6(self):
        with self.conn.popen(["ip", "-6", "neigh"]) as proc:
            yield from self._parse_neigh(proc.stdout)

class FreeBsdNeighbourTable(NeighbourTable):
    def get_arp4(self):
        with self.conn.popen(["arp", "-na"]) as proc:
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

    def get_ndp6(self):
        with self.conn.popen(["ndp", "-na"]) as proc:
            for line in proc.stdout:
                line = line.strip().decode("utf-8").split()
                if line[0] != "Neighbor":
                    assert(":" in line[0])
                    yield {
                        "ip": line[0],
                        "mac": line[1],
                        "dev": line[2],
                    }

class SolarisNeighbourTable(NeighbourTable):
    def get_arp4(self):
        with self.conn.popen(["arp", "-na"]) as proc:
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

    def get_ndp6(self):
        with self.conn.popen(["netstat", "-npf", "inet6"]) as proc:
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

class SnmpNeighbourTable(NeighbourTable):
    AF_INET = 1
    AF_INET6 = 2

    def __init__(self, conn, community="public"):
        self.community = community
        super().__init__(conn)
        self._cache = {
            self.AF_INET: [],
            self.AF_INET6: [],
        }

    def _walk(self, mib):
        with self.conn.popen(["snmpbulkwalk", "-v2c",
                              "-c%s" % self.community,
                              "-Onq",
                              self.conn.host, mib]) as proc:
            for line in proc.stdout:
                line = line.strip().decode("utf-8").split()
                oid = line[0].split(".")
                value = line[1]
                yield oid, value

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
