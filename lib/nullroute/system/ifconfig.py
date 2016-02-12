import subprocess

def sh_escape(arg):
    return "'%s'" % arg.replace("'", "'\\''")

def sh_join(args):
    return " ".join(map(sh_escape, args))

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
        return subprocess.Popen(["ssh", "-q", self.host, sh_join(args)],
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
