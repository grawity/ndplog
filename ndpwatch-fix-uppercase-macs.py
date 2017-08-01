#!/usr/bin/env python3
# ndpwatch - poll ARP & ND caches and store to database
# (c) 2016 Mantas Mikulėnas <grawity@gmail.com>
# Released under the MIT License (dist/LICENSE.mit)
from nullroute.core import *
import sqlalchemy as δ

config = Env.find_config_file("ndpwatch.conf")
db_url = None

with open(config, "r") as f:
    for line in f:
        if line.startswith("#"):
            continue
        k, v = line.strip().split(" = ", 1)
        if k == "db":
            db_url = v

if not db_url:
    Core.die("database URL not configured")

δEngine = δ.create_engine(db_url)
δConn = δEngine.connect()

st = δ.sql.text("""
        SELECT ip_addr, mac_addr FROM arplog
        WHERE mac_addr != LOWER(mac_addr)
     """)
r = δConn.execute(st)
for ip, mac in r:
    mac = mac.lower()
    print(mac, "--", ip)

    oldest_id = 0
    first_seen = 0
    last_seen = 0

    st = δ.sql.text("""
            SELECT id, mac_addr, first_seen, last_seen FROM arplog
            WHERE ip_addr = :ip
            AND LOWER(mac_addr) = :mac
        """)
    r = δConn.execute(st.bindparams(ip=ip, mac=mac))
    r = [*r]
    print(" - found", len(r), "entries")
    for e_id, e_mac, e_first, e_last in r:
        print("   |", e_id, e_mac)
        if e_id < oldest_id or oldest_id == 0:
            oldest_id = e_id
        if e_first < first_seen or first_seen == 0:
            first_seen = e_first
        if e_last > last_seen or last_seen == 0:
            last_seen = e_last

    print(" - deleting remaining rows with {mac}".format(**locals()), end="")
    st = δ.sql.text("""
            DELETE FROM arplog
            WHERE ip_addr = :ip AND LOWER(mac_addr) = :mac AND id != :id
        """)
    r = δConn.execute(st.bindparams(id=oldest_id, ip=ip, mac=mac))
    print(" =>", r.rowcount, "rows deleted")

    print(" - updating id {oldest_id} with {first_seen}…{last_seen}".format(**locals()), end="")
    st = δ.sql.text("""
            UPDATE arplog
            SET mac_addr = :mac, first_seen = :first, last_seen = :last
            WHERE ip_addr = :ip AND LOWER(mac_addr) = :mac AND id = :id
        """)
    r = δConn.execute(st.bindparams(id=oldest_id, ip=ip, mac=mac, first=first_seen, last=last_seen))
    print(" =>", r.rowcount, "rows updated")
