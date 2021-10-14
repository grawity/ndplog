# ndpwatch

A script to poll the neighbor caches (aka ARP tables) from hosts and gateways, then store in a MySQL database.

The purpose of neighbor data collection is to allow tracing unknown IP addresses back to the physical device, which is especially useful for IPv6 subnets where hosts may use Privacy Extensions to rapidly switch their addresses, but may also help with IPv4 in case of hosts which have static configuration (accidentally or maliciously).

(Doesn't this defeat the point of Privacy Extensions? No, not really; they are only meant to hide you from servers – not from your own network operator who knows your layer-2 address anyway.)

### Dependencies

The following Python modules are needed:

  - `MySQLdb` (python-mysqlclient, python3-mysqldb)
  - `tikapy` (for Mikrotik RouterOS devices)

### Configuration

Linux, Solaris, and RouterOS hosts can be polled (the former via SSH, the latter via RouterOS API). See included `ndpwatch.conf.example`.
