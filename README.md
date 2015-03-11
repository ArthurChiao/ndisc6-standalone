ndisc6
=======================================
Distributed under GPLv2. For full licensing details, see COPYING.
This program is for study purpose.

`ndisc6` is an IPv6 neighbor discovery tool, similar to the `arping` tool
in IPv4 network.

The source code is extracted and modified from the
[`NDisc6`](http://www.remlab.net/ndisc6/) - a package of IPv6 diagnostic tools.
While the `NDisc6` tools are designed for running on various Unix systems,
this ndisc6 is simplified, and only tested on **Linux** environment,
and it is easy to insert it into your own code.

# Compile
```bash
cd src
make
```

# Usage
```bash
./ndisc6 <dst-ipv6-addr> <device>
```
for example,
```bash
./ndisc6 fe80::be30:5bff:fef6:73b0 eth0
```
