# FreeBSD networking landscape for Arcana (SDN + IETF YANG agent contract)

Research date: 2026-10-13. Scope: FreeBSD 14.3 / 15.0 / 15.1 releases and `main` (16-CURRENT), the
FreeBSD ports tree as of today (`INDEX-15`), and upstream projects. Project rules applied when judging
fit: base system first, ports only where they remove real work, no kernel work of our own, everything in C.

How this was verified: the ports `INDEX-15` was downloaded from
<https://download.freebsd.org/ports/index/INDEX-15.bz2> on 2026-10-13 (38 877 ports) and grepped;
port Makefiles were read from <https://cgit.freebsd.org/ports/plain/...>; man pages from
<https://man.freebsd.org/cgi/man.cgi?...manpath=FreeBSD+15.0-RELEASE>; kernel sources from
<https://cgit.freebsd.org/src/plain/...> (branch `main` unless a `?h=` branch is named);
release notes from <https://cgit.freebsd.org/doc/plain/website/content/en/releases/>.
Where a claim rests on a search-engine summary rather than a primary page I say so, and where I could
not verify I say "could not verify".

Release baseline facts used below:

* FreeBSD 15.0-RELEASE: 2025-12-02 (<https://www.freebsd.org/releases/15.0R/announce/>); supported until 2029-12-31.
* FreeBSD 15.1-RELEASE: 2026-06-16 (<https://www.freebsd.org/releases/15.1R/relnotes/>, announcement via search).
* Latest 14.x release notes available: 14.3 (<https://cgit.freebsd.org/doc/plain/website/content/en/releases/14.3R/relnotes.adoc>).
* `options NETLINK` is in `sys/amd64/conf/DEFAULTS` on releng/15.0
  (<https://cgit.freebsd.org/src/plain/sys/amd64/conf/DEFAULTS?h=releng/15.0>); netlink first appeared
  as a module in 13.2 (<https://cgit.freebsd.org/doc/plain/website/content/en/releases/13.2R/relnotes.adoc>, "not included in GENERIC").
* `options ROUTE_MPATH` is in GENERIC on releng/14.3 and releng/15.0
  (<https://cgit.freebsd.org/src/plain/sys/amd64/conf/GENERIC?h=releng/15.0>, line 35); on `main` the
  compile option was retired, i.e. multipath is always on (commit "routing: Retire ROUTE_MPATH compile option",
  <https://cgit.freebsd.org/src/log/?qt=grep&q=ROUTE_MPATH>).
* GENERIC on `main` has `VIMAGE`, `IPSEC_SUPPORT`, `IPSEC_OFFLOAD`, `FIB_ALGO`, `KERN_TLS`, `device netmap`
  (<https://cgit.freebsd.org/src/plain/sys/amd64/conf/GENERIC>).

---

## 1. YANG tooling

### libyang

* **Exists:** `net/libyang3` **3.13.6** (port added 2026-04-08, maintainer olivier@, BSD-3-Clause, depends on `devel/pcre2`,
  cmake) — <https://cgit.freebsd.org/ports/plain/net/libyang3/Makefile>, <https://www.freshports.org/net/libyang3/>.
  Also `net/libyang2` **2.1.148** (<https://cgit.freebsd.org/ports/plain/net/libyang2/Makefile>). `net/libyang` 1.0.240 is
  DEPRECATED with expiry 2026-06-30 (<https://www.freshports.org/net/libyang/>) and is gone from INDEX-15.
* **Upstream:** libyang has moved past 3.x — Debian ships `libyang` 5.8.6 (<https://tracker.debian.org/media/packages/liby/libyang/control-5.8.6-2>)
  and Repology's "newest" is 6.4.6 (<https://repology.org/project/libyang/versions>). The FreeBSD port is therefore
  one or two major (ABI-breaking) versions behind. **Could not verify** what API changes 4.x–6.x bring; assume a
  C API break between 3.x and later majors and pin to the port's 3.13.6 API if we depend on it.
* **Can:** YANG 1.0/1.1 parsing, validation, JSON (RFC 7951)/XML data trees, YANG Metadata, Schema Mount, YANG Structure,
  plugins; ships `yanglint(1)` and `yangre` (<https://raw.githubusercontent.com/CESNET/libyang/master/README.md>).
* **Cannot (in 3.13.6):** CBOR/SID encoding (see below), NETCONF transport (that is libnetconf2), datastores (sysrepo).
* **Driven from C:** direct library API (`ly_ctx_*`, `lyd_*`, `lys_*`), pkg-config `libyang`. yanglint is a CLI only.
* **License:** BSD-3-Clause (port and upstream README badge).

### sysrepo / netopeer2 / libnetconf2

* **Not in ports.** No `sysrepo`, `netopeer2`, `libnetconf2` entries in INDEX-15 (grep of `INDEX-15`, 2026-10-13);
  cgit returns 404 for `net/sysrepo`, `net/netopeer2`, `net/libnetconf2`.
* Upstream latest (Repology, <https://repology.org/project/sysrepo/versions>, `.../netopeer2/...`, `.../libnetconf2/...`):
  sysrepo 5.1.0, netopeer2 2.4.5, libnetconf2 4.6.2 — all require a libyang major newer than the port's 3.13.6.
  Debian/Gentoo package them (<https://packages.debian.org/sid/admin/netopeer2>,
  <https://mirrors.edge.kernel.org/gentoo-portage/net-misc/netopeer2/netopeer2-2.2.35.ebuild>). Whether they build on
  FreeBSD: **could not verify**.
* Consequence for Arcana: a NETCONF server on FreeBSD today means either porting the CESNET stack ourselves (new ports,
  shared-memory datastore design, systemd-ish assumptions) or using clixon (below) or writing a minimal NETCONF-over-SSH
  endpoint on top of libyang3 + base `libssh`? (base has no libssh; `security/libssh` 0.12.2 is in ports).

### pyang / yanglint

* `net-mgmt/py-pyang` **2.1.1** (MIT per port; needs py-lxml) — <https://cgit.freebsd.org/ports/plain/net-mgmt/py-pyang/Makefile>;
  **no** `devel/py-pyang`. Upstream PyPI is 2.7.1 (<https://pypi.org/pypi/pyang/json>). The port's version is old
  but already contains the SID plugin: `pyang/plugins/sid.py` exists at tag `pyang-2.1.1`
  (<https://raw.githubusercontent.com/mbj4668/pyang/pyang-2.1.1/pyang/plugins/sid.py>) and upstream README lists RFC 9595 (YANG SID)
  (<https://raw.githubusercontent.com/mbj4668/pyang/master/README.md>). Python only; usable as a build-time tool
  (`pyang --sid-generate-file`), not from the C daemon.
* `yanglint` comes with libyang3 (see above).

### RESTCONF server in ports

* **Yes: `devel/clixon` 6.5.0** ("YANG-based toolchain including CLI, NETCONF and RESTCONF interfaces"; C; port license
  APACHE20, upstream dual Apache-2.0/GPLv2; depends on `devel/cligen` 6.5.0; RESTCONF option NATIVE (embedded HTTP/1+2
  server via `www/nghttp2`) / FCGI (behind nginx) / OFF) — <https://cgit.freebsd.org/ports/plain/devel/clixon/Makefile>,
  <https://raw.githubusercontent.com/clicon/clixon/master/README.md>. Upstream latest 7.1.0
  (<https://repology.org/project/clixon/versions>). Clixon has its own YANG parser and XML datastore (not libyang)
  — stated in README as "embedded database and transaction mechanism"; **could not verify** libyang independence beyond the
  dependency list (port depends only on cligen/nghttp2). Sponsored by Netgate.
  Driven from C via its backend plugin API (plugins are `.so` loaded by `clixon_backend`), or via NETCONF/RESTCONF.
* Nothing else RESTCONF-shaped in INDEX-15 (grep `restconf|netconf` returned only libyang2/3 and clixon).

### YANG-CBOR (RFC 9254) / SID (RFC 9595) / CORECONF

* **C:** no implementation in ports or base. libyang has an **open, unmerged** PR #2449 "Add CBOR Support to libyang (#2130)"
  (opened 2025-11-03, uses `libcbor`, optional at build time); IETF 125 (March 2026) slides still call it work in progress
  (<https://datatracker.ietf.org/meeting/125/materials/slides-125-netconf-cbor-encoding-for-https-based-yang-notifications-transport-00>,
  <https://datatracker.ietf.org/meeting/123/materials/slides-123-hackathon-sessd-adding-cbor-support-in-libyang-00>;
  PR copy at <https://ohotnik.duckdns.org/CESNET/libyang/pull/2449> — official GitHub was not reachable from this session,
  so merge status **could not be verified**).
* **CORECONF:** draft-ietf-core-comi is at -21 (March 2026), not an RFC (<https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-core-comi-21.txt>).
  Only known open implementation: **pycoreconf** (Python, needs the `ltn22/pyang` fork for SID files, cbor2)
  (<https://pypi.org/project/pycoreconf/0.0.4>, <https://raw.githubusercontent.com/alex-fddz/pycoreconf/main/README.md>). Not on FreeBSD.
* **Building blocks on FreeBSD for a C implementation:** `net/libcoap` 4.3.5 (C, BSD-2, GnuTLS)
  (<https://cgit.freebsd.org/ports/plain/net/libcoap/Makefile>), `devel/libcbor` 0.14.0, `devel/tinycbor` 7.0 (INDEX-15).
  Base has `lib/libcbor` but it is `PRIVATELIB` (for libfido2) and not linkable by third parties
  (<https://cgit.freebsd.org/src/plain/lib/libcbor/Makefile>). Base `libnv` (nvlist, `PACKAGE=runtime`) is public
  (<https://cgit.freebsd.org/src/plain/lib/libnv/Makefile>) but is not CBOR.
* Conclusion: YANG-CBOR/SID on FreeBSD is green-field C work (libyang3 for the schema side + hand-written CBOR
  encoder per RFC 9254, SIDs generated offline with pyang).

### gNMI / gRPC on FreeBSD

* `devel/grpc` **1.84.0** (C++; port license BSD3CLAUSE) and `devel/py-grpcio` 1.84.0, `net/grpcurl`, `net/grpcui`,
  `devel/protobuf-c` 1.5.2, `devel/nanopb` 0.4.9.1, `www/libnghttp2` 1.70.0 (INDEX-15).
  gRPC's C core is "a low level API... other languages are built on top" (<https://raw.githubusercontent.com/grpc/grpc/master/src/core/README.md>);
  practical use from plain C is unsupported upstream — a C gNMI server means either C++ or hand-rolled HTTP/2 (libnghttp2) + protobuf-c.
* **No gNMI port** (no `gnmi`/`gnmic` in INDEX-15). `gnmic` upstream 0.49.0 (Go) and nixpkgs lists FreeBSD among its
  platforms (<https://mynixos.com/nixpkgs/package/gnmic>), so it builds with the ports `lang/go`. `net/gobgp` 3.25.0 (Apache-2.0, Go) has a gRPC API.
* **YANG-Push / gNMI servers:** none in ports; nothing in base.

---

## 2. Routing

### BIRD 3.x

* `net/bird3` **3.4.0** (GPLv2, maintainer olivier@) — <https://cgit.freebsd.org/ports/plain/net/bird3/Makefile>;
  upstream 3.4.0 released 2026-10-12 (NEWS: <https://gitlab.nic.cz/labs/bird/-/raw/v3.4.0/NEWS>) — the port is current.
  `net/bird2` 2.20.0 also exists with flavors `netlink` (default) and `rtsock` (<https://cgit.freebsd.org/ports/plain/net/bird2/Makefile>).
* **Protocols built by the port:** options BFD BABEL BMP BGP MRT OSPF PIPE RADV RIP RPKI (all default) plus `static`
  (`RT_PROT+= static`), passed as `--with-protocols`. Upstream's full list is
  `aggregator bfd babel bgp bmp [bridge] evpn l3vpn mrt ospf pipe radv rip rpki static`
  (<https://gitlab.nic.cz/labs/bird/-/raw/v3.4.0/configure.ac>, line 365). **So the FreeBSD package does not build
  `l3vpn`, `aggregator`, `evpn` or `bridge`.** Kernel/Device/Direct are always built. Flowspec is a BGP channel / table type,
  not a protocol, so it is available. RPKI needs `security/libssh`.
* **System backend:** the port forces `--with-sysconfig=bsd-netlink` — BIRD 3 on FreeBSD talks netlink, not rtsock.
  The 2022 FreeBSD-netlink patch supported "multiple tables, multipath, nexthops and nexthop groups. No MPLS support yet";
  RTA_PREFSRC and "prohibit" nexthops were unsupported then
  (<https://bird.network.cz/pipermail/bird-users/2022-December/016448.html>,
  <https://bird.network.cz/pipermail/bird-users/2022-December/016413.html>). NEWS mentions "BSD: Support for IPv4 routes
  with IPv6 nexthop on FreeBSD" and "BSD: fixed onlink flag assumption with Netlink".
* **Kernel protocol:** `kernel table N` selects a FIB; `merge paths [limit N]` for ECMP export; `metric` and `netlink rx buffer`
  are Linux-only (<https://gitlab.nic.cz/labs/bird/-/raw/v3.4.0/doc/bird.sgml>, labels `krt-kernel-table`, `krt-merge-paths`).
  Privilege restriction "is not implemented in BSD port of BIRD" (same doc, line 209).
* **Flowspec:** `flow4`/`flow6` tables (SAFI 133), RFC 8955 validation (`validate`/`base table` on flowspec channels)
  (bird.sgml §"Flowspec for IPv4 and IPv6" and `bgp-validate`). BIRD only redistributes/originates flowspec; it does not
  install rules into any firewall ("Insertion of the rules into kernel is not implemented",
  <https://bird.network.cz/pipermail/bird-users/2018-February/011961.html>). Filters "do not support much flowspec parsing"
  (bird.sgml line 1940).
* **MPLS/L3VPN/EVPN:** present upstream (MPLS subsystem since 2.14, L3VPN RFC 4364, EVPN with VXLAN in 2.20 via Linux netlink bridge),
  but (a) the port does not build l3vpn/evpn, and (b) FreeBSD has no MPLS data plane (see below).
* **BMP:** working since 3.0.0 (NEWS). **ASPA:** yes. **BFD, Babel, RIP, OSPF, RAdv, Pipe, MRT, RPKI (RTR over TCP/SSH, TCP-MD5):** yes.
* **Driven from C:** BIRD has no library; control is the `birdc` text protocol over the UNIX control socket
  (`/var/run/bird.ctl`, numeric-coded replies) plus config file + `configure` reload. Route export to a daemon:
  not supported natively (no FPM equivalent); one would read the kernel via netlink instead.
* **Flowspec enforcement on FreeBSD data plane:** nothing exists. Would be an Arcana component: read BIRD's flow4/flow6 table
  (CLI socket) and program `ipfw` tables/rules (`deny`, `pipe` for rate, `setdscp`, `fwd`) or `pf` anchors via libpfctl. FRR/OpenBGPD
  likewise only distribute flowspec (below).

### FRRouting

* `net/frr10` **10.7.1_1** (GPLv2, maintainer olivier@) — <https://cgit.freebsd.org/ports/plain/net/frr10/Makefile>;
  upstream newest is also 10.7.1 (<https://repology.org/project/frr/versions>). `net/frr9` 9.1.3_2 also present.
  Options: BACKTRACE, FPM (default on), RPKI (default, `net-mgmt/rtrlib`), LDPD (off), MULTIPATH (64 vs 16), SNMP, SCRIPTING (lua 5.3),
  CONFIGROLLBACKS (sqlite), PAM, SHARPD, TCMALLOC, DATACENTER.
* **Feature matrix (docs stable-10.6, FreeBSD column)** — <https://docs.frrouting.org/en/stable-10.6/_sources/about.rst.txt>:
  zebra Y; **VRF N**; **MPLS N**; Backup Nexthops N; Nexthop-group weight 16-bit N; **pbrd N**; bgpd Y; VRF/L3VPN **CP**
  (control-plane only); **EVPN CP**; VNC CP; **Flowspec CP**; **ldpd N**; VPWS/VPLS N; nhrpd N; ospfd Y; **Segment Routing N**;
  ospf6d Y; isisd Y; ripd/ripngd/babeld/eigrpd Y; pimd Y (SSM Y, ASM N, EVPN BUM N); **vrrpd N**.
  The FreeBSD 14 build guide says "MPLS is not supported on FreeBSD... LDP can be built, but may have limited use" and
  "PIM for IPv6 is not currently supported" (<https://docs.frrouting.org/projects/dev-guide/en/latest/building-frr-for-freebsd14.html>).
* **Kernel interface:** "the Netlink interface is used on Linux, and route sockets are used on FreeBSD"
  (<https://docs.frrouting.org/en/latest/zebra.html>). VRF backend needs Linux VRF devices or netns (`--vrfwnetns`), so on
  FreeBSD only the default VRF exists; FreeBSD's multiple FIBs are **not** mapped to FRR VRFs.
* **Useful for a C daemon:** FPM (`dplane_fpm_nl`) streams the FIB as netlink-format messages over a TCP socket — a clean,
  documented way for Arcana to consume FRR's routes (zebra.html, "FIB push interface"). vtysh is the CLI; there is no C library API,
  but `mgmtd`/northbound and a gRPC northbound exist upstream (`grpc.html` in the docs index) — gRPC northbound is not enabled by the port.

### OpenBGPD

* `net/openbgpd9` **9.2** (port says MIT; maintainer pi@; libevent; options BGPLGD looking-glass daemon) —
  <https://cgit.freebsd.org/ports/plain/net/openbgpd9/Makefile>; `net/openbgpd8` 8.9, `net/openbgpd7` 7.9; plain `net/openbgpd` was removed 2025.
  Portable tree "known to build and work on ... FreeBSD" (<https://raw.githubusercontent.com/openbgpd-portable/openbgpd-portable/master/README.md>).
* **FIB on FreeBSD:** `kroute-freebsd.c` is compiled when `HOST_FREEBSD` (routing socket); `fib-update`, `fib-priority`, `rtable N`
  (= FreeBSD FIB number) are in bgpd.conf (<https://raw.githubusercontent.com/openbgpd-portable/openbgpd-portable/master/src/bgpd/Makefile.am>,
  <https://man.openbsd.org/bgpd.conf.5>). 8.8 "Fix FIB handling on FreeBSD when an interface is destroyed"; 8.9 "Fix a busy loop error
  in the pfkey handling for OpenBSD and FreeBSD" (<https://ftp.openbsd.org/pub/OpenBSD/OpenBGPD/openbgpd-8.9-relnotes.txt>).
* **pf tables:** `pftable.c` (uses `/dev/pf` `DIOCR*` ioctls) is built when `HAVE_PFTABLE`; FreeBSD's pf has those ioctls, but whether
  the FreeBSD port enables it **could not be verified** (the port Makefile has no explicit option). CARP interaction is OpenBSD-only
  (`carp-disabled.c` elsewhere).
* **Flowspec:** added in 8.0 — "Right now only announcement of flowspec rules is possible"
  (<https://ftp.openbsd.org/pub/OpenBSD/OpenBGPD/openbgpd-8.0-relnotes.txt>). bgpd.conf `flowspec (inet|inet6) rule [set ...]`, action
  via ext-communities (`ext-community flow-rate ...`), `announce flowspec` on neighbors; bgpctl `flowspec add|delete|flush|show`
  (<https://man.openbsd.org/bgpd.conf.5>, <https://man.openbsd.org/bgpctl.8>). No enforcement into pf; receive side is RIB only
  (**could not verify** whether 9.x learns received flowspec into the RIB for `bgpctl show rib`).
* **Filters:** prefix-set, as-set, origin-set, roa-set, ASPA (RTR, with IPsec/TCP-MD5 to RTR since 8.7), communities/large/ext
  communities, add-path send/receive, MRT dumps, graceful restart, `rde evaluate all`; 9.2 "Automatically set 'fib-update no' when the
  extended nexthop encoding..." (<https://ftp.openbsd.org/pub/OpenBSD/OpenBGPD/openbgpd-9.2-relnotes.txt>).
* **Driven from C:** `bgpctl` over a UNIX socket using OpenBSD `imsg` framing (not a stable public API); config reload via SIGHUP.

### FreeBSD kernel routing

* **Nexthops / multipath:** FreeBSD 13 rewrote routing around nexthop objects; multipath "featuring 64-wide multipath routes with
  O(1) lookup", `ROUTE_MPATH` default, `net.route.multipath` sysctl
  (<https://cgit.freebsd.org/doc/plain/website/content/en/releases/13.0R/relnotes.adoc>). Nexthop groups are immutable, weighted
  (default 1, max 2^24-1), max datapath width 64 (<https://papers.FreeBSD.org/2021/eurobsdcon/chernikov-routing_freebsd_13.files/chernikov-routing_freebsd_13.pdf>).
  Code: `sys/net/route/{nhop.c,nhgrp.c,nhgrp_ctl.c,route_ctl.c,route_subscription.c,route_temporal.c}`
  (<https://cgit.freebsd.org/src/tree/sys/net/route>).
* **fib_algo:** `options FIB_ALGO` in GENERIC; IPv4 algorithms `bsearch4`, `radix4`, `radix4_lockless` built-in
  (<https://cgit.freebsd.org/src/plain/sys/netinet/in_fib_algo.c>), IPv6 `radix6`, `radix6_lockless`; `dpdk_lpm4`/`dpdk_lpm6`
  and `fib_dxr` are loadable modules (<https://cgit.freebsd.org/src/tree/sys/modules>, 13.2 relnotes). Sysctls under `net.route.algo.*`.
* **Multiple FIBs:** `options ROUTETABLES=N` or tunable `net.fibs=N`, N < 65536; `setfib(1)`, `setfib(2)`, `SO_SETFIB`
  (<https://man.freebsd.org/cgi/man.cgi?query=setfib&sektion=2&manpath=FreeBSD+15.0-RELEASE>). 14.0 added `defaultrouter_fibN`
  rc.conf variables (14.0 relnotes). 15.0 added `net.inet.{tcp,udp,raw}.bind_all_fibs` so sockets in different FIBs can bind the same
  address (<https://cgit.freebsd.org/doc/plain/website/content/en/releases/15.0R/relnotes.adoc>). ng_netflow maps FIB -> IPFIX/v9 domain_id.
  FIBs are *not* VRFs: one interface list, one ARP/ND table; IPv6 scoping is per-interface.
* **netlink(4)** (<https://man.freebsd.org/cgi/man.cgi?query=netlink&sektion=4&manpath=FreeBSD+15.0-RELEASE>):
  families `NETLINK_ROUTE` and `NETLINK_GENERIC`; `NETLINK_ADD_MEMBERSHIP`, `NETLINK_CAP_ACK`, `NETLINK_EXT_ACK`.
  Route messages implemented in `sys/netlink/route/*.c`: `RTM_{NEW,DEL,GET}ROUTE`, `RTM_{NEW,DEL,GET}LINK`, `RTM_{NEW,DEL,GET}ADDR`,
  `RTM_{NEW,DEL,GET}NEIGH`, `RTM_{NEW,DEL,GET}NEXTHOP` (nexthop groups via `NHA_GROUP`, type `NEXTHOP_GRP_TYPE_MPATH`)
  (<https://cgit.freebsd.org/src/plain/sys/netlink/route/nexthop.c>). `RTM_NEWLINK` with `IFLA_LINKINFO/IFLA_INFO_KIND` creates and
  modifies cloned interfaces (`ifc_create_ifp_nl`, `ifc_modify_ifp_nl`) for drivers that register netlink cloners
  (<https://cgit.freebsd.org/src/plain/sys/netlink/route/iface.c>); geneve's commit states ifconfig creates it via netlink. No `RTM_*RULE`,
  no qdisc/tc messages.
  **Generic netlink families registered in the tree (`genl_register_family`):** `nlctrl` (framework), `carp` (CMD_GET/CMD_SET,
  <https://cgit.freebsd.org/src/plain/sys/netinet/ip_carp_nl.h>), **`pfctl`** (the pf family; ~50 `PFNL_CMD_*` covering rules,
  states, tables, addrs, OS fingerprints, limiters — <https://cgit.freebsd.org/src/plain/sys/netpfil/pf/pf_nl.h>), `pflow`
  (LIST/CREATE/DEL/SET/GET, <https://cgit.freebsd.org/src/plain/sys/net/pflow.h>), `nlsysevent`
  (<https://cgit.freebsd.org/src/plain/sys/netlink/netlink_sysevent.c>), `ktest` (<https://cgit.freebsd.org/src/plain/sys/tests/ktest.c>).
  **There is no `ipfw` genl family**; ipfw is controlled via `setsockopt(IP_FW3)` opcodes (`IP_FW_XADD`, `IP_FW_TABLE_XADD`,
  `IP_FW_SET_SWAP`, ... <https://cgit.freebsd.org/src/plain/sys/netinet/ip_fw.h>). `pf_nl.c` and `pflow.c` are **absent from
  releng/14.0 and releng/14.3** (cgit 404), so the pf and pflow netlink families are 15.0+.
  **C API:** `snl(3)` header-only library in base (`netlink/netlink_snl.h`, `netlink_snl_generic.h`, `netlink_snl_route.h`)
  (<https://man.freebsd.org/cgi/man.cgi?query=snl&sektion=3&manpath=FreeBSD+15.0-RELEASE>); genetlink(4)
  (<https://man.freebsd.org/cgi/man.cgi?query=genetlink&sektion=4&manpath=FreeBSD+15.0-RELEASE>). Routing socket `route(4)` remains
  (RTM_ADD/DELETE/CHANGE/GET/IFINFO/NEWADDR/IFANNOUNCE ...). `lib/libpfctl` and `lib/libifconfig` are `INTERNALLIB` (not installed as
  shared libs; <https://cgit.freebsd.org/src/plain/lib/libpfctl/Makefile>, <https://cgit.freebsd.org/src/plain/lib/libifconfig/Makefile>) —
  usable only by copying source or statically building against the tree.
* **Policy / route-based steering available today:** per-socket FIB (`SO_SETFIB`), `ipfw setfib N|tablearg` and `ipfw fwd`, pf
  `rtable N` (inbound only), pf `route-to`/`reply-to`/`dup-to` (pools, `prefer-ipv6-nexthop` in 15.0), weighted nexthop groups (ECMP),
  `lagg` hashing. No MPLS/SR steering; no tc-like classful egress scheduling except dummynet/ALTQ.
* **MPLS:** none in any release. GSoC 2026 "Native MPLS Support for FreeBSD" (mentors B. Simpson, A. Chernikov) finished phases 1–5
  in a project branch: shim header + EtherType hooks, ported OpenBSD ldpd, in-kernel LFIB (`sys/netmpls`), AF_MPLS netlink routes
  interoperating with unmodified BIRD, nhop/nhgrp ECMP. Open items: inner-packet flow hash, route(8)/netstat tooling, BIRD ECMP
  reconciliation; **`AF_MAX` bump is an ABI change "and cannot be merged within a major release"**
  (<https://wiki.freebsd.org/SummerOfCode2026Projects/NativeMPLSSupportForFreeBSD>). So: 17.0 at the earliest, not for us.
* **Segment routing (SR-MPLS/SRv6):** nothing found for FreeBSD (searches returned Linux only).

---

## 3. Data-plane features (14.x / 15.x)

Sources: ipfw(8) <https://man.freebsd.org/cgi/man.cgi?query=ipfw&sektion=8&manpath=FreeBSD+15.0-RELEASE>,
pf.conf(5) <https://man.freebsd.org/cgi/man.cgi?query=pf.conf&sektion=5&manpath=FreeBSD+15.0-RELEASE>, and the man pages linked inline.

### ipfw (base, module `ipfw`, `ipfw_nat`, `ipfw_nat64`, `ipfw_nptv6`, `ipfw_pmod`, `dummynet`)

* **Tables:** key types addr/iface/number/flow/mac; `create ... type T valtype MASK algo A limit N locked missing or-flush`;
  value types usable as `tablearg`: `skipto, pipe, fib, nat, dscp, tag, divert, netgraph, limit, nh4, mark` (ipfw(8) §lookup/valtype);
  `table NAME atomic add k v ...`, `table NAME swap OTHER`, `table NAME lookup addr`, `ipfw internal {iflist|monitor|talist|vlist}`.
* **Sets:** 32 sets; `set swap A B`, `set move`, `set enable/disable` — atomic ruleset replacement (man: "atomically swap two rulesets").
* **NAT:** in-kernel libalias (`ipfw nat`), **nat64lsn / nat64stl / nat64clat**, **nptv6** (all with create/config/stats).
* **dummynet (dnctl(8)):** schedulers `fifo, wf2q+, rr, qfq, fq_codel, fq_pie`, AQM `codel`, `pie`; pipes/queues/scheds
  (sources `sys/netpfil/ipfw/dn_sched_*.c`, `dn_aqm_*.c`).
* **Actions:** `divert`, `tee`, `netgraph cookie`, `ngtee cookie` (ng_ipfw(4), 32-bit cookies since 15.0), `setfib`, `setdscp`, `setmark`/`mark`
  (32-bit sticky mark, table key), `fwd`, `tag/untag`, `reass`, `tcp-setmss`, `ipttl` match, `-D` dynamic-state listing; counters via
  `ipfw show/zero`.
* **Control from C:** `setsockopt(IP_FW3)` with TLV'd opcodes (`ip_fw.h`); no public library; `ipfwpcap(8)`/divert sockets for packets.

### pf (base, modules `pf`, `pflog`, `pfsync`, `pflow`)

* **Anchors** (nested, `load anchor`, per-anchor tables via `pfctl -a`), **ALTQ** (`cbq`, `priq`, `hfsc`, `fairq`, `codel`),
  **dummynet in pf** (`dnpipe`, `dnqueue`, both directions), **`rtable N`**, `route-to/reply-to/dup-to`, `prefer-ipv6-nexthop` (15.0),
  **`af-to` NAT64**, `set prio`, `set tos`, `divert-to`/`divert-reply`, **Ethernet rules** (`ether block/pass`, §ETHERNET FILTERING),
  `scrub`, `synproxy`, `syncookies`, `max-src-conn*`, `tag/tagged`, `received-on`, `ridentifier`, SCTP, `match` rules,
  `set state-defaults pflow`, OpenBSD-style NAT syntax (15.0), default-to-drop tunable `net.pf.default_to_drop` (14.3/15.0).
  All counts above come from the 15.0 pf.conf(5); 14.3 pf.conf(5) also has dnpipe/af-to (fetched).
* **pfsync(4):** protocol versions `1301` (13.x), `1400` (14.0), default 15.0 format syncs route-to/af-to/rtable/dummynet/tags/scrub;
  `syncdev`, `syncpeer` (unicast), `defer`, `maxupd`; CARP demotion coupling (<https://man.freebsd.org/cgi/man.cgi?query=pfsync&sektion=4&manpath=FreeBSD+15.0-RELEASE>).
* **pflow(4):** "imported into FreeBSD 15.0"; NetFlow v5 and **IPFIX (10)** over **UDP only** (no SCTP/TCP/DTLS); exports only states
  from rules with the `pflow` keyword; IPv4, IPv6 and **NAT44 (RFC 8158)** templates; configured with `pflowctl(8)`; netlink family `pflow`
  (<https://man.freebsd.org/cgi/man.cgi?query=pflow&sektion=4&manpath=FreeBSD+15.0-RELEASE>,
  <https://cgit.freebsd.org/src/plain/sys/netpfil/pf/pflow.c>, Netgate blog <https://netgate.com/blog/packet-flow-data>).
* **Control from C:** since 15.0, `pfctl`/`libpfctl` use the **`pfctl` generic-netlink family** (`sys/netpfil/pf/pf_nl.c`) instead of
  `/dev/pf` ioctls (bug 296521 notes the 15.0 conversion: <https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=296521>); pf(4) still
  documents the DIOC* ioctls (<https://man.freebsd.org/cgi/man.cgi?query=pf&sektion=4&manpath=FreeBSD+15.0-RELEASE>). `libpfctl` is
  INTERNALLIB. Known 15.x issue: pf netlink blocks non-VNET jails from running pfctl (bug 296521).

### netgraph (base; `libnetgraph(3)`, control via `ng_socket(4)`, `ngctl -j` jail attach in 15.0)

Node types in tree (<https://cgit.freebsd.org/src/tree/sys/netgraph>): `ng_netflow` (**v5 and v9 only**, IPv6 in v9, FIB->domain_id,
hooks `ifaceN/outN/export/export9`, msgs setdlt/setifindex/settimeouts/setconfig/settemplate/setmtu —
<https://man.freebsd.org/cgi/man.cgi?query=ng_netflow&sektion=4&manpath=FreeBSD+15.0-RELEASE>; **no IPFIX**), `ng_bridge`, `ng_vlan`,
`ng_vlan_rotate`, `ng_one2many`, `ng_tee`, `ng_bpf`, `ng_car` (srTCM RFC 2697, trTCM RFC 2698, Cisco RED-like, shaping),
`ng_pipe` (bandwidth/delay/loss/dup/BER emulation), `ng_nat`, `ng_ipfw`, `ng_tag`, `ng_patch`, `ng_checksum`, `ng_macfilter`,
`ng_hub`, `ng_eiface`, `ng_ether`, `ng_iface`, `ng_ksocket`, `ng_l2tp`, `ng_pppoe`, `ng_ppp`, `ng_mppc`, `ng_pptpgre`, `ng_gif`,
`ng_tcpmss`, `ng_split`, `ng_source`, `ng_hole`, `ng_echo`, `ng_device`, `ng_UI`, `ng_async`, `ng_cisco`, `ng_frame_relay`, `ng_lmi`,
`ng_rfc1490`, `ng_vjc`, `ng_deflate`, `ng_pred1`, `ng_tty`, bluetooth nodes.
C API: `NgMkSockNode`, `NgSendMsg`, `NgSendAsciiMsg`, `NgRecvMsg`, `NgSendData`, `NgRecvData`
(<https://man.freebsd.org/cgi/man.cgi?query=netgraph&sektion=3&manpath=FreeBSD+15.0-RELEASE>). bhyve has a netgraph backend.

### Tunnels and virtual interfaces (base)

* **if_ovpn(4):** OpenVPN DCO in kernel; interface created by the OpenVPN daemon, "requires no configuration other than that done by OpenVPN"
  (<https://man.freebsd.org/cgi/man.cgi?query=ovpn&sektion=4&manpath=FreeBSD+15.0-RELEASE>); `security/openvpn` 2.7.8 in ports. Control is OpenVPN's.
* **wg(4):** in base since 13.2/14.0 ("reintegrated", 13.2 and 14.0 relnotes); configured with `wg(8)` from `net/wireguard-tools`
  1.0.20260223 (ioctl + nvlist); peers, allowed-ips, persistent keepalive (`p_persistent_keepalive_interval` in `sys/dev/wg/if_wg.c`)
  (<https://man.freebsd.org/cgi/man.cgi?query=wg&sektion=4&manpath=FreeBSD+15.0-RELEASE>, <https://cgit.freebsd.org/src/plain/sys/dev/wg/if_wg.c>).
* **if_ipsec(4):** route-based ESP tunnels, `reqid`, v4/v6 inner over v4/v6 outer; SAs from IKE daemon or `setkey`
  (<https://man.freebsd.org/cgi/man.cgi?query=if_ipsec&sektion=4&manpath=FreeBSD+15.0-RELEASE>).
* **gre(4):** `grekey`, `enable_csum`, `enable_seq`, **GRE-in-UDP (RFC 8086)**; **no keepalive** (no match in if_gre.c)
  (<https://man.freebsd.org/cgi/man.cgi?query=gre&sektion=4&manpath=FreeBSD+15.0-RELEASE>). **gif(4)**: IP-in-IP, no keepalive.
* **vxlan(4):** unicast or multicast mode, learning FDB with `vxlantimeout`, `vxlanflush`, FDB dump via `net.link.vxlan.N.ftable.dump` sysctl,
  stateless HW offload (RX/TX csum, TSO) following `vxlandev`; **no static FDB programming API and no EVPN control plane**
  (<https://man.freebsd.org/cgi/man.cgi?query=vxlan&sektion=4&manpath=FreeBSD+15.0-RELEASE>).
* **geneve(4):** `sys/net/if_geneve.c` is in **`main` only** (commit by Pouria Mousavizadeh Tehrani, 2026-04-13, review D54172,
  RFC 8926, IPv4/IPv6 unicast+multicast underlay, csum/TSO offload, netlink-based ifconfig; `IFCAP2_GENEVE_HWCSUM/HWTSO` in if.h)
  (<https://reviews.freebsd.org/D54172>, <https://cgit.freebsd.org/src/log/sys/modules/if_geneve?showmsg=1>,
  <https://cgit.freebsd.org/src/plain/sys/net/if_geneve.c>). Not in stable/15, releng/15.1 or stable/14 (cgit 404) — so 16.0 unless MFC'd.
* **vlan(4), lagg(4)** (failover, LACP, loadbalance, roundrobin, broadcast; hash from NIC RSS or `use_flowid`), **epair(4)**, **carp(4)**
  (unicast peers since 14.0; netlink family `carp`), **bridge(4)**.
* **if_bridge VLAN filtering (15.0):** `vlanfilter`, `ifuntagged`/`iftagged`/`+iftagged`/`-iftagged`, `ifvlanproto` (802.1Q/802.1ad), RSTP/STP,
  span/sticky/private; member-interface addresses now return EINVAL (compat sysctl `net.link.bridge.member_ifaddrs`, removed in 16)
  (<https://man.freebsd.org/cgi/man.cgi?query=if_bridge&sektion=4&manpath=FreeBSD+15.0-RELEASE>,
  <https://man.freebsd.org/cgi/man.cgi?query=ifconfig&sektion=8&manpath=FreeBSD+15.0-RELEASE>,
  design note <https://people.freebsd.org/~ivy/bridge_vlan_filtering.txt>; future goals RSTP/MSTP/EVPN-VXLAN bridging).
* **Stable MAC change** for bridge/epair in 15.0 (relnotes).

### netmap / VALE

* `device netmap` in GENERIC. Native drivers on FreeBSD: `cxgbe, em, iflib (igb/em), ix, ixl, re, vtnet`; others emulated.
  **VALE** software switch (`valeSSS:PPP`, ~20 Mpps/core, up to 254 ports/switch), netmap pipes, monitors, `libnetmap(3)` (public, `PACKAGE=netmap`),
  `valectl(8)` (<https://man.freebsd.org/cgi/man.cgi?query=netmap&sektion=4&manpath=FreeBSD+15.0-RELEASE>,
  <https://man.freebsd.org/cgi/man.cgi?query=vale&sektion=4&manpath=FreeBSD+15.0-RELEASE>). bhyve has `net_backend_netmap.c`
  (<https://cgit.freebsd.org/src/tree/usr.sbin/bhyve>). VALE has no OpenFlow/flow-table semantics — it is a learning L2 switch
  unless you load a custom lookup via the netmap bridge API.

### Open vSwitch / DPDK

* `net/openvswitch` **2.17.12** (Apache-2.0) — <https://cgit.freebsd.org/ports/plain/net/openvswitch/Makefile>; builds without DPDK
  (no DPDK dependency/option). OVS 2.17 LTS reached **EOL in Feb 2025** per the OVS release schedule
  (<https://docs.openvswitch.org/en/latest/internals/release-process/>); upstream newest is 4.0.0 (Repology). On FreeBSD OVS runs only the
  **userspace `netdev` datapath** (tap(4) based, "experimental", in-band control not implemented)
  (<https://docs.openvswitch.org/en/latest/intro/install/userspace/>). No kernel datapath, no netmap datapath (2014 BSDCan plan never shipped).
* `net/dpdk` **25.11.3** (BSD-3; amd64/aarch64/powerpc64le; kmods `contigmem`, `nic_uio`) and `net/dpdk-20.11`
  (<https://cgit.freebsd.org/ports/plain/net/dpdk/Makefile>, <https://doc.dpdk.org/guides/freebsd_gsg/build_dpdk.html>). PMDs marked
  FreeBSD-supported in the DPDK NIC matrix: bnxt, cxgbe, e1000, enic, fm10k(+vf), gve, i40e, iavf, ice, igb(+vf), ipn3ke, ixgbe(+vf), pcap,
  sfc, virtio — **no mlx5** (<https://doc.dpdk.org/guides/nics/overview.html>, parsed row "FreeBSD").

### Offloads, SR-IOV, RSS, hashing, marking

* **ifnet capabilities** (`sys/net/if.h`): RXCSUM/TXCSUM(+IPv6), TSO4/6, LRO, VLAN_HWTAGGING/HWFILTER/HWTSO, VXLAN_HWCSUM/HWTSO,
  GENEVE_HWCSUM/HWTSO (main), TXTLS4/6 + RXTLS4/6 (kTLS), TXRTLMT (HW rate limiting), **HWRXTSTMP**, IPSEC_OFFLOAD, TOE4/6, NETMAP, MEXTPG.
* **SR-IOV:** `iovctl(8)` + `iovctl.conf(5)`, PF/VF schemas in `/dev/iov/`
  (<https://man.freebsd.org/cgi/man.cgi?query=iovctl&sektion=8&manpath=FreeBSD+15.0-RELEASE>); PF drivers with IOV code in tree:
  ixgbe (`if_sriov.c`), e1000/igb (`if_igb_iov.c`), ice (`ice_iov.c`), ixl (`ixl_pf_iov.c`), mlx5 (`mlx5_eswitch.c`, `mlx5_vport.c`); bnxt none.
* **RSS:** `options RSS` (NOTES, not GENERIC), Toeplitz, `net.inet.rss.*` (`sys/net/rss_config.c`); `lagg` uses NIC RSS hash;
  multipath flow hashing for TCP/UDP/raw when multipath routes exist (Chernikov slides).
* **IPv6 flow label:** kernel sets it automatically (`net.inet6.ip6.auto_flowlabel`, default 1, `sys/netinet6/in6_proto.c`); no per-socket
  `IPV6_FLOWINFO` sockopt found in ip6(4) 15.0 (**could not verify** a way to set an arbitrary label per socket; raw sockets can).
* **DSCP marking:** `IP_TOS` / `IPV6_TCLASS` sockopts (ip(4), ip6(4)), `ipfw setdscp`, `pf set tos`, `ng_car` colouring.
* **Policy routing:** see §2 (setfib/SO_SETFIB, ipfw setfib/fwd, pf rtable/route-to).
* **CARP:** base, unicast peers (14.0), `net.inet.carp.*`, demotion, pfsync coupling; netlink family `carp`.
* **802.1Qbv/TSN:** nothing found for FreeBSD (no taprio equivalent; searches returned Linux only). **IP-TFS/AGGFRAG:** nothing in `sys/netipsec`.
* **Tunnel keepalives:** wg (persistent keepalive), OpenVPN (userspace), gre/gif/vxlan none; BFD comes from BIRD/FRR only.
* **TCP stacks:** `TCP_RACK`/`TCP_BBR`/`TCPHPTS` options (NOTES), `net.inet.tcp.functions_default`; CUBIC default (`CC_CUBIC` in DEFAULTS);
  SO_SPLICE (15.0); SO_MAX_PACING_RATE with HW rate limiting (cxgbe/mlx5 TXRTLMT).

---

## 4. Measurement

* **STAMP (RFC 8762):** nothing in ports or base (INDEX-15 has no `stamp`/`twamp`). Known open implementations elsewhere:
  `stamp-suite` (Rust, 2022, <https://rust-digger.code-maven.com/crates/stamp-suite>), Scapy `contrib.stamp`
  (<https://osgeo.cn/scapy/api/scapy.contrib.stamp.html>), BBF OB-STAMP (containerised, <https://broadband-forum.atlassian.net/wiki/spaces/BBF/pages/46671736/Open+Broadband+-+Simple+Two-Way+Active+Measurement+Protocol+OB-STAMP>).
  STAMP's base mode is a stateless UDP reflector — a natural small C component for Arcana using `SO_TIMESTAMP`+`SO_TS_CLOCK`.
* **TWAMP:** no port. `net/owamp` **3.3_1** (Apache-2.0 per port, maintainer pi@) installs only `owampd/owping/powstream/owfetch/owstats`
  (<https://cgit.freebsd.org/ports/plain/net/owamp/pkg-plist>) — **OWAMP only**. Upstream perfSONAR owamp is 4.4.6 (Repology) and has
  included TWAMP (`twampd`, `twping`) since perfSONAR 4.1 (<https://github.com/perfsonar/owamp/pull/16>,
  <https://lists.internet2.edu/sympa/arc/perfsonar-user/2019-07/msg00056.html>) — so updating the port to 4.x would give TWAMP for free
  (**could not verify** that 4.x builds on FreeBSD).
* **ping(8):** standard RTT output; `-D` means don't-fragment, not timestamps; ICMP timestamp replies via `net.inet.icmp.tstamprepl`
  (<https://man.freebsd.org/cgi/man.cgi?query=ping&sektion=8&manpath=FreeBSD+15.0-RELEASE>).
* **Socket timestamps:** `SO_TIMESTAMP` (µs timeval), `SO_BINTIME` (sub-ns bintime), `SO_TS_CLOCK` = `SO_TS_REALTIME_MICRO` | `SO_TS_BINTIME` |
  `SO_TS_REALTIME` (ns) | `SO_TS_MONOTONIC` (ns) (<https://man.freebsd.org/cgi/man.cgi?query=getsockopt&sektion=2&manpath=FreeBSD+15.0-RELEASE>);
  `SCM_TIME_INFO` with `ST_INFO_HW`/`ST_INFO_HW_HPREC` tells whether the stamp came from NIC hardware
  (<https://cgit.freebsd.org/src/plain/sys/sys/socket.h>). BPF: `BIOCSTSTAMP` with `BPF_T_NANOTIME`, monotonic, bintime variants (bpf(4)).
  Kernel timecounters: TSC-low/HPET (`kern.timecounter.*`, timecounters(4)); `clock_gettime` ns.
* **Alternate marking (RFC 9341/9343):** no open implementation found anywhere, FreeBSD or otherwise (search; RFC 9947 SRv6 variant has only
  vendor claims).

---

## 5. IPsec / IKE

* **Kernel (base, `IPSEC_SUPPORT` + `ipsec.ko`):** ESP ciphers `aes-cbc`, `aes-ctr`, `aes-gcm-16`, `chacha20-poly1305`, `null`; AH/ESP auth
  `hmac-sha1`, `hmac-sha2-256/384/512`, `aes-xcbc-mac`, `null`; **ESN** (`setkey -esn`, `SADB_X_SAFLAGS_ESN`); **NAT-T** (`-natt`, `-natt_mtu`,
  `udpencap.c`, `net.inet.ipsec.natt_cksum_policy`); PF_KEY (RFC 2367) + `libipsec(3)` (public, `PACKAGE=runtime`); socket policies
  `IP_IPSEC_POLICY`; `if_ipsec` VTI
  (<https://man.freebsd.org/cgi/man.cgi?query=setkey&sektion=8&manpath=FreeBSD+15.0-RELEASE>,
  <https://man.freebsd.org/cgi/man.cgi?query=ipsec&sektion=4&manpath=FreeBSD+15.0-RELEASE>, <https://cgit.freebsd.org/src/plain/sys/netipsec/xform_esp.c>).
  **Not present:** TFC padding (no `tfc` in `sys/netipsec`), IP-TFS/AGGFRAG (RFC 9347), XFRM-style marks/interfaces (reqid is the only selector).
  Deprecated RFC 8221 algorithms were removed in 13.0.
* **Inline IPsec offload:** `options IPSEC_OFFLOAD` in GENERIC 15.0 ("New in-kernel inline IPSEC offload infrastructure", driver opts in with
  `IFCAP2_IPSEC_ACCEL`); **mlx5en on ConnectX-6+** (practically CX-6 Dx/CX-7) is the only driver
  (15.0 relnotes; <https://reviews.freebsd.org/D44220>, <https://reviews.freebsd.org/D44222>; `sys/netipsec/ipsec_offload.c` is NVIDIA-copyrighted
  and **absent from stable/14** per cgit 404 → 15.0+ only).
* **strongSwan:** `security/strongswan` **6.1.0** (GPLv2; upstream newest 6.1.0) — options default on: VICI, SWANCTL, GCM, IKEV1, KDF, ML (ML-KEM), PKI,
  **KERNELLIBIPSEC** (userspace IPsec via TUN; bug 295828 asked for it for vnet jails) (<https://cgit.freebsd.org/ports/plain/security/strongswan/Makefile>,
  <https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=295828>). On FreeBSD charon uses the **kernel-pfkey** (SAD/SPD via PF_KEY) and **kernel-pfroute**
  (routes/interfaces via routing socket) plugins (plugin list: <https://docs.strongswan.org/docs/latest/plugins/plugins.html>); IPsec in GENERIC since
  11, NAT-T since 11.1 (<https://docs.strongswan.org/docs/latest/os/freebsd.html>). FreeBSD-specific limits found: no XFRM interfaces/marks;
  route-based VPN with `if_ipsec` works by matching the interface `reqid` to the CHILD_SA reqid (pfSense "routed IPsec/VTI" since 11.1,
  <https://redmine.pfsense.org/issues/8544>); reqid space ~16 k for manually specified reqids (<https://redmine.pfsense.org/issues/4188>);
  historical MOBIKE SA-update limitation (2013 forum, may be stale). Driven from C via **VICI** (UNIX socket, documented binary protocol; `libvici`
  C client ships with strongSwan) or `swanctl` CLI.
* **libreswan:** `security/libreswan` 4.12_3 is in ports (INDEX-15); FreeBSD support quality **could not verify**.
* **racoon/ipsec-tools:** `security/ipsec-tools` 0.8.2_13 still in ports (BSD-3, NAT-T/DPD/frag/hybrid options) but upstream is "PROJECT
  ABANDONED" since 2014 (<https://ipsec-tools.sourceforge.net/>). Do not build on it.
* **Base `setkey(8)`:** manual SAs/SPDs, suitable for Arcana-managed static keys if no IKE is wanted.

---

## 6. Telemetry

* **Flow export (kernel):** `pflow(4)` (15.0+, v5/IPFIX UDP, pf states only), `ng_netflow(4)` (v5/v9, any netgraph-hooked traffic, no IPFIX).
* **Flow export (userspace, ports):** `net-mgmt/softflowd` 1.0.0_1 (BSD-2; pcap-based; NetFlow v1/v5/v9 and IPFIX, PSAMP in ipfix.c; developed/tested
  on OpenBSD and Linux — <https://raw.githubusercontent.com/irino/softflowd/master/README.md>), `net-mgmt/pmacct` 1.7.9 (GPLv2; nfprobe/sfprobe IPFIX/sFlow),
  `net-mgmt/flowd` 0.9.1.
* **Collectors:** `net-mgmt/nfdump` 1.7.8 (BSD-3; NetFlow/sFlow/IPFIX; upstream 1.7.10), `net-mgmt/ipfixcol2` 2.8.0 + `libfds` (GPLv2), pmacct.
  **`goflow2`: not in ports.**
* **sFlow:** `net/hsflowd` 1.24.1 (host-sflow; README lists FreeBSD among supported platforms — <https://raw.githubusercontent.com/sflow/host-sflow/master/README>;
  port Makefile states no LICENSE), `net/sflowtool` 6.10, `net/p5-Net-sFlow`.
* **pcap:** libpcap + tcpdump 4.99.5 in base (15.0 relnotes). **DTrace:** base; 15.0 `dtrace -x oformat` JSON/XML via libxo; `in_kdtrace`/`sctp_kdtrace`
  probes in the stack.
* **Prometheus:** `sysutils/node_exporter` 1.11.0_8 (Apache-2.0); base `usr.sbin/prometheus_sysctl_exporter(8)`; `net-mgmt/prometheus-bird-exporter`,
  `sysutils/snmp_exporter`; `net-mgmt/telegraf` 1.40.1; `otelcol-contrib` 0.138.0; `net-mgmt/net-snmp` 5.9.5 and base `bsnmpd`.
* **gNMI / YANG-Push servers:** none (see §1).

---

## 7. Time / DetNet

* **Kernel time:** timecounters (TSC-low, HPET, ACPI-fast), `clock_gettime` with ns resolution, `ffclock(4)` feed-forward clock
  (<https://man.freebsd.org/cgi/man.cgi?query=timecounters&sektion=4&manpath=FreeBSD+15.0-RELEASE>).
* **Hardware RX timestamps:** `IFCAP_HWRXTSTMP`; mbuf `M_TSTMP`/`M_TSTMP_HPREC` (`rcv_tstmp` in ns, `sys/sys/mbuf.h`); set by **cxgbe** (`t4_sge.c`)
  and **mlx5en** (`mlx5_en_rx.c`; 2017 review <https://reviews.freebsd.org/D12638>); surfaced to sockets via `SCM_TIME_INFO`.
  **No PTP hardware clock framework** (no `ptp(4)`, no `*_ptp.c` in `sys/dev/e1000`, `sys/dev/ixgbe`, `sys/dev/ice`), **no TX hardware timestamps**,
  so igb/ixgbe/ice cannot do 1588 hardware timestamping on FreeBSD (searches found only Linux PHC material).
* **PTP daemons:** `net/ptpd2` 2.3.1_2 (BSD-2, 2015-era code, software timestamping) — <https://cgit.freebsd.org/ports/plain/net/ptpd2/Makefile>;
  **no linuxptp port** (INDEX-15); upstream linuxptp 4.4 is Linux-only (PHC/SO_TIMESTAMPING). NTP: base `ntpd`, ports `chrony` 4.9, `ntpsec`, `openntpd`.
* **TSN (802.1Qbv/Qav/Qci, DetNet):** nothing in FreeBSD; dummynet/ALTQ are the only egress schedulers.

---

## 8. Control-plane security (GRASP / BRSKI / ACP)

* **GRASP (RFC 8990):** reference Python 3 implementation `graspy` by Brian Carpenter ("NOT INTENDED FOR PRODUCTION USE"; tested on Windows/Linux/macOS,
  "should work on any host with ... Posix compliant TCP/IPv6") — <https://raw.githubusercontent.com/becarpenter/graspy/master/README.md>. The GRASP draft's
  implementation-status section also listed a C++ implementation from BUPT (<https://datatracker.ietf.org/doc/draft-ietf-anima-grasp-15>); no public
  code found. A GRASP rendezvous extension draft (July 2026) adds gsend/grecv to the Python prototype
  (<https://www.ietf.org/archive/id/draft-carpenter-anima-grasp-rendezvous-01.html>). **No C implementation; nothing on FreeBSD** (graspy should run
  under `lang/python3` — could not verify).
* **BRSKI (RFC 8995):** reference implementation "Minerva" (Ruby, M. Richardson, <https://github.com/ANIMAgus-minerva>, cited in RFC 8995 §"minervagithub");
  **open-brski** (Rust MASA/Registrar/Pledge + Dart agent, MIT, Munich UAS, for BRSKI-PRM — <https://datatracker.ietf.org/doc/draft-ietf-anima-brski-prm/writeup/>);
  Siemens implementations are internal. None in FreeBSD ports; Rust and Ruby toolchains exist in ports so they could in principle run — **could not verify**.
* **ACP (RFC 8994):** no open-source implementation found (search returned only the RFC). Building blocks exist on FreeBSD: IPv6 link-local ULA addressing,
  `wg`/`if_ipsec`/GRE tunnels, `security/libssh`, base OpenSSL/`certctl`; an ACP would be Arcana-built.

---

## 9. Other relevant items

* **FreeBSD 15.0 networking changes** (<https://cgit.freebsd.org/doc/plain/website/content/en/releases/15.0R/relnotes.adoc>): `SO_SPLICE`;
  pflow import; pf `net.pf.default_to_drop`, `prefer-ipv6-nexthop`, OpenBSD NAT syntax; pfsync protocol update (`version 1301/1400` compat);
  kTLS default in GENERIC; `bind_all_fibs`; `connect_inaddr_wild`; inline IPsec offload + mlx5; `ngctl -j`; ng_ipfw 32-bit cookies; removal of
  ipfw 7/8 compat; stable MAC regeneration for bridge/epair; TCP `nolocaltimewait` default change; `ip6addrctl -j`; AIM for em/igb/lem; jail descriptors
  and jail kevent filters; `sysctl -j`; vnet sysctl tunables; bhyve on arm64/riscv, `slirp` backend, NUMA; `FreeBSD-ports` repo rename; pkgbase.
* **FreeBSD 15.1** (2026-06-16): no networking-stack features of note for us (wifi/LinuxKPI, scheduler tunable, C23, Unicode); several pf SAs
  (SA-26:09 "pf silently ignores certain rules", SCTP stack overflow) and SA-26:05 route (<https://cgit.freebsd.org/doc/plain/website/content/en/releases/15.1R/relnotes.adoc>).
* **CHERI:** out of scope (CheriBSD is a separate downstream; not considered).
* **bhyve for VNFs:** `virtio-net`/`e1000` with backends `tap`, `netgraph` (`path=…,peerhook=…`), `netmap`/VALE (`net_backend_netmap.c`), `slirp`;
  arm64/riscv in 15.0; `libvmmapi`/`bhyvectl` in base (<https://man.freebsd.org/cgi/man.cgi?query=bhyve&sektion=8&manpath=FreeBSD+15.0-RELEASE>).
* **Jails with vnet as network functions:** `vnet=new`, `vnet.interface`, `epair`, per-jail pf/ipfw/netgraph/routing tables, jail descriptors and
  kevent (15.0), `ngctl -j`, `sysctl -j`, `ip6addrctl -j`; `net.fibs` is per-vnet (`sysctl -j foo net.fibs=2` example in 14.3/15.0 relnotes);
  `libjail(3)` in base. Caveat: pf netlink in 15.x blocks *non*-vnet jails from pfctl (bug 296521).
* **Base C libraries useful to Arcana:** `libnv` (nvlist), `libucl`, `libxo`, `libsbuf`, `libifconfig` (INTERNALLIB — copy), `libpfctl` (INTERNALLIB — copy),
  `snl(3)` (header-only netlink), `libnetgraph`, `libnetmap`, `libipsec`, `libjail`, `libpcap`, `libcasper`/Capsicum, OpenSSL, `libfetch`, `libssh`? (ports).

---

## Summary table: capability -> FreeBSD answer

| Capability | FreeBSD answer (as of 2026-10-13) | Where |
|---|---|---|
| YANG library (C) | libyang **3.13.6** (upstream now 5.x/6.x, API break) | port `net/libyang3`, BSD-3 |
| yanglint | yes (with libyang3) | port |
| pyang / SID generation | pyang **2.1.1** (has `sid` plugin; upstream 2.7.1) | port `net-mgmt/py-pyang` |
| NETCONF server (sysrepo/netopeer2/libnetconf2) | **none** | — (build from source, unverified) |
| RESTCONF server | **clixon 6.5.0** (C, native HTTP/2 or FCGI, also NETCONF+CLI) | port `devel/clixon`, Apache-2.0/GPLv2 |
| YANG-CBOR / SID / CORECONF | **none** (libyang PR #2449 unmerged; pycoreconf is Python) | — ; building blocks `net/libcoap`, `devel/libcbor` |
| gRPC / gNMI | grpc 1.84 (C++), protobuf-c 1.5.2; **no gNMI port** | ports |
| YANG-Push / gNMI server | **none** | — |
| BGP/OSPF/BFD/Babel/RIP/RPKI/BMP/MRT/Pipe/Static | BIRD 3.4.0 (netlink backend) | port `net/bird3`, GPLv2 |
| BIRD L3VPN / EVPN / aggregator / bridge protocols | **not built by the port** (and no MPLS kernel) | — |
| BGP flowspec distribution | BIRD (flow4/flow6 + RFC 8955 validation), FRR (CP), OpenBGPD 8.0+ (announce only) | ports |
| Flowspec enforcement in data plane | **none** — needs an Arcana translator to ipfw/pf | base (ipfw/pf) + our code |
| FRR | 10.7.1; VRF/MPLS/PBR/LDP/VRRP/SR **N** on FreeBSD; EVPN/L3VPN control-plane only; FPM netlink push available | port `net/frr10`, GPLv2 |
| OpenBGPD | 9.2; FIB via rtsock; pftable (unverified on FreeBSD); flowspec announce-only | port `net/openbgpd9`, ISC/MIT |
| Multiple FIBs | base, `net.fibs` ≤ 65536, `SO_SETFIB`, `bind_all_fibs` (15.0) | base |
| ECMP / nexthop groups | base, 64-wide weighted groups, flow hashing; option retired (always on) in main | base |
| fib_algo | base: bsearch4/radix4(_lockless)/radix6(_lockless) + dpdk_lpm4/6, dxr modules | base |
| netlink(4) | base (13.2 module, DEFAULTS since 14/15): ROUTE/LINK/ADDR/NEIGH/NEXTHOP; genl: nlctrl, carp, **pfctl**, **pflow**, nlsysevent, ktest; snl(3) | base |
| ipfw | base: tables+values (nh4, fib, dscp, mark...), atomic set swap, nat/nat64lsn/stl/clat/nptv6, dummynet (wf2q+/rr/qfq/fq_codel/fq_pie, codel/pie), divert, netgraph, setfib, setdscp, `ipfw internal`; control = `IP_FW3` sockopt | base |
| pf | base: anchors, ALTQ, dummynet (dnpipe/dnqueue), rtable, af-to NAT64, ethernet rules, route-to, pfsync, pflow; control = `pfctl` genl family (15.0+) | base |
| pflow IPFIX exporter | base **15.0+** (v5/IPFIX, UDP only) | base |
| ng_netflow | base, v5/v9 only (no IPFIX) | base |
| netgraph nodes (bridge/vlan/one2many/tee/bpf/car/pipe/nat/...) | base, libnetgraph(3) | base |
| if_ovpn / wg / if_ipsec / gre(-in-UDP) / gif / vxlan / vlan / lagg / epair / carp | base | base |
| geneve | **main only** (2026-04, not in 15.x releases) | base (16-CURRENT) |
| bridge VLAN filtering | base **15.0+** (802.1Q/802.1ad, RSTP) | base |
| netmap / VALE | base (`device netmap`), libnetmap public | base |
| Open vSwitch | 2.17.12 (EOL LTS), userspace netdev datapath only, no DPDK | port `net/openvswitch` |
| DPDK | 25.11.3 (Intel/Broadcom/Chelsio/sfc/virtio PMDs, no mlx5) | port `net/dpdk` |
| SR-IOV | base `iovctl` (ixgbe, igb, ice, ixl, mlx5) | base |
| HW offloads | csum/TSO/LRO/VLAN/VXLAN/kTLS/TXRTLMT/HWRXTSTMP/IPsec inline (mlx5, 15.0) | base |
| RSS / flow label / DSCP | base (`options RSS`; `auto_flowlabel`; IP_TOS/IPV6_TCLASS, ipfw setdscp, pf set tos) | base |
| MPLS | **none** (GSoC 2026 branch; ABI bump blocks merge before 17) | — |
| Segment routing, 802.1Qbv/TSN, IP-TFS, alternate marking | **none** | — |
| STAMP / TWAMP | **none in ports** (owamp 3.3 is OWAMP-only; upstream owamp 4.x has TWAMP) | port `net/owamp` (stale) |
| Socket timestamps | base: SO_TIMESTAMP/SO_BINTIME/SO_TS_CLOCK (ns), SCM_TIME_INFO (HW flag) | base |
| HW RX timestamps | base: cxgbe, mlx5en only; no PHC, no TX stamps | base |
| PTP daemon | ptpd2 2.3.1 (software stamps); **no linuxptp** | port `net/ptpd2` |
| IKE | strongSwan 6.1.0 (VICI/swanctl; kernel-pfkey + kernel-pfroute; if_ipsec via reqid) | port `security/strongswan`, GPLv2 |
| Kernel IPsec | base: AES-CBC/CTR/GCM, ChaCha20-Poly1305, SHA2, ESN, NAT-T, if_ipsec; **no TFC pad, no IP-TFS** | base |
| IPsec offload | base 15.0+: mlx5 ConnectX-6Dx/7 inline | base |
| racoon | ports, upstream abandoned 2014 | port `security/ipsec-tools` (avoid) |
| Flow collectors / exporters | softflowd, nfdump, pmacct, ipfixcol2, flowd; **no goflow2** | ports |
| sFlow | hsflowd 1.24.1, sflowtool | ports |
| pcap / DTrace | base (tcpdump 4.99.5; dtrace libxo output in 15.0) | base |
| Prometheus | node_exporter 1.11.0 (port); `prometheus_sysctl_exporter` (base) | base + port |
| GRASP / BRSKI / ACP | graspy (Python demo), Minerva (Ruby), open-brski (Rust); **no C, nothing on FreeBSD** | — |
| VNF hosting | bhyve (tap/netgraph/netmap/slirp backends), vnet jails + epair, jail descriptors (15.0) | base |
