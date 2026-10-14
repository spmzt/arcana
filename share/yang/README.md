# The YANG corpus

The IETF and IANA modules Arcana is to implement or build on
([../../docs/PLAN-SDN-YANG.md](../../docs/PLAN-SDN-YANG.md), step
0.2.1), as published: each extracted from its RFC between `<CODE
BEGINS>` and `<CODE ENDS>`, or taken from the IANA YANG parameters
registry for the modules IANA maintains (`iana-*`, current revisions
as of 2026-10-13), for the dependencies the named RFCs did not carry,
and for `ietf-yang-types` and `ietf-inet-types` at RFC 9911's revision
(2025-12-22, which replaces RFC 6991's and against which their IETF SID
ranges are registered). Nothing here is edited; a deviation, when Arcana needs one, is a
module of its own.

`lint.sh` compiles every module with `yanglint` (net/libyang3 3.13.6),
alone and all together, and checks that Arcana's deviations hold. It is a developer's check: building Arcana does
not need libyang (D-3), only regenerating the C code from these will.

`ietf-ipv6-router-advertisements` is a submodule of
`ietf-ipv6-unicast-routing`, compiled with it. `ietf-l3vpn-ntw`,
`ietf-network-vpn-pm`, `ietf-te-topology` and `ietf-vn` use identities
of modules they import as defaults, so they compile with their imports
implemented (`yanglint -i`), as an implementation of them will.

| File | | Source |
|---|---|---|
| `iana-crypt-hash@2014-08-06.yang` | module | IANA registry |
| `iana-icmpv4-types@2025-12-22.yang` | module | IANA registry |
| `iana-icmpv6-types@2025-12-22.yang` | module | IANA registry |
| `iana-if-type@2026-03-17.yang` | module | IANA registry |
| `iana-ipv6-ext-types@2025-12-22.yang` | module | IANA registry |
| `iana-routing-types@2025-09-03.yang` | module | IANA registry |
| `ietf-access-control-list@2019-03-04.yang` | module | RFC 8519 |
| `ietf-alarms-x733@2019-09-11.yang` | module | RFC 8632 |
| `ietf-alarms@2019-09-11.yang` | module | RFC 8632 |
| `ietf-datastores@2018-02-14.yang` | module | RFC 8342 |
| `ietf-ethertypes@2019-03-04.yang` | module | RFC 8519 |
| `ietf-i2nsf-ike@2021-07-14.yang` | module | RFC 9061 |
| `ietf-i2nsf-ikec@2021-07-14.yang` | module | RFC 9061 |
| `ietf-i2nsf-ikeless@2021-07-14.yang` | module | RFC 9061 |
| `ietf-inet-types@2025-12-22.yang` | module | IANA, RFC 9911 |
| `ietf-interfaces@2018-02-20.yang` | module | RFC 8343 |
| `ietf-ip@2018-02-22.yang` | module | RFC 8344 |
| `ietf-ipsec-iptfs@2023-01-31.yang` | module | RFC 9348 |
| `ietf-ipv4-unicast-routing@2018-03-13.yang` | module | RFC 8349 |
| `ietf-ipv6-router-advertisements@2018-03-13.yang` | submodule | RFC 8349 |
| `ietf-ipv6-unicast-routing@2018-03-13.yang` | module | RFC 8349 |
| `ietf-key-chain@2017-06-15.yang` | module | RFC 8177 |
| `ietf-l3vpn-ntw@2022-02-14.yang` | module | RFC 9182 |
| `ietf-lime-time-types@2019-04-16.yang` | module | IANA, RFC 8532 |
| `ietf-logical-network-element@2019-01-25.yang` | module | RFC 8530 |
| `ietf-netconf-acm@2018-02-14.yang` | module | RFC 8341 |
| `ietf-netconf@2011-06-01.yang` | module | RFC 6241 |
| `ietf-network-instance@2019-01-21.yang` | module | RFC 8529 |
| `ietf-network-state@2018-02-26.yang` | module | RFC 8345 |
| `ietf-network-topology-state@2018-02-26.yang` | module | RFC 8345 |
| `ietf-network-topology@2018-02-26.yang` | module | RFC 8345 |
| `ietf-network-vpn-pm@2023-03-20.yang` | module | RFC 9375 |
| `ietf-network@2018-02-26.yang` | module | RFC 8345 |
| `ietf-origin@2018-02-14.yang` | module | RFC 8342 |
| `ietf-packet-fields@2019-03-04.yang` | module | RFC 8519 |
| `ietf-restconf-monitoring@2017-01-26.yang` | module | RFC 8040 |
| `ietf-restconf@2017-01-26.yang` | module | RFC 8040 |
| `ietf-routing-types@2017-12-04.yang` | module | RFC 8294 |
| `ietf-routing@2018-03-13.yang` | module | RFC 8349 |
| `ietf-sap-ntw@2023-06-20.yang` | module | RFC 9408 |
| `ietf-sid-file@2024-07-31.yang` | module | RFC 9595 |
| `ietf-subscribed-notifications@2019-09-09.yang` | module | RFC 8639 |
| `ietf-te-topology@2020-08-06.yang` | module | IANA, RFC 8795 |
| `ietf-te-types@2020-06-10.yang` | module | IANA, RFC 8776 |
| `ietf-vn@2025-03-27.yang` | module | IANA, RFC 9731 |
| `ietf-vpn-common@2022-02-11.yang` | module | RFC 9181 |
| `ietf-yang-library@2019-01-04.yang` | module | RFC 8525 |
| `ietf-yang-patch@2017-02-22.yang` | module | RFC 8072 |
| `ietf-yang-push@2019-09-09.yang` | module | RFC 8641 |
| `ietf-yang-schema-mount@2019-01-14.yang` | module | RFC 8528 |
| `ietf-yang-structure-ext@2020-06-17.yang` | module | RFC 8791 |
| `ietf-yang-types@2025-12-22.yang` | module | IANA, RFC 9911 |

## Arcana's own modules

What FreeBSD has beyond the published modules, as Arcana's own modules
(PLAN-SDN-YANG's "The agent as a YANG device"). Each leaf names the
FreeBSD facility it is read from and written to. Their SIDs are in
Arcana's provisional block (SIDS.md), their `.sid` files beside them.

| File | | What |
|---|---|---|
| `arcana-interfaces@2026-10-14.yang` | module | augments `ietf-interfaces`: driver name, MTU, Ethernet and hardware addresses, groups, FIB and tunnel FIB, capabilities, media; vlan(4), lagg(4), bridge(4) and epair(4) |
| `arcana-ip-deviations@2026-10-14.yang` | module | deviates `ietf-ip`: forwarding, DAD's probes and temporary addresses are the host's sysctls, IPv4 cannot be turned off on one interface, one MTU for both families: config false |
| `arcana-network-instance@2026-10-14.yang` | module | FreeBSD's FIBs (setfib(2), `net.fibs`) as `ietf-network-instance`'s: a `fib` case with the FIB's number; a FIB cannot be disabled, and there is no VSI or VV root (an if_bridge(4) is an interface) |
| `arcana-routing@2026-10-14.yang` | module | identities for `ietf-routing`'s `source-protocol`: a route's origin as FreeBSD's netlink(4) says it (`rtm_protocol`), where RFC 8349 has none |

The `.sid` files of the IETF and IANA modules the agent fills
(`ietf-interfaces`, `ietf-ip`, `iana-if-type`, `ietf-yang-types`,
`ietf-inet-types`) are Arcana's too: IANA registers their ranges and
publishes no file, so they are numbered here (SIDS.md). So are those
of the ones with no IETF range (`ietf-routing`, its address families,
`ietf-network-instance`), from Arcana's block. A module's file numbers
every item of it, whatever another module deviates:
`arcana-network-instance` takes `vsi-root` away, its number stays.

The agent's C structures and tables of the modules it fills are
committed in `usr.sbin/arcana-agent/yang/`; `make regen-yang` there
remakes them and `make check` fails when they are not what it makes.
