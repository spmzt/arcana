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

Since 2026-10-14 a module is taken from
[YangModels/yang](https://github.com/YangModels/yang) as published
there (standard/ietf/RFC, standard/iana, standard/ieee/published; a
working-group draft's from experimental/ietf-extracted-YANG-modules,
at the revision taken), with what it imports.  The routing protocols'
(`ietf-ospf`, `ietf-rip`, `ietf-isis`, `ietf-babel`, `ietf-bgp`) are
only imported, by `arcana-routing`: their identities name a route's
origin.

| File | | Source |
|---|---|---|
| `iana-bfd-types@2021-10-21.yang` | module | RFC 9127 |
| `iana-bgp-afi-safi-types@2026-08-14.yang` | module | draft-ietf-idr-bgp-model, its 2026-08-14 revision (YangModels/yang) |
| `iana-bgp-capabilities@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `iana-bgp-community-types@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `iana-bgp-notification@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `iana-bgp-rib-types@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `iana-crypt-hash@2014-08-06.yang` | module | IANA registry |
| `iana-icmpv4-types@2025-12-22.yang` | module | IANA registry |
| `iana-icmpv6-types@2025-12-22.yang` | module | IANA registry |
| `iana-if-type@2026-03-17.yang` | module | IANA registry |
| `iana-ipv6-ext-types@2025-12-22.yang` | module | IANA registry |
| `iana-routing-types@2025-09-03.yang` | module | IANA registry |
| `ieee802-dot1q-types@2023-10-26.yang` | module | IEEE Std 802.1Q (YangModels/yang, standard/ieee/published/802.1) |
| `ieee802-ethernet-interface@2025-09-10.yang` | module | IEEE Std 802.3 (YangModels/yang, standard/ieee/published/802.3) |
| `ieee802-ethernet-phy-type@2025-09-10.yang` | module | IEEE Std 802.3 (YangModels/yang, standard/ieee/published/802.3) |
| `ietf-access-control-list@2019-03-04.yang` | module | RFC 8519 |
| `ietf-alarms-x733@2019-09-11.yang` | module | RFC 8632 |
| `ietf-alarms@2019-09-11.yang` | module | RFC 8632 |
| `ietf-babel@2024-10-10.yang` | module | RFC 9647 |
| `ietf-bfd-types@2022-09-22.yang` | module | RFC 9314 |
| `ietf-bgp-capabilities@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-common-errors@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-common-multiprotocol@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-common@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-community-types@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `ietf-bgp-neighbor@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-rib-attributes@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-rib-tables@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-rib@2026-08-14.yang` | submodule | draft-ietf-idr-bgp-model |
| `ietf-bgp-session-security@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `ietf-bgp-types@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `ietf-bgp@2026-08-14.yang` | module | draft-ietf-idr-bgp-model |
| `ietf-crypto-types@2024-10-10.yang` | module | RFC 9640 |
| `ietf-datastores@2018-02-14.yang` | module | RFC 8342 |
| `ietf-ethertypes@2019-03-04.yang` | module | RFC 8519 |
| `ietf-i2nsf-ike@2021-07-14.yang` | module | RFC 9061 |
| `ietf-i2nsf-ikec@2021-07-14.yang` | module | RFC 9061 |
| `ietf-i2nsf-ikeless@2021-07-14.yang` | module | RFC 9061 |
| `ietf-if-ethernet-like@2026-06-19.yang` | module | draft-ietf-netmod-intf-ext-yang, its 2026-06-19 revision (YangModels/yang) |
| `ietf-if-extensions@2025-08-07.yang` | module | draft-ietf-netmod-intf-ext-yang, its 2025-08-07 revision (YangModels/yang) |
| `ietf-if-vlan-encapsulation@2026-07-06.yang` | module | draft-ietf-netmod-sub-intf-vlan-model, its 2026-07-06 revision (YangModels/yang) |
| `ietf-inet-types@2025-12-22.yang` | module | IANA, RFC 9911 |
| `ietf-interfaces@2018-02-20.yang` | module | RFC 8343 |
| `ietf-ip@2018-02-22.yang` | module | RFC 8344 |
| `ietf-ipsec-iptfs@2023-01-31.yang` | module | RFC 9348 |
| `ietf-ipv4-unicast-routing@2018-03-13.yang` | module | RFC 8349 |
| `ietf-ipv6-router-advertisements@2018-03-13.yang` | submodule | RFC 8349 |
| `ietf-ipv6-unicast-routing@2018-03-13.yang` | module | RFC 8349 |
| `ietf-isis@2022-10-19.yang` | module | RFC 9130 |
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
| `ietf-ospf@2022-10-19.yang` | module | RFC 9129 |
| `ietf-packet-fields@2019-03-04.yang` | module | RFC 8519 |
| `ietf-restconf-monitoring@2017-01-26.yang` | module | RFC 8040 |
| `ietf-restconf@2017-01-26.yang` | module | RFC 8040 |
| `ietf-rip@2020-02-20.yang` | module | RFC 8695 |
| `ietf-routing-policy@2021-10-11.yang` | module | RFC 9067 |
| `ietf-routing-types@2017-12-04.yang` | module | RFC 8294 |
| `ietf-routing@2018-03-13.yang` | module | RFC 8349 |
| `ietf-sap-ntw@2023-06-20.yang` | module | RFC 9408 |
| `ietf-sid-file@2024-07-31.yang` | module | RFC 9595 |
| `ietf-subscribed-notifications@2019-09-09.yang` | module | RFC 8639 |
| `ietf-tcp-common@2024-10-10.yang` | module | RFC 9643 |
| `ietf-tcp@2024-10-10.yang` | module | RFC 9648 |
| `ietf-te-topology@2020-08-06.yang` | module | IANA, RFC 8795 |
| `ietf-te-types@2020-06-10.yang` | module | IANA, RFC 8776 |
| `ietf-vn@2025-03-27.yang` | module | IANA, RFC 9731 |
| `ietf-vpn-common@2022-02-11.yang` | module | RFC 9181 |
| `ietf-yang-library@2019-01-04.yang` | module | RFC 8525 |
| `ietf-yang-patch@2017-02-22.yang` | module | RFC 8072 |
| `ietf-yang-push@2019-09-09.yang` | module | RFC 8641 |
| `ietf-yang-schema-mount@2019-01-14.yang` | module | RFC 8528 |
| `ietf-yang-semver@2026-03-03.yang` | module | draft-ietf-netmod-yang-semver (YangModels/yang) |
| `ietf-yang-structure-ext@2020-06-17.yang` | module | RFC 8791 |
| `ietf-yang-types@2025-12-22.yang` | module | IANA, RFC 9911 |
| `openconfig-extensions@2025-01-02.yang` | module | OpenConfig (Apache-2.0), from YANG Catalog; `openconfig-procmon`'s import |
| `openconfig-procmon@2019-03-15.yang` | module | OpenConfig (Apache-2.0), from YANG Catalog; its grouping is used by `arcana-processes` |
| `openconfig-types@2024-01-31.yang` | module | OpenConfig (Apache-2.0), from YANG Catalog; `openconfig-procmon`'s import |
| `openconfig-yang-types@2024-05-30.yang` | module | OpenConfig (Apache-2.0), from YANG Catalog; `openconfig-procmon`'s import |

## Arcana's own modules

What FreeBSD has beyond the published modules, as Arcana's own modules
(PLAN-SDN-YANG's "The agent as a YANG device"). Each leaf names the
FreeBSD facility it is read from and written to. Their SIDs are in
Arcana's provisional block (SIDS.md), their `.sid` files beside them.

| File | | What |
|---|---|---|
| `arcana-interfaces@2026-10-14.yang` | module | augments `ietf-interfaces`: driver name, groups, tunnel FIB, capabilities, media; a vlan(4)'s priority, lagg(4), bridge(4); an epair(4) end's other in a vnet. What a standard has is the standard's: the MTU `ietf-ip`'s ipv4 mtu (and `ietf-if-extensions`' max-frame-size), the Ethernet addresses `ietf-if-ethernet-like`'s, the FIB RFC 8529's bind-ni-name, an epair's other end `ietf-if-extensions`' peer-interface, a vlan's tag `ietf-if-vlan-encapsulation`'s outer-tag and its parent `ietf-if-extensions`' parent-interface, an Ethernet's auto-negotiation, duplex and PMD IEEE 802.3's `ieee802-ethernet-interface` |
| `arcana-ip-deviations@2026-10-14.yang` | module | deviates `ietf-ip`: forwarding, DAD's probes and temporary addresses are the host's sysctls, IPv4 cannot be turned off on one interface, one MTU for both families, ipv4's (the link's), so ipv6's is config false |
| `arcana-jails@2026-10-14.yang` | module | FreeBSD's jails (jail(8), jail(2)): those jail.conf(5) defines, as jail(8) -e resolves them, and those running, as jail_get(2) gives them; start, stop, restart, kill as actions; a vnet jail's logical network element (RFC 8530); the list and action operations of arcana.yaml converted (Y-3) |
| `arcana-sysctl@2026-10-14.yang` | module | FreeBSD's kernel state, sysctl(3): sysctl.conf(5)'s settings as configuration (written in place), the values with their kind, whether writable and what they are said to be as state; the sysctl and sysctl-parts operations of arcana.yaml converted (Y-3) |
| `arcana-processes@2026-10-14.yang` | module | FreeBSD's processes (kvm_getprocs(3), libprocstat(3)) in OpenConfig's shape: `openconfig-procmon`'s list, augmented with what FreeBSD has besides (parent, user, jail, run state, wait channel, nice, priority, threads, CPU time and the decayed share, blocks read and written), one process's files and threads, the jails' totals; signal (kill(2)) and renice (setpriority(2)) actions; the processes operation of arcana.yaml converted (Y-3) |
| `arcana-kernel@2026-10-14.yang` | module | FreeBSD's kernel: rc.conf's kld_list as configuration; the files linked and their modules, those available, its memory (malloc(9) types, uma(9) zones) as state; load an rpc, unload an action; the kernel operation of arcana.yaml converted (Y-3) |
| `arcana-storage@2026-10-14.yang` | module | FreeBSD's storage: GEOM's disks and partitions, each with its health (nvmecontrol, smartctl), the ZFS pools with their vdevs and those importable, datasets and snapshots, the mounts, fstab(5)'s text and entries, the swap; a dataset's key loaded, unloaded, changed, fstab replaced, a snapshot sent, one received, as actions; the storage, fstab, zfs-send, zfs-receive and zfs-key operations of arcana.yaml converted (Y-3) |
| `arcana-jobs@2026-10-14.yang` | module | the agent's jobs: the queue, each job's trace as a flat list of steps naming their parents; submit (an rpc), cancel and confirm (actions); the job-submit, jobs, job, job-cancel and job-confirm operations of arcana.yaml converted (Y-3) |
| `arcana-jobs-kinds@2026-10-14.yang` | submodule | of arcana-jobs: the kinds of job, a change each, made from share/arcana/jobs.yaml by jobs.awk (out=yang), not to be edited; `make regen-yang` in usr.sbin/arcana-agent remakes it |
| `arcana-packages@2026-10-14.yang` | module | FreeBSD's packages (pkg(8)), the host's and, by an augment of arcana-jails, a running jail's: those installed (pkg query) with the newer version the repository has (pkg version -vRl '<'); refresh (pkg update) and upgrade (pkg upgrade) as actions; the packages and pkg-upgrade operations of arcana.yaml converted (Y-3) |
| `arcana-services@2026-10-14.yang` | module | FreeBSD's services: the rc.d scripts of rc(8), each enabled by its rcvar and set by its other rc.conf variables (configuration, as sysrc(8) has it), running or not (service(8) status); start, stop, restart, reload as actions; the services, service-action and service-config operations of arcana.yaml converted (Y-3) |
| `arcana-network-instance@2026-10-14.yang` | module | FreeBSD's FIBs (setfib(2), `net.fibs`) as `ietf-network-instance`'s: a `fib` case with the FIB's number; a FIB cannot be disabled, and there is no VSI or VV root (an if_bridge(4) is an interface) |
| `arcana-routing@2026-10-14.yang` | module | identities for `ietf-routing`'s `source-protocol`: a route's origin as FreeBSD's netlink(4) says it (`rtm_protocol`), where RFC 8349 has none and no routing protocol's module does (OSPF, RIP, IS-IS, Babel and BGP are `ietf-ospf`'s, `ietf-rip`'s, `ietf-isis`'s, `ietf-babel`'s, `ietf-bgp`'s) |

The `.sid` files of the IETF and IANA modules the agent fills
(`ietf-interfaces`, `ietf-ip`, `iana-if-type`, `ietf-yang-types`,
`ietf-inet-types`) are Arcana's too: IANA registers their ranges and
publishes no file, so they are numbered here (SIDS.md). So are those
of the ones with no IETF range (`ietf-routing`, its address families,
`ietf-network-instance`, `ietf-logical-network-element`), from
Arcana's block. A module's file numbers
every item of it, whatever another module deviates:
`arcana-network-instance` takes `vsi-root` away, its number stays.

The agent's C structures and tables of the modules it fills are
committed in `usr.sbin/arcana-agent/yang/`; `make regen-yang` there
remakes them and `make check` fails when they are not what it makes.
