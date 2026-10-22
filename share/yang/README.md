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
| `iana-tls-cipher-suite-algs@2024-10-16.yang` | module | IANA registry, RFC 9645; `ietf-tls-common`'s import |
| `ieee802-dot1ax-linkagg@2025-09-30.yang` | module | IEEE Std 802.1AX (YangModels/yang, standard/ieee/published/802.1) |
| `ieee802-dot1ax-types@2025-09-30.yang` | module | IEEE Std 802.1AX (YangModels/yang, standard/ieee/published/802.1) |
| `ieee802-dot1q-bridge@2023-10-26.yang` | module | IEEE Std 802.1Q (YangModels/yang, standard/ieee/published/802.1) |
| `ieee802-dot1q-rstp-bridge@2025-02-04.yang` | module | IEEE Std 802.1Q (YangModels/yang, standard/ieee/published/802.1) |
| `ieee802-dot1q-rstp@2025-02-04.yang` | module | IEEE Std 802.1Q (YangModels/yang, standard/ieee/published/802.1) |
| `ieee802-dot1q-types@2023-10-26.yang` | module | IEEE Std 802.1Q (YangModels/yang, standard/ieee/published/802.1) |
| `ieee802-ethernet-interface@2025-09-10.yang` | module | IEEE Std 802.3 (YangModels/yang, standard/ieee/published/802.3) |
| `ieee802-ethernet-phy-type@2025-09-10.yang` | module | IEEE Std 802.3 (YangModels/yang, standard/ieee/published/802.3) |
| `ieee802-types@2023-10-22.yang` | module | IEEE Std 802 (YangModels/yang, standard/ieee/published/802) |
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
| `ietf-keystore@2024-10-10.yang` | module | RFC 9642; `ietf-syslog`'s TLS import |
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
| `ietf-syslog@2025-04-30.yang` | module | RFC 9742; syslog.conf(5) and newsyslog.conf(5) read as it (gula/ylog.c) |
| `ietf-subscribed-notifications@2019-09-09.yang` | module | RFC 8639 |
| `ietf-tcp-common@2024-10-10.yang` | module | RFC 9643 |
| `ietf-tcp@2024-10-10.yang` | module | RFC 9648 |
| `ietf-te-topology@2020-08-06.yang` | module | IANA, RFC 8795 |
| `ietf-te-types@2020-06-10.yang` | module | IANA, RFC 8776 |
| `ietf-tls-client@2024-10-10.yang` | module | RFC 9645; `ietf-syslog`'s TLS transport |
| `ietf-tls-common@2024-10-10.yang` | module | RFC 9645 |
| `ietf-truststore@2024-10-10.yang` | module | RFC 9641 |
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
| `arcana-interfaces@2026-10-14.yang` | module | augments `ietf-interfaces`: driver name, groups, tunnel FIB, capabilities, media; a vlan(4)'s priority, a lagg(4)'s protocol, hash and ports' priorities and flags, a bridge(4) member's own flags; an epair(4) end's other in a vnet. What a standard has is the standard's: the MTU `ietf-ip`'s ipv4 mtu (and `ietf-if-extensions`' max-frame-size), the Ethernet addresses `ietf-if-ethernet-like`'s, the FIB RFC 8529's bind-ni-name, an epair's other end `ietf-if-extensions`' peer-interface, a vlan's tag `ietf-if-vlan-encapsulation`'s outer-tag and its parent `ietf-if-extensions`' parent-interface, an Ethernet's auto-negotiation, duplex and PMD IEEE 802.3's `ieee802-ethernet-interface`, a lagg IEEE 802.1AX's `ieee802-dot1ax-linkagg` (a key group and system each, LACP's state), a bridge IEEE 802.1Q's `ieee802-dot1q-bridge` and its members' RSTP `ieee802-dot1q-rstp-bridge`'s |
| `arcana-ieee802-deviations@2026-10-14.yang` | module | deviates IEEE 802.1AX's `ieee802-dot1ax-linkagg`: FreeBSD's LACP keeps no administrative key (each port's is derived from its speed), so a key group's actor-admin-key is not mandatory |
| `arcana-ip-deviations@2026-10-14.yang` | module | deviates `ietf-ip`: forwarding, DAD's probes and temporary addresses are the host's sysctls, IPv4 cannot be turned off on one interface, one MTU for both families, ipv4's (the link's), so ipv6's is config false |
| `arcana-jails@2026-10-14.yang` | module | FreeBSD's jails (jail(8), jail(2)): those jail.conf(5) defines, as jail(8) -e resolves them, and those running, as jail_get(2) gives them; start, stop, restart, kill as actions; a vnet jail's logical network element (RFC 8530); the list and action operations of arcana.yaml converted (Y-3) |
| `arcana-sysctl@2026-10-14.yang` | module | FreeBSD's kernel state, sysctl(3): sysctl.conf(5)'s settings as configuration (written in place), the values with their kind, whether writable and what they are said to be as state; the sysctl and sysctl-parts operations of arcana.yaml converted (Y-3) |
| `arcana-processes@2026-10-14.yang` | module | FreeBSD's processes (kvm_getprocs(3), libprocstat(3)) in OpenConfig's shape: `openconfig-procmon`'s list, augmented with what FreeBSD has besides (parent, user, jail, run state, wait channel, nice, priority, threads, CPU time and the decayed share, blocks read and written), one process's files and threads, the jails' totals; signal (kill(2)) and renice (setpriority(2)) actions; the processes operation of arcana.yaml converted (Y-3) |
| `arcana-log@2026-10-14.yang` | module | what FreeBSD's syslogd(8) wrote, read: the log directory's files (newsyslog(8)'s packed ones too) and a read's lines, followed by position; the kernel's message buffer as @dmesg; each line's facility and severity as `ietf-syslog`'s, where syslogd -v wrote them; the log operation of arcana.yaml converted (Y-3); how syslogd writes is `ietf-syslog` itself |
| `arcana-kernel@2026-10-14.yang` | module | FreeBSD's kernel: rc.conf's kld_list as configuration; the files linked and their modules, those available, its memory (malloc(9) types, uma(9) zones) as state; load an rpc, unload an action; the kernel operation of arcana.yaml converted (Y-3) |
| `arcana-storage@2026-10-14.yang` | module | FreeBSD's storage: GEOM's disks and partitions, each with its health (nvmecontrol, smartctl), the ZFS pools with their vdevs and those importable, datasets and snapshots, the mounts, fstab(5)'s text and entries, the swap; a dataset's key loaded, unloaded, changed, fstab replaced, a snapshot sent, one received, as actions; the storage, fstab, zfs-send, zfs-receive and zfs-key operations of arcana.yaml converted (Y-3) |
| `arcana-jobs@2026-10-14.yang` | module | the agent's jobs: the queue, each job's trace as a flat list of steps naming their parents; submit (an rpc), cancel and confirm (actions); the job-submit, jobs, job, job-cancel and job-confirm operations of arcana.yaml converted (Y-3) |
| `arcana-jobs-kinds@2026-10-14.yang` | submodule | of arcana-jobs: the kinds of job, a change each, made from share/arcana/jobs.yaml by jobs.awk (out=yang), not to be edited; `make regen-yang` in usr.sbin/arcana-agent remakes it |
| `arcana-packages@2026-10-14.yang` | module | FreeBSD's packages (pkg(8)), the host's and, by an augment of arcana-jails, a running jail's: those installed (pkg query) with the newer version the repository has (pkg version -vRl '<'); refresh (pkg update) and upgrade (pkg upgrade) as actions; the packages and pkg-upgrade operations of arcana.yaml converted (Y-3) |
| `arcana-services@2026-10-14.yang` | module | FreeBSD's services: the rc.d scripts of rc(8), each enabled by its rcvar and set by its other rc.conf variables (configuration, as sysrc(8) has it), running or not (service(8) status); start, stop, restart, reload as actions; the services, service-action and service-config operations of arcana.yaml converted (Y-3) |
| `arcana-network-instance@2026-10-14.yang` | module | FreeBSD's FIBs (setfib(2), `net.fibs`) as `ietf-network-instance`'s: a `fib` case with the FIB's number; a FIB cannot be disabled, and there is no VSI or VV root (an if_bridge(4) is an interface) |
| `arcana-firewall@2026-10-15.yang` | module | FreeBSD's firewall, ipfw(8), the host's and, by an augment of arcana-jails, a vnet jail's: the kept rules file (ipfw commands, loaded at boot by rc.conf's firewall_script), its rules, other lines and the aliases written `$name` in them, and rc.conf's firewall variables as configuration; what the kernel has as state: loaded, enabled, verbose, the rules with their sets and counters (`ipfw -S show`), the dynamic rules (`ipfw -D show`), the tables (`ipfw table all list`), NAT (`ipfw nat show config`), dummynet's pipes, schedulers and queues (`ipfw pipe|sched|queue show`); the trace action, the kernel's own say on an address's packets (dtrace, `ipfw:::rule-matched`); the ipfw-rules and fw-trace operations of arcana.yaml and the network operation's ipfw kind converted (Y-3); what changes the firewall is a job of kind ipfw (arcana-jobs) |
| `arcana-troubleshoot@2026-10-15.yang` | module | what a FreeBSD host says of a packet, asked: path-check (what it would do with one from a source to a destination and with its reply, nothing sent: its addresses, net.inet.ip.forwarding, the routes by netlink(4) per FIB, the neighbours, ipfw's ruleset walked as ip_fw2.c would, rule by rule, the findings), traceroute (one round of traceroute(8)), capture (tcpdump(1)'s lines and pcap); the path-check, traceroute and capture operations of arcana.yaml converted (Y-3) |
| `arcana-history@2026-10-15.yang` | module | how busy the host has been, which the agent samples (kern.cp_time, getloadavg(3), vm.stats.vm, getifaddrs(3), devstat(3), rctl(8) per jail): step, keep and the limits that make a threshold event as configuration; the sampler and its samples, each taken apart by interface, disk and jail, as state; a read after a time; the history operation of arcana.yaml converted (Y-3) |
| `arcana-events@2026-10-15.yang` | module | what happened on the host, numbered: netlink(4)'s routes, links, addresses and neighbours of the host's network and each vnet jail's, a threshold crossed, a kernel message, a tunnel's state, a fault, a security policy's rule seeing a packet, a job's end, a jail's state (EVFILT_JAIL), a crash (kern.logsigexit); each kind an identity, its data the case of that kind, typed; the list kept, a read after a number, and the notification; the events and event operations of arcana.yaml converted (Y-3) |
| `arcana-bird@2026-10-15.yang` | module | the BIRD routing daemon (net/bird3), the host's and a vnet jail's: bird.conf and the files it includes as configuration, each with its SHA-256; what birdc(8) tells as state (status, each protocol with a BGP neighbour's own and an RPKI cache's, its channels with their filters and routes in and out, the OSPF neighbours, the BFD sessions, the tables); the routes of a table as an action; the bird and bird-routes kinds of the network operation and the bird-config operation of arcana.yaml converted (Y-3) |
| `arcana-wireguard@2026-10-15.yang` | module | if_wg(4) as wg(8) show dump tells of it, the host's and a vnet jail's: each interface's public key and listen port, each peer's public key, endpoint, allowed IPs, last handshake, bytes and keepalive; a private or preshared key only said to be there; the wireguard kind of the network operation converted (Y-3); keys and peers are jobs of kind wireguard |
| `arcana-netgraph@2026-10-15.yang` | module | netgraph(4) as ngctl(8) list -l tells of it, the host's and a vnet jail's: each node's name, type and id, each hook's peer node and hook; the netgraph kind of the network operation converted (Y-3); the graph is changed by jobs of kind netgraph |
| `arcana-host@2026-10-15.yang` | module | a FreeBSD host as its agent says it: uname(3), kern.osreldate, hw.ncpu, hw.physmem, kern.boottime, kern.securelevel, the agent's version and build, the plugins it has as identities (BIRD, wg, strongSwan, Squid, dnsmasq, Suricata, c-icap; a jail's by an augment of arcana-jails), how busy it is now (kern.cp_time, getloadavg(3), vm.stats.vm, swap, zpool list), the certificates OpenSSL trusts (certctl(8)); the hello, list (its host), stats and certs operations of arcana.yaml converted (Y-3) |
| `arcana-agent@2026-10-15.yang` | module | the agent itself: its listeners (TCP, SCTP, unix) and sessions, its own TLS files (certificate, CAs, a key waiting; csr and install as actions), update (a program sent), build and console-update (a repository built on the host), source-head and source-log (a repository read over SSH with confirmed host keys), config-export (the host's configuration as a bundle: facts, packages by hand, the files Arcana manages) and config-apply (a bundle made the host's, with the report) as actions; the transport, tls, agent-update, agent-build, console-update, source-head, source-log, config-export and config-apply operations converted (Y-3) |
| `arcana-jail-files@2026-10-15.yang` | module | augments `arcana-jails`: the files jails are made with, as the jail-conf job writes them (jail.conf.d, the defaults every jail includes, the templates, each jail's file); the jail-files operation converted (Y-3) |
| `arcana-probe@2026-10-15.yang` | module | the tunnels the host measures as an SD-WAN edge does (Mplify 119 §11.4): each target (ICMP echo on a raw socket; interval, size, DSCP, down and up counts, timeout, evaluation interval, history, thresholds) as configuration, kept for the next start; what the probes have seen as state (each target's state and counters, the sample in progress, the samples kept: one-way delay, delay variation, loss, least and most, sent and answered); a read after a time; the sdwan-probes operation and the targets of the sdwan read converted (Y-3) |
| `arcana-sdwan@2026-10-15.yang` | module | the host as an SD-WAN edge (MEF 70.2, Mplify 119): the classification and steering rules (an ipfw set, tables, dummynet and NAT objects), the policy tables' candidates, and the BIRD, dnsmasq, unbound, Squid and Suricata instances of the services, one each in its FIB, as the console writes them (configuration); what the edge is doing as state (the rules' counters, the steer with what the probes say, each instance running with its protocols, leases, CA or alerts, the security policies' record, the tunnels' IPsec keys, the faults of the day); the sdwan, sdwan-rules, sdwan-steer, sdwan-bird, sdwan-dhcp, sdwan-dns, sdwan-proxy and sdwan-ids operations converted (Y-3) |
| `arcana-sshd@2026-10-15.yang` | module | the base system's sshd(8), the host's and a jail's: the settings that matter (sshd -T), the banner, the host keys with their certificates (ssh-keygen -l, -L), the users who may sign in with their authorized keys, the user CAs trusted; the ssh operation converted (Y-3); the changes are jobs of kind ssh |
| `arcana-routing@2026-10-14.yang` | module | identities for `ietf-routing`'s `source-protocol`: a route's origin as FreeBSD's netlink(4) says it (`rtm_protocol`), where RFC 8349 has none and no routing protocol's module does (OSPF, RIP, IS-IS, Babel and BGP are `ietf-ospf`'s, `ietf-rip`'s, `ietf-isis`'s, `ietf-babel`'s, `ietf-bgp`'s) |

The wire itself, since 2026-10-22 (cblink version 2): the family specs
as YANG, written by `share/arcana/wire.awk` and regenerated by `make
regen-wire` (`make check-wire` fails when they are not what the specs
make); the programs are built from these, not from the specs.

| File | | What |
|---|---|---|
| `arcana@2026-10-22.yang` | module | `share/arcana/arcana.yaml` on the wire: every attribute set a grouping (one struct each, by `cg:struct`), every operation an rpc of the family's command number (`fam:command`), a dump's forms an rpc of their own, an event a structure of its multicast group, a stream's payload a structure |
| `arcana-cluster@2026-10-22.yang` | module | `share/arcana/cluster.yaml` on the wire, the same way: the consoles of a cluster to each other |
| `arcana-family@2026-10-22.yang` | module | the extensions the two say the family by: family, version, command, auth, dump, stream, credit, group; no data nodes, no SIDs |

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
