# Plan: Arcana as an SDN on FreeBSD, and cblink as a YANG protocol

Written 2026-10-13 from a reading of the RFCs listed at the end and of
the tree as it is (agent 0.103.0, console 0.164.0). It says where
Arcana stands in the IETF's SDN vocabulary, what it becomes, how the
agent's contract is turned into YANG data models carried by cblink,
which parts of the models FreeBSD can realise and which it cannot,
and the work, broken into phases and numbered tasks. Decisions for
the user are marked **D-n** with their trade-offs; the plan's own
recommendation is given with each. Nothing here is committed to
until a decision says so.

Markers on tasks, as in PLAN-119-SASE.md: **G** the generator and
libcblink (`cblink/`), **A** the agent, **C** the console, **P** the
page, **L** the lab (run for real on the VM or the jails), **D** the
documents (ARCHITECTURE.md, the book, openapi, TODO).

## Where we stand

In RFC 7426's terms (planes and abstraction layers):

| RFC 7426 | Arcana today |
|---|---|
| Forwarding plane | the FreeBSD kernel: FIBs, ipfw and dummynet, gre/gif/geneve/vxlan/wg/ipsec(4) tunnels, netgraph, if_bridge |
| Operational plane | what the agent reads: interfaces, routes, sysctl, jails, services, packages, counters |
| Device and resource Abstraction Layer (DAL) | **missing**: `share/arcana/arcana.yaml` is a transport contract, not a model. 25 of its 60 operations carry their data as an opaque `json: text` blob (every network, storage, sysctl, kernel, log, events and history table, and all nine `sdwan-*` exchanges). Only jails, services, jobs, traces, routes and packages are typed |
| Control plane | split: BIRD on the edges (BGP, OSPF, BFD), the steering in the agent (`invidia/sdwan.c`, first tunnel not down), the manager in the console (`sdwan_edge.c`) |
| Control Abstraction Layer (CAL) | **missing**: no module both sides share |
| Management plane | the console: enrolment, updates, settings, workflows, audit |
| Management Abstraction Layer (MAL) | `hosts.c`, `sdwan_edge.c`, `jobs.yaml` |
| Southbound (CPSI and MPSI) | cblink v1 over mTLS: control and management on one channel, one priority |
| Northbound (NSAL) | 72 REST paths of Arcana's own shape, API tokens read-only |
| Application plane | the PWA, workflows, the SD-WAN manager, SASE |

What already matches the RFCs' architecture, and is kept: one
privileged agent per host and an unprivileged controller; a
generated, typed, mTLS-protected southbound with notifications and
flow-controlled streams; a service document that is checked, planned
and applied (RFC 9315's fulfilment loop) with a trace of every step
(explainability); safe mode with confirm-or-revert; a per-service FIB
with its own BIRD instance (a VRF); tunnels per FIB; probes, faults
and threshold alerts; policy steering with local failover; dummynet
shares; the CA and the one-time enrolment token. In RFC 9543's and
9732's terms the SD-WAN service is already an "assured bandwidth"
enhanced VPN realised on a per-service NRP; in RFC 8969's terms the
agent is the "controller embedded on a device" the framework allows.

What is missing is named by the frameworks: a model-based DAL; a
control abstraction shared by console and agent; NMDA datastores so
that what the host runs can be compared with what was intended
(drift); subscriptions instead of polling (the console polls jobs
once a second, which RFC 8456's benchmarks would expose as the bound
on every "time" metric); a standard northbound; standard performance
measurement (ICMP echo is not a registered PM source); a first-class
NRP object; a management overlay that survives data-plane faults
(RFC 8994); and a second controller (CAP).

## The target

RFC 8309's three models and RFC 8969's three tiers, placed:

```
 customer                 orchestrator / controller                 devices
 ┌──────────┐  RESTCONF   ┌─────────────────────────────┐  cblink 2  ┌───────────────┐
 │ PWA, apps│ ──────────▶ │ arcana-console (Kore)       │ ─────────▶ │ arcana-agent  │
 │ arcanactl│  JSON 7951  │ customer models: ietf-vn,   │  YANG-CBOR │ device models:│
 │          │  YANG-Push  │   MEF 70.2 (import/export)  │  SIDs      │ interfaces,ip,│
 │          │  over SSE   │ network models: l3vpn-ntw,  │  NMDA      │ routing, NI,  │
 │          │             │   sap, network-vpn-pm, acl  │  YANG-Push │ LNE, acl,     │
 │          │             │ fleet = schema mount of     │  NACM      │ ipsec, alarms,│
 │          │             │   every host's root         │            │ arcana-*      │
 └──────────┘             └─────────────────────────────┘            └───────────────┘
                                   │ east-west: BIRD iBGP/OSPF/BFD between edges;
                                   │ GRASP over the ACP (later)
```

| Layer | Target |
|---|---|
| DAL | YANG modules the agent implements: `ietf-interfaces`, `ietf-ip`, `ietf-routing` with v4ur/v6ur and the RA submodule, `ietf-network-instance` (one instance per FIB), `ietf-logical-network-element` (one per vnet jail, its root a schema mount), `ietf-access-control-list` with RFC 9899 (compiled to ipfw), `ietf-i2nsf-ikeless` and `-ike` (RFC 9061, setkey/PF_KEY and strongSwan), `ietf-alarms` (faults), `ietf-yang-library`, `ietf-netconf-acm`, `ietf-subscribed-notifications` and `ietf-yang-push`; and Arcana modules for what the IETF has no model of: jails, rc.d services and rc.conf, pkg, ZFS and GEOM, sysctl, kernel modules, jobs and traces, processes, logs, probes, dummynet (the NRP), BIRD, WireGuard, netgraph, plugins |
| Wire | cblink 2: the same 24-byte frame, mTLS over TCP or SCTP, do/dump/notify/stream and credit; the body one RFC 9254 YANG-CBOR map keyed by RFC 9595 SIDs; the framework items (`error`, `credit`, `hello`, `close`, `notification`) `sx:structure`s of a `cblink` YANG module |
| Operations | `GET` (do and dump; CORECONF's FETCH spread over MULTI frames), `EDIT` (YANG Patch with instance-identifier targets; merge, replace, create, delete, remove, insert, move; rollback-on-error), `RPC` (rpcs and actions), `GET-SID`; subscriptions as push streams |
| Datastores | `running` = the configuration files (rc.conf, jail.conf, loader.conf, sysctl.conf, rtadvd.conf, the kept ipfw rules, swanctl conf.d); `intended` = running; `candidate` optional, with confirmed commit = today's `job-confirm`; `arcana:live` a dynamic datastore for what is changed in the kernel and not persisted (today's `address live`); `operational` = the kernel, with origin |
| CAL | an `arcana-steer` module: the steering state (candidates, chosen, reasons) and the events that change it, read and written by the console and by the agent's local failover, carried on a stream of its own |
| NBI | RESTCONF (RFC 8040) with JSON (RFC 7951) over Kore, YANG Patch, `ietf-restconf-monitoring` streams as SSE, YANG-Push with the RESTCONF binding; `application/yang-data+cbor` passed through for the PWA; the fleet as `arcana-fleet:hosts/host[name]/root`, an inline schema mount per host |
| Service models | RFC 9181 common types; RFC 9182 L3NM as the network model of a service; RFC 9408 SAPs as the inventory of attachment points; RFC 9731 VN as the customer view of a service; RFC 9375 PM as the performance view; the MEF 70.2 document kept as an import/export format over them (D-4) |
| Control plane | BIRD stays the distributed part (BGP, OSPF, BFD, Babel); the console is the controller for steering policy, slices, flowspec origination, ACLs; the agent keeps local failover |
| Measurement | STAMP (RFC 8762, 8972) sender and reflector in the agent; ICMP kept as fallback; alternate marking (RFC 9341, 9342) passively by ipfw colour counters; percentiles per measurement interval |
| Telemetry | YANG-Push periodic and on-change over push streams; IPFIX or NetFlow v9 by `ng_netflow` per service FIB; BMP from BIRD |
| Management overlay | the ACP of RFC 8994, as far as FreeBSD allows (D-11) |

## Decisions to take first

Each with the options, the trade-off and the recommendation. D-1 to
D-3 gate Phase Y-1; the rest gate the phase named.

**D-1 The wire.** Keep cblink's frame and carry YANG-CBOR in the
body. The body becomes one YANG-CBOR map whose top-level keys are
absolute SIDs and whose framework items are YANG structures of a
`cblink` module (wire version 2). The alternative, a wrapper map
holding the YANG item under one positive key beside today's negative
framework keys, keeps version 1 bit-compatible but runs two decoders
in series and leaves the framework untyped. Recommendation: version
2; version 1 frames stay valid for the legacy families during the
migration (the header's `version` field exists for this). Tags 4
(decimal64) and 43–47 (union discriminators, absolute SID) are
allowed; indefinite lengths stay forbidden, as CORECONF does.

**D-2 Replacing the protocol altogether.** cblink 2 as above, versus
NETCONF or RESTCONF on every agent (standard tooling reaches every
host; but an HTTP or SSH server in the root daemon, a second auth
layer, and nothing of cblink's streams and notifications), versus
CORECONF over CoAP (the closest design to cblink 2, but a CoAP stack
and DTLS instead of TLS, and no implementation in C exists anywhere).
Recommendation: cblink 2 on the southbound, RESTCONF only on the
console. The console is then the one place standard tools talk to,
which is also RFC 8309's picture.

**D-3 The YANG compiler.** cblink-gen must understand YANG 1.1.
(a) A parser and schema compiler in C of our own, 12–15 k lines,
10–14 weeks, bounded by a strict profile (it rejects what it does not
implement) and cross-checked in CI against `pyang -f tree` and
`yanglint`: no dependency, the same schema model and XPath parser
serve the runtime validator, a `yanglint`-lite for Arcana's modules.
(b) libyang 3.13.6 (ports, pinned: upstream is at 5.x/6.x) linked
into cblink-gen at build time, ~2.5 k lines of glue, 3–4 weeks: the
reference implementation, but a build dependency on pcre2 and libyang
for Arcana's developers (not for users: generated C is committed).
(c) A pyang plugin writing an intermediate file cblink-gen reads: 3
weeks, Python in the developers' build, a second schema language to
keep. Recommendation: (a), decided at the end of Y-0 on a two-week
parser prototype; (b) is the schedule fallback and shares the
emitter, so swapping later costs little. The runtime needs its own
C evaluator in every case (no YANG-CBOR or SID implementation exists
in C: libyang's pull request is unmerged).

**D-4 The MEF 70.2 document.** (a) Keep it as the source of truth and
derive L3NM, SAP, VN and PM as read-only views: no migration, the
book stands, but the IETF models are decorative and two schemas are
maintained forever. (b) Make L3NM + SAP (+ the Arcana augmentations)
the source of truth and keep the MEF document as an import and
export format: one schema, standard tooling can write services, the
console's planner reads L3NM; the cost is rewriting `sdwan.c`'s
reader and the book's SD-WAN part, and MEF attributes that L3NM lacks
(policy map, application flows, breakout rules, security policies)
live in augmentations. (c) Retire the document. Recommendation: (b);
the MEF vocabulary stays the user's vocabulary in the page, L3NM is
what is stored and exchanged.

**D-5 RFC 4364 on FreeBSD.** L3NM's route distinguishers and route
targets presume MPLS VPNs. FreeBSD has no MPLS (the GSoC branch needs
an ABI bump; not before 17), and net/bird3 does not build `l3vpn` or
`evpn`. Options: (a) RD/RT as bookkeeping; membership by per-service
tunnels and a per-FIB BIRD session per edge pair, as today, O(VPN ×
PE²) sessions; (b) one BGP session per edge pair carrying all VPNs as
`vpn4`/`vpn6` routes with fake labels and a VXLAN VNI per VPN as the
real encapsulation, next hop the far VTEP: standards-shaped, scales,
but needs BIRD's `mpls` domain to work without kernel support (to be
tried in Y-0) and is new code of its own; (c) the console pushes
static routes per FIB: simplest, no RT semantics, poor convergence.
Recommendation: (a) now with RD/RT carried and checked for
uniqueness, (b) tried as a Y-0 spike and taken up in Y-6 if BIRD
cooperates. Either way `vpn-type` other than `l3vpn` is refused.

**D-6 VRF realisation.** A FIB per `vpn-node` (light, what SD-WAN
does, but leaky: loopback visible in every FIB unless
`net.add_addr_allfibs=0`, daemons need `setfib`, FIB count is a boot
tunable) versus a vnet jail per `vpn-node` (real isolation, own lo0,
own sysctls, own BIRD, dhcpd, pimd and ipfw; more processes, jail
lifecycle). Recommendation: both, chosen per service: FIB by default,
jail when the service needs multicast, DHCP, NAT or its own firewall.
Both are modelled already: FIB = `ietf-network-instance`, jail =
`ietf-logical-network-element`.

**D-7 The ACL engine.** ipfw (already driven, tables, dummynet for
rate-limit, divert, `call`/`return`, fib and jail matches; cannot
match ICMP code, ECN, TCP ECE/CWR/AE, payload) versus pf (anchors
give named ordered ACLs, `tos`, ICMP code, E/W flags; no dummynet
shaping, a second filter on every packet). Recommendation: ipfw as
the engine, features advertised accordingly, the unmappable fields
refused with an extended ack; a pf backend of the same module later
if wanted.

**D-8 Probes.** STAMP sender and reflector in the agent (standard
`pm-source`, one-way delay with NTP, loss per direction with the
direct-measurement TLV, DSCP echo; a reflector per service FIB on UDP
862; ~1 k lines) versus ICMP only (works today, against anything, no
standard label, RTT/2). Recommendation: STAMP between Arcana edges,
ICMP for foreign targets, one probe model with a `kind`; both report
through RFC 9375 with `pm-source-stamp` or `arcana:pm-source-icmp`.

**D-9 Coexistence.** Run the `arcana` v1 family and cblink 2 side by
side for one release cycle (mixed fleets keep working; the agent
registers both, the console prefers 2 when a host has it) versus a
flag day (less code, breaks a fleet updated host by host).
Recommendation: side by side until Y-4 ends, then v1 frozen and
removed in Y-5. `agent-update` carries the agents across.

**D-10 The northbound.** RESTCONF replacing `/api` (one surface;
breaks the Android app, `arcanactl`'s console paths and token users
once) versus RESTCONF beside `/api` for a cycle. Recommendation:
beside, with `/api` frozen when RESTCONF covers it and removed one
release later; the PWA moves first.

**D-11 The ACP's routing.** RFC 8994 requires RPL (no FreeBSD
implementation; the profile is a few thousand lines of our own)
versus BIRD Babel or OSPFv3 in the ACP context as the variation the
RFC's Appendix A.8 describes (non-conformant, a port, quick).
Recommendation: Babel first with the variation recorded in the
certificate's extension field, RPL as the conformance target later;
an ACP domain never mixes the two. Also: the ACP context as a vnet
jail (the RFC's preferred "logical container") rather than a FIB.

**D-12 Autonomy.** How much decision moves out of the console: none
beyond today's local failover (every change explained by the trace
tree) versus ASAs of RFC 9222 in an unprivileged `arcana-asa` beside
the agent, negotiating over GRASP on the ACP (steering in step on
both ends, rekey, address allocation without the console; their
decisions audited as events). Recommendation: not before the ACP
exists (Y-7); then steering and rekey only.

Smaller decisions are listed with the phases that need them.

## cblink 2: the protocol

What stays: the frame, `seq` correlation, flags, the control family's
role, transports (TCP, TLS 1.3, AF_UNIX, SCTP, DTLS over SCTP), stream
ids and parity, credit, `max_*` limits, `ENOBUFS` on dropped
notifications, PROXY and peer credentials. About 8 k of libcblink's
20.7 k lines are untouched.

What changes:

- **Body.** One CBOR map. Top-level keys are absolute SIDs (RFC
  9595, 63-bit, unsigned); nested keys are SID deltas relative to the
  parent schema node (RFC 9254 §3.2), signed, which is why the body
  cannot keep cblink's negative framework keys: a `v4ur:destination-
  prefix` under `rt:route` or an `ni:bind-ni-name` under
  `if:interface` is a negative delta. Framework data moves into
  structures of a `cblink` module: `error` (`ietf-coreconf`'s
  structure, SID 1024, augmented with `errno` and `cookie`), `credit`,
  `hello` (limits, implementation, yang-library content-id), `close`,
  `notification` (`event-time`, `event` anydata), `warning`. `PATH`
  becomes `error-data-node`, an instance-identifier, the same array
  shape as today; `MISS_TYPE` becomes `error-tag missing-element`.
  FreeBSD errno numbering survives as a leaf.
- **Types.** `flag` becomes `empty` (null on the wire); `flags`
  becomes `bits` (byte string, LSB first); `float` goes, `decimal64`
  comes (tag 4); new kinds identityref (a SID), instance-identifier,
  union (tags 43–46 where ambiguous), leafref (the target's type).
  Strings carry patterns and lengths in characters. Integers keep
  their ranges.
- **Operations.** `family` stays a protocol multiplexer: 0 is `ctrl`
  (regenerated from `cblink-ctrl.yang`), 1 is `cblink-yang`, the
  datastore protocol; legacy numbers stay valid and are never reused.
  `cmd` within family 1: `GET` (do for one node, dump for a list or
  many targets: one MULTI frame per instance `{[SID, keys]: entry}`,
  which is CORECONF's `yang-instances` sequence spread over frames;
  parameters datastore, targets, depth, fields, with-defaults,
  with-origin), `EDIT` (a `cblink:edit` structure shaped like RFC
  8072's YANG Patch with instance-identifier targets; the console
  converts api-path strings), `RPC` (`{SID(rpc): input}` →
  `{SID(rpc): output}`; actions keyed `{[SID(action), keys...]:
  input}`), `GET-SID` (the module's `ietf-sid-file` structure, so a
  generic client can decode what an agent speaks). Commit, cancel,
  discard and a connection-scoped lock are rpcs of a
  `cblink-datastore` module behind the `candidate` feature.
- **Unknown nodes.** Ignored on reads of operational data from a
  newer peer (forward compatibility, as today); refused in edits
  (`unknown-element`), as every YANG protocol does.
- **Subscriptions.** `establish-subscription` (RFC 8639) is a push
  stream open: the request carries the rpc input, the accept the rpc
  output (`id`); records and subscription-state notifications flow as
  `S_DATA` in order under credit; `S_HCLOSE` from the publisher is
  `subscription-completed`, `S_CLOSE` from the subscriber
  `delete-subscription`, `S_RESET` from the publisher
  `subscription-terminated` with the reason. Credit exhaustion is
  `subscription-suspended {unsupportable-volume}` and its return
  `subscription-resumed`: the transport's flow control implements RFC
  8639 §2.4.3 better than NOTIFY's best-effort drop. `modify`, `kill`,
  `resync` are rpcs. Configured subscriptions (the agent calling the
  console) reuse the enrolment and reconnect machinery. Multicast
  groups and `NOTIFY` frames stay as the stateless fast path.
- **Capabilities.** `ctrl getfamily` and `hello` give way to
  `ietf-yang-library` (module set, features, deviations, content-id);
  the console caches per host and refreshes on
  `yang-library-update`. Features advertise optional parts
  (`if-mib`, `pre-provisioning`, `candidate`, `on-change`,
  `configured`, `vnet`, `stamp`, ...); deviations document FreeBSD's
  divergences (global `forwarding`, one MTU for both address
  families, `priority-tagged` encapsulation unsupported) instead of
  silent misbehaviour.
- **Versioning.** The `.sid` files are the "numbers are forever"
  ledger: a SID is never reused or removed, an item that goes gets
  `status obsolete`, a module revision adds items at the end of its
  range. Module revision replaces the family version; the library's
  `content-id` is the capability hash. IETF modules with IANA SIDs
  (coreconf 1000, yang-types 1100, inet-types 1150, crypt-hash 1200,
  netconf-acm 1250, sid-file 1300, interfaces 1500, ip 1600, system
  1700, iana-if-type 1800) use them; the others (routing, v4ur, v6ur,
  network-instance, logical-network-element, yang-library,
  datastores, origin, schema-mount, subscribed-notifications,
  yang-push, yang-patch, restconf, restconf-monitoring,
  yang-structure-ext, acl, packet-fields, i2nsf-*, vpn-common,
  l3vpn-ntw, sap, vn, network-vpn-pm, alarms) and Arcana's own get
  SIDs from a mega-range Arcana asks IANA for (RFC 9595 §7, Expert
  Review); until then a self-chosen block above 2^40, with the
  recorded risk that IANA later assigns those modules differently
  and Arcana keeps its numbers (no CORECONF interoperation is
  claimed).
- **Validation.** A static table engine in libcblink (today's
  `cbl_policy` grown up: types, ranges, lengths, patterns, enums,
  bits, identity derivation, union, mandatory, min/max-elements,
  keys, unique within a list, config-false rejected in edits, choice
  exclusivity, defaults) and a separate `cbl_xpath` evaluator for
  `when`, `must`, leafref existence, instance-identifier existence,
  subtree and XPath filters, NACM paths and schema-mount
  parent-references. The XPath subset ("XPath-lite": child, parent,
  self, descendant-or-self, key predicates, `current()`, `deref()`,
  `derived-from()`, `derived-from-or-self()`, `enum-value()`,
  `bit-is-set()`, `re-match()`, `count()`, `not()`, string functions,
  arithmetic, comparisons with node-set semantics, `|`) covers every
  expression in the target modules; the generator refuses anything
  outside it, so the runtime never meets what it cannot evaluate.
  Patterns are XSD regular expressions translated to POSIX ERE at
  generation time and compiled with `regcomp`; the translator fails
  loudly on constructs it does not know. Validation runs in full on
  edits of `running`, `candidate` and `arcana:live`; on rpc input;
  never on operational reads (RFC 8342 §5.3).
- **Errors.** `error-tag` identities give the console RFC 8040 §7's
  HTTP status for free; `error-app-tag` and `error-message` come from
  `must` statements; `errno` stays for arcanactl.

Expressiveness, both ways. cblink keeps what YANG lacks: credit
streams and half-close, multicast with the `ENOBUFS` marker, framed
dumps, connection limits (`hello`), cookies and warnings in acks,
SCTP. YANG brings what cblink lacks: typedefs, groupings,
augmentation by third parties, deviations, features, identities,
union, bits, decimal64, patterns, defaults, units, status; keyed and
ordered lists, choice, presence, config/state and NMDA; mandatory,
min/max-elements, unique, must, when; edit semantics with
rollback-on-error, candidate and confirmed commit; actions on list
entries; subscriptions with filters, replay, periodic and on-change;
NACM; yang-library; schema mount; the standard models and their
tools. Deliberately not implemented (the profile): `anyxml` content
validation, full XPath 1.0, XSD regex beyond the subset, a `startup`
datastore, locks across connections; recursive groupings (a trace
step containing steps) become a flat list with a parent leafref.

## The generator

cblink-gen reads YANG modules and `.sid` files and writes, per
module set: C structs (`has_` flags, arrays for lists and leaf-lists,
union variants, `cbl_bytes` for binary and bits), schema tables (node
kind, delta, type, constraints, children, keys, when/must expression
ids, defaults, config, mandatory, min/max, ordered-by, identity
closure, feature table, SID table), builders and parsers, datastore
handler stubs per top-level container or list, rpc/action handler
prototypes, notification helpers, subscription helpers, the Markdown
and RFC 8340 tree diagrams, and updated `.sid` files (missing items
assigned in RFC 9595 §6 order only with `--assign`; a schema item
without a SID is otherwise a build error). It reads `.sid` JSON with
base libucl. It verifies: imports and prefixes with revisions,
typedef restriction inheritance, groupings with `refine` and
uses-scoped `augment`, `augment` on containers, lists, choices, cases,
rpc input/output and notifications with `when`, `choice`/`case`
shorthand and `default`, `deviation` (not-supported, add, replace,
delete), `feature`/`if-feature` expressions with pruning,
identities with several bases, config inheritance, `mandatory`,
`status`, `ordered-by`, `unique`, `action` and `notification` in data,
`anydata`, submodules, YANG 1.0 modules (netconf-acm), the extensions
`sx:structure`, `sx:augment-structure`, `yangmnt:mount-point`,
`nacm:default-deny-*`, `sn:subscription-state-notification`. It
rejects what the profile excludes with a diagnostic naming the
statement.

## The agent as a YANG device

| Module | FreeBSD realisation (operational source; config sink) | Deviations and features |
|---|---|---|
| `ietf-interfaces` | getifaddrs(3), `if_data` counters, SIOCGIFFLAGS/MEDIA/DESCR, vlan/bridge/lagg ioctls for layering, netlink RTM_GETLINK; sinks rc.conf `ifconfig_<if>`, `cloned_interfaces`, SIOCIFCREATE2, SIOCSIFFLAGS; events from rtsock RTM_IFINFO/IFANNOUNCE or netlink groups | broadcast counters omitted (if_data merges them into multicast); `link-up-down-trap-enable` not supported; features `if-mib`, `pre-provisioning` (interfaces moved into jails) |
| `arcana-interfaces` (augment) | vlan id and parent, bridge members and STP flags, lagg proto and ports, epair peer and vnet, link MTU, `ether`, media, groups, fib (→ `bind-ni-name`), capability bits | |
| `ietf-ip` | AF_INET/INET6 ifaddrs, SIOCAIFADDR(_IN6)/SIOCDIFADDR, ARP/ND caches by sysctl NET_RT_FLAGS or netlink RTM_GETNEIGH, `SIOCGIFINFO_IN6` flags, address lifetimes; sinks rc.conf `ifconfig_<if>`, `_alias<n>`, `_ipv6`, `static_arp_pairs`, `static_ndp_pairs` | `forwarding`, `dup-addr-detect-transmits`, temporary addresses are host-global sysctls: reported with origin `system`, per-interface writes refused by a deviation; one MTU for both families |
| `ietf-routing`, `ietf-ipv4-unicast-routing`, `ietf-ipv6-unicast-routing`, RA submodule | NET_RT_DUMP per FIB or netlink RTM_GETROUTE with RTA_TABLE; RTF_STATIC/LOCAL/PINNED → source-protocol; RTF_BLACKHOLE/REJECT → special next hops; ECMP via RTA_MULTIPATH; `active-route` by RTM_GET; sinks rc.conf `defaultrouter`, `static_routes`, `route_<name>`, `ipv6_*`, and the kernel by rtsock or netlink; RA: rtadvd.conf and `rtadvctl reload` | `router-id` not at the host root; `prohibit` next hop unsupported; `last-updated` tracked by the agent from events; `multiple-ribs` off at the root: other FIBs are network instances |
| `ietf-network-instance` | one instance per FIB 1..`net.fibs`−1 named by the agent (names kept in `/usr/local/etc/arcana/fibs.conf`), `vrf-root` a shared-schema mount of routing, v4ur, v6ur and yang-library; `bind-ni-name` ↔ SIOCGIFFIB/SIOCSIFFIB and rc.conf `fib N` | creation needs `net.fibs` in loader.conf and a reboot: `ni-assignment-failed` with a reboot-required flag; per-AF binding equals the interface's; no `vsi-root` (if_bridge is an interface) |
| `ietf-logical-network-element` | one per vnet jail (`jail_get`, `vnet = new`), `root` an inline mount served by a long-lived helper attached with `jail_attach(2)` speaking cblink 2 over a socketpair (the same proxied-connection mechanism as the fleet mount at the console); `bind-lne-name` ↔ SIOCSIFVNET and jail.conf `vnet.interface`; jail events from `exec.poststart`/`poststop` hooks Arcana writes into jail.conf | non-vnet jails are not LNEs (their addresses appear as host aliases with an `arcana-jails:owner` augment) |
| `ietf-access-control-list`, `ietf-packet-fields`, RFC 9899 | an ACL = a reserved ipfw rule band ended by `return`, entered by `call` from attachment rules (`in recv`, `out xmit`, `via`), names in rule comments; prefix sets = tables swapped atomically; port sets = lists ≤ 30 or number tables; protocol sets = or-blocks; ICMP sets = type lists; fragments by `frag df/mf/offset`; extension headers by `ext6hdr`; flags-bitmask by `tcpflags`; `rate-limit` = a dummynet pipe; `log-action` = `log logdst`; `counter-action` = a `count` rule per name; applied through the set-swap transaction with the rest of the ruleset | features match-on-eth/ipv4/ipv6/tcp/udp/icmp, eth, ipv4, ipv6, mixed-*, acl-aggregate-stats, interface-attachment, match-on-alias; not interface-stats (unless blocks are duplicated per attachment), match-on-payload (unless ng_bpf is wired), vlan/isid/mpls. Refused with an extended ack: ICMP code, ECN, ihl, exact fragment offset, identification, TCP data-offset/reserved/urgent/options pattern, ECE/CWR/AE bits, IPv6 ff/lf, Mobility/HIP/Shim6 headers. Arcana augments: attachment to a FIB, a jail, all interfaces; `default-action`; `stateful` (keep-state); reject code |
| `ietf-i2nsf-ikeless` (RFC 9061) | PF_KEYv2 in-process (libipsec): SADB_ADD/UPDATE/DELETE/GET/DUMP, SADB_X_SPDADD/SPDDELETE/SPDDUMP, SADB_REGISTER for SADB_ACQUIRE, SADB_EXPIRE; selectors with single ports; ESN with an explicit window (`-r 128`), NAT-T; or the ipsec(4) interface's reqid for route-based policies (today's uswe) | notifications `sadb-acquire` and `sadb-expire` exact, `sadb-seq-overflow` synthesised, `sadb-bad-spi` absent (no kernel notification); refused: port ranges, `espintcp`, `pfp-flag`, `seq-overflow true`, `tfc-pad`, per-SA `df-bit`, `dscp-mapping`, IV, packet and idle lifetimes, selectors on the SA |
| `ietf-i2nsf-ike` (RFC 9061) | strongSwan: files in conf.d as the persisted configuration, VICI for state (`list-sas`) and events; identities, PSK, EAP, signatures with the host's own key (private keys never pushed); lifetimes; proposals from IANA ids by the tables in the notes | refused: `id-null`, per-connection initial-contact, fragmentation MTU, half-open timers; `number-ike-sas/half-open-cookies` absent |
| `ietf-ipsec-iptfs` (RFC 9348) | only `ipsec-stats` tx/rx packets and octets per SA from the lifetime counters | everything else refused: the kernel has no AGGFRAG/IP-TFS; the configuration augment is not feature-gated, so writes are refused with `operation-not-supported` and the console hides the subtree behind an Arcana capability |
| `ietf-alarms` (RFC 8632) | the faults and threshold alerts, resource = link or interface instance-identifier, alarm-type-id Arcana identities, severity, cleared, time-created | |
| `ietf-yang-library`, `ietf-yang-schema-mount`, `ietf-netconf-acm`, `ietf-subscribed-notifications`, `ietf-yang-push` | the runtime: per-mount library; groups from the certificate's subject or the socket's uid; rule-lists; enforcement at rpc, data-node and notification; periodic timers; on-change by rtsock/netlink events and jail polling, dampening, YANG Patch emission; subtree and XPath filters; replay from the event number for job traces and events | `on-change-unsupported` for counters; NACM replaces the per-op `auth` flag (`default-deny-all` on privileged rpcs) |
| Arcana modules | `arcana-jails` (every jail(8) parameter as a leaf, actions start/stop/restart/kill, the LNE link), `arcana-services` (rc.d scripts, rcvars, `service` actions, rc.conf variables), `arcana-packages` (pkg, upgrade rpc), `arcana-jobs` (the queue, submit rpc, cancel and confirm actions, traces as a flat list with parent ids, a notification stream per job), `arcana-storage` (GEOM, zpool, zfs, mounts, fstab, snapshots, send/receive streams), `arcana-sysctl` (`sysctl[name]{value}` persisted to sysctl.conf), `arcana-kernel` (modules, kld_list), `arcana-processes`, `arcana-log`, `arcana-history`, `arcana-events`, `arcana-probe` (STAMP and ICMP sessions, percentiles, measurement interval), `arcana-dummynet` (schedulers, pipes, queues: the NRP), `arcana-steer` (the CAL), `arcana-bird`, `arcana-wireguard`, `arcana-netgraph`, `arcana-plugins`, `arcana-host` (facts, router-id, node role, capabilities), `arcana-agent` (update, build rpcs) | the 430 named items of `arcana.yaml` map mechanically; the JSON blobs become typed lists |

Every module Arcana writes avoids decimal64, keeps `when`/`must`
within XPath-lite, and uses identities for open sets.

## The console as controller

- **RESTCONF.** `/.well-known/host-meta`, `/restconf` with `data`,
  `operations`, `yang-library-version`; api-path parsing; OPTIONS,
  HEAD, GET, POST, PUT, PATCH (plain and YANG Patch), DELETE with RFC
  8040's status table; ETag and Last-Modified from the host's commit
  counter; `content`, `depth`, `fields`, `filter`, `insert`, `point`,
  `start-time`, `stop-time`, `with-defaults`; `ietf-restconf:errors`
  from the agent's error structure; streams listed under
  `restconf-state` and served as `text/event-stream`;
  `establish-subscription` by POST, the SSE location in the reply;
  `application/yang-data+cbor` passed through unchanged for the PWA.
  The console's own datastore (`arcana-console`: users, enrolment
  tokens, settings, API tokens, workflows, SD-WAN services) is served
  by the same code from the libucl files it keeps today.
- **The fleet.** `arcana-fleet:hosts/host[name]/root`, an inline
  mount: the console strips the prefix, translates the api-path to a
  SID instance-identifier with that host's cached SID tables,
  forwards a `GET`/`EDIT`/`RPC`, translates the reply (RFC 7951 ↔
  9254: names ↔ SIDs with module qualification, int64 strings,
  base64, `[null]` for empty, bits names, enum names, identityref
  `mod:name`, instance-identifier strings, union by canonical form,
  origin as `@` annotations). Subscriptions whose filter spans hosts
  fan out and merge.
- **NACM.** The console maps WebAuthn users and API tokens to NACM
  users and passes the identity per connection (one agent connection
  per console user) to a console the agent trusts by certificate;
  the agent enforces.
- **Service models.** `ietf-l3vpn-ntw` with `ietf-vpn-common` as the
  stored service (D-4); `ietf-sap-ntw` as the inventory of attachment
  points, each agent dumping its node, termination points and SAPs
  into a network the console holds; `ietf-vn` as the customer view
  (access points = UNIs, VN members = tunnels, `if-selected` = the
  steering outcome, thresholds as `path-metric-bounds` with Arcana
  metric identities for loss and delay variation, the `underlay`
  augment carrying encapsulation, outer addresses, FIB, DSCP, SA and
  BFD references); `ietf-network-vpn-pm` as the performance view
  (one `network` per service and one underlay network, two
  unidirectional links per tunnel, `pm-type-vpn-tunnel`, per-class
  entries per DSCP). Arcana identities extend `vpn-common`:
  `service-type sd-wan`, `protocol-type wireguard` and `ipsec`,
  `routing-protocol-type carp` and `babel`, `pm-source icmp-echo`
  and `alt-marking`.
- **The planner.** Reads L3NM, resolves profiles and node overrides,
  allocates FIBs, addresses, RDs, VNIs and table names from a ledger,
  and emits edits to each host's device modules (interfaces, ip,
  routing, NI, LNE, acl, ikeless, dummynet, bird, probe, steer),
  checked and planned before applied as today. Infeasible requests
  are refused with the reason and the nearest feasible alternative
  (RFC 9543 step 2, RFC 8578 §11.3.1).
- **Assurance.** Intended versus operational per host (NMDA): a hand
  edit becomes a `drift` alarm; per-statement SLO compliance from PM
  records as the top-level view; the trace tree plus a "why" record
  (which measurements, which alternatives were rejected) for every
  steering change.
- **Event-driven.** The console subscribes to each agent's events and
  job traces instead of polling; its reaction time becomes
  milliseconds, which RFC 8456's benchmarks then measure honestly.

## What Arcana claims of the frameworks

- **SDN (RFC 7426).** ARCHITECTURE.md names every component's plane
  and layer; the DAL is the YANG module set; the CAL is
  `arcana-steer`; control traffic (steering swaps, probe and BFD
  notifications) gets a stream of its own, on SCTP a stream of its
  own too; `arcanactl` is an application on the SBI. A second console
  (primary/standby sharing the data directory, agents trusting the CA
  rather than one console) is a later phase.
- **Intent (RFC 9315).** The MEF document and L3NM are service
  models, not intent; an `arcana-intent` module (SLOs, reachability,
  encryption, underlay preference, breakout, placement constraints)
  translated into L3NM is Y-7 work; until then nothing is called
  intent.
- **Telemetry (RFC 9232).** YANG-Push over push streams with RFC
  8639/8641's names and semantics exactly; flow records by
  `ng_netflow` per service FIB (NetFlow v9; IPFIX to be verified on
  the lab, `pflow(4)` is pf-only); BMP from BIRD 3.4; syslog over
  TLS; telemetry role on tokens separate from configuration.
- **Slices (RFC 9543) and NRP-based VPNs (RFC 9732).** A slice is an
  L3NM service with SDPs = SAPs (VLAN per slice by default, 5-tuple
  classification as an option), connectivity constructs mapped to a
  named NRP: an `arcana-dummynet` object per link (scheduler tier,
  queue weight, buffer, DSCP class) plus a tunnel set; the console's
  admission ledger refuses what does not fit; isolation offered in
  tiers (shared weight, dedicated queue and tunnel, dedicated WAN
  interface), never claimed as hard. The TEAS slice service YANG is a
  northbound view when it is an RFC.
- **DetNet (RFC 8655, 9938, 8578).** Claimed as a DetNet-IP
  forwarding sub-layer with engineering bounds, no PREOF: per-flow
  dummynet queues from an RFC 9016 traffic specification, a `prio`
  tier, the tick (`net.inet.ip.dummynet.hz`) raised on such hosts,
  pinned explicit routes per FIB owned by the console, BFD failover.
  Use cases served: RFC 8578's band A (tens of milliseconds, five
  nines, failover); band B engineered; band C refused.
- **CATS (RFC 10053).** Services with a CS-ID (an anycast address or a
  VIP with `fwd`), instances = jails, contact instances = jail
  addresses, C-SMA = the agent's normalised score (versioned Arcana
  function until the metrics draft is an RFC), C-NMA = probes and
  counters, C-PS = the console writing candidate sets and agents
  re-ranking locally, affinity by ipfw dynamic state. An
  `arcana-cats` module aligned with the RFC's terms.
- **ACP (RFC 8994) and ASAs (RFC 9222).** Certificates with the
  AcpNodeName otherName from the console's CA, a ULA from the domain
  name, a vnet jail as the ACP context, strongSwan IKEv2 with the
  RFC's profile over link-local, a GRASP daemon of our own (DULL per
  interface, ACP instance over TLS), EST renewal at 50 %, Babel first
  (D-11), the console reached over the ACP first. Claimed as "ACP
  without BRSKI": the token enrolment stays (RFC 8994 §6.11.7.1
  permits it); no IDevIDs exist on general hosts.
- **Auto-discovery VPN (RFC 7018).** The console publishes a signed
  per-service peer directory by YANG-Push; agents reconcile tunnels
  from it; shortcut tunnels between spokes triggered by flow
  telemetry with dwell and hysteresis; reflexive endpoints learned
  from the hub. Arcana meets 9 of the 16 requirements today; this
  takes it to 14 (federation and multicast stay out).
- **Benchmarks (RFC 8455, 8456).** A `bench/` harness on one host
  with vnet jails as devices: topology discovery time, asynchronous
  message processing time and rate, proactive path provisioning time
  and rate, topology change detection time, control sessions
  capacity, discovery size, forwarding table capacity, exception and
  DoS handling, network re-provisioning time with local failover
  disabled and reported separately. Reactive provisioning and
  controller failover declared not applicable with the reason.
- **ICN (RFC 8763) and NFV challenges (RFC 8568).** Vocabulary only:
  overlay, underlay, slice, SFC made explicit as an ordered function
  chain per policy; host descriptors in `arcana-host` for placement
  checks; no ICN work.

## What cannot be mapped

Consolidated from the per-RFC notes. "Kernel" means it would need
kernel work, which Arcana does not do.

| Area | Not realisable on FreeBSD, and why |
|---|---|
| MPLS and segment routing (9181, 9182, 9732, 9543, 9938, 7426's PCEP, 9899 `mpls-values`, 10053 SRv6 paths) | no MPLS or SRv6 forwarding in the kernel (GSoC branch, not before 17); net/bird3 does not build l3vpn/evpn; FRR on FreeBSD has no MPLS, LDP, SR or VRF |
| RFC 4364 as an operational object (9182 RD/RT, `auto-assigned-rd`, VPN SAFIs; 8955 SAFI 134) | follows from the above; bookkeeping only (D-5) |
| L2 services: pseudowires, VPLS, EVPN, VXLAN bgp-mode, L2TPv3, `vxlan` with several static unicast peers on one interface (9181, 9182) | no LDP or EVPN; vxlan(4) has one `vxlanremote`; approximation under Arcana identities with vxlan + if_bridge only |
| IS-IS, S-BFD, OSPF sham links, `max-lsa`, RIP holddown, TCP-AO, IPv6 site-of-origin, BGP warning-threshold, native as-override, IPv6 router-id (9182) | BIRD lacks them; FreeBSD has no TCP-AO |
| VRRP on the wire (9181, 9182) | carp(4) only, wire-incompatible: an Arcana `carp` identity instead |
| `priority-tagged` (L3NM's default) and `qinany` encapsulations | vlan(4) refuses VID 0 and has no wildcard inner tag |
| Multicast beyond pimd: MLD router side, PIMv6, bidir PIM, Auto-RP, anycast RP, MSDP, IGMP snooping in if_bridge, group limits (9181, 9182, 8578) | no maintained daemons; bridge has no snooping |
| MACsec (9182 layer-2 encryption, 9543 security SLE) | not in FreeBSD |
| IP-TFS / AGGFRAG, TFC padding (9348, 9061) | not in netipsec; strongSwan's IP-TFS is Linux-XFRM only |
| `sadb-bad-spi`; per-SA replay drop counters; port ranges in selectors; `espintcp`; PFP; per-SA DF and DSCP mapping; packet and idle lifetimes (9061) | PF_KEY has no such notification and no range extension; the kernel ignores or lacks them |
| ACL matches: ICMP code, ECN value, IHL, exact fragment offset, identification, TCP data-offset/reserved/urgent-pointer/options pattern, ECE/CWR/AE flags, IPv6 first/last fragment, Mobility/HIP/Shim6 headers, payload patterns, VLAN TCI, I-SID (8519, 9899) | ipfw's vocabulary; pf covers ICMP code, ECN and E/W only; payload only via ng_bpf or Suricata |
| 9899 attachment to a VRF, device or all interfaces | the published module has none; an Arcana augment |
| FlowSpec enforcement in the kernel; ICMP code; IPv6 prefix offsets; two-octet TCP flags; packet-per-second limits (8955) | BIRD distributes, nothing enforces: the agent translates to ipfw; dummynet is bytes (ng_car has pps) |
| DetNet PREOF, network coding, worst-case latency, misordering bounds, time-gated and credit-based shapers, TSN and FlexE, nanosecond link latency, per-flow hardware resources (8655, 9938, 9732, 9543) | nothing in the kernel; dummynet is a software shaper with a millisecond tick |
| Hardware timestamps, PTP accuracy below tens of microseconds (8972, 8578) | RX stamps only on cxgbe and mlx5, no TX stamps or PHC; ptpd2 only |
| IPv6 AltMark option, link-based alternate marking across foreign hops, marks seen inside encrypted tunnels by the underlay (9342) | ipfw cannot insert options; only edges are measurement points |
| TE topology leafrefs, abstract nodes, connectivity matrices, Type 2 explicit paths, RSVP/GMPLS constraints, bandwidth reservation across the underlay, `vn-compute` on a device (9731) | controller-only or signalled-TE notions; the SD-WAN underlay is not TE-visible |
| Broadcast counters distinct from multicast; `maximum-routes`; `last-updated` on routes (9375, 8343, 8349) | if_data merges them; no per-FIB limit; no timestamp in the kernel RIB |
| RPL, BRSKI/IDevID/MASA, per-port DULL on a bridge, DTLS-only constrained profile (8994, 8995) | no implementations; no manufacturer identities on general hosts (D-11) |
| IOAM, postcard telemetry, in-band OAM, sFlow sampling in base, gNMI (9232, 9938) | not in the kernel or in base |
| ForCES, OpenFlow, PCEP, I2RS protocol (7426) | no implementations; not pursued |
| Reactive path provisioning, controller failover (8455, 8456) | not applicable to Arcana's design: no packet-in, standalone console |
| ICN forwarding, BIER, CDN migration, 6LoWPAN (8763); multi-operator MANO, 5G slicing, VM portability (8568) | out of scope |

## The phases

Each phase ends with something that runs beside the legacy family, is
reviewed, bumps the agent and console versions, updates ARCHITECTURE,
the openapi document and the book, and is run on the lab where it
says L.

### Y-0 Spike (3 weeks)

- **0.1 Body decoder.** G: SID-delta keys, tags 4 and 43–47, the
  `cblink` structures, hand-written SID tables for `ietf-interfaces`;
  encode and decode an `interfaces` dump; measure frame sizes against
  v1.
- **0.2 Parser prototype.** G: a YANG 1.1 lexer and parser over the
  module corpus (the IETF modules named above plus ietf-vpn-common
  and ietf-l3vpn-ntw, the largest); two weeks; the evidence for D-3.
- **0.3 BIRD VPN spike.** L: `net/bird3` 3.4.0 with an `mpls` domain
  and `vpn4` tables on two jails without kernel MPLS; whether routes
  are exchanged and labels allocated; the evidence for D-5(b).
- **0.4 ng_netflow and pflow.** L: what `ng_netflow` exports on
  15.x/16 (v5, v9, IPFIX?); the evidence for the telemetry choice.
- **0.5 IANA.** D: request a SID mega-range (RFC 9595 §7); choose the
  provisional block.
- **0.6 Decisions.** D-1 to D-3 taken; D-4 to D-12 recorded with their
  dates in this plan.

### Y-1 The generator and the wire (14 weeks)

Depends on Y-0.

- **1.1 Lexer and parser.** G: RFC 7950 §14 ABNF, string forms,
  submodules, extension statements, YANG 1.0 and 1.1. ~1.5 k lines.
- **1.2 Schema compiler.** G: imports and prefixes, typedef
  inheritance, groupings with refine and uses-augment, augment on
  every target with `when`, choice/case, deviations, features,
  identities, config and mandatory rules, schema-node-id resolution,
  diagnostics; the profile's refusals. ~5–6 k lines. The risk item.
- **1.3 XPath-lite parser.** G: shared by generator and runtime.
  ~1.2 k.
- **1.4 SID tooling.** G: `.sid` read and write with libucl,
  verification, assignment, ranges, obsolete items, the
  `ietf-sid-file` structure for `GET-SID`. ~1.2 k.
- **1.5 Pattern translator.** G: XSD regex subset → ERE, with the RFC
  6991 patterns as the generation-time test. ~0.5 k; fallback an own
  matcher.
- **1.6 Emitter.** G: structs, tables, builders, parsers, handler
  stubs, helpers, Markdown and tree diagrams; replaces `gen_c.c` and
  `gen_md.c`. ~5–6 k.
- **1.7 libcblink wire 2.** G: `cbl_decode`, `cbl_attr`, `cbl_policy`,
  `cbl_msg`, `cbl_frame`, `cbl_stream` credit frames; the `cblink`
  module's structures; version 1 and 2 side by side; `ctrl`
  regenerated from `cblink-ctrl.yang`. ~3 k changed.
- **1.8 Static validator.** G: the table engine building an instance
  tree. Part of 1.7's rewrite; the evaluator comes in Y-2.
- **1.9 `ietf-interfaces` and `arcana-interfaces`.** A: collectors
  from getifaddrs, if_data, ioctls, netlink; rtsock events. ~2.5 k.
- **1.10 `ietf-ip`.** A: addresses, neighbours, nd6 flags, lifetimes,
  the global sysctls with origin `system`, the deviations. ~2 k.
- **1.11 First GET.** A, C: the agent registers family 1 beside
  `arcana`; `GET` and dump of operational interfaces and addresses;
  the console reads them through a thin translator and shows them on
  the Network tab in place of `netstat --libxo json`. L: on the lab,
  every interface type Arcana makes.
- **1.12 Tests.** G: a generator corpus (every IETF module above,
  pathological cases), decoder fuzzers with tags, `pyang -f tree`
  cross-check in CI. D: GENERATOR.md, SPEC-FORMAT.md replaced by
  YANG.md, WIRE-FORMAT.md version 2.

### Y-2 Datastores, routing, instances (16 weeks)

Depends on Y-1.

- **2.1 Instance tree and edit engine.** G: defaults, keys and
  unique, identity derivation, leafref resolution, merge, replace,
  create, delete, remove, insert, move, diff for on-change. ~5 k.
- **2.2 XPath-lite evaluator.** G: node sets, coercions, functions,
  `must` and `when`, filters, parent-reference, NACM path matcher;
  property tests against libyang in CI. ~3–3.5 k.
- **2.3 Datastore engine.** A: `running` round-trip editors for
  rc.conf and rc.conf.d (Arcana-owned fragments where rc(8) reads
  them), jail.conf (libjailconf), loader.conf, sysctl.conf,
  rtadvd.conf, the kept ipfw rules, swanctl conf.d, preserving
  comments and order; `candidate` with commit, confirmed commit and
  rollback (today's job-confirm generalised); `arcana:live`;
  operational collectors; the apply transaction with undo. ~6–8 k.
  The second risk item.
- **2.4 `ietf-routing`, v4ur, v6ur.** A: per-FIB dumps, static routes
  in rc.conf and the kernel, ECMP by netlink, `active-route`,
  source-protocol mapping, route events. ~2.5 k.
- **2.5 Router advertisements.** A: rtadvd.conf writer and reader,
  `rtadvctl reload`. ~0.8 k.
- **2.6 `ietf-network-instance`.** A: FIB names, `vrf-root` mount,
  `bind-ni-name`, `net.fibs` and the reboot flag,
  `parent-reference`. ~0.8 k.
- **2.7 `ietf-logical-network-element`.** A: the attached helper per
  vnet jail over a socketpair, interface moves, jail hooks in
  jail.conf, per-LNE library. ~1.5 k.
- **2.8 yang-library and schema mount runtime.** A: per-mount
  libraries, nested mounts (NIs inside an LNE), dispatch. ~1.5 k.
- **2.9 First EDIT.** C: an address added persistently through
  `EDIT` on `running` and live through `arcana:live`; a static route;
  an interface moved into a jail. L: the lab, with a hand edit of
  rc.conf shown as drift.
- **2.10 Tests.** round-trip fixtures for every file editor,
  validator tests from RFC 7950's examples, XPath tests.

### Y-3 The Arcana modules, subscriptions, NACM (14 weeks)

Depends on Y-2.

- **3.1 The Arcana modules.** A: `arcana-jails`, `-services`,
  `-packages`, `-jobs`, `-storage`, `-sysctl`, `-kernel`,
  `-processes`, `-log`, `-history`, `-events`, `-bird`, `-wireguard`,
  `-netgraph`, `-plugins`, `-host`, `-agent`, `-dummynet`; the 430
  items of `arcana.yaml` mapped, the JSON blobs replaced by typed
  lists. ~4 k C, ~2.5 k YANG.
- **3.2 Subscriptions.** A: `ietf-subscribed-notifications` and
  `ietf-yang-push` on push streams: periodic timers, on-change by
  events with dampening and YANG Patch emission, subtree and XPath
  filters, state-change notifications, suspension on credit,
  monitoring counters, configured subscriptions calling the console.
  ~3.5–4 k.
- **3.3 NACM.** A: groups from the certificate or uid, rule-lists,
  enforcement at the three points, counters; the console passes the
  user. ~1.5 k.
- **3.4 Event-driven console.** C: subscriptions replace the one-second
  polls of jobs, stats, lists and the SD-WAN read; the Kore module's
  one connection per agent carries long-lived streams; reconnect
  logic. Benchmarks before and after (8.1).
- **3.5 `arcana-steer`, the CAL.** A, C: candidates, chosen, reasons,
  the events; the agent's local failover writes it, the console reads
  and writes it; a stream of its own, an SCTP stream of its own.
- **3.6 arcanactl.** C: reads and writes YANG paths (`arcanactl get
  /ietf-interfaces:interfaces`), libxo output unchanged for the old
  verbs during coexistence.
- **3.7 Tests.** every former operation's test rewritten against the
  module; the root suite on real jails.

### Y-4 RESTCONF and the service models (16 weeks)

Depends on Y-3.

- **4.1 RESTCONF layer.** C: discovery, api-path, methods, status
  table, conditional requests, query parameters, errors, YANG Patch,
  `restconf-monitoring`, SSE. ~3 k.
- **4.2 JSON ↔ CBOR.** C: the schema-driven translator. ~2.5 k.
- **4.3 The fleet mount.** C: `arcana-fleet`, per-host SID and library
  cache, proxying, YANG-Push fan-out and relay, NACM identity. ~1.5 k.
- **4.4 The console's own datastore.** C: `arcana-console` served by
  RESTCONF from the libucl files; `/api` paths mapped one by one and
  frozen.
- **4.5 `ietf-vpn-common` and `ietf-l3vpn-ntw`.** C: stored as the
  service (D-4), the Arcana augmentations (policy map, application
  flows, breakout, security policies, probes, steering criteria, the
  routing domains), the MEF 70.2 importer and exporter, the planner
  reading L3NM and the allocation ledger (FIBs, addresses, RDs,
  VNIs, tables).
- **4.6 `ietf-sap-ntw`.** A, C: each agent dumps its node, TPs and
  SAPs with `sap-status`; the console holds the SAP network and the
  physical network under it; the anomaly rules as checks; the
  Appendix D flow (free SAP → access id) in the planner.
- **4.7 `ietf-vn`.** C: the customer view: access points, VNAPs, VN
  members with `if-selected` and `oper-status` from `arcana-steer`
  and the probes, `path-metric-bounds` with Arcana metric identities
  for loss and delay variation, the `arcana-sdwan-underlay` augment,
  `vn-compute` as the console's Check over per-edge feasibility
  calls.
- **4.8 PWA.** P: RESTCONF JSON or CBOR pass-through, SSE
  subscriptions, forms generated from the yang-library (the schema
  page already renders a schema). 3–4 weeks.
- **4.9 Book and openapi.** D: the API page from the RESTCONF
  description; the SD-WAN part rewritten over L3NM with the MEF terms
  kept in the page. (The book is kept by the session on the user's
  machine.)
- **4.10 Phase close.** L: a service written as L3NM through
  RESTCONF, applied on the lab's jails, read back as VN and SAP, the
  same service exported as a MEF document and re-imported unchanged.

### Y-5 Measurement, alarms, telemetry (12 weeks)

Depends on Y-3; independent of Y-4.

- **5.1 STAMP reflector and sender.** A: UDP 862 per service FIB
  (SO_SETFIB, IP_RECVTOS, SO_TIMESTAMP with SO_TS_CLOCK realtime, a
  monotonic clock for RTT), stateless and stateful reflector, SSID,
  the TLVs of RFC 8972 (extra padding, location, timestamp
  information from `ntp_gettime`, class of service, direct
  measurement from ipfw counters, HMAC with libcrypto), authenticated
  mode by default on plain tunnels; `arcana-probe` config shaped
  after the expired `ietf-stamp` draft, state after RFC 9375. ~1 k.
  L: dummynet `plr` and `delay` seen in the metrics; interoperation
  with a TWAMP Light reflector.
- **5.2 Percentiles and intervals.** A: raw samples kept per
  measurement interval (default 60 s), three percentiles, loss as
  count and decimal percentage, microsecond units, per-class sessions
  per DSCP, start and end as date-and-time.
- **5.3 `ietf-network-vpn-pm`.** C: one network per service plus the
  underlay, two links per tunnel, `pm-type-vpn-tunnel`,
  `vpn-tunnel-type` with the Arcana identities for wg and ipsec,
  typed TP counters from if_data, per-FIB route counts, underlay-link
  probes.
- **5.4 `ietf-alarms`.** A, C: faults and TCAs as alarms with
  resources that are instance-identifiers, shelving, the alarm
  inventory; the Paths tab reads alarms.
- **5.5 Alternate marking.** A, C: `setdscp` colour pairs flipped on
  a timer per service, paired `count dscp` rules at the ends, counters
  read at L/2 by the `IP_FW3` sockopt with a block number, the
  clustered partition of RFC 9342 §5.1 in the console with Appendix A
  as the unit test, the in-band variant through STAMP's direct
  measurement TLV for steering. L: three jails, loss localised to one
  cluster.
- **5.6 Flow telemetry.** A: `ng_netflow` per service FIB (by 0.4's
  result), sampling, per-zone; BMP from BIRD to the console; the
  console's compact time-series store with retention per class.
- **5.7 Phase close.** L, D: the measurement chapter; TODO's verified
  list.

### Y-6 ACLs, IPsec, FlowSpec (12 weeks)

Depends on Y-3; independent of Y-4 and Y-5.

- **6.1 `ietf-access-control-list` with RFC 9899.** A: the ipfw
  compiler (bands, `call`/`return`, tables with shadow swap, port
  sets, protocol or-blocks, ICMP lists, fragments, extension headers,
  flags-bitmask, `rate-limit` as a pipe, `log-action`,
  `counter-action`), the refusals, the features, the Arcana augments
  (FIB, jail, all interfaces, default-action, stateful, reject code),
  applied in the set-swap transaction with the SD-WAN rules.
  `net.inet.ip.fw.tables_max` raised at start. The SASE `ip-block`
  policies compiled through the same module.
- **6.2 `ietf-i2nsf-ikeless`.** A: PF_KEYv2 in-process replacing
  setkey text, SADB_REGISTER for acquire and expire notifications,
  the seq-overflow synthesis, the ipsec(4)-interface mapping for
  route-based policies, uswe's keys arriving as `esp-sa/key` from the
  agent's own derivation (the console never sees them), RFC 9061
  Appendix D.2's rekey order; `net.key.preferred_oldsa = 0`.
- **6.3 `ietf-i2nsf-ike`.** A: swanctl files as the persisted
  configuration, VICI for `list-sas` and events, the IANA algorithm
  tables, private keys refused; `ipsec-stats` of RFC 9348 per SA; an
  `ipsec-capabilities` dump.
- **6.4 Key chains.** A, C: an `ietf-key-chain` (RFC 8177) module for
  BGP, OSPF, RIP and BFD authentication and customer encryption
  profiles, mapped to BIRD passwords, setkey tcp-md5 SAs and swanctl
  secrets; write-only leaves.
- **6.5 FlowSpec.** A, C: BIRD per-service `flow4`/`flow6` channels
  with `validate on`, the agent polling `show route table ... all`
  (1 s when channels exist), the RFC 8955 §5.1 ordering with the
  reference Python as the oracle, the ipfw translation of all 13
  components with the unsupported cases counted and reported, actions
  (rate 0 deny, rate bytes a pipe, rate packets `ng_car` when loaded,
  sample log and count, terminal composition, redirect `setfib` by
  RT → domain, marking `setdscp`), a dedicated set rebuilt
  atomically before the SD-WAN set, caps; the console originating
  flowspec as static routes with extended communities on the route
  reflector. L: drop, mark, refib round trips; a UNI eBGP stand-in
  accepted for its own prefix and refused for a foreign one.
- **6.6 D-5(b) if 0.3 succeeded.** C, A: `vpn4`/`vpn6` between edges
  with fake labels and a VXLAN VNI per VPN; RD/RT become operational.
- **6.7 Phase close.** L, D.

### Y-7 The frameworks (16 weeks)

Depends on Y-4 and Y-5.

- **7.1 The NRP object.** A, C: `arcana-dummynet` as a first-class
  object (scheduler tier template per link: `prio` for control and
  voice, WF2Q+ tiers for assured, best effort residual; queue weight,
  buffer, DSCP class; the tunnel set), referenced by services; the
  admission ledger with an overbooking factor per tier; the
  `(tunnel set, DSCP)` identifier on the wire; isolation tiers as
  SLEs; OAM probes classified into the construct's queue, BFD in the
  control class.
- **7.2 Slices.** C: SDP placement per UNI (VLAN or 5-tuple),
  connectivity constructs P2P/P2MP/A2A mapped to NRPs, SLOs evaluated
  from PM, availability with period and maximum single outage,
  rejection with alternatives. The TEAS slice YANG as a view when
  published.
- **7.3 DetNet-f.** A, C: RFC 9016 traffic specification → per-flow
  queue and policer, `prio` tier, tick raised, console-owned explicit
  routes per FIB with a reconvergence policy, capability honesty
  (`worst-case-delay unknown`, an estimate), the band-A/B/C statement
  in the book; an RFC 9633 profile as a northbound view.
- **7.4 CATS.** A, C: `arcana-cats`: services with CS-IDs, instances,
  the normalised score (versioned), candidate sets with dwell and
  hysteresis, affinity by dynamic state, Egress instance choice by
  `fwd` or a load-balancer jail; compute scores optionally as BGP
  communities through the reflector.
- **7.5 The ACP.** A, C: certificates with AcpNodeName, Registrar-ID
  and node numbers persisted, the ULA, the `acp` vnet jail, GRASP
  daemon (DULL per interface, adjacency table, ACP instance over TLS
  1.3), strongSwan IKEv2 with the RFC's profile and if_ipsec per
  neighbour, Decider/Follower and backoff, Babel in BIRD inside the
  jail, EST server in the console announced by `SRV.est`, renewal at
  50 %, CRL on the console's ULA, configured remote neighbours with
  the console host as hub (NAT-T), the console connecting over the
  ULA first, admin down by ipfw, NTP over the ACP, an `arcana-acp`
  module for the diagnostics of §9.1. L: four jails, data plane cut,
  management stays.
- **7.6 Auto-discovery VPN.** C, A: the signed peer directory per
  service published by YANG-Push, agents reconciling tunnels from it,
  shortcut tunnels from flow telemetry with lifetimes, reflexive
  endpoints from the hub, multi-gateway entries for remote users,
  events for every establishment and fallback.
- **7.7 ASAs (D-12).** A: `arcana-asa`, unprivileged, GRASP objectives
  `arcana:steer` (flooded tunnel state so both ends switch in step)
  and `arcana:sa-rekey` (negotiated, dry run), decisions flooded to
  the console as events, an Instance Manifest, roles in certificates.
- **7.8 Intent.** C: `arcana-intent` statements translated into L3NM,
  the plan showing both, drift and SLO compliance per statement, the
  "why" record, retraction removing exactly what a statement caused.
- **7.9 Phase close.** L, D: ARCHITECTURE.md rewritten in RFC 7426's
  terms; the conformance chapter of the book extended to these RFCs.

### Y-8 Removal, benchmarks, conformance (6 weeks)

- **8.1 Benchmarks.** L: `bench/` with vnet jails, epairs, bridges,
  cpuset separation, agent and console timestamp logs (a test-only
  option of the device emulator), a UDP sequence generator, the RFC
  8456 tests with RFC 8455's terms and units, run before 3.4 and
  after, and nightly at a larger scale; the not-applicable list.
- **8.2 Legacy removal.** G, A, C: the `arcana` v1 family and `/api`
  removed one release after Y-4 froze them; `agent-update` carries
  the last v1 agents across.
- **8.3 Conformance.** D: per RFC, the features advertised, the
  deviations, the refused nodes and the cannot-map list, in the
  book's conformance chapter and in `ietf-yang-library`.
- **8.4 Second console.** C: primary/standby sharing the data
  directory and the CA; agents trusting the CA, not one console;
  RFC 8456's failover benchmark becomes applicable.

## Order and effort

| Phase | Weeks | Needs | Delivers |
|---|---|---|---|
| Y-0 | 3 | — | the three decisions, four spikes |
| Y-1 | 14 | Y-0 | generator, wire 2, interfaces and ip readable |
| Y-2 | 16 | Y-1 | datastores, edits, routing, FIBs, jails as LNEs |
| Y-3 | 14 | Y-2 | every operation as YANG, subscriptions, NACM, event-driven console |
| Y-4 | 16 | Y-3 | RESTCONF, L3NM/SAP/VN, the PWA on RESTCONF |
| Y-5 | 12 | Y-3 | STAMP, PM, alarms, alternate marking, flow telemetry |
| Y-6 | 12 | Y-3 | ACLs, IPsec by the models, key chains, FlowSpec |
| Y-7 | 16 | Y-4, Y-5 | NRP, slices, DetNet-f, CATS, ACP, ADVPN, ASAs, intent |
| Y-8 | 6 | Y-4 | benchmarks, removal, conformance, second console |

Y-4, Y-5 and Y-6 are independent and can run in parallel. One
engineer: 109 weeks in sequence, about 25 months. Two: Y-1 and Y-2
split as generator-and-libcblink against agent-datastores (one
engineer's critical path through Y-3 is ~44 weeks), then Y-4
against Y-5 and Y-6, then Y-7 shared: about 15 months. Estimated
lines: 58–68 k of C new or rewritten (cblink is 20.7 k today, ~8 k
survive; the agent 38 k, the console 25 k, the page 41 k, of which
the operation handlers and the SD-WAN JSON paths are rewritten),
2.5–3 k of YANG for Arcana's modules. Confidence medium: the schema
compiler's corners (1.2) and the configuration files' round trip
(2.3) are where it would overrun.

## Risks

- The compiler's corners: mitigated by the profile (refuse what is
  not implemented), the module corpus bound to what Arcana needs, and
  `pyang`/`yanglint` cross-checks in CI; D-3's fallback is libyang at
  build time with the same emitter.
- XPath semantics: generation-time subset check; property tests
  against libyang.
- rc.conf fidelity: Arcana-managed values kept in `rc.conf.d`
  fragments Arcana owns where rc(8) reads them (`netif`, `routing`,
  per service), a conflict with the user's rc.conf refused with a
  clear message.
- On-change cost on big tables: event sources (rtsock, netlink, jail
  hooks) rather than diffing; counters periodic only.
- Jail helpers: one long-lived attached helper per running vnet jail,
  started lazily, speaking cblink 2 over a socketpair, which is the
  same mechanism as the fleet mount: one proxy design, twice.
- SID governance: the IANA request early; `.sid` files reviewed like
  ABI files.
- BIRD without kernel MPLS (D-5b): a spike before any design rests
  on it.
- The ACP depends on strongSwan, a port; a native IKEv2 is out of
  reach; the DTLS channel of the constrained profile is the fallback
  that needs no IKE but a tun(4) tunnel.
- Scope: Y-7 is eight features; each stands alone and can be dropped
  or delayed without touching Y-1 to Y-6.

## Open questions, short

Beyond D-1 to D-12: whether multicast (pimd) is in scope at all;
whether the SD-WAN edge may host customer CEs as jails (slice SDP
placement 1, which blurs the trust boundary); which RFC 8578 bands to
market; whether `match-on-payload` is wired through ng_bpf or
Suricata or neither; whether flow records leave the edge or only
summaries; whether the agent's unprivileged autonomy (D-12) is wanted
at all.

## The RFCs read

Listed by the user: 9899, 9731, 9408, 9375, 9348, 9182, 9181, 9061,
8969, 8309, 10053, 9938, 9732, 9543, 9342, 9315, 9232, 9222, 8994,
8972, 8955, 8763, 8655, 8578, 8568, 8456, 8455, 7426, 7018. Read
because those rest on them: 8519 and 6991 (ACLs and types), 8762
(STAMP), 9341 (alternate marking), 8956 (FlowSpec IPv6), 8345, 8346
and 8795 (topologies), 8453 (ACTN), 8299 (L3SM, as far as 9182
refers to it), 9347 (AGGFRAG), 8990 and 8995 (GRASP and BRSKI, as far
as 8994 depends on them), 7950, 7951, 9254, 9595, 8040, 8072, 8342,
8525, 8528, 8341, 8639, 8641, 8791, 8343, 8344, 8349, 8529, 8530,
8632, 9016, 9633 (DetNet YANG, referenced), 8177 (key chains,
referenced), and draft-ietf-core-comi (CORECONF). The notes behind
this plan, one file per RFC with the full tree diagrams, the
node-by-node FreeBSD mapping, the cannot-map lists and the open
decisions, are kept with the session that wrote it and can be added
to the tree under `docs/notes/` if wanted.
