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
| Operations | `GET` (do and dump, one instance per MULTI frame), `EDIT` (YANG Patch with instance-identifier targets; merge, replace, create, delete, remove, insert, move; rollback-on-error), `RPC` (rpcs and actions), `GET-SID`; subscriptions as push streams |
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

**D-1 The wire: decided 2026-10-13, version 2.** Keep cblink's frame
and carry YANG-CBOR in the body. The body becomes one YANG-CBOR map whose top-level keys are
absolute SIDs and whose framework items are YANG structures of a
`cblink` module (wire version 2). The alternative, a wrapper map
holding the YANG item under one positive key beside today's negative
framework keys, keeps version 1 bit-compatible but runs two decoders
in series and leaves the framework untyped. Recommendation: version
2 (the header's `version` field exists for this); with D-9, version 1
is not kept. Tags 4 (decimal64) and 43–47 (union discriminators,
absolute SID) are allowed; indefinite lengths stay forbidden, which
RFC 9254 §3 lets a protocol do.

**D-2 Replacing the protocol altogether: decided 2026-10-13, cblink
2 south, RESTCONF on the console only.** cblink 2 as above, versus
NETCONF or RESTCONF on every agent (standard tooling reaches every
host; but an HTTP or SSH server in the root daemon, a second auth
layer, and nothing of cblink's streams and notifications), versus
management over CoAP with YANG-CBOR (close to cblink 2 in spirit,
but a CoAP stack and DTLS instead of TLS, no RFC defining it yet, and
no implementation in C anywhere). Recommendation: cblink 2 on the southbound, RESTCONF only on the
console. The console is then the one place standard tools talk to,
which is also RFC 8309's picture.

**D-3 The YANG compiler: decided 2026-10-13, libyang.** cblink-gen
links `net/libyang3` (3.13.6 in ports, BSD-3; pinned to the 3.x API,
upstream is at 5.x/6.x) at build time and walks its compiled schema
(`lys_parse_*`, `lysc_node`, resolved types with their ranges,
patterns and enums, `when`/`must` text, deviations and features
applied): ~2.5 k lines of glue instead of a 12–15 k-line compiler of
our own, 8–10 weeks saved. It is a build dependency for Arcana's
developers only: the generated C is committed, as `cbl_ctrl_gen.c` is
today, so a user building Arcana needs nothing beyond the base
toolchain. The alternatives were a compiler of our own (no
dependency, the most work, the most risk) and a pyang plugin (Python
in the build, a second intermediate language). What stays ours
either way: the SID tooling (libyang has none), the XPath-lite parser
and evaluator for the runtime, and the YANG-CBOR encoder and decoder
(no implementation exists in C anywhere).

**D-4 The MEF 70.2 document: decided 2026-10-13, L3NM wherever the
two overlap.** RFC 9182 is what is stored and exchanged; MEF 70.2's
terms are kept only for what L3NM has no node for (application flows,
the policy map, performance criteria, breakout, security policies,
the tunnel virtual connections), as Arcana augmentations of L3NM,
and the MEF document survives as an import and export format. The
options weighed: (a) Keep it as the source of truth and
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
targets presume MPLS VPNs. FreeBSD has no MPLS forwarding (the GSoC
branch needs an ABI bump; not before 17). BIRD itself has had the
`l3vpn` protocol since 2.14 (RFC 4364 and 4659, in 3.x too) and
EVPN over VXLAN tunnels since 2.19, but the `net/bird3` port's
protocol options are BFD, Babel, BMP, BGP, MRT, OSPF, Pipe, RAdv, RIP
and RPKI, so `--with-protocols` leaves `l3vpn` out: a one-line port
change adds it. EVPN's data plane in BIRD is the Linux bridge FDB over
netlink, which FreeBSD's netlink does not offer. Options: (a) RD/RT as bookkeeping; membership by per-service
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
*Y-0's evidence for (b), 2026-10-13, on the lab VM (16-CURRENT):*
BIRD 3.3.3 from the ports tree, built with `l3vpn` added to
`RT_PROT` (nothing else changed), in two vnet jails joined by an
epair: an `mpls` domain and table, a `vpn4` table, a VRF table and an
`l3vpn` protocol (RD 65000:1, route target (rt, 65000, 1)) in each, one
iBGP session with `vpn4 mpls` and `next hop self`. BIRD allocates the
labels (1000 for its own site, 1001 for what it learns) and carries the
VPN routes with RD and labels both ways with no kernel MPLS; nothing
reaches the kernel until asked. A vxlan(4) per VPN in FIB 1 (the VRF)
between the two ends, and a kernel protocol exporting the VRF table to
FIB 1 through a filter that sets the gateway to the far end of the
vxlan, forward a ping across, three of three, with FIB 0 untouched.
So (b) works, with three things learnt: vxlan(4)'s cloner is attached
in the host's vnet only, so a vxlan for a vnet-jail edge is made on the
host and moved in; a jail may not set a vxlan's VNI or ends, so they
are set before the move; and `net.fibs` is per vnet, raised inside the
jail. The port's `RT_PROT` needs `l3vpn` (a change to send to its
maintainer), and the plan's 3.4.0 is 3.3.3 in the ports tree today.

**D-6 VRF realisation.** A FIB per `vpn-node` (light, what SD-WAN
does, but leaky: loopback visible in every FIB unless
`net.add_addr_allfibs=0`, daemons need `setfib`, FIB count is a boot
tunable) versus a vnet jail per `vpn-node` (real isolation, own lo0,
own sysctls, own BIRD, dhcpd, pimd and ipfw; more processes, jail
lifecycle). Recommendation: both, chosen per service: FIB by default,
jail when the service needs multicast, DHCP, NAT or its own firewall.
Both are modelled already: FIB = `ietf-network-instance`, jail =
`ietf-logical-network-element`.

**D-7 The ACL engine: decided, ipfw** (the user's; recorded
2026-10-14).  ipfw (already driven, tables, dummynet for
rate-limit, divert, `call`/`return`, fib and jail matches; cannot
match ICMP code, ECN, TCP ECE/CWR/AE, payload) versus pf (anchors
give named ordered ACLs, `tos`, ICMP code, E/W flags; no dummynet
shaping, a second filter on every packet). Recommendation: ipfw as
the engine, features advertised accordingly, the unmappable fields
refused with an extended ack; a pf backend of the same module later
if wanted.

**D-8 Probes: decided 2026-10-13, STAMP.** A STAMP sender and
reflector in the agent (RFC 8762 and 8972: a registered `pm-source`,
one-way delay with NTP, loss per direction with the direct-measurement
TLV, DSCP echo; a reflector per service FIB on UDP 862; ~1 k lines).
ICMP echo stays only for targets that are not Arcana edges, reported
under an Arcana `pm-source` identity. No implementation in C exists
to port: the open-source ones found (cerfcast/teaparty, the
`stamp-suite` crate) are Rust; they serve as interoperation peers in
the lab.

**D-9 Coexistence: decided 2026-10-13, none.** cblink 2 replaces the
`arcana` v1 family outright; agent and console of one release speak
only version 2. A fleet is carried across by `agent-update` from the
last v1 console before the console itself is updated, and the two
never mix. Nothing in libcblink keeps the v1 body decoder, the
attribute policies or the YAML spec language.

**D-10 The northbound: decided 2026-10-13, RESTCONF replaces
`/api`.** One surface. The PWA, `arcanactl` and the Android app move
in the same release; the WebAuthn ceremonies and the enrolment
endpoints, which RESTCONF has no place for, stay as Arcana's own
resources beside `/restconf` (see Y-4).

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
  `sx:structure`s (RFC 8791) of a `cblink` module: `error`, with the
  fields of RFC 8040's `errors` (`error-type`, `error-tag`,
  `error-app-tag`, `error-path` as an instance-identifier,
  `error-message`, `error-info`) plus `errno` and `cookie`; `credit`;
  `hello` (limits, implementation, yang-library content-id); `close`;
  `notification` (`event-time`, `event` anydata, the shape of RFC
  8040 §6.4); `warning`. `PATH` becomes `error-path`, the same array
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
  each frame self-contained; parameters datastore, targets, depth,
  fields, with-defaults, with-origin), `EDIT` (a `cblink:edit` structure shaped like RFC
  8072's YANG Patch with instance-identifier targets; the console
  converts api-path strings), `RPC` (`{SID(rpc): input}` →
  `{SID(rpc): output}`; actions keyed `{[SID(action), keys...]:
  input}`), `GET-SID` (the module's `ietf-sid-file` structure of RFC
  9595, so a generic client can decode what an agent speaks). Commit,
  cancel, discard and a connection-scoped lock are rpcs of a
  `cblink-datastore` module behind the `candidate` feature, with the
  semantics of RFC 6241's.
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
  (RFC 9595's initial allocations: yang-types 1100, inet-types 1150,
  crypt-hash 1200, netconf-acm 1250, sid-file 1300, interfaces 1500,
  ip 1600, system 1700, iana-if-type 1800) use them; the others (routing, v4ur, v6ur,
  network-instance, logical-network-element, yang-library,
  datastores, origin, schema-mount, subscribed-notifications,
  yang-push, yang-patch, restconf, restconf-monitoring,
  yang-structure-ext, acl, packet-fields, i2nsf-*, vpn-common,
  l3vpn-ntw, sap, vn, network-vpn-pm, alarms) and Arcana's own get
  SIDs from a mega-range Arcana asks IANA for (RFC 9595 §7, Expert
  Review); until then a self-chosen block above 2^40, with the
  recorded risk that IANA later assigns those modules differently
  and Arcana keeps its numbers (no interoperation with other
  SID-keyed protocols is claimed). Decided 2026-10-14: for now RFC
  9595's range for experimental use (60 000 to 99 999), each module
  where it was, 2^40 + X now 60 000 + X; a registered block (a
  mega-range, or a PEN's ranges by RFC 9997) later.
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

cblink-gen has libyang parse and compile the YANG modules (D-3),
reads the `.sid` files itself, and writes, per module set: C structs (`has_` flags, arrays for lists and leaf-lists,
union variants, `cbl_bytes` for binary and bits), schema tables (node
kind, delta, type, constraints, children, keys, when/must expression
ids, defaults, config, mandatory, min/max, ordered-by, identity
closure, feature table, SID table), builders and parsers, datastore
handler stubs per top-level container or list, rpc/action handler
prototypes, notification helpers, subscription helpers, the Markdown
and RFC 8340 tree diagrams, and updated `.sid` files (missing items
assigned in RFC 9595 §6 order only with `--assign`; a schema item
without a SID is otherwise a build error). It reads `.sid` JSON with
base libucl. libyang resolves imports, typedef inheritance, groupings,
augments, choice shorthand, deviations, features, identities, config
inheritance and submodules; cblink-gen walks the compiled tree and
reads the extensions it needs (`sx:structure`,
`sx:augment-structure`, `yangmnt:mount-point`, `nacm:default-deny-*`,
`sn:subscription-state-notification`), parses every `when`, `must`
and `path` with the XPath-lite parser and rejects what the profile
excludes with a diagnostic naming the statement, so that the runtime
never meets an expression it cannot evaluate.

## The agent as a YANG device

| Module | FreeBSD realisation (operational source; config sink) | Deviations and features |
|---|---|---|
| `ietf-interfaces` | getifaddrs(3), `if_data` counters, SIOCGIFFLAGS/MEDIA/DESCR, vlan/bridge/lagg ioctls for layering, netlink RTM_GETLINK; sinks rc.conf `ifconfig_<if>`, `cloned_interfaces`, SIOCIFCREATE2, SIOCSIFFLAGS; events from rtsock RTM_IFINFO/IFANNOUNCE or netlink groups | broadcast counters omitted (if_data merges them into multicast); `link-up-down-trap-enable` not supported; features `if-mib`, `pre-provisioning` (interfaces moved into jails) |
| `arcana-interfaces` (augment) | FreeBSD's own beside the standard models (2026-10-14): driver, groups, tunnel FIB, capability bits, media words, epair's peer in a vnet, vlan PCP, lagg's FreeBSD protocols and hash, bridge members' FreeBSD flags; the MTU `ietf-ip`'s and `ietf-if-extensions`' max-frame-size, `ether` `ietf-if-ethernet-like`'s, fib `bind-ni-name`, epair's peer `ietf-if-extensions`', vlan `ietf-if-vlan-encapsulation`'s, lagg IEEE 802.1AX's, bridge IEEE 802.1Q's, media IEEE 802.3's | |
| `ietf-ip` | AF_INET/INET6 ifaddrs, SIOCAIFADDR(_IN6)/SIOCDIFADDR, ARP/ND caches by sysctl NET_RT_FLAGS or netlink RTM_GETNEIGH, `SIOCGIFINFO_IN6` flags, address lifetimes; sinks rc.conf `ifconfig_<if>`, `_alias<n>`, `_ipv6`, `static_arp_pairs`, `static_ndp_pairs` | `forwarding`, `dup-addr-detect-transmits`, temporary addresses are host-global sysctls: reported with origin `system`, per-interface writes refused by a deviation; one MTU for both families |
| `ietf-routing`, `ietf-ipv4-unicast-routing`, `ietf-ipv6-unicast-routing`, RA submodule | NET_RT_DUMP per FIB or netlink RTM_GETROUTE with RTA_TABLE; RTF_STATIC/LOCAL/PINNED → source-protocol; RTF_BLACKHOLE/REJECT → special next hops; ECMP via RTA_MULTIPATH; `active-route` by RTM_GET; sinks rc.conf `defaultrouter`, `static_routes`, `route_<name>`, `ipv6_*`, and the kernel by rtsock or netlink; RA: rtadvd.conf and `rtadvctl reload` | `router-id` not at the host root; `prohibit` next hop unsupported; `last-updated` tracked by the agent from events; `multiple-ribs` off at the root: other FIBs are network instances |
| `ietf-network-instance` | one instance per FIB 1..`net.fibs`−1 named by the agent (names kept in `/usr/local/etc/arcana/fibs.conf`), `vrf-root` a shared-schema mount of routing, v4ur, v6ur and yang-library; `bind-ni-name` ↔ SIOCGIFFIB/SIOCSIFFIB and rc.conf `fib N` | creation raises `net.fibs` live (it grows, never shrinks) and keeps it in loader.conf; a reboot-required flag where the kernel will not grow it; per-AF binding equals the interface's; no `vsi-root` (if_bridge is an interface) |
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
  fan out and merge. RESTCONF never reaches a host itself: the path
  of one request is

  ```
  PUT /restconf/data/arcana-fleet:hosts/host=web1/root/ietf-ip:...
      /interface=em0/ipv4/address=192.0.2.1  {"prefix-length": 24}
   console: session or token → NACM user; api-path → the host web1,
            then the remainder parsed against web1's yang-library;
            JSON → CBOR by web1's SID tables (RFC 7951 → 9254)
   cblink 2 to web1 over mTLS (the ACP's ULA first, later):
     EDIT {cblink:edit: [{operation: replace,
                          target: [SID(ip:address), "em0", "192.0.2.1"],
                          value: {Δprefix-length: 24}}]}  datastore running
   agent:   NACM check; validate the resulting tree (types, when,
            must, leafref); render rc.conf's ifconfig_em0 line;
            SIOCAIFADDR; operational now shows the address with
            origin intended; ack, or an error structure
   console: 204 No Content, or the error-tag mapped to an HTTP
            status per RFC 8040 §7 with ietf-restconf:errors
  ```

  The agent is the only process that touches the kernel and the
  files; the console is the only one that speaks HTTP. A reading
  (`GET`) runs the same way with a cblink dump, one instance per
  frame, streamed back as JSON.
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
  interface), never claimed as hard. An IETF slice service model
  becomes a northbound view if and when one is an RFC.
- **DetNet (RFC 8655, 9938, 8578).** Claimed as a DetNet-IP
  forwarding sub-layer with engineering bounds, no PREOF: per-flow
  dummynet queues from an RFC 9016 traffic specification, a `prio`
  tier, the tick (`net.inet.ip.dummynet.hz`) raised on such hosts,
  pinned explicit routes per FIB owned by the console, BFD failover.
  Use cases served: RFC 8578's band A (tens of milliseconds, five
  nines, failover); band B engineered; band C refused.
- **CATS (RFC 10053).** Services with a CS-ID (an anycast address or a
  VIP with `fwd`), instances = jails, contact instances = jail
  addresses, C-SMA = the agent's normalised score (a versioned Arcana
  function until the IETF publishes one), C-NMA = probes and
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
| MPLS and segment routing (9181, 9182, 9732, 9543, 9938, 7426's PCEP, 9899 `mpls-values`, 10053 SRv6 paths) | no MPLS or SRv6 forwarding in the kernel (GSoC branch, not before 17); BIRD's `l3vpn` exists but the port omits it (a port option adds it) and its labels have no kernel to go to; BIRD's EVPN data plane is Linux's bridge netlink; FRR on FreeBSD has no MPLS, LDP, SR or VRF |
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

### Y-0 Spike (2 weeks)

- **0.1 Body decoder.** G: SID-delta keys, tags 4 and 43–47, the
  `cblink` structures, hand-written SID tables for `ietf-interfaces`;
  encode and decode an `interfaces` dump; measure frame sizes against
  v1.
- **0.2 libyang spike.** G: the module corpus (the IETF modules named
  above plus ietf-vpn-common and ietf-l3vpn-ntw, the largest)
  compiled with libyang 3.13.6 and `yanglint`; what the compiled tree
  gives for resolved types, `when`/`must` text, deviations and
  features; the extension plugins needed.
- **0.3 BIRD VPN spike.** L: `net/bird3` 3.4.0 built with `l3vpn`
  added to its protocol options, an `mpls` domain and `vpn4` tables
  on two jails without kernel MPLS; whether routes are exchanged and
  labels allocated; the evidence for D-5(b).
- **0.4 ng_netflow and pflow.** L: what `ng_netflow` exports on
  15.x/16 (v5, v9; IPFIX is the user's own item in TODO.md); the
  evidence for the telemetry choice.
- **0.5 IANA.** D: request a SID mega-range (RFC 9595 §7); choose the
  provisional block.
- **0.6 Decisions.** D-5 to D-7, D-11 and D-12 recorded with their
  dates in this plan.

### Y-1 The generator and the wire (8 weeks)

Depends on Y-0.

- **1.1 libyang front end.** G: cblink-gen linked with libyang at
  build time (`CBLINK_GEN_LIBYANG` in `cblink.mk`, found in
  `${LOCALBASE}`); the compiled-schema walk into cblink-gen's own
  schema model; extension plugins for the five extensions; the
  profile's refusals with diagnostics. ~2.5 k lines.
- **1.2 Build.** G, D: `net/libyang3` a build dependency of cblink's
  generator and of `make check`'s cross-checks, not of the installed
  programs; the port's `BUILD_DEPENDS`; the generated files committed
  as today.
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
  module's structures; the version 1 body decoder, attribute policies
  and the YAML spec reader removed (D-9); `ctrl` regenerated from
  `cblink-ctrl.yang`. ~3 k changed.
- **1.8 Static validator.** G: the table engine building an instance
  tree. Part of 1.7's rewrite; the evaluator comes in Y-2.
- **1.9 `ietf-interfaces` and `arcana-interfaces`.** A: collectors
  from getifaddrs, if_data, ioctls, netlink; rtsock events. ~2.5 k.
- **1.10 `ietf-ip`.** A: addresses, neighbours, nd6 flags, lifetimes,
  the global sysctls with origin `system`, the deviations. ~2 k.
- **1.11 First GET.** A, C: on a branch until Y-3 lands (D-9: no
  coexistence on `main`), `GET` and dump of operational interfaces
  and addresses; the console reads them through a thin translator
  and shows them on the Network tab in place of `netstat --libxo
  json`. L: on the lab, every interface type Arcana makes.
- **1.12 Tests.** G: a generator corpus (every IETF module above,
  pathological cases), decoder fuzzers with tags, `yanglint` tree
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

- **Before each conversion:** the standard models for its area,
  docs/notes/standard-models.md (2026-10-14): an RFC's module used as
  it is with Arcana's augments, a working-group draft's followed, an
  Arcana module only where none exists.
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
  /ietf-interfaces:interfaces`) with libxo output; the old verbs go
  with the old family.
- **3.7 Tests.** every former operation's test rewritten against the
  module; the root suite on real jails.
- **3.8 The switch.** A, C: the branch of 1.11 merged; one release
  with agent and console speaking only cblink 2; the previous release
  is the last that `agent-update` sends from a v1 console, and the
  book says to update the agents before the console.

### Y-4 RESTCONF and the service models (16 weeks)

Depends on Y-3.

- **4.1 RESTCONF layer.** C: discovery, api-path, methods, status
  table, conditional requests, query parameters, errors, YANG Patch,
  `restconf-monitoring`, SSE. ~3 k.
- **4.2 JSON ↔ CBOR.** C: the schema-driven translator. ~2.5 k.
- **4.3 The fleet mount.** C: `arcana-fleet`, per-host SID and library
  cache, proxying, YANG-Push fan-out and relay, NACM identity. ~1.5 k.
- **4.4 The console's own datastore.** C: `arcana-console` served by
  RESTCONF from the libucl files; `/api` removed (D-10). What RESTCONF
  has no place for stays as Arcana's own resources beside it: the
  WebAuthn ceremonies (`/auth/register`, `/auth/login`, their
  `begin` and `finish`), logout, `assetlinks.json`, enrolment by
  token (`/enrol`), and health. The Android app's logins use those
  and its data calls move to `/restconf`; it is updated in the same
  release (its WebAuthn origin and `assetlinks.json` are unchanged).
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
  mode by default on plain tunnels; an `arcana-stamp` module of our
  own for the sessions (no RFC defines a STAMP YANG model), the
  results in RFC 9375's shape. ~1 k. L: dummynet `plr` and `delay`
  seen in the metrics; interoperation with a TWAMP Light reflector and
  with one of the open-source STAMP implementations.
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
  0.4's result (2026-10-13, 16-CURRENT): `ng_netflow` exports
  NetFlow v5 on its `export` hook and v9 on `export9`, both at once,
  and nothing else; IPFIX stays the TODO item. An expired flow waits
  in a partly filled datagram until it fills (30 records for v5, some
  1400 bytes for v9) or the node shuts down, so a quiet service's
  flows can wait without bound: 5.6 needs a flush on a timer, from the
  agent (a `flush` message the node does not have, so a kernel change
  the user decides) or by rebuilding the export hook, or accepts it.
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
- **6.5 FlowSpec.** A, C: BIRD, chosen for its netlink integration
  and because the routing stays in one daemon (ExaBGP was weighed:
  it speaks BGP from Python with no FIB of its own, and would be a
  second daemon beside BIRD). Per-service `flow4`/`flow6` channels
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
- **6.6 D-5(b) if 0.3 succeeded.** C, A: the port option for
  `l3vpn`; `vpn4`/`vpn6` between edges with labels BIRD allocates
  but the kernel never sees, and a VXLAN VNI per VPN as the
  encapsulation; RD/RT become operational.
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
  rejection with alternatives; an IETF slice service model as a view
  if one is published.
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
- **8.2 Migration notes.** D: UPDATING.md on the two flag days (the
  agent's in Y-3, the console API's in Y-4), and what a fleet on an
  older release does first.
- **8.3 Conformance.** D: per RFC, the features advertised, the
  deviations, the refused nodes and the cannot-map list, in the
  book's conformance chapter and in `ietf-yang-library`.
- **8.4 Second console.** C: primary/standby sharing the data
  directory and the CA; agents trusting the CA, not one console;
  RFC 8456's failover benchmark becomes applicable.

## The steps, commit by commit

Each task above cut into the smallest steps that can each be one
reviewed commit with its own test: a step changes one thing, and the
check named with it is what the commit's test runs. Markers as above.
A step never leaves `main` unbuildable; where a step would, it says
"branch". Nothing here is started until the user says so.

### Y-0

- 0.1.1 G: a test program encoding `{1500: {1: [{1: "em0", 3: 1500}]}}`
  by hand with libcbor and decoding it by SID deltas; check: round trip.
- 0.1.2 G: tags 4 and 43–47 accepted by `cbl_decode` under a flag,
  every other tag still refused; check: the fuzzer corpus.
- 0.1.3 G: the `cblink` module's `error`, `credit`, `hello`, `close`,
  `notification` written in YANG, their `.sid` file by hand; check:
  `yanglint` validates the module.
- 0.1.4 G: frame sizes of an `interfaces` dump, v1 against the
  hand-encoded v2, in a note under `docs/notes/`; check: the numbers.
- 0.2.1 G: `net/libyang3` installed on the VM; the module corpus
  (`share/yang/`: ietf-yang-types, inet-types, interfaces, ip,
  routing, v4ur, v6ur, network-instance, logical-network-element,
  yang-library, datastores, origin, schema-mount, netconf-acm,
  subscribed-notifications, yang-push, yang-patch, restconf,
  restconf-monitoring, yang-structure-ext, iana-if-type, acl,
  packet-fields, ethertypes, iana-icmpv4/v6-types, iana-ipv6-ext-types,
  i2nsf-ikec/ike/ikeless, ipsec-iptfs, vpn-common, l3vpn-ntw, sap-ntw,
  vn, network-vpn-pm, alarms, key-chain) fetched from the RFCs and
  checked in; check: `yanglint` compiles every one.
- 0.2.2 G: a 200-line program against libyang 3.x printing, for the
  corpus, each node's kind, SID-able name, resolved type with ranges,
  patterns and enums, `when`/`must` text, config, mandatory, keys,
  features and deviations; check: output matches `yanglint -f tree`.
- 0.2.3 G: the five extensions (`sx:structure`,
  `sx:augment-structure`, `yangmnt:mount-point`,
  `nacm:default-deny-*`, `sn:subscription-state-notification`) read
  through libyang's extension plugin interface; check: each found in
  the corpus.
- 0.3.1 L: `net/bird3` built with `l3vpn` in `RT_PROT` on the VM; check:
  `bird --version` and `protocol l3vpn` parses.
- 0.3.2 L: two jails, an `mpls` domain, `vpn4` tables, one BGP session
  with `vpn4 mpls` channels; check: routes with RD and labels on both
  sides in `birdc show route table`, nothing in the kernel.
- 0.3.3 L: a vxlan(4) per VPN with the far VTEP as next hop by a
  BIRD filter; check: a ping across; the result written to D-5. Done
  2026-10-13, 0.3.1 to 0.3.3: see D-5's evidence.
- 0.4.1 L: `ng_netflow` with `ng_ksocket` to `nfdump`/`nfcapd`; check:
  the version in the records on 15.x and on 16; the result written to
  the TODO item and to 5.6. Done 2026-10-13 on 16-CURRENT, with a
  listener of a few lines for the collector (nfdump is not installed)
  and the node between two eiface(4) interfaces: v5 and v9, no IPFIX.
  15.x not run: no 15.x host in the lab.
- 0.5.1 D: the IANA request for a SID mega-range sent; the provisional
  block (2^40) recorded in `share/yang/SIDS.md`. Taken 2026-10-14: RFC
  9595's experimental range for now, no request sent.
- 0.6.1 D: D-5, D-6, D-7, D-11, D-12 taken or deferred, dated here.

### Y-1

- 1.1.1 G: `cblink.mk` and the generator's Makefile find libyang in
  `${LOCALBASE}` (`pkg-config libyang`); check: builds with and fails
  clearly without.
- 1.1.2 G: cblink-gen's schema model (`schema.h`: node, type,
  constraint, identity, feature, module) and the walk from
  `lysc_node` into it; check: the corpus walked, node counts equal
  `yanglint`'s.
- 1.1.3 G: resolved types: integer ranges, string lengths and
  patterns, enumeration values, bits positions, identityref bases,
  union members, leafref paths, decimal64 fraction digits, defaults,
  units; check: a table per module compared with `yanglint -f info`.
- 1.1.4 G: features applied (`--features`), deviations applied,
  `if-feature` pruning; check: `ietf-ip` with and without `ipv6-privacy-autoconf`.
- 1.1.5 G: the extension plugins of 0.2.3 in the generator; check:
  structures and mount points in the schema model.
- 1.1.6 G: the profile's refusals (full XPath beyond lite, XSD
  constructs beyond the subset, `anyxml` validation) as diagnostics
  `file:line: error:`; check: a pathological module per refusal.
- 1.2.1 D, G: `net/libyang3` as `BUILD_DEPENDS` of the port's
  generator; the generated files committed; `make` without libyang
  skips regeneration; check: a clean build on a host without libyang.
- 1.3.1 G: XPath-lite tokenizer and parser to an AST (paths, axes,
  predicates, functions, operators, literals, `$USER`); check: every
  `when`, `must` and `path` in the corpus parses.
- 1.3.2 G: the generator rejects AST nodes outside the subset; check:
  one module with `position()` refused.
- 1.4.1 G: `.sid` reader (libucl) into the schema model; check: the
  IANA `.sid` files of RFC 9595 read.
- 1.4.2 G: `.sid` verifier: every schema item has a SID, no duplicates,
  ranges respected, obsolete kept; check: a tampered file refused.
- 1.4.3 G: `--assign`: new items numbered in RFC 9595 §6 order into
  the module's range, the file rewritten; check: byte-identical on a
  second run.
- 1.4.4 G: `ietf-sid-file` structure emitted for `GET-SID`; check:
  decodes to the input file.
- 1.5.1 G: XSD regex → ERE translator (`\d \s \w \p{L} \p{N}`, classes,
  `[^…]`, `{n,m}`, groups, alternation); check: RFC 6991's patterns
  with good and bad values.
- 1.5.2 G: unknown XSD constructs refused at generation; check: a
  pattern with class subtraction refused.
- 1.6.1 G: struct emission per container, list, rpc input/output,
  notification, structure; check: compiles for the corpus with
  `-Wall -Werror`.
- 1.6.2 G: schema tables (kind, delta, type, constraints, children
  sorted by delta, keys, when/must ids, defaults, config, mandatory,
  min/max, ordered-by); check: table size per module reported.
- 1.6.3 G: identity closure table and feature table; check:
  `derived-from` lookups for every identityref base.
- 1.6.4 G: SID table and the mapping delta → child per node; check:
  dense arrays chosen where deltas are contiguous.
- 1.6.5 G: builders and parsers per node; check: encode then decode
  every struct of the corpus with every optional present and absent.
- 1.6.6 G: handler stubs (`get`, `edit` per top-level node), rpc and
  action prototypes, notification senders; check: the kv example
  rewritten in YANG links against them.
- 1.6.7 G: Markdown and RFC 8340 tree diagrams; check: diff against
  `yanglint -f tree`.
- 1.7.1 G: `cbl_frame` version 2 accepted, version 1 refused with
  `EPROTONOSUPPORT`; check: the fuzzer.
- 1.7.2 G: `cbl_decode` keyed by SID deltas against the schema tables,
  the two-pass size-before-allocation behaviour kept; check: limits
  tests.
- 1.7.3 G: kinds `empty`, `bits`, `identityref`, `instance-identifier`,
  `union`, `decimal64`; `flag` and `float` removed; check: one test
  per kind.
- 1.7.4 G: the `cblink` structures replace negative keys in
  `cbl_msg`, errors, credit, hello, close; check: every existing
  libcblink test rewritten passes.
- 1.7.5 G: `cbl_policy`, `cbl_attr` and the YAML spec reader removed;
  `spec.c`, `yaml.c`, `gen_c.c`, `gen_md.c` deleted; check: `make`.
- 1.7.6 G: `ctrl` regenerated from `cblink-ctrl.yang`; check: resolve,
  subscribe, ping, hello as before.
- 1.8.1 G: the static validator over the instance tree: types,
  ranges, lengths in code points, patterns, enum, bits, identity
  derivation, union, mandatory, min/max-elements, keys, unique,
  config-false in edits, choice exclusivity, defaults; check: one
  test per rule from RFC 7950's examples.
- 1.9.1 A: `ietf-interfaces` operational collector (getifaddrs,
  if_data, SIOCGIFFLAGS/MEDIA/DESCR, if_nametoindex); check: equals
  `ifconfig` and `netstat -i` on the VM.
- 1.9.2 A: layering (`higher-layer-if`, `lower-layer-if`) from vlan,
  bridge and lagg ioctls; check: a vlan on a lagg on two members.
- 1.9.3 A: `arcana-interfaces` augment: vlan, bridge, lagg, epair,
  mtu, ether, media, groups, fib, capabilities; check: each type made
  by the existing jobs reads back.
- 1.9.4 A: rtsock events (RTM_IFINFO, IFANNOUNCE) into the event
  sources; check: an interface created and destroyed seen.  Found
  (2026-10-14): the agent's netlink(4) watch (RTNLGRP_LINK, the host's
  and each vnet jail's) has them: made, flags, MTU, link state,
  renamed (gone by the old name, come by the new), destroyed.  The
  kernel announces nothing, on netlink or rtsock, for a description,
  a FIB, a group, a link-layer address (iflladdr_event is not
  netlink's), media, capabilities, or a vlan's, lagg's or bridge's
  settings: for 3.2.3's on-change, those are told by the agent's own
  jobs that change them, or polled.
- 1.10.1 A: `ietf-ip` addresses v4/v6 with origin and status; check:
  equals `ifconfig`.
- 1.10.2 A: neighbours from NET_RT_FLAGS RTF_LLINFO (v4 and v6),
  `is-router`, state; check: equals `arp -an`, `ndp -an`.
- 1.10.3 A: the global sysctls with origin `system` and the deviation
  module `arcana-ip-deviations`; check: `yanglint` with deviations.
  Done (2026-10-14) but the origin: an annotation (RFC 8342, RFC 7952)
  the codec does not carry yet; it comes with 2.1's
  instance tree, which keeps each node's origin.
- 1.11.1 A, branch: family 1 registered with `GET` and dump for
  interfaces and ip; check: `arcanactl` (a `get` verb) dumps them.
- 1.11.2 C, branch: a translator from the dump to the Network tab's
  rows; check: the browser test's Network tab unchanged in look.
- 1.11.3 L: every interface type Arcana makes, read through the new
  path on the VM; written to TODO's verified list.
- 1.12.1 G: generator corpus test (`make check` runs cblink-gen on
  every module and diffs trees against `yanglint`); check: CI green.
- 1.12.2 G: decoder fuzzer extended with tags and deltas; check: an
  hour of fuzzing clean.
- 1.12.3 D: YANG.md (the profile), GENERATOR.md, WIRE-FORMAT.md
  version 2; SPEC-FORMAT.md removed.

### Y-2

- 2.1.1 G: the instance tree (`cbl_data`): nodes, keys, ordered lists,
  defaults materialised on demand; check: build, walk, free.
- 2.1.2 G: edit operations merge, replace, create, delete, remove on
  the tree with `data-exists`/`data-missing` errors; check: RFC 6241
  §7.2's examples.
- 2.1.3 G: insert and move for `ordered-by user` with `point` and
  `where`; check: RFC 8072's examples.
- 2.1.4 G: diff between two trees as a YANG Patch; check: round trip.
- 2.1.5 G: leafref and instance-identifier existence; check: a
  dangling reference refused.
- 2.2.1 G: XPath-lite evaluator: node sets, paths, predicates; check:
  the corpus's `path` statements resolve on sample data.
- 2.2.2 G: coercions and comparisons with node-set semantics,
  arithmetic, `and`/`or`; check: RFC 8349's RA `must`s.
- 2.2.3 G: functions `current`, `deref`, `derived-from(-or-self)`,
  `enum-value`, `bit-is-set`, `re-match`, `count`, `not`, the string
  functions; check: one test each.
- 2.2.4 G: `when` and `must` over the tree with error-message and
  error-app-tag; check: v4ur's `when`s on augments.
- 2.2.5 G: subtree filter and XPath filter; NACM path matcher;
  parent-reference node sets; check: RFC 6241 §6's filter examples.
- 2.2.6 G: property tests of the evaluator against libyang's
  evaluator in CI (developer tool); check: no divergence on the
  corpus.
- 2.3.1 A: rc.conf reader and writer preserving comments and order
  (the existing `sysrc`-shaped editor generalised), with
  `rc.conf.d/` fragments Arcana owns; check: a fixture corpus
  round-trips byte for byte.
- 2.3.2 A: the conflict rule: a variable set in the user's rc.conf
  and in an Arcana fragment refused with a message; check: fixture.
- 2.3.3 A: loader.conf, sysctl.conf and rtadvd.conf editors; check:
  fixtures.
- 2.3.4 A: `running` assembled from the files into an instance tree
  for interfaces, ip, routing; check: equals the files on the VM.
- 2.3.5 A: `EDIT` on `running`: validate the result, render the
  files, apply to the kernel, undo on failure (file copies restored);
  check: a failing ioctl leaves the files as they were.
- 2.3.6 A: `arcana:live`: edits applied to the kernel only, origin
  `dynamic`; check: today's `address live` test passes through it.
- 2.3.7 A: `candidate`, `commit`, `discard-changes`; check: RFC 6241
  §8.3's sequence.
- 2.3.8 A: `confirmed-commit` with timeout and `persist`, the revert
  = today's safe mode; check: the existing safe-mode tests pass
  through it, including the one that cuts the connection.
- 2.3.9 A: operational with `with-origin` (intended, system, dynamic,
  learned, default); check: a system interface, a configured one, a
  live address.
- 2.3.10 A: `with-defaults` report-all, trim, explicit; check: RFC
  6243's examples.
- 2.4.1 A: RIB dump per FIB by NET_RT_DUMP with fibnum; `source-
  protocol`, special next hops, `active`; check: equals `netstat -rn`.
- 2.4.2 A: ECMP by netlink RTA_MULTIPATH as `next-hop-list`; check:
  two gateways for one prefix.
- 2.4.3 A: static routes in `running` ↔ rc.conf `static_routes`,
  `route_<name>`, `defaultrouter`, IPv6 variants; check: fixtures.
- 2.4.4 A: static routes applied to the kernel by rtsock or netlink
  with `-fib`; check: `route -n get`.
- 2.4.5 A: `active-route` action by RTM_GET; check: equals `route get`.
- 2.4.6 A: route events per FIB (one rtsock per FIB or netlink
  groups) into the event sources; `last-updated` tracked; check: an
  added route seen.
- 2.5.1 A: rtadvd.conf ↔ the RA submodule, `rtadvctl reload`; check:
  `rtadvctl show` after an edit.
- 2.6.1 A: `ietf-network-instance` entries from `net.fibs`, names in
  `fibs.conf`; check: the list on a host with `net.fibs=4`.
- 2.6.2 A: `vrf-root` mount serving routing per FIB; check: the FIB's
  table under the mount.
- 2.6.3 A: `bind-ni-name` by SIOCGIFFIB/SIOCSIFFIB and rc.conf `fib`;
  `bind-ni-name-failed`; check: `ifconfig em0 fib 2` reads back.
- 2.6.4 A: `net.fibs` in loader.conf with the reboot-required flag
  when a new instance is asked for; check: the flag in the reply.
- 2.7.1 A: LNE list from `jail_get` with `vnet = new`; check: equals
  `jls -v`.
- 2.7.2 A: the attached helper: fork, `jail_attach`, cblink 2 over a
  socketpair, lazily started, stopped with the jail; check: a jail's
  interfaces read through it.
- 2.7.3 A: `root` mount dispatching to the helper; nested NIs inside;
  check: a FIB's routes inside a jail.
- 2.7.4 A: `bind-lne-name` by SIOCSIFVNET and jail.conf
  `vnet.interface` through libjailconf; `bind-lne-name-failed`; check:
  an epair moved and moved back.
- 2.7.5 A: jail start and stop seen by `exec.poststart`/`poststop`
  hooks Arcana writes into jail.conf; check: an event per start.
- 2.8.1 A: `ietf-yang-library` at the root and under each mount with
  `content-id`; `yang-library-update` on change; check: `GET` of the
  library.
- 2.8.2 A: `ietf-yang-schema-mount` state (`schema-mounts`); check:
  RFC 8528's examples' shape.
- 2.9.1 C: persistent and live address edits through `EDIT`; a static
  route; an interface moved into a jail; check: the browser test.
- 2.9.2 L: a hand edit of rc.conf shown as drift (intended ≠
  running); written to TODO's verified list.
- 2.10.1 G, A: the fixture corpus for every file editor under
  `tests/fixtures/`; validator tests from RFC 7950's examples; XPath
  tests; check: `make check`.

### Y-3

- 3.1.1 A: `arcana-jails` from `arcana.yaml`'s jail set and jail(8)'s
  parameter list; actions start, stop, restart, kill; the LNE link;
  check: `list` and `action` tests pass through it.
- 3.1.2 A: `arcana-services`: scripts, rcvars, actions, rc.conf
  variables as leaves in `running`; check: the services tests.
- 3.1.3 A: `arcana-packages` and the upgrade rpc with a job; check:
  the packages tests.
- 3.1.4 A: `arcana-jobs`: the queue as a list, `submit` rpc, `cancel`
  and `confirm` actions, traces as a flat list with parent ids; check:
  the jobs tests; the trace tree rebuilt in the page.
- 3.1.5 A: `arcana-storage` (GEOM, pools, datasets, snapshots, mounts,
  fstab; send and receive as streams); check: the storage tests, the
  root ZFS test.
- 3.1.6 A: `arcana-sysctl` (`running` ↔ sysctl.conf, operational from
  sysctl(3)); `arcana-kernel` (modules, `kld_list`); check: tests.
- 3.1.7 A: `arcana-processes` (on `openconfig-procmon`; done),
  `arcana-log`, `arcana-history`, `arcana-events` (numbered,
  replayable); check: tests.
- 3.1.8 A: `arcana-bird`, `arcana-wireguard`, `arcana-netgraph`,
  `arcana-plugins`; check: the plugin tests.
- 3.1.9 A: `arcana-host` (facts, router-id, role, capabilities),
  `arcana-agent` (update and build rpcs); check: `hello`'s tests.
- 3.1.10 A: `arcana-dummynet` (schedulers, pipes, queues) read and
  written; check: the QoS tests.
- 3.1.11 A: `arcana-probe` (sessions, config, results) over today's
  ICMP engine; check: the probe tests.
- 3.1.12 A: the SD-WAN reads and writes (`sdwan`, `-rules`, `-steer`,
  `-bird`, `-dhcp`, `-dns`, `-proxy`, `-ids`) as typed modules; the
  JSON gone; check: the SD-WAN tests and the two-jail lab.
- 3.2.1 A: `ietf-subscribed-notifications` streams list, `establish`
  as a push-stream open with the id in the accept; check: one record.
- 3.2.2 A: periodic YANG-Push with `period` and `anchor-time`; check:
  stats pushed every second.
- 3.2.3 A: on-change with dampening and YANG Patch records from the
  event sources (interfaces, addresses, routes, jails, jobs); check:
  an address added arrives as a patch.
- 3.2.4 A: subtree and XPath filters on subscriptions; check: one
  interface's counters only.
- 3.2.5 A: state-change notifications; suspension on credit
  exhaustion and resumption; `modify`, `kill`, `resync` rpcs; check:
  a slow subscriber suspended and resumed.
- 3.2.6 A: replay from the event number for events and job traces;
  check: a subscription from an old number.
- 3.2.7 A: configured subscriptions: the agent calling the console
  as receiver over cblink; check: the console restarted, records
  resume.
- 3.2.8 A: subscription monitoring counters; check: `GET` of
  `subscriptions`.
- 3.3.1 A: NACM groups from the certificate's subject or the socket's
  uid, rule-lists in `running`; check: RFC 8341's examples.
- 3.3.2 A: enforcement for rpcs, data nodes (read as omission) and
  notifications; counters; check: one test per point.
- 3.3.3 A, C: the console's user passed per connection to an agent
  that trusts it by certificate role; check: two users, two views.
- 3.4.1 C: one long-lived cblink connection per agent with streams;
  reconnect with backoff; check: an agent restarted.
- 3.4.2 C: jobs, stats, lists and the SD-WAN read taken from
  subscriptions, the one-second polls removed; check: the browser
  test's timings.
- 3.4.3 C: `events` subscribed and relayed to the page; check: an
  event within a second in the page.
- 3.5.1 A, C: `arcana-steer`: candidates, chosen, reason, events;
  written by local failover and by the console; check: a failover
  seen on both.
- 3.5.2 G, A: the control stream: a push stream of its own for steer
  and probe notifications, its own SCTP stream; check: order kept
  under a bulk dump.
- 3.6.1 C: `arcanactl get|set|rpc <path>` with libxo output; the old
  verbs removed; check: the arcanactl tests rewritten.
- 3.7.1 A, C: every former operation's test against its module; the
  root suite on real jails; check: `make check` green as root.
- 3.8.1 A, C: the branch of 1.11 merged; versions bumped; UPDATING.md
  on the flag day and the order (agents first from the last v1
  console); check: a fleet of two updated on the lab in that order.

### Y-4

- 4.1.1 C: `/.well-known/host-meta`, `/restconf`, `yang-library-
  version`; check: RFC 8040 §3.1's examples.
- 4.1.2 C: api-path parser (percent-decoding, module qualification,
  list keys, leaf-list values, empty keys); check: §3.5.3's examples.
- 4.1.3 C: GET with `content`, `depth`, `fields`, `with-defaults`;
  check: §4.8's examples.
- 4.1.4 C: POST, PUT, PATCH (plain), DELETE with the status table,
  `Location`, 409 on `data-exists`; check: §4's examples.
- 4.1.5 C: YANG Patch (`application/yang-patch+json`) forwarded as one
  `EDIT`; check: RFC 8072's examples.
- 4.1.6 C: ETag and Last-Modified from the host's commit counter;
  conditional requests; check: §3.4.1.2 and §3.4.1.3.
- 4.1.7 C: `ietf-restconf:errors` from the agent's error structure
  with §7's status mapping; check: one test per error-tag.
- 4.1.8 C: `restconf-state/streams` and SSE delivery with the §6.4
  envelope; `Last-Event-ID` → replay; check: a stream over curl.
- 4.1.9 C: `establish-subscription` by POST with the SSE location;
  check: a periodic subscription from curl.
- 4.1.10 C: `application/yang-data+cbor` pass-through; check: the
  PWA's decoder reads it.
- 4.2.1 C: JSON → CBOR by schema (names → SIDs with module
  qualification, numbers, strings, base64, empty, bits, enums,
  identityref, instance-identifier strings, union by canonical form);
  check: RFC 7951's examples both ways.
- 4.2.2 C: CBOR → JSON including origin as `@` annotations; check:
  RFC 7952's example shape.
- 4.3.1 C: `arcana-fleet` module; the host prefix stripped and the
  remainder resolved against the host's cached library and SID
  tables; check: a GET to two hosts of different revisions.
- 4.3.2 C: the SID and library cache refreshed on
  `yang-library-update`; check: an agent updated under the console.
- 4.3.3 C: fan-out subscriptions merged with the host prefix on each
  record; check: two hosts' events on one stream.
- 4.4.1 C: `arcana-console` module served from the libucl files
  (settings, tokens, workflows, enrolment tokens, users); check: GET
  and PUT of a setting.
- 4.4.2 C: the WebAuthn ceremonies, logout, `assetlinks.json`, enrol
  and health moved beside `/restconf`; `/api` removed; check: the
  console tests rewritten.
- 4.4.3 (the app's repository, spmzt/arcana-apk): the Android app
  reimplemented as a RESTCONF client: WebAuthn and the token QR code
  as today, then every read a `GET` on `/restconf/data/...` with
  `fields` and `depth`, every change a `PATCH` or `PUT`, every action
  a `POST` on `/restconf/operations/...`, events and job traces by
  SSE subscriptions, errors from `ietf-restconf:errors`, and the
  forms it shows generated from each host's `ietf-yang-library` the
  way the page's are (4.8.3), so a new module needs no app release;
  `application/yang-data+cbor` where the app prefers CBOR. Briefed
  from this plan when 4.1 lands; check: the app against the lab's
  console.
- 4.5.1 C: `ietf-vpn-common` and `ietf-l3vpn-ntw` stored as the
  service; check: RFC 9182's Appendix A example accepted.
- 4.5.2 C: the Arcana augmentations of L3NM: application flows, the
  policy map, performance criteria, breakout, security policies,
  tunnel virtual connections, probes, steering criteria, routing
  domains; check: today's example document expressible.
- 4.5.3 C: the MEF 70.2 importer (document → L3NM + augments) and
  exporter; check: the example document imports and exports to the
  same bytes.
- 4.5.4 C: the planner reading L3NM: profiles and node overrides
  resolved, the allocation ledger (FIBs, addresses, RDs, VNIs, table
  names) persisted; check: the plan of the example equals today's.
- 4.5.5 C: the planner emitting device edits (interfaces, ip,
  routing, NI, LNE, dummynet, bird, probe, steer) instead of
  `sdwan-*` JSON; check: the two-jail lab applies and passes.
- 4.5.6 C: refusal of the infeasible with the reason and an
  alternative; check: a bandwidth over the link refused.
- 4.6.1 A: each agent's node, TPs and SAPs dumped with `sap-status`;
  check: equals the interface list.
- 4.6.2 C: the SAP network and the physical network under it; the
  anomaly rules as checks; check: RFC 9408 §5's cases.
- 4.6.3 C: the Appendix D flow in the planner (free SAP → access id);
  check: a service placed on a free SAP.
- 4.7.1 C: `ietf-vn` view: access points and VNAPs from UNIs, members
  from tunnels, `oper-status` and `if-selected` from `arcana-steer`;
  check: RFC 9731's example shape for the lab service.
- 4.7.2 C: `path-metric-bounds` with Arcana metric identities for
  loss and delay variation; the `arcana-sdwan-underlay` augment;
  check: the TCA thresholds round-trip.
- 4.7.3 C: `vn-compute` as the Check over per-edge feasibility rpcs;
  check: an infeasible member reported with `error-info`.
- 4.8.1 P: the page's fetch layer on RESTCONF JSON (or CBOR
  pass-through); check: the browser test.
- 4.8.2 P: SSE subscriptions replace the page's polling; check:
  timings in the browser test.
- 4.8.3 P: forms generated from the yang-library for the Arcana
  modules (the schema page's renderer reused); check: a jail made
  from a generated form.
- 4.9.1 D: the API page from the RESTCONF description; openapi.yaml
  retired or generated; the book's chapters (kept by the session on
  the user's machine).
- 4.10.1 L: a service written as L3NM through RESTCONF, applied on
  the lab, read back as VN and SAP, exported as MEF and re-imported
  unchanged; written to TODO's verified list.

### Y-5

- 5.1.1 A: STAMP reflector, stateless, UDP 862 per service FIB,
  unauthenticated 44-byte packets, T2/T3 by SO_TIMESTAMP and
  clock_gettime; check: a TWAMP Light sender gets replies.
- 5.1.2 A: stateful reflector mode; SSID; check: sequence counters.
- 5.1.3 A: STAMP sender replacing the ICMP engine's scheduling for
  Arcana targets, RTT with reflector time removed, directional loss;
  check: dummynet `plr` seen per direction.
- 5.1.4 A: timestamp information TLV from `ntp_gettime`; one-way delay
  only when both error estimates allow, else half RTT flagged; check:
  dummynet `delay` one way.
- 5.1.5 A: class-of-service TLV with DSCP echo; check: `tcpdump -v`.
- 5.1.6 A: direct-measurement TLV from ipfw counters; location TLV;
  check: NAT detection on the lab.
- 5.1.7 A: authenticated mode (HMAC-SHA-256-128, libcrypto), keys over
  cblink, on by default on plain tunnels; check: a tampered packet
  refused.
- 5.1.8 A: `arcana-stamp` module (sessions, config, counters) and
  `kind` in `arcana-probe` (stamp, icmp); check: both kinds in one
  service.
- 5.1.9 L: interoperation with one open-source STAMP implementation
  and a TWAMP Light reflector; written to TODO's verified list.
- 5.2.1 A: raw samples per measurement interval; three percentiles;
  loss as count and decimal percentage; microseconds; check: the
  numbers against a sorted dump.
- 5.2.2 A: measurement interval (default 60 s) with start and end as
  date-and-time; per-class sessions per DSCP; check: two classes.
- 5.3.1 C: `ietf-network-vpn-pm`: one network per service and the
  underlay, two links per tunnel, `pm` entries from the agents'
  records; check: RFC 9375's examples' shape.
- 5.3.2 A: typed TP counters from if_data; per-FIB route counts;
  check: equals `netstat`.
- 5.3.3 A, C: underlay-link probes (the far edge's WAN address, FIB
  0); check: `pm-type-network-link` entries.
- 5.4.1 A: `ietf-alarms`: faults and TCAs as alarms with
  instance-identifier resources; check: RFC 8632's examples' shape.
- 5.4.2 C: alarm inventory and shelving; the Paths tab reads alarms;
  check: the browser test.
- 5.5.1 A: `setdscp` colour pairs flipped on timer L per service,
  `count dscp` rules at the ends with the SD-WAN rules; check: the
  rules in `ipfw show`.
- 5.5.2 A: counters read at L/2 by `IP_FW3` with a block number,
  pushed as records; check: timing within guard band.
- 5.5.3 C: per-tunnel loss per block; the RFC 9342 §5.1 partition with
  Appendix A as the unit test; check: four clusters.
- 5.5.4 A: the in-band variant through STAMP's direct-measurement TLV
  for steering; check: steering on loss without the console.
- 5.5.5 L: three jails, loss on one tunnel localised to its cluster.
- 5.6.1 A: `ng_netflow` per service FIB with sampling (v9, by 0.4's
  result: no IPFIX); check: records at a collector jail.
- 5.6.2 C: BMP from BIRD to the console; check: a session's updates
  seen.
- 5.6.3 C: a compact time-series store with retention per class;
  check: a week of samples on the VM's disk budget.
- 5.7.1 D: the measurement chapter; TODO.

### Y-6

- 6.1.1 A: ACL bands and the name map; `call`/`return`; attachment
  rules `in recv`/`out xmit`/`via`; names in comments; check: RFC
  8519's Appendix A examples installed and read back.
- 6.1.2 A: the match table of RFC 8519 (eth, ipv4, ipv6, tcp, udp,
  icmp, ports with operators, interfaces); check: one test per field.
- 6.1.3 A: the refusals with extended acks (ICMP code, ECN, ihl,
  offset, identification, TCP fields, ECE/CWR/AE, IPv6 ff/lf, the three
  extension headers); check: one test per refusal.
- 6.1.4 A: actions and logging; aggregate statistics from rule
  counters; check: `ipfw -a list`.
- 6.1.5 A: RFC 9899 defined sets: prefix sets as tables with shadow
  swap, port sets as lists or number tables, protocol sets as
  or-blocks, ICMP sets as lists, aliases decomposed; check: Appendix
  B's examples.
- 6.1.6 A: RFC 9899 matches: fragments v4 and v6 isf, extension
  headers, flags-bitmask, set references; check: Appendix B.1, B.2,
  B.6.
- 6.1.7 A: RFC 9899 actions: `rate-limit` as a pipe, `log-action`,
  `counter-action`; check: B.6 at 20 bytes per second.
- 6.1.8 A: the Arcana augments: attachment to a FIB, a jail, all
  interfaces; `default-action`; `stateful`; reject code; check: one
  test each.
- 6.1.9 A: ACLs applied inside the set-swap transaction with the
  SD-WAN rules; `tables_max` raised at start; check: an apply with
  both.
- 6.1.10 C: the SASE `ip-block` policies compiled through the ACL
  module; check: the SASE tests.
- 6.2.1 A: PF_KEYv2 in-process (libipsec): SADB_ADD/UPDATE/DELETE/GET/
  DUMP replacing setkey text; check: the SA tests and the root ipsec
  test.
- 6.2.2 A: SPD by SADB_X_SPDADD/SPDDELETE/SPDDUMP and the ipsec(4)
  reqid mapping; check: a policy both ways.
- 6.2.3 A: SADB_REGISTER; `sadb-acquire` and `sadb-expire`
  notifications; `sadb-seq-overflow` synthesised; check: a soft
  expiry seen.
- 6.2.4 A: `ietf-i2nsf-ikeless` lists over the above; the refusals;
  `net.key.preferred_oldsa=0`; check: RFC 9061 Appendix B's example.
- 6.2.5 A, C: uswe's keys as `esp-sa/key` from the agent's own
  derivation; Appendix D.2's rekey order; check: the rekey test.
- 6.3.1 A: VICI for `list-sas`, `stats` and events in place of
  `--list-sas --pretty`; check: the state leaves.
- 6.3.2 A: `ietf-i2nsf-ike` over the swanctl files: pad entries,
  connections, lifetimes, proposals from the IANA tables; private
  keys refused; check: Appendix A's example.
- 6.3.3 A: `ipsec-stats` per SA (RFC 9348's one usable part); the
  `traffic-flow-security` augment refused with
  `operation-not-supported`; an `ipsec-capabilities` dump; check:
  tests.
- 6.4.1 A, C: `ietf-key-chain` (RFC 8177) mapped to BIRD passwords,
  tcp-md5 SAs and swanctl secrets; write-only leaves; check: a BGP
  session with a chain.
- 6.5.1 A: BIRD per-service `flow4`/`flow6` channels with `validate
  on` in the templates; check: a flowspec route accepted and an
  invalid one refused.
- 6.5.2 A: the `show route table ... all` flowspec parser; check: RFC
  8955 §4.3 and RFC 8956 §3.8 examples through BIRD static routes.
- 6.5.3 A: ordering per §5.1 with the reference Python as oracle;
  check: property test.
- 6.5.4 A: the ipfw translation of the 13 components; unsupported
  specs counted and reported; check: one test per component.
- 6.5.5 A: actions (deny, pipe, `ng_car`, log and count, terminal
  composition, `setfib` by RT, `setdscp`); check: one test each.
- 6.5.6 A: the dedicated set rebuilt atomically before the SD-WAN set;
  caps; faults; check: a flapping table.
- 6.5.7 C: flowspec originated as static routes with extended
  communities on the reflector; check: the round trip on the lab.
- 6.5.8 L: drop, mark, refib on the lab; a UNI eBGP stand-in accepted
  for its own prefix and refused for a foreign one.
- 6.6.1 C, A (if 0.3 succeeded): the port option; `vpn4`/`vpn6` with
  BIRD's labels and a VXLAN VNI per VPN; RD/RT operational; check:
  two VPNs over one session.
- 6.7.1 D: the firewall and IPsec chapters; TODO.

### Y-7

- 7.1.1 A: `arcana-dummynet` NRP objects (scheduler tier templates,
  queue weight, buffer, DSCP class, tunnel set) referenced by
  services; check: today's QoS expressed as NRPs.
- 7.1.2 C: the admission ledger with an overbooking factor per tier;
  refusal; check: a sum over the link refused.
- 7.1.3 A, C: isolation tiers as SLEs; probes in the construct's
  queue, BFD in the control class; check: congestion seen by probes.
- 7.2.1 C: SDP placement per UNI (VLAN or 5-tuple); constructs P2P,
  P2MP, A2A mapped to NRPs; check: one of each on the lab.
- 7.2.2 C: SLOs evaluated from PM; availability with period and
  maximum single outage; check: an outage counted.
- 7.3.1 A, C: RFC 9016 traffic specification → per-flow queue and
  policer; the `prio` tier; the tick raised; check: bounded queueing
  under load on the lab.
- 7.3.2 C: console-owned explicit routes per FIB with a reconvergence
  policy; capability leaves (`worst-case-delay unknown`, estimate);
  check: a link cut re-planned.
- 7.3.3 D: the band A/B/C statement; an RFC 9633 profile as a view.
- 7.4.1 A, C: `arcana-cats`: services with CS-IDs, instances,
  contact instances, the normalised score; check: the score from
  `arcana-host` facts.
- 7.4.2 C, A: candidate sets with dwell and hysteresis; affinity by
  dynamic state; Egress instance choice by `fwd`; check: two
  instances, one failing.
- 7.4.3 A: compute scores as BGP communities through the reflector
  (optional); check: a community seen.
- 7.5.1 C: certificates with AcpNodeName, Registrar-ID and node
  numbers persisted, the ULA and sub-scheme per host; check: a
  certificate's SAN.
- 7.5.2 A: the `acp` vnet jail made by the agent with `lo1`, the ULA
  and the black hole route; check: the jail on a fresh host.
- 7.5.3 A: `arcana-acp` daemon: DULL GRASP per interface, the
  adjacency table; check: two jails see each other.
- 7.5.4 A: IKEv2 channels by strongSwan with the RFC's profile over
  link-local, if_ipsec per neighbour; Decider/Follower; backoff;
  check: a channel up between two jails.
- 7.5.5 A: BIRD Babel in the jail announcing the prefix; check: the
  far ULA reachable.
- 7.5.6 A: the ACP GRASP instance (TCP 7017 flooding, TLS 1.3
  unicast); `SRV.est` flooded by the console host; check: the
  objective in a host's cache.
- 7.5.7 C: EST server (`/.well-known/est/cacerts`, `csrattrs`,
  `simplereenroll`) over the ACP; renewal at 50 %; CRL on the ULA;
  check: a renewal before expiry.
- 7.5.8 C, A: configured remote neighbours with the console host as
  hub (NAT-T); tunneled neighbours over SD-WAN tunnels; check: an edge
  behind a NAT jail.
- 7.5.9 C: cblink over the ULA first; check: the data-plane route
  removed, the console still reads the host.
- 7.5.10 A: admin down redefined for ACP interfaces; NTP over the ACP;
  `arcana-acp` state and faults (§9.1); check: the diagnostics view.
- 7.5.11 L: four jails: L2 adjacency, hub over a WAN jail, ACP over a
  wg tunnel; written to TODO's verified list.
- 7.6.1 C: the signed peer directory per service published by
  YANG-Push; check: a spoke reads it.
- 7.6.2 A: agents reconciling tunnels from the directory; check: a
  peer's address changed, tunnels back without a job.
- 7.6.3 C, A: shortcut tunnels from flow telemetry with lifetimes and
  hysteresis; reflexive endpoints from the hub; check: two spokes
  behind NATs shortcut or fall back visibly.
- 7.6.4 C: multi-gateway entries for remote users; events for every
  establishment and fallback; check: a user moved between gateways.
- 7.7.1 A: `arcana-asa`, unprivileged, over the agent's socket; the
  Instance Manifest; roles in certificates; check: it starts and
  stops with the agent.
- 7.7.2 A: `arcana:steer` objective flooded so both ends switch in
  step; check: a tunnel down, both ends on the same candidate within
  a second.
- 7.7.3 A: `arcana:sa-rekey` negotiated with dry run; check: a rekey
  without the console.
- 7.8.1 C: `arcana-intent` statements translated into L3NM; the plan
  showing both; check: a statement becomes the example service.
- 7.8.2 C: drift and SLO compliance per statement; the "why" record;
  retraction; check: a retracted statement removes only its own.
- 7.9.1 D: ARCHITECTURE.md in RFC 7426's terms; the conformance
  chapter extended.

### Y-8

- 8.1.1 L: `bench/` harness: jails, epairs, bridges, cpuset, the UDP
  sequence generator, agent and console timestamp logs behind a
  test-only option; check: one run end to end.
- 8.1.2 L: the RFC 8456 tests one by one with RFC 8455's names and
  units; the not-applicable list; check: the report table.
- 8.1.3 L: the run before 3.4 (from a tag) and after; nightly at the
  larger scale; check: CI artefact.
- 8.2.1 D: UPDATING.md on the two flag days.
- 8.3.1 D: per RFC, features, deviations, refusals and the cannot-map
  list in the book's conformance chapter and in `ietf-yang-library`.
- 8.4.1 C: primary/standby consoles sharing the data directory and
  the CA; agents trusting the CA, not one console; check: the standby
  takes over; the failover benchmark run.

## Order and effort

| Phase | Weeks | Needs | Delivers |
|---|---|---|---|
| Y-0 | 2 | — | the spikes, the remaining decisions |
| Y-1 | 8 | Y-0 | generator on libyang, wire 2, interfaces and ip readable |
| Y-2 | 16 | Y-1 | datastores, edits, routing, FIBs, jails as LNEs |
| Y-3 | 14 | Y-2 | every operation as YANG, subscriptions, NACM, event-driven console |
| Y-4 | 16 | Y-3 | RESTCONF, L3NM/SAP/VN, the PWA on RESTCONF |
| Y-5 | 12 | Y-3 | STAMP, PM, alarms, alternate marking, flow telemetry |
| Y-6 | 12 | Y-3 | ACLs, IPsec by the models, key chains, FlowSpec |
| Y-7 | 16 | Y-4, Y-5 | NRP, slices, DetNet-f, CATS, ACP, ADVPN, ASAs, intent |
| Y-8 | 6 | Y-4 | benchmarks, removal, conformance, second console |

Y-4, Y-5 and Y-6 are independent and can run in parallel. One
engineer: 102 weeks in sequence, about 23 months. Two: Y-1 and Y-2
split as generator-and-libcblink against agent-datastores (one
engineer's critical path through Y-3 is ~38 weeks), then Y-4
against Y-5 and Y-6, then Y-7 shared: about 14 months. Estimated
lines: 48–56 k of C new or rewritten (cblink is 20.7 k today, ~8 k
survive; the agent 38 k, the console 25 k, the page 41 k, of which
the operation handlers and the SD-WAN JSON paths are rewritten),
2.5–3 k of YANG for Arcana's modules. Confidence medium: the
configuration files' round trip (2.3) and the XPath-lite evaluator
(2.2) are where it would overrun.

## Risks

- libyang's API: pinned to 3.x (upstream moved to 5.x and 6.x); the
  port is kept at a version cblink-gen builds with, and the generated
  files are committed so a libyang change never breaks a user's
  build.
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
referenced), 6241 (NETCONF, for the edit and commit semantics). The
plan relies on RFCs only; where a note under `docs/notes/` cites an
Internet-Draft, that is context, not a dependency. The notes, one
file per RFC with the full tree diagrams, the node-by-node FreeBSD
mapping, the cannot-map lists and the open decisions, are in
[notes/](notes/README.md).
