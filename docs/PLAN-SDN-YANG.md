# Plan: Arcana as an SDN on FreeBSD, and cblink as a YANG protocol

What is left of the work that makes Arcana an SDN in the IETF's
vocabulary: the agent's contract carried as YANG data models by
cblink's YANG family (family 1), the console a controller with a
standard northbound, the frameworks' parts FreeBSD can realise. What
the agent serves now is in share/yang/README.md and the book; this
plan holds only what is still to do and what is decided for it.
Decisions for the user are marked **D-n** with their trade-offs and
the plan's recommendation. Nothing here is started until the user
says so.

Markers on tasks, as in PLAN-119-SASE.md: **G** the generator and
libcblink (`cblink/`), **A** the agent, **C** the console, **P** the
page, **L** the lab (run for real on the VM or the jails), **D** the
documents (ARCHITECTURE.md, the book, openapi, TODO).

## What is missing

Named by the frameworks and not yet in Arcana: configuration
datastores (NMDA's running, candidate, intended) with edits through
them, so that what a host runs is compared with what was intended
(drift); access control by NACM; a control abstraction both console
and agent share (the CAL); subscriptions in the console in place of
its one-second polls of jobs, stats, lists and the SD-WAN read; a
standard northbound; standard performance measurement (ICMP echo is
not a registered PM source); a first-class NRP object; a management
overlay that survives data-plane faults (RFC 8994); and a second
controller.

## The target

RFC 8309's three models and RFC 8969's three tiers, placed:

```
 customer                 orchestrator / controller                 devices
 ┌──────────┐  RESTCONF   ┌─────────────────────────────┐  cblink 2  ┌───────────────┐
 │ PWA, apps│ ──────────▶ │ arcana-console              │ ─────────▶ │ arcana-agent  │
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
| DAL | YANG modules the agent implements: `ietf-interfaces`, `ietf-ip`, `ietf-routing` with v4ur/v6ur and the RA submodule, `ietf-network-instance` (one instance per FIB), `ietf-logical-network-element` (one per vnet jail, its root a schema mount), `ietf-access-control-list` with RFC 9899 (compiled to ipfw), `ietf-i2nsf-ikeless` and `-ike` (RFC 9061, PF_KEY and strongSwan), `ietf-alarms`, `ietf-yang-library`, `ietf-netconf-acm`, `ietf-subscribed-notifications` and `ietf-yang-push`; and Arcana modules for what the IETF has no model of |
| Operations | `GET` (do and dump, one instance per MULTI frame), `EDIT` (YANG Patch with instance-identifier targets; merge, replace, create, delete, remove, insert, move; rollback-on-error), `RPC` (rpcs and actions), `GET-SID`; subscriptions as push streams |
| Datastores | `running` = the configuration files (rc.conf, jail.conf, loader.conf, sysctl.conf, rtadvd.conf, the kept ipfw rules, swanctl conf.d); `intended` = running; `candidate` optional, with confirmed commit = the jobs' confirm; `arcana:live` a dynamic datastore for what is changed in the kernel and not persisted (the `address live` job); `operational` = the kernel, with origin |
| CAL | an `arcana-steer` module: the steering state (candidates, chosen, reasons) and the events that change it, read and written by the console and by the agent's local failover, carried on a stream of its own |
| NBI | RESTCONF (RFC 8040) with JSON (RFC 7951) over the console's libwebsockets server, YANG Patch, `ietf-restconf-monitoring` streams as SSE, YANG-Push with the RESTCONF binding; `application/yang-data+cbor` passed through for the PWA; the fleet as `arcana-fleet:hosts/host[name]/root`, an inline schema mount per host |
| Service models | RFC 9181 common types; RFC 9182 L3NM as the network model of a service; RFC 9408 SAPs as the inventory of attachment points; RFC 9731 VN as the customer view of a service; RFC 9375 PM as the performance view; the MEF 70.2 document an import/export format over them (D-4) |
| Control plane | BIRD stays the distributed part (BGP, OSPF, BFD, Babel); the console is the controller for steering policy, slices, flowspec origination, ACLs; the agent keeps local failover |
| Measurement | STAMP (RFC 8762, 8972) sender and reflector in the agent; ICMP kept as fallback; alternate marking (RFC 9341, 9342) passively by ipfw colour counters; percentiles per measurement interval |
| Telemetry | YANG-Push periodic and on-change over push streams; NetFlow v9 by `ng_netflow` per service FIB; BMP from BIRD |
| Management overlay | the ACP of RFC 8994, as far as FreeBSD allows (D-11) |

## Open decisions

**D-5 RFC 4364 on FreeBSD.** L3NM's route distinguishers and route
targets presume MPLS VPNs. FreeBSD has no MPLS forwarding (the GSoC
branch needs an ABI bump; not before 17). BIRD has the `l3vpn`
protocol (RFC 4364 and 4659) and EVPN over VXLAN, but the `net/bird3`
port's `RT_PROT` leaves `l3vpn` out (a one-line port change adds it),
and BIRD's EVPN data plane is the Linux bridge FDB over netlink, which
FreeBSD's netlink does not offer. Options: (a) RD/RT as bookkeeping;
membership by per-service tunnels and a per-FIB BIRD session per edge
pair, O(VPN × PE²) sessions; (b) one BGP session per edge pair
carrying all VPNs as `vpn4`/`vpn6` routes with labels BIRD allocates
and the kernel never sees, and a VXLAN VNI per VPN as the real
encapsulation, next hop the far VTEP: standards-shaped, scales, new
code of its own; (c) the console pushes static routes per FIB:
simplest, no RT semantics, poor convergence. Recommendation: (a) now
with RD/RT carried and checked for uniqueness, (b) in Y-6 (6.6). Either
way `vpn-type` other than `l3vpn` is refused.
What (b) rests on, run on the lab VM: BIRD built with `l3vpn` in
`RT_PROT`, an `mpls` domain and table, a `vpn4` table, a VRF table and
an `l3vpn` protocol per edge, one iBGP session with `vpn4 mpls` and
`next hop self`, carries the VPN routes with RD and labels both ways
with no kernel MPLS; a vxlan(4) per VPN in the VRF's FIB, and a kernel
protocol exporting the VRF table to that FIB through a filter that sets
the gateway to the far end of the vxlan, forwards across with FIB 0
untouched. vxlan(4)'s cloner is attached in the host's vnet only, so a
vxlan for a vnet-jail edge is made on the host and moved in; a jail may
not set a vxlan's VNI or ends, so they are set before the move;
`net.fibs` is per vnet, raised inside the jail.

**D-6 VRF realisation.** A FIB per `vpn-node` (light, what SD-WAN
does, but leaky: loopback visible in every FIB unless
`net.add_addr_allfibs=0`, daemons need `setfib`, FIB count is a boot
tunable) versus a vnet jail per `vpn-node` (real isolation, own lo0,
own sysctls, own BIRD, dhcpd and ipfw; more processes, jail
lifecycle). Decided (2026-10-28): one FIB per `vpn-node`, modelled
as `ietf-network-instance`.

**D-11 The ACP's routing.** RFC 8994 requires RPL (no FreeBSD
implementation; the profile is a few thousand lines of our own)
versus BIRD Babel or OSPFv3 in the ACP context as the variation the
RFC's Appendix A.8 describes (non-conformant, a port, quick).
Recommendation: Babel first with the variation recorded in the
certificate's extension field, RPL as the conformance target later;
an ACP domain never mixes the two. Also: the ACP context as a vnet
jail (the RFC's preferred "logical container") rather than a FIB.

**D-12 Autonomy.** How much decision moves out of the console: none
beyond the agent's local failover (every change explained by the trace
tree) versus ASAs of RFC 9222 in an unprivileged `arcana-asa` beside
the agent, negotiating over GRASP on the ACP (steering in step on
both ends, rekey, address allocation without the console; their
decisions audited as events). Recommendation: not before the ACP
exists (Y-7); then steering and rekey only.

Smaller decisions are listed with the phases that need them.

## Decided, and binding on the rest

- **D-1 The wire.** cblink's frame with one RFC 9254 YANG-CBOR map as
  the body, keyed by RFC 9595 SIDs, the framework items `sx:structure`s
  of the `cblink` module (wire version 2).
- **D-2 The protocols.** cblink 2 on the southbound; RESTCONF on the
  console only, the one place standard tools talk to.
- **D-3 The YANG compiler.** cblink-gen compiles the modules with
  libyang 3 (`net/libyang3`); what is Arcana's own: the SID tooling,
  the XPath-lite evaluator, the YANG-CBOR codec.
- **D-4 The MEF 70.2 document.** RFC 9182 (L3NM) is what is stored and
  exchanged; MEF 70.2's terms stay for what L3NM has no node for
  (application flows, the policy map, performance criteria, breakout,
  security policies, the tunnel virtual connections), as Arcana
  augmentations of L3NM; the MEF document is an import and export
  format, and the user's vocabulary in the page.
- **D-7 The ACL engine.** ipfw (tables, dummynet for rate-limit,
  divert, `call`/`return`, fib and jail matches; it cannot match ICMP
  code, ECN, TCP ECE/CWR/AE, payload): features advertised
  accordingly, the unmappable fields refused with an extended ack.
- **D-8 Probes.** A STAMP sender and reflector in the agent (RFC 8762
  and 8972: a registered `pm-source`, one-way delay with NTP, loss per
  direction with the direct-measurement TLV, DSCP echo; a reflector per
  service FIB on UDP 862). ICMP echo stays only for targets that are
  not Arcana edges, under an Arcana `pm-source` identity. No C
  implementation exists to port; the Rust ones (cerfcast/teaparty, the
  `stamp-suite` crate) are interoperation peers in the lab.
- **D-9 One wire.** Agent, arcanactl and console speak version 2 alone.
  The operations of `share/arcana/arcana.yaml` are an interim module
  written by `share/arcana/wire.awk`, an rpc an operation; the YAML
  stays their editing source until Y-3 moves each onto its module.
- **D-10 The northbound.** RESTCONF replaces `/api`. The PWA,
  `arcanactl` and the Android app move in the same release; the
  WebAuthn ceremonies and the enrolment endpoints stay as Arcana's own
  resources beside `/restconf` (4.4).

## What cblink still needs

The YANG family serves GET, EDIT (create, replace, delete; all or
nothing), RPC and actions, NOTIFY, GET-SID and SUBSCRIBE. The remaining
steps need of it:

- **Datastores.** A datastore parameter on GET and EDIT (`running`,
  `candidate`, `arcana:live`, `operational`); commit, cancel, discard
  and a connection-scoped lock as rpcs of a `cblink-datastore` module
  behind the `candidate` feature, with RFC 6241's semantics (2.3.7,
  2.3.8); `with-defaults` and `with-origin` on GET, origin carried as an
  RFC 7952 annotation (2.3.9, 2.3.10).
- **Edits.** YANG Patch's merge, remove, insert and move beside create,
  replace and delete (4.1.5). Unknown nodes are refused in edits
  (`unknown-element`) and ignored on operational reads from a newer
  peer. Validation runs in full on edits of `running`, `candidate` and
  `arcana:live` and on rpc input, never on operational reads (RFC 8342
  §5.3).
- **Targets.** A list entry (`[SID, keys...]`) as a GET's target, for
  RESTCONF's api-paths (4.1.3).
- **Subscriptions.** Subtree filters, filters by reference, `modify`,
  suspension on credit exhaustion as `subscription-suspended
  {unsupportable-volume}` and its return `subscription-resumed`,
  replay, configured subscriptions (3.2.4 to 3.2.8).
- **Capabilities.** Features advertising optional parts (`if-mib`,
  `pre-provisioning`, `candidate`, `on-change`, `configured`, `vnet`,
  `stamp`, ...) and deviations documenting FreeBSD's divergences in
  the library; `yang-library-update` when it changes, on which the
  console refreshes its per-host cache (2.8.1, 4.3.2).
- **Errors.** `error-tag` identities give the console RFC 8040 §7's
  HTTP status; `error-app-tag` and `error-message` come from `must`
  statements; `errno` stays for arcanactl (4.1.7).
- **SIDs.** The `.sid` files are the "numbers are forever" ledger: a
  SID is never reused or removed, an item that goes gets `status
  obsolete`, a module revision adds items at the end of its range.
  Arcana's modules and the IETF modules without IANA SIDs take RFC
  9595's experimental range (60 000 to 99 999); a registered block
  later (0.5.1).

## The agent as a YANG device

What each module still needs of FreeBSD: the sinks its configuration
is written to, and its deviations. Every module Arcana writes avoids
decimal64, keeps `when`/`must` within XPath-lite, and uses identities
for open sets.

| Module | FreeBSD realisation (operational source; config sink) | Deviations and features |
|---|---|---|
| `ietf-interfaces` | sinks rc.conf `ifconfig_<if>`, `cloned_interfaces`, SIOCIFCREATE2, SIOCSIFFLAGS | broadcast counters omitted (if_data merges them into multicast); `link-up-down-trap-enable` not supported; features `if-mib`, `pre-provisioning` (interfaces moved into jails) |
| `ietf-ip` | sinks SIOCAIFADDR(_IN6)/SIOCDIFADDR, rc.conf `ifconfig_<if>`, `_alias<n>`, `_ipv6`, `static_arp_pairs`, `static_ndp_pairs` | `forwarding`, `dup-addr-detect-transmits`, temporary addresses are host-global sysctls: reported with origin `system`, per-interface writes refused by a deviation; one MTU for both families |
| `ietf-routing`, `ietf-ipv4-unicast-routing`, `ietf-ipv6-unicast-routing`, RA submodule | sinks rc.conf `defaultrouter`, `static_routes`, `route_<name>`, `ipv6_*`, and the kernel by rtsock or netlink; RA: rtadvd.conf and `rtadvctl reload` | `router-id` not at the host root; `prohibit` next hop unsupported; `last-updated` tracked by the agent from events; `multiple-ribs` off at the root: other FIBs are network instances |
| `ietf-network-instance` | `vrf-root` a shared-schema mount of routing, v4ur, v6ur and yang-library; `bind-ni-name` ↔ SIOCSIFFIB and rc.conf `fib N`; names in `/usr/local/etc/arcana/fibs.conf` | creation raises `net.fibs` live (it grows, never shrinks) and keeps it in loader.conf; a reboot-required flag where the kernel will not grow it; per-AF binding equals the interface's; no `vsi-root` (if_bridge is an interface) |
| `ietf-logical-network-element` | `root` an inline mount served by a long-lived helper attached with `jail_attach(2)` speaking cblink 2 over a socketpair (the same proxied-connection mechanism as the fleet mount at the console); `bind-lne-name` ↔ SIOCSIFVNET and jail.conf `vnet.interface` | non-vnet jails are not LNEs (their addresses appear as host aliases with an `arcana-jails:owner` augment) |
| `ietf-access-control-list`, `ietf-packet-fields`, RFC 9899 | an ACL = a reserved ipfw rule band ended by `return`, entered by `call` from attachment rules (`in recv`, `out xmit`, `via`), names in rule comments; prefix sets = tables swapped atomically; port sets = lists ≤ 30 or number tables; protocol sets = or-blocks; ICMP sets = type lists; fragments by `frag df/mf/offset`; extension headers by `ext6hdr`; flags-bitmask by `tcpflags`; `rate-limit` = a dummynet pipe; `log-action` = `log logdst`; `counter-action` = a `count` rule per name; applied through the set-swap transaction with the rest of the ruleset | features match-on-eth/ipv4/ipv6/tcp/udp/icmp, eth, ipv4, ipv6, mixed-*, acl-aggregate-stats, interface-attachment, match-on-alias; not interface-stats (unless blocks are duplicated per attachment), match-on-payload (unless ng_bpf is wired), vlan/isid/mpls. Refused with an extended ack: ICMP code, ECN, ihl, exact fragment offset, identification, TCP data-offset/reserved/urgent/options pattern, ECE/CWR/AE bits, IPv6 ff/lf, Mobility/HIP/Shim6 headers. Arcana augments: attachment to a FIB, a jail, all interfaces; `default-action`; `stateful` (keep-state); reject code |
| `ietf-i2nsf-ikeless` (RFC 9061) | PF_KEYv2 in-process (libipsec): SADB_ADD/UPDATE/DELETE/GET/DUMP, SADB_X_SPDADD/SPDDELETE/SPDDUMP, SADB_REGISTER for SADB_ACQUIRE, SADB_EXPIRE; selectors with single ports; ESN with an explicit window (`-r 128`), NAT-T; or the ipsec(4) interface's reqid for route-based policies (uswe) | notifications `sadb-acquire` and `sadb-expire` exact, `sadb-seq-overflow` synthesised, `sadb-bad-spi` absent (no kernel notification); refused: port ranges, `espintcp`, `pfp-flag`, `seq-overflow true`, `tfc-pad`, per-SA `df-bit`, `dscp-mapping`, IV, packet and idle lifetimes, selectors on the SA |
| `ietf-i2nsf-ike` (RFC 9061) | strongSwan: files in conf.d as the persisted configuration, VICI for state (`list-sas`) and events; identities, PSK, EAP, signatures with the host's own key (private keys never pushed); lifetimes; proposals from IANA ids | refused: `id-null`, per-connection initial-contact, fragmentation MTU, half-open timers; `number-ike-sas/half-open-cookies` absent |
| `ietf-ipsec-iptfs` (RFC 9348) | only `ipsec-stats` tx/rx packets and octets per SA from the lifetime counters | everything else refused: the kernel has no AGGFRAG/IP-TFS; the configuration augment is not feature-gated, so writes are refused with `operation-not-supported` and the console hides the subtree behind an Arcana capability |
| `ietf-alarms` (RFC 8632) | shelving as the control's configuration; `purge-alarms` and `compress-alarms` actions | |
| `ietf-yang-library`, `ietf-yang-schema-mount`, `ietf-netconf-acm`, `ietf-subscribed-notifications`, `ietf-yang-push` | per-mount libraries; NACM groups from the certificate's subject or the socket's uid, rule-lists, enforcement at rpc, data-node and notification; on-change by netlink(4) and EVFILT_JAIL events; subtree filters; replay from the event number for job traces and events | `on-change-unsupported` for counters; NACM replaces the per-op `auth` flag (`default-deny-all` on privileged rpcs) |
| Arcana modules still to write | `arcana-steer` (the CAL, 3.5), `arcana-stamp` (5.1.8), `arcana-dummynet` (the NRP, 7.1), `arcana-cats` (7.4), `arcana-acp` (7.5), `arcana-intent` (7.8) | the served Arcana modules' configuration written through `EDIT`; their arcana.yaml operations retired, the JSON blobs typed (Y-3) |

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
  by the same code from the libucl files it keeps.
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
  checked and planned before applied. Infeasible requests are refused
  with the reason and the nearest feasible alternative (RFC 9543 step
  2, RFC 8578 §11.3.1).
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
  `ng_netflow` per service FIB (NetFlow v9; `pflow(4)` is pf-only);
  BMP from BIRD; syslog over TLS; telemetry role on tokens separate
  from configuration.
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
  from the hub. This takes Arcana to 14 of the 16 requirements
  (federation and multicast stay out).
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

"Kernel" means it would need kernel work, which Arcana does not do.

| Area | Not realisable on FreeBSD, and why |
|---|---|
| MPLS and segment routing (9181, 9182, 9732, 9543, 9938, 7426's PCEP, 9899 `mpls-values`, 10053 SRv6 paths) | no MPLS or SRv6 forwarding in the kernel (GSoC branch, not before 17); BIRD's `l3vpn` labels have no kernel to go to; BIRD's EVPN data plane is Linux's bridge netlink; FRR on FreeBSD has no MPLS, LDP, SR or VRF |
| RFC 4364 as an operational object (9182 RD/RT, `auto-assigned-rd`, VPN SAFIs; 8955 SAFI 134) | follows from the above; bookkeeping only (D-5) |
| L2 services: pseudowires, VPLS, EVPN, VXLAN bgp-mode, L2TPv3, `vxlan` with several static unicast peers on one interface (9181, 9182) | no LDP or EVPN; vxlan(4) has one `vxlanremote`; approximation under Arcana identities with vxlan + if_bridge only |
| IS-IS, S-BFD, OSPF sham links, `max-lsa`, RIP holddown, TCP-AO, IPv6 site-of-origin, BGP warning-threshold, native as-override, IPv6 router-id (9182) | BIRD lacks them; FreeBSD has no TCP-AO |
| VRRP on the wire (9181, 9182) | carp(4) only, wire-incompatible: an Arcana `carp` identity instead |
| `priority-tagged` (L3NM's default) and `qinany` encapsulations | vlan(4) refuses VID 0 and has no wildcard inner tag |
| Multicast routing: IGMP and MLD router side, PIM, MSDP, IGMP snooping in if_bridge, group limits (9181, 9182, 8578) | out of scope |
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
| IPFIX from `ng_netflow` (9232) | it exports NetFlow v5 and v9 only (IPFIX is a kernel item in TODO.md) |
| ForCES, OpenFlow, PCEP, I2RS protocol (7426) | no implementations; not pursued |
| Reactive path provisioning, controller failover (8455, 8456) | not applicable to Arcana's design: no packet-in, standalone console |
| ICN forwarding, BIER, CDN migration, 6LoWPAN (8763); multi-operator MANO, 5G slicing, VM portability (8568) | out of scope |

## The phases

Each phase ends reviewed, bumps the agent's and the console's
versions, updates ARCHITECTURE.md, the openapi document and the book,
and is run on the lab where it says L.

### Y-0 Decisions

- **0.5 SIDs.** D: a registered SID block once Arcana interoperates
  with another SID-keyed peer.
- **0.6 Decisions.** D-5, D-6, D-11 and D-12 taken or deferred.

### Y-1 The Network tab

- **1.11 The Network tab by YANG.** C: what the tab's interfaces still
  read from the agent's own operation (CARP, the interface flags) read
  through family 1.

### Y-2 Datastores, routing, instances

- **2.3 Datastore engine.** A: `running` round-trip editors for
  rc.conf and rc.conf.d (Arcana-owned fragments where rc(8) reads
  them), jail.conf (libjailconf), loader.conf, sysctl.conf,
  rtadvd.conf, the kept ipfw rules, swanctl conf.d, preserving
  comments and order; `candidate` with commit, confirmed commit and
  rollback (the jobs' confirm generalised); `arcana:live`;
  the apply transaction with undo. The risk item. Its safety design
  is the user's to review before an `EDIT` of `running` is served.
  In the tree, tested, not yet behind an `EDIT`: lib/libvarconf
  (rc.conf, rc.conf.d, loader.conf and sysctl.conf read and changed in
  place, and 2.3.2's conflict rule), rcroutes.c's `rcr_apply` (static
  routes), yni.c's `yni_grow` and `yni_bind_apply`, rtadv.c's
  `rtadv_write`, ysystem.c's `ysysctl_conf_write` and
  `ykernel_kld_write`, the jails' and packages' actions. The agent
  edits rc.conf through sysrc(8) until 2.3.5.
- **2.4 `ietf-routing`, v4ur, v6ur.** A: static routes in `running`
  written to rc.conf and applied to the kernel.
- **2.5 Router advertisements.** A: rtadvd.conf as the RA submodule's
  `running`, `rtadvctl reload`.
- **2.6 `ietf-network-instance`.** A: the `vrf-root` mount,
  `parent-reference`, `bind-ni-name` and `net.fibs` written.
- **2.7 `ietf-logical-network-element`.** A: the attached helper per
  vnet jail over a socketpair, the `root` mount, interface moves,
  per-LNE library.
- **2.8 yang-library and schema mount runtime.** A: per-mount
  libraries, nested mounts (NIs inside an LNE), dispatch,
  `yang-library-update`.
- **2.9 First EDIT.** C: an address added persistently through
  `EDIT` on `running` and live through `arcana:live`; a static route;
  an interface moved into a jail. L: the lab, with a hand edit of
  rc.conf shown as drift.
- **2.10 Tests.** round-trip fixtures for every file editor,
  validator tests from RFC 7950's examples, XPath tests.

### Y-3 The conversions, subscriptions, NACM

Depends on Y-2 for every write.

- **Before each conversion:** the standard models for its area: an
  RFC's module used as it is with Arcana's augments, a working-group
  draft's followed, an Arcana module only where none exists. With each
  operation converted, its task's { } Schema panel in the console
  shows its YANG model beside the CBOR schema, in the same commit.
- **3.1 The Arcana modules.** A: each module's read and its actions
  are served (a snapshot's send and receive wait for streams, 3.4);
  what is left is its configuration written through `EDIT` and its
  operations of arcana.yaml retired from the interim module (D-9), the
  JSON blobs replaced by typed lists.
- **3.2 Subscriptions.** A: on-change from the event sources rather
  than a read every dampening period, subtree filters, suspension on
  credit, `modify`, replay, monitoring counters, configured
  subscriptions calling the console.
- **3.3 NACM.** A: groups from the certificate or uid, rule-lists,
  enforcement at the three points, counters; the console passes the
  user. ~1.5 k.
- **3.4 Event-driven console.** C: subscriptions replace the one-second
  polls of jobs, stats, lists and the SD-WAN read; the console's
  one connection per agent carries long-lived streams; reconnect
  logic. Benchmarks before and after (8.1).
- **3.5 `arcana-steer`, the CAL.** A, C: candidates, chosen, reasons,
  the events; the agent's local failover writes it, the console reads
  and writes it; a stream of its own, an SCTP stream of its own.
- **3.6 arcanactl.** C: writes YANG paths (`set`) beside `get`,
  `action`, `subscribe` and `notifications`, with libxo output; the
  old verbs go with the interim module.
- **3.7 Tests.** every former operation's test rewritten against the
  module; the root suite on real jails.
- **3.8 The switch.** A, C: the interim module gone with its last
  operation.

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
  kept in the page.
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
- **5.4 `ietf-alarms`.** A, C: shelving, the purge and compress
  actions; the Paths tab reads alarms.
- **5.5 Alternate marking.** A, C: `setdscp` colour pairs flipped on
  a timer per service, paired `count dscp` rules at the ends, counters
  read at L/2 by the `IP_FW3` sockopt with a block number, the
  clustered partition of RFC 9342 §5.1 in the console with Appendix A
  as the unit test, the in-band variant through STAMP's direct
  measurement TLV for steering. L: three jails, loss localised to one
  cluster.
- **5.6 Flow telemetry.** A: `ng_netflow` per service FIB, sampling,
  per-zone; BMP from BIRD to the console; the console's compact
  time-series store with retention per class. `ng_netflow` exports
  NetFlow v5 on its `export` hook and v9 on `export9`, nothing else.
  An expired flow waits in a partly filled datagram until it fills
  (30 records for v5, some 1400 bytes for v9) or the node shuts down,
  so a quiet service's flows can wait without bound: 5.6 needs a flush
  on a timer, from the agent (a `flush` message the node does not
  have, so a kernel change the user decides) or by rebuilding the
  export hook, or accepts it.
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
- **6.5 FlowSpec.** A, C: BIRD, which keeps the routing in one daemon
  (ExaBGP would be a second daemon beside it, with no FIB of its own).
  Per-service `flow4`/`flow6` channels
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
- **6.6 D-5(b).** C, A: `l3vpn` added to the port's `RT_PROT` (a change
  for its maintainer); `vpn4`/`vpn6` between edges with labels BIRD
  allocates but the kernel never sees, and a VXLAN VNI per VPN as the
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

### Y-8 Benchmarks, conformance, second console (6 weeks)

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
A step never leaves `main` unbuildable. "(the rest)" marks a step
whose first part is served.

### Y-0

- 0.5.1 D: a registered SID block (an IANA mega-range by RFC 9595 §7,
  Expert Review, or a Private Enterprise Number's ranges by RFC 9997)
  recorded in `share/yang/SIDS.md`, Arcana's modules moved into it from
  the experimental range.
- 0.6.1 D: D-5, D-11, D-12 taken or deferred, recorded here; D-6
  taken (one FIB per vpn-node).

### Y-1

- 1.11.2 C (the rest): CARP and the interface flags on the Network tab
  read through family 1, CARP by `ietf-vrrp` (RFC 8347) with an Arcana
  `carp` identity; check: the browser test's Network tab unchanged in
  look.

### Y-2

- 2.3.1 A (done): rc.conf reader and writer preserving comments and order,
  with `rc.conf.d/` fragments Arcana owns; check: a fixture corpus
  round-trips byte for byte.
- 2.3.2 A (done): the conflict rule: a variable set in the user's rc.conf
  and in an Arcana fragment refused with a message; check: fixture.
- 2.3.3 A (done): loader.conf, sysctl.conf and rtadvd.conf editors; check:
  fixtures.
- 2.3.4 A (done): `running` assembled from the files into an instance tree
  for interfaces, ip, routing; check: equals the files on the VM.
- 2.3 safety design, decided 2026-10-28:
  - rc.conf: one file of Arcana's, `/usr/local/etc/rc.conf.d/arcana`,
    named in `rc_conf_files` (one line in `/etc/rc.conf`, written once
    with the user's confirmation), so every rc script reads it. A
    variable also set in the user's files: a warning and an explicit
    confirm to overwrite; overwritten, the new value is written to
    Arcana's file and the conflicting line commented out where it is
    in the user's (`#var="value"  # taken by Arcana`), never removed;
    put back when the commit fails. The user moves a service's
    variables under Arcana deliberately with arcana-services' `convert`
    action (`arcanactl services convert [-n] [name ...]`), which lists
    each variable taken with its file and line.
  - Changes through `candidate` and a confirmed commit, undone unless
    confirmed.
  - A boot-time tunable written to its file with a "takes effect after
    reboot" warning; a live change that cannot be undone refused
    unless the request accepts its warning.
  - An undo that fails raises an alarm; where the subsystem allows a
    safe try and error (routing), it is tried again; failing again,
    the rollback stops and a bug report is written for the console,
    which recommends filing it. Arcana never files it: it is for the
    user to review, about the error and not the host's configuration.
    Whatever cannot be rolled back safely says so beforehand.
  - Step by step: interfaces, addresses and routes first, then a
    module at a time.
- 2.3.5 A (done): `EDIT` on `running`: validate the result, render the
  files (the rc.conf.d fragments in place of sysrc(8)), apply to the
  kernel, undo on failure (file copies restored); check: a failing
  ioctl leaves the files as they were.
- 2.3.6 A: `arcana:live`: edits applied to the kernel only, origin
  `dynamic`; check: the `address live` test passes through it.
- 2.3.7 A (done): `candidate`, `commit`, `discard-changes`; check: RFC 6241
  §8.3's sequence.
- 2.3.8 A (done): `confirmed-commit` with timeout and `persist`, the revert
  = safe mode; check: the safe-mode tests pass through it, including
  the one that cuts the connection.
- 2.3.9 A (done, cblink 0.2.15): operational with `with-origin`
  (intended, system, learned, default; unknown for what was set by
  hand), origin an RFC 7952 annotation in YANG-CBOR (tag 109) and JSON;
  `ietf-ip`'s host-global sysctls with origin `system`; check: a system
  address, a configured interface (`agent_test:datastores`,
  `yds_test:with_origin`, `console_test:restconf_write`). `dynamic`
  waits on 2.3.6's `arcana:live`.
- 2.3.10 A (done): `with-defaults` report-all, report-all-tagged
  (ietf-defaults' `default`, draft-ietf-netconf-default-attribute),
  trim, explicit served on GET; check: RFC 6243's examples.
- 2.4.3 A (done): static routes in `running` written to rc.conf
  `static_routes`, `route_<name>`, `defaultrouter`, IPv6 variants by
  an `EDIT`; check: fixtures.
- 2.4.4 A (done): an `EDIT`'s static routes applied to the
  kernel by netlink per FIB (`rcr_apply`); check: `route -n get`.
- 2.5.1 A (done): rtadvd.conf ↔ the RA submodule in `running` (`rtadv_write`
  behind an `EDIT`), `rtadvctl reload`; check: `rtadvctl show` after
  an edit. Every capability of rtadvd.conf(5) since `arcana-ra`
  (router preference, route information, RDNSS, DNSSL, PREF64,
  mtu=auto, noifprefix, nolladdr, clockskew, vltimedecr, pltimedecr;
  unknown fields kept in `other-capability`): the record written
  whole, `rtadvctl reload` where rtadvd runs on the same interfaces,
  a restart where not; `arcana-ra:rtadvd` in operational from
  `rtadvctl -v show`; the console's form on an interface's row
  (ra.c), saved by a confirmed commit, its warnings accepted there.
- 2.6.2 A (done): `vrf-root` mount serving routing per FIB, with
  `parent-reference` (`/if:interfaces`, in `schema-mounts`); check: the
  FIB's table under the mount.
- 2.6.3 A (done): `bind-ni-name` written by an `EDIT`
  (`yni_bind_apply`: SIOCSIFFIB and rc.conf `fib`);
  `bind-ni-name-failed`; check: `ifconfig em0 fib 2` reads back.
- 2.6.4 A (done): a new instance asked for by an `EDIT`
  (`yni_grow`: `net.fibs` raised and kept in loader.conf) with the
  reboot-required flag in the reply; check: the flag in the reply.
- 2.7.2 A (done): the attached helper (`invidia/lneroot.c`): the
  agent run again as `--scope-helper JID lne-serve`, `jail_attach`,
  the same YANG handler table served over a socketpair
  (cblink's `cbl_conn_new_fd()`), started at the jail's first
  read, one request at a time, stopped with the jail (EVFILT_JAIL),
  started again where it died; check: `agent_root_test:lne_root`.
- 2.7.3 A (done): the `root` mount filled from the helper's GET
  (`cbl_msg_ydecode_member` into `cbl_ymount_data`): the jail's
  interfaces, routing, network instances with their `vrf-root`s, its
  YANG library and schema-mounts; `schema-mounts` lists `root`
  inline; `max_depth` 32 everywhere (a jail's instances' routing goes
  past 16); check: a FIB's routes inside a jail, the same case.
- 2.7.4 A (done): `bind-lne-name` written by a commit (`yifedit.c`):
  `do_if_vnet()` (ifconfig vnet, jail.conf `vnet.interface` by
  libjailconf where the jail is defined; `not-kept` warned otherwise),
  moved alone or refused `lne-assignment-failed`; back on the host its
  addresses, MTU, state made live again; undone at the timeout; the
  jails' interfaces listed in the host's with their `bind-lne-name`;
  `bind-lne-name-failed` when the jail stops with a bound interface;
  check: `agent_root_test:lne_bind`.
- 2.8.1 A (done): `ietf-yang-library` under each `vrf-root` with its
  `content-id`, and the top's with NMDA's three datastores. The set
  changes only with a new agent, whose restart ends every session, so
  `yang-library-update` has nothing to say while one runs; check:
  `GET` of a mount's library (`agent_test:datastores_instances`).
- 2.8.2 A (done): `ietf-yang-schema-mount` state (`schema-mounts`): the
  agent's `vrf-root` shared, the console's `arcana-fleet` `agent`
  mount inline; check: RFC 8528's examples' shape.
- 2.9.1 C: persistent and live address edits through `EDIT`; a static
  route; an interface moved into a jail; check: the browser test.
- 2.9.2 L (done, console drift.c): a hand edit shown as drift: a host's
  Summary reads running and the operational configuration with its
  origins and shows the edit between them (`GET /api/servers/<id>/drift`,
  `console_test:services`, `pwa_test:pwa_firewall`).
- 2.10.1 G, A: the fixture corpus for every file editor under
  `tests/fixtures/`; validator tests from RFC 7950's examples; XPath
  tests; check: `make check`.

### Y-3

- 3.1.1 A (done): `arcana-jails`: jail.conf as `running` through
  `EDIT`; the list and action operations retired; check: the `list`
  and `action` tests pass through the module.  Done (ira/yjailedit.c,
  lifecycle.c): running is each jail's parameters as jail(8) -e
  resolves them, its file, and `boot` (jail_enable, jail_list) from
  the files rc(8) reads (libvarconf); the operational state is the
  list operation's read, the running jails by libjail, the bird,
  firewall and jail-files augments refined to state.  A commit edits
  the jail's own block in place, every other line kept (libjailconf:
  the first value where the statement was, jc_replace(), the others
  added after it, an empty value a bare boolean), makes a new jail a
  file of its own in jail.conf.d and takes one away with its file,
  each file read back by libjailconf and all by jail(8) -e, the jails
  then what was asked; a parameter the file's defaults give, not the
  jail's own, is refused, every file put back; `boot` is jail_list and
  jail_enable in Arcana's rc.conf file by rcarcana.c's rules
  (rc-conf-files, rc-conf-conflict), never an empty list.  start,
  stop, restart and kill are the module's actions, one change at a
  time as the agent's own, their steps told on the steps group as an
  operation's trace was (ywork_told()), which arcanactl -t and the
  console's trace collect.  The console's jails, action and address
  replies keep their shapes (ytrans_jails(), ytrans_jail(),
  ytrans_jail_action()); its enable and disable stay the jail-action
  job, waited for: by a commit they would meet rc-conf-conflict
  wherever /etc/rc.conf sets jail_list, which the page does not ask to
  accept yet (as 3.1.2's enable and disable).  arcanactl's list,
  start, stop, restart and kill are the module's; enable and disable
  its `boot` by EDIT and commit, -a the accepts.  Check:
  `datastores_jails`, `jail_boot` (the job), `list`, `start`,
  `failures`, `trace`, `many_jails`, `yang_jails`, `yang_actions`; the
  console's `jails`; `pwa_hosts`.
- 3.1.2 A: `arcana-services`: rcvars and rc.conf variables as leaves
  in `running`; the services, service-action and service-config
  operations retired; check: the services tests.  Done, the first
  half (ira/ysvcedit.c): running is each script with `enabled`
  (`<name>_enable`) and its `<name>_*` variables from the files rc(8)
  reads (libvarconf), the operational read has them beside the
  operation's; a commit writes what differs to Arcana's rc.conf file
  by rcarcana.c's rules, a service at a time (its rcvar as `service
  <name> rcvar` names it, a variable of its own or its rcvar's stem's;
  the rcvar is `enabled`'s alone), every file put back where a later
  one fails; check: `datastores_services`.  Left: the three
  operations' retirement, which turns the console's enable, disable
  and config writes into an EDIT and commit: those meet
  `rc-conf-conflict` on every host whose /etc/rc.conf sets the
  variable (sshd_enable does), so the console must carry the accept
  from the page, or keep those writes as the service-action and
  service-config jobs (3.1.4) and retire the operations alone.  A
  decision for the user.
- 3.1.3 A (done): `arcana-packages`: the packages and pkg-upgrade
  operations retired; check: the packages tests.  Done (ira/ypackages.c,
  yarcana.c): the host's packages and a jail's (arcana-jails' jail)
  are state: those installed (pkg query) read with the host's, a
  jail's by the read action; what the repository has newer by the
  refresh action (pkg version -vRl '<'; update, pkg update first, the
  one change; ignore-osversion past a repository for a newer FreeBSD,
  the error naming IGNORE_OSVERSION as before), the repositories and
  pkgbase beside; the upgrade action is pkg-upgrade's (every-jail, the
  host's in every running jail one after the other); the pkg-upgrade
  job, its lanes and the stall watchdog are as they were.  Their
  steps are told on the steps group as the jails'.  The console's
  packages and upgrade replies keep their shapes (ytrans_packages(),
  ytrans_pkg_upgrade()); arcanactl's packages and pkg-upgrade are the
  actions.  The second SID range is 79 500.  Check: `packages`,
  `yang_packages`; the console's `churn`, `services`; `pwa_hosts`.
- 3.1.4 A: `arcana-jobs`: the job-submit, jobs, job, job-cancel and
  job-confirm operations retired; check: the jobs tests; the trace
  tree rebuilt in the page.
- 3.1.5 A: `arcana-storage`: a snapshot sent and one received
  (streams) as actions; the storage, fstab, zfs-send, zfs-receive and
  zfs-key operations retired; check: the storage tests, the root ZFS
  test.
- 3.1.6 A (done): `arcana-sysctl` (`running` ↔ sysctl.conf) and
  `arcana-kernel` (`kld_list` in `running`); the sysctl, sysctl-parts
  and kernel operations retired; check: tests.  Done
  (superbia/ysysedit.c, sysctl.c): running is sysctl.conf's settings
  and kld_list from the files rc(8) reads (libvarconf); a commit of
  `sysctl` writes sysctl.conf in place and sets the kernel to each
  value changed as sysctl(8) does, a value refused puts the file back,
  a tunable the loader alone sets (CTLFLAG_TUN, not writable) is
  refused for loader.conf, one taken out is said to keep its value
  (`sysctl-unset`); a commit of `kernel` writes kld_list to Arcana's
  rc.conf file (rcarcana.c's rules), the kernel as it is, said where
  the list and it differ (`kld-list`); the load rpc and the unload
  action load and unload now.  The kernel's values are read by the
  module's `read` action a part at a time (prefix, after, count; a
  jail's network's), which the console's /sysctl and its WebSocket
  parts and arcanactl's `sysctl` use, `kmod` is `get kernel`.  The
  jobs of kind sysctl and kmod stay as jobs (3.1.4).  Check:
  `datastores_sysctl`, `datastores_kernel`, `kernel`, `yang_system`;
  the console's `services`, `churn`, `mtls`, `tls_ec`.
- 3.1.7 A: syslog.conf written from `ietf-syslog`; the processes,
  log, history, events and event operations retired; check: tests.
  Done, the first half (gula/ylog.c, gula/ysyslog.c): a commit of
  `syslog` writes Arcana's lines in /usr/local/etc/syslog.d/arcana.conf
  and their rotation (file-limit-size, file-limit-duration) in
  /usr/local/etc/newsyslog.conf.d/arcana.conf, which FreeBSD's
  syslog.conf and newsyslog.conf include (`syslog-include` where they
  do not); an action left as it is stays where it is, one changed is
  written whole in Arcana's file and the user's lines of it commented
  out only where accepted (`syslog-conf-conflict`); read back before
  `service syslogd onereload` (syslogd has no check of its own), every
  file put back where that fails; refused: TLS, a destination named
  otherwise than by its address, facility-override, block and stop,
  cron2, retention, a rollover not in whole hours. Check:
  `datastores_syslog`, `yang_log`. Left: the operations' retirement.
- 3.1.8 A: `arcana-bird`, `arcana-wireguard`, `arcana-netgraph`: the
  network operation's kinds and bird-config retired; check: the plugin
  tests.
- 3.1.9 A: the hello, list, stats, certs, agent and jail-files
  operations retired; check: `hello`'s tests.
- 3.1.10 A: the ipfw-rules, fw-trace, path-check, traceroute and
  capture operations retired; check: the firewall tests.
- 3.1.11 A: `arcana-probe`'s targets written through `EDIT`; the
  sdwan-probes operation retired; check: the probe tests.
- 3.1.12 A: `arcana-sdwan` written through `EDIT` in place of the
  console's JSON; the sdwan, sdwan-rules, sdwan-steer, sdwan-bird,
  sdwan-dhcp, sdwan-dns, sdwan-proxy and sdwan-ids operations retired;
  check: the SD-WAN tests and the two-jail lab.
- 3.2.3 A (done): on-change from the event sources in place of a
  read every dampening period: interfaces, routing, network instances
  and logical network elements are told by netlink(4)'s and the jails'
  events, a job's, a changed file rc(8) reads, a commit (cblink tells
  those itself), and a minute on for what the kernel announces nowhere
  (`agent_root_test:onchange_address`). Was: The events, the alarms and the jobs are
  told (cbl_ysub_told, cbl_ysub_changed); interfaces, addresses, routes
  and jails are still read each period, as they change outside the
  agent too. The kernel announces nothing, on netlink or rtsock, for a
  description, a FIB, a group, a link-layer address, media,
  capabilities, or a vlan's, lagg's or bridge's settings: those are
  told by the agent's own jobs that change them, or polled; check: an
  address added arrives as a patch within the dampening period.
- 3.2.4 A (the rest): subtree filters on subscriptions, once their
  YANG-CBOR has an encoding (RFC 6241's are XML); the XPath filter
  meanwhile; check: one interface's counters only.
- 3.2.7 A (done): configured subscriptions: the agent calling the console
  as receiver; check: the console restarted, records resume.  Done
  (2026-10-28): RFC 8639's `configured` feature, the transport
  HTTPS-notif (draft-ietf-netconf-https-notif, its
  `ietf-subscribed-notif-receivers` and `ietf-https-notif-transport`
  vendored with SIDs) with JSON encoding; publisher the agent, receiver
  the console.  cblink keeps them beside the dynamic ones
  (cbl_ysub.c): running's `subscriptions` told by
  `cbl_ysub_configure()` from the program's edit handler and at its
  start, each receiver its state machine (connecting, active) and a
  thread of the subscription's own, records to the program's transport
  (`cbl_ysub_set_transport()`), a receiver connected again told
  `subscription-started` with `replay-previous-event-time` and replayed
  what it missed from the stream's replay, then `replay-completed`.
  The agent (invidia/ynotif.c) keeps the container in
  `--subscriptions` (subscriptions.cbor) and is the HTTP/1.1 client
  over OpenSSL: GET capabilities once, POST relay-notification per
  record, its own certificate shown, the console's CA and the system's
  trusted.  The console (notif.c) is the receiver at
  `/api/notif/<host>/{capabilities,relay-notification}` on its TLS
  listeners, the agent authenticated by its certificate (role, the
  host's name), the records kept in `notif/<host>.jsonl` of the data
  directory, read at `/api/servers/<host>/notifications`;
  `/api/servers/<host>/subscription` says what to PUT in the host's
  candidate (RESTCONF) and commit.  Checked: cblink's ysub_test
  (configured), agent_tls_test (configured, with a stand-in receiver),
  console_test (notif_receiver: the console restarted, the records
  there, the agent back and what it missed replayed).  A per-host
  token beside the certificate (2026-10-28): web.conf's `notif_auth`
  (`certificate` the default, `token`, `either`); `POST
  /api/servers/<host>/subscription/token` makes 32 random bytes and
  shows them once, in the document, as the https-receiver's
  `arcana-notif:token` (the vendored `ietf-http-client@2024-08-15` has
  no client identity, so an augment of Arcana's, SIDs 79 300), the
  console keeping the SHA-256 in the host's record; the agent sends it
  as `Authorization: Bearer`, keeps it in `--subscriptions` (0600),
  `nacm:default-deny-all`; a plain listener takes records by it.
  Checked: console_test (notif_token: a plain listener, the agent
  sending it, a new token retiring the old, either; notif_receiver:
  the token alone refused with certificate), agent_tls_test
  (configured: the header sent).  Left: no UI form yet (the API gives
  the document to PUT); a receiver's `reset` action and `suspended`
  are there but untested; subtree filters as 3.2.4.
- 3.3.1 A (done): NACM groups from the certificate's subject or the socket's
  uid, rule-lists in `running`; check: RFC 8341's examples. RFC 8341
  followed strictly (decided 2026-10-28): its groups, rule-lists and
  defaults as written, not a mapping of the console's roles onto it.
  Done for the rpcs (0.227.0, superbia/admit.c): the console is in group
  admin by default, whose rule-list permits every rpc; any other peer has
  no rule and is refused. Open: data nodes and notifications (cblink has
  no hook for them), the ietf-netconf-acm module served read-only, and
  the user per request (3.3.3, a wire field).
- 3.3.2 A (done): enforcement for rpcs, data nodes (read as omission) and
  notifications; counters; check: one test per point.
- 3.3.3 A, C (done): the console's user passed per connection to an agent
  that trusts it by certificate role; check: two users, two views.
- 3.4.1 C: one long-lived cblink connection per agent with streams;
  reconnect with backoff; check: an agent restarted.
- 3.4.2 C: jobs, stats, lists and the SD-WAN read taken from
  subscriptions, the one-second polls removed, the JSON off the wire;
  check: the browser test's timings.
- 3.4.3 C: `events` subscribed and relayed to the page; check: an
  event within a second in the page.
- 3.5.1 A, C: `arcana-steer`: candidates, chosen, reason, events;
  written by local failover and by the console; check: a failover
  seen on both.
- 3.5.2 G, A: the control stream: a push stream of its own for steer
  and probe notifications, its own SCTP stream; check: order kept
  under a bulk dump.
- 3.6.1 C (the rest): `arcanactl set <path>` (an `EDIT`) with libxo
  output; the old verbs removed with the interim module; check: the
  arcanactl tests rewritten.
- 3.7.1 A, C: every former operation's test against its module; the
  root suite on real jails; check: `make check` green as root.
- 3.8.1 A, C: the interim module, `share/arcana/wire.awk` and
  arcana.yaml's operations removed once the last is converted;
  versions bumped; UPDATING.md on the flag day; check: a fleet of two
  updated on the lab.

### Y-4

- 4.1.1 to 4.1.3 done (console restconf.c): discovery, the root,
  `yang-library-version`, the api-path parsed against the console's
  tables and sent to the agent as an XPath filter, GET with `content`,
  `depth`, `fields` and `with-defaults`.
- 4.1.4 done (console restconf.c): POST (201, `Location`; 409
  `data-exists`), PUT (201 made, 204 replaced), plain PATCH (204; 404
  where its target is not; of the datastore, its top-level nodes
  merged), DELETE (204; 409 `data-missing`), `insert` and `point`,
  OPTIONS with `Accept-Patch`, all of the candidate.  The agents take a
  top-level node whole: the console reads the candidate's nodes an edit
  goes through, makes the edit in its own instance tree
  (`cbl_dtree_edit()`) and sends them back in one `EDIT`.  Open: PUT of
  the whole datastore (501), HEAD, edits through a mount point.
- 4.1.5 done (console restconf.c): YANG Patch
  (`application/yang-patch+json`), its seven operations, `where` and
  `point`, made as 4.1.4's edits are, in order, and sent as one `EDIT`,
  all or nothing; `yang-patch-status` ok, an edit's errors by its
  `edit-id`, or the agent's refusal as global errors; the `:yang-patch`
  capability.
- 4.1.6 done (console restconf.c): ETag and Last-Modified of running and
  the candidate, on reads and on changes; `If-Match`, `If-None-Match`,
  `If-Modified-Since`, `If-Unmodified-Since` (304, 412), `*` by what is
  there.  The agents keep no change counter: the console keeps one per
  host, counting the changes it forwards (an `EDIT`, commit,
  cancel-commit, discard-changes), a confirmed commit's undo at its
  timeout, and the events that say the configuration changed (`conf`,
  `job`, `undo-failed`) whenever it reads them; its run's number is in
  each tag.  Open: a change the console does not hear of (another
  client's commit) changes no tag; a counter in cblink's datastores
  would be exact.
- 4.1.7 done (console restconf.c): a test per error-tag the console says
  (access-denied, invalid-value, operation-not-supported,
  operation-failed, in-use, data-exists, data-missing,
  missing-attribute, bad-attribute, unknown-element, unknown-namespace,
  bad-element, malformed-message), §7's status of each.  Open: the
  agent's own error-tag, which cblink puts on the wire but has no
  accessor for (the console maps its errno).
- 4.1.8 done (console rcstream.c): `restconf-state/streams`, a host's
  NETCONF stream each, as SSE with the §6.4 envelope; an event's time
  its id, `Last-Event-ID` the agent's replay from it.
- 4.1.9 done (console rcstream.c): `establish-subscription` POSTed under
  a host's entry, its id and URI answered, the URI's GET its stream.
- 4.1.10 C: `application/yang-data+cbor` pass-through; check: the
  PWA's decoder reads it.
- 4.2.1 C: JSON → CBOR by schema (names → SIDs with module
  qualification, numbers, strings, base64, empty, bits, enums,
  identityref, instance-identifier strings, union by canonical form);
  check: RFC 7951's examples both ways.
- 4.2.2 C: CBOR → JSON including origin as `@` annotations; check:
  RFC 7952's example shape.
- 4.3.1 C (the rest): the remainder resolved against the host's cached
  library and SID tables rather than the console's own; check: a GET
  to two hosts of different revisions. `arcana-fleet` and the host
  prefix are done.
- 4.3.2 C: the SID and library cache refreshed on
  `yang-library-update`; check: an agent updated under the console.
- 4.3.3 done (console rcstream.c): the `fleet` stream, every host's on
  one thread and one reply, each record nested in its host's entry.
- 4.4.1 C: `arcana-console` module served from the libucl files
  (settings, tokens, workflows, enrolment tokens, users); check: GET
  and PUT of a setting.
- 4.4.2 C: the WebAuthn ceremonies, logout, `assetlinks.json`, enrol
  and health moved beside `/restconf`; `/api` removed; check: the
  console tests rewritten.
- 4.4.3 (the Android app's repository): the app reimplemented as a
  RESTCONF client: WebAuthn and the token QR code as they are, then
  every read a `GET` on `/restconf/data/...` with `fields` and
  `depth`, every change a `PATCH` or `PUT`, every action a `POST` on
  `/restconf/operations/...`, events and job traces by SSE
  subscriptions, errors from `ietf-restconf:errors`, and the forms it
  shows generated from each host's `ietf-yang-library` the way the
  page's are (4.8.3), so a new module needs no app release;
  `application/yang-data+cbor` where the app prefers CBOR. Briefed
  from this plan when 4.1 lands; check: the app against the lab's
  console.
- 4.5.1 C: `ietf-vpn-common` and `ietf-l3vpn-ntw` stored as the
  service; check: RFC 9182's Appendix A example accepted.
- 4.5.2 C: the Arcana augmentations of L3NM: application flows, the
  policy map, performance criteria, breakout, security policies,
  tunnel virtual connections, probes, steering criteria, routing
  domains; check: the example document expressible.
- 4.5.3 C: the MEF 70.2 importer (document → L3NM + augments) and
  exporter; check: the example document imports and exports to the
  same bytes.
- 4.5.4 C: the planner reading L3NM: profiles and node overrides
  resolved, the allocation ledger (FIBs, addresses, RDs, VNIs, table
  names) persisted; check: the plan of the example equals the MEF
  planner's.
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
  retired or generated; the book's chapters.
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
- 5.4.2 A, C: shelving (the alarms' control in `running`), the
  `purge-alarms` and `compress-alarms` actions; the Paths tab reads
  alarms; check: the browser test.
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
- 5.6.1 A: `ng_netflow` per service FIB with sampling (v9); check:
  records at a collector jail.
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
- 6.6.1 C, A: `l3vpn` in the port's `RT_PROT`; `vpn4`/`vpn6` with
  BIRD's labels and a VXLAN VNI per VPN (made on the host and moved
  into a vnet-jail edge, its VNI and ends set before the move);
  RD/RT operational; check: two VPNs over one session.
- 6.7.1 D: the firewall and IPsec chapters; TODO.

### Y-7

- 7.1.1 A: `arcana-dummynet` NRP objects (scheduler tier templates,
  queue weight, buffer, DSCP class, tunnel set) referenced by
  services; check: the SD-WAN QoS expressed as NRPs.
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

## Order

| Phase | Weeks | Needs | Delivers |
|---|---|---|---|
| Y-0 | — | — | D-5, D-6, D-11, D-12; a registered SID block, later |
| Y-1 | — | — | the Network tab wholly by YANG |
| Y-2 | — | — | datastores, edits, static routes, RA, FIB and jail mounts |
| Y-3 | — | Y-2 | the operations converted, subscriptions' rest, NACM, event-driven console, the CAL |
| Y-4 | 16 | Y-3 | RESTCONF, L3NM/SAP/VN, the PWA on RESTCONF |
| Y-5 | 12 | Y-3 | STAMP, PM, alarms' rest, alternate marking, flow telemetry |
| Y-6 | 12 | Y-3 | ACLs, IPsec by the models, key chains, FlowSpec, D-5(b) |
| Y-7 | 16 | Y-4, Y-5 | NRP, slices, DetNet-f, CATS, ACP, ADVPN, ASAs, intent |
| Y-8 | 6 | Y-4 | benchmarks, conformance, second console |

Y-4, Y-5 and Y-6 are independent and can run in parallel. The
configuration files' round trip (2.3) is where the work would overrun.

## Risks

- libyang's API: pinned to 3.x (upstream at 5.x and 6.x); the port is
  kept at a version cblink-gen builds with.
- rc.conf fidelity: Arcana-managed values kept in `rc.conf.d`
  fragments Arcana owns where rc(8) reads them (`netif`, `routing`,
  per service), a conflict with the user's rc.conf refused with a
  clear message; base rc.conf variables, never an Arcana spelling of
  what the base has.
- On-change cost on big tables: event sources (netlink(4), EVFILT_JAIL)
  rather than diffing; counters periodic only.
- Jail helpers: one long-lived attached helper per running vnet jail,
  started lazily, speaking cblink 2 over a socketpair, which is the
  same mechanism as the fleet mount: one proxy design, twice.
- SID governance: `.sid` files reviewed like ABI files; the
  experimental range is no claim to interoperate with other SID-keyed
  peers until 0.5.1.
- D-5(b) rests on a BIRD built with `l3vpn`, which the port leaves out
  until its maintainer takes the change.
- The ACP depends on strongSwan, a port; a native IKEv2 is out of
  reach; the DTLS channel of the constrained profile is the fallback
  that needs no IKE but a tun(4) tunnel.
- Scope: Y-7 is eight features; each stands alone and can be dropped
  or delayed without touching Y-2 to Y-6.

## Open questions, short

Beyond D-5, D-6, D-11 and D-12: whether the SD-WAN edge may host customer CEs as jails (slice
SDP placement 1, which blurs the trust boundary); which RFC 8578 bands
to market; whether `match-on-payload` is wired through ng_bpf or
Suricata or neither; whether flow records leave the edge or only
summaries; whether the agent's unprivileged autonomy (D-12) is wanted
at all.

## The RFCs

The frameworks: 9899, 9731, 9408, 9375, 9348, 9182, 9181, 9061, 8969,
8309, 10053, 9938, 9732, 9543, 9342, 9315, 9232, 9222, 8994, 8972,
8955, 8763, 8655, 8578, 8568, 8456, 8455, 7426, 7018. Those they rest
on: 8519 and 6991 (ACLs and types), 8762 (STAMP), 9341 (alternate
marking), 8956 (FlowSpec IPv6), 8345, 8346 and 8795 (topologies), 8453
(ACTN), 8299 (L3SM, as far as 9182 refers to it), 9347 (AGGFRAG), 8990
and 8995 (GRASP and BRSKI, as far as 8994 depends on them), 7950,
7951, 7952, 9254, 9595, 8040, 8072, 8342, 8525, 8528, 8341, 8347,
8639, 8641, 8791, 8343, 8344, 8349, 8529, 8530, 8632, 9016, 9633
(DetNet YANG), 8177 (key chains), 6241 (NETCONF, for the edit and
commit semantics), 6243 (with-defaults). The plan relies on RFCs
only.
