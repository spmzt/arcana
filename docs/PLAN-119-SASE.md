# Plan: Mplify 119 (the Universal SD-WAN Edge) and SASE

Written 2026-10-11, after MEF 70.2 phases 1 to 6. Mplify 119 is read
from the document; SASE is planned from MEF 88, MEF 117 and MEF 118 as
I know them, not from a copy at hand: put the PDFs in ~ and the SASE
part gets checked against them before any of it is built.

## Where we stand

What Arcana has after phase 6 is a complete MEF 70.2 edge and manager:
a FIB per service on each edge; tunnels of gre, gif, geneve or wg,
under IPsec IKEv2 where asked; ICMP probes with delay, variation and
loss; ipfw classification and steering with local failover; breakout,
NAT, dummynet bandwidth, egress blocks; static, BGP and OSPF at the
UNIs by a BIRD instance per service, iBGP between the edges by the
tunnels. The console is the manager and, through those BIRD
instances, the control plane.

Mplify 119 keeps all of that (its §7.6 says a USWE complies with MEF
70.1) and fixes how an edge of one vendor talks to a service of
another: the routing domains, the tunnel format, the keys, the fault
and performance reporting, and the configuration steps a manager
sends. Most of its requirements fall on what we already have; four
things are new in kind.

## Mplify 119: what is new in kind

1. **Routing domains** (§7.3, R15–R26). Four of them, each a VRF with
   a route distinguisher, route targets and an MPLS label: the UCS
   domain (the underlay, our FIB 0), the SD-WAN Service domain (the
   control plane and the tunnels' own addresses), the Subscriber
   domain (our per-service FIB), and an Internet Breakout domain of
   its own (R20–R26: breakout routes kept apart from the subscriber's
   and the underlay's). Today our breakout is a default route in the
   subscriber FIB; 119 wants it in a FIB of its own with the UNIs'
   routes imported into it (R25, R26).

2. **The tunnel format** (§10, §11.2, R41–R66). Every UTVC (data) and
   CTVC (control) is IPsec in tunnel mode, ESP with ESN and UDP
   encapsulation, AES-256 and SHA-1 at least (AES-GCM allowed), with
   **manually configured SAs** whose keys come from key pairs each
   edge generates (NIST 800-56A: a Diffie-Hellman pair, the public
   half sent to the manager, which passes it to the far edges) and
   rotates at the half-life of a key lifetime the manager sets, with
   an activation time it also sets, so NTP is a step of its own
   (§12.2.2). Inside the IPsec tunnel, Mplify 119 wants every packet
   as GRE with protocol type 0x8847 carrying one MPLS label that names
   the routing domain (R61–R64, R66). FreeBSD's gre(4) carries IP and
   IPv6 only and the kernel has no MPLS; that would take a kernel
   piece of our own, which Arcana does not carry. **Not supported for
   now**: the routing domains keep their own tunnels, and the labels
   a document reserves are kept for the day it is (see 119-4 below).

3. **Faults by BFD** (§10.5, R58–R60, R159): every tunnel is watched
   by single-hop BFD (MEF 66 §7.2.1.2), 100 to 300 ms, multiplier 3,
   the DSCP of the tunnel, and a fault is declared when BFD says so.
   Our ICMP probes stay for the performance metrics (§11.4 keeps
   ping); BFD takes over the up/down decision.

4. **The control plane as RFC 4364** (§8.3, R9–R14, R120–R128): the
   edge's control plane interface (CPI) runs iBGP to the SD-WAN Vendor
   Control Plane over a CTVC, secured by TCP MD5 (R12), four-octet AS
   numbers, communities and extended communities, VPNv4 and VPNv6
   routes with the domains' route distinguishers, route targets and
   labels. Our full mesh of per-service iBGP sessions becomes sessions
   to a route reflector: BIRD on the console's host or on an edge the
   document names.

The rest of 119 is the management plane's list of what a manager
sends (§12.2, steps 1–12): VRFs, NTP, UCS UNI interfaces (addresses
static, DHCP or SLAAC, VRF, routing protocol, auto-negotiation), the
CTVC (keys, algorithms, lifetime, DSCP and PCP, interface), the CPI,
the UTVCs, the SD-WAN UNIs (static, BGP, OSPF: done), application
flows, zones, the policy map, BFD, faults (kept 24 hours, D5) and
performance monitoring with threshold crossing alerts (stateless and
stateful, with a damping factor, O1). Our document already carries
most of it in MEF 70.2's terms; the gaps are listed per phase.

## Mplify 119: the phases

Each phase is a commit, reviewed first, with agent and console
versions, docs, openapi, tests, and a lab run on the VM where it says
so.

- **119-1, faults and the control session.** BFD on every tunnel in
  the service's BIRD instance (`protocol bfd`, the interval,
  multiplier and DSCP from the document, R159), the agent reading
  `show bfd sessions` and raising the `sdwan-tunnel` event from it;
  the steering's "down" taken from BFD when it is there, from the
  probes when not. TCP MD5 on the edges' iBGP (`password` in the
  template, R12) and four-octet AS numbers checked (R13). NTP as a
  step (§12.2.2): `ntpd` on the edge with the server the document
  names, through the services plumbing we have. The fault catalogue
  of §11.3.2 as event types with the attributes of Table 5, kept 24
  hours by the agent (D5) and listed on Paths. Threshold crossing
  alerts (§11.4): per policy's performance criteria, a TCA event when
  a metric crosses, stateless with damping 1 (O1) first. No new data
  plane. Lab: the two-jail lab with BFD between them.

- **119-2, the routing domains.** The document gets, per service,
  `domains`: the service domain's FIB and prefix (the tunnels' and
  CPI's addresses move there from the reserved prefixes), the
  breakout domain's FIB, and each domain's route distinguisher,
  route targets and label (R15–R20, checked unique). The apply makes
  the FIBs, puts the tunnel interfaces' addresses in the service
  domain, and moves breakout to its FIB: the UNIs' routes imported
  into it (R25, R26), the default route there, the flows' breakout
  rules sending to it with `setfib` instead of a default route in the
  subscriber FIB. UCS interfaces with DHCP or SLAAC addressing
  (§12.2.3.2, §12.2.3.3) and a VRF of their own where the UCS routes
  (§12.2.3.4, §12.2.3.5: BIRD on the UCS side too). Lab: breakout
  from the breakout FIB on the two jails.

- **119-3, manually keyed IPsec.** Tunnel mode on an ipsec(4)
  interface with a reqid, the SAs set by the agent with setkey(8)
  (ESP, ESN, UDP encapsulation, AES-256-CBC with HMAC-SHA1 at least,
  AES-GCM when both ends have it, R41–R50, R55). Keys: each edge
  generates an X25519 or P-256 pair per tunnel end (R51–R53, the
  private half never leaves the agent), tells the console the public
  half, the console passes the far one (as it passes wg keys today,
  R111, R135), and both ends derive the SA keys from the agreement
  with a KDF (NIST SP 800-56A, R54). A key lifetime and an activation
  time per tunnel in the document (R112, R136); the agent makes a new
  pair at the half-life (R110, R134), the console schedules the
  switch at the time it sets, both ends installing the new SA beside
  the old and switching at the second (so NTP from 119-1 matters).
  The UTVC kind `uswe` appears, encrypted this way; the IKEv2 tunnels
  we have stay for MEF 70.2 services. Lab: two jails, SAs by setkey,
  a rekey at the half-life without loss.

- **119-4, MPLS in GRE: not supported.** The labels on one tunnel
  would need a netgraph node of our own in the kernel (a GRE of type
  0x8847 carrying one label, the label naming the domain), which is
  kernel work Arcana does not take on. Decided 2026-10-11. The domains
  are told apart by their own tunnels instead, and a document's
  labels stay reserved. A node written that day lives outside this
  repository, in ~/code/ng_mplsgre, should the decision change.

- **119-5, the control plane as RFC 4364.** The CPI: a CTVC per edge
  to the control plane's host (a UTVC in kind, R5, R6, encrypted the
  same way) or a virtual interface (R2, §12.2.4.2). The control plane
  itself: BIRD on the console's host or on the edge the document
  names, as a route reflector with `vpn4` and `vpn6` channels, the
  domains' RDs and RTs, the edges' BIRD instances peering with it by
  the CTVC with TCP MD5 (R12), four-octet AS, communities and
  extended communities (R9, R10), MPLS labels per domain in the
  VPN routes (R18–R20, R29–R34). The full mesh of 70.2 phase 6 is
  kept for services without a control plane host. Lab: three jails,
  one the reflector.

- **119-6, the management plane's steps and conformance.** The apply
  ordered and named as §12.1's activity flow (steps 1–12), the
  document's attributes mapped one by one to R89–R160 with a table
  in docs/USING.md saying which requirement each is, and a
  conformance list with what is not done (multiple subscriber
  domains, the MEF 10.4 Ethernet UNI attributes of R96, stateful TCA
  if not done). The Universal Management Plane's transport (§7.5,
  §12) is ours: the console and cblink; a NETCONF/YANG or REST
  binding is listed as later, not planned.

What 119 needs that the lab cannot give: an SD-WAN Vendor Edge of
another vendor to interoperate with. Each phase is verified between
two Arcana edges in USWE mode; the format (GRE 0x8847, the label, the
SA parameters) is checked against the RFCs with tcpdump.

## SASE: what it is, in MEF's terms

SASE (MEF 117) is an SD-WAN service with security applied to the
application flows and with zero-trust access: MEF 88 defines the
security policies and their criteria (what is blocked or inspected:
IP addresses, DNS, URLs, malware, intrusion, with lists and feeds);
MEF 118 the zero-trust framework (actors, targets, identity, a policy
decision per session, continuous verification); MEF 117 ties them to
the service: SASE service end points (a UNI, a remote user's device, a
cloud), the security functions at them, and the identities and
sessions behind the policies. MEF 70.2 already has the hook: the
AF-SECURITY-INGRESS and AF-SECURITY-EGRESS policy criteria name a
MEF 88 security policy, and our document already carries
`security_policies` by name. So SASE is MEF 88 policies filled in,
then access by identity, then the functions that need a proxy.

FreeBSD gives: ipfw tables for address lists (fed by the console from
feeds); Unbound in base for DNS filtering (RPZ or local zones, an
instance per service in its FIB); dummynet for rate limits; WireGuard
for remote users; from packages, Squid with peek-and-splice for URL
and domain filtering of TLS by SNI without breaking it, c-icap with
ClamAV for malware on what is cleartext, Suricata for intrusion
detection and prevention. The agent's package, service and
configuration plumbing already handles installing and running these.

## SASE: the phases

- **SASE-1, MEF 88 security policies in the document.** A security
  policy is a name and criteria: `ip-block` (allow and deny lists of
  prefixes, and named lists from feeds), `dns-domain-filter` (domains
  denied, by lists), `dns-protocol-filter` (DNS only to the provider's
  resolver), `rate-limit` (a cap, by dummynet), `log` (what is denied
  is logged). Applied where AF-SECURITY-INGRESS or -EGRESS names
  them: the rules compiler adds, in the flow's block, `deny` rules by
  the policy's tables before the forward, `log` where asked; DNS: an
  Unbound instance per service on each edge in the service's FIB,
  the UNI's provider address its address, the denied domains as
  local zones, and `fwd` of port 53 from the UNI to it where the
  protocol filter says so. The page gets a Security tab under SD-WAN
  with the policies, their lists and the counts of what they denied.
  Lab: two jails, a denied prefix and a denied domain.

- **SASE-2, feeds and the record.** Lists fetched by the console on a
  schedule from URLs in the settings (and pasted lists), versioned,
  pushed as tables; what is denied logged by ipfw into the agent's
  events with the flow, the policy and the list, kept and shown with
  the faults; an export of the record. The feeds' fetch goes through
  the console's host only.

- **SASE-3, access by identity.** A SASE service end point of kind
  `remote`: WireGuard on an edge the document names, each identity a
  peer with an address from a reserved prefix, each identity in a
  zone, so the policies and the security policies apply to a person
  as they do to a UNI's hosts. Identities are the console's users
  (sign-in keys we have) or names with a key each; the console issues
  a user's WireGuard configuration once, as the API tokens are shown
  once. A session is the peer's handshake; its last handshake and
  traffic shown; a revoked identity's peer removed within the tick.
  This is MEF 118's actor and target with a policy decision per
  session; continuous verification is the handshake and a
  re-authorisation interval, device posture is out of scope.

- **SASE-4, the functions that need a proxy.** URL and domain
  filtering of HTTP and of TLS by SNI (Squid, peek and splice, no
  interception of the content), malware scanning of cleartext HTTP
  (c-icap with ClamAV), intrusion detection and prevention (Suricata
  on the UNI, IPS by ipfw divert or netmap), each a security policy
  criterion (`url-filter`, `malware`, `ids` with its rule sets),
  installed from packages by the apply where a policy needs them,
  their alerts into the events. Transparent by ipfw `fwd` of ports
  80 and 443 from the UNI to the proxy in the service's FIB.

- **SASE-5, zero-trust framework and conformance.** MEF 118's terms
  on the page and in the document: actors, targets, the policy per
  pair, sessions, the audit trail; MEF 117's service attributes
  mapped one by one once the document is at hand; a conformance list.

## Order and effort

119-1 and SASE-1 are independent and each about the size of a 70.2
phase; they come first, in that order, unless you say otherwise.
119-2 and 119-3 follow; 119-4 is not done (no kernel work);
119-5 depends on 119-2 and 119-3. SASE-2 and SASE-3 follow SASE-1;
SASE-4 brings packages and a proxy and is reviewed on its own; SASE-5
last. Nothing here changes a MEF 70.2 service that does not ask for
it: USWE is a tunnel kind and a control plane a service opts into,
security policies are named by the policies that want them.

## The tasks

Each task is one commit, reviewed before it goes in, with the agent's
or the console's version bumped, its tests in the suite, and
docs/USING.md and openapi.yaml where it shows. A: the agent, C: the
console, U: the page, T: tests, L: the lab on the VM. "Done when" is
what the review looks at. Tasks of one phase run in order; phases as
said under Order and effort.

### Left over from MEF 70.2

- **0.1 SLAAC at a UNI** (§11.5, R137). C: `uni.ipv6.mode: slaac`
  takes the first subnet's prefix; the apply writes an rtadvd entry for
  the UNI interface and enables rtadvd (`rtadvd_interfaces`). A: an
  `rtadvd` job (interface, prefix, remove) through the rc.conf and
  service plumbing we have. T: agent job test, apply test. Done when
  a host behind the lab jail's UNI gets an address of the prefix.
- **0.2 DHCP at a UNI** (§11.4, R130; §11.5, R134, R136). FreeBSD's
  base has no DHCP server: `dnsmasq` from packages, one instance per
  service in its FIB (the BIRD instances' pattern), its pool a
  reserved prefix inside the UNI's prefix, the provider address the
  router. C: `uni.ipv4.mode: dhcp` with `pool`; validator (R130). A:
  `sdwan-dhcp` op keeping the instances. T, L. Done when a lab host
  leases an address and reaches the far UNI.

### 119-1 Faults and the control session

- **1.1 BFD in the service's BIRD instance.** C: `swvc.bfd` (interval
  100–300 ms, multiplier 3, dscp; validator, R159); the BIRD
  configuration gets `protocol bfd` on the tunnel interfaces with
  those values, and the edge iBGP sessions `bfd on`. T: apply test
  shows the block. Done when the stand-in run shows it and a lab run
  has sessions up.
- **1.2 BFD read and events.** A: each instance's `show bfd sessions`
  parsed into the `sdwan` read (`bfd: [{interface, neighbor, state,
  since}]`) and polled every second; a change raises `sdwan-tunnel`
  with `by: bfd` (R60). U: Paths shows BFD beside the probe's state.
  T: agent test with the stand-in's output changing. Done when
  cutting the lab epair raises the event within a second.
- **1.3 Steering by BFD.** A: the steer's "down" is BFD's when the
  tunnel has a session, the probe's when not. T: agent steer test
  with a BFD-down candidate. Done when the lab's failover follows
  the cut without waiting for the probe.
- **1.4 iBGP with TCP MD5, four-octet AS.** C: `swvc.md5` written as
  `password` into the edge template (R12); AS up to 4294967295
  already checked (R13); the validator refuses a service without
  `md5` when `control_plane` is set (119-5) and warns otherwise. T:
  apply test. Done when two lab instances peer with the password.
- **1.5 NTP** (§12.2.2, R93). C: `edges[].ntp: [servers]`, a step
  before the tunnels. A: an `ntp` job (servers, remove) writing
  ntp.conf's servers between markers and enabling ntpd. T: job test.
  Done when the lab jail syncs.
- **1.6 The fault catalogue** (§11.3.2, Table 5; D5). A: event types
  for UNI down, UCS link down, tunnel down (BFD, probe), BGP peer
  down, instance not running, key rotation failed, each with time,
  type, severity, object and description; kept 24 hours in the
  events store regardless of its size cap. U: Faults lists them with
  a type filter. T: agent events test. Done when each type is raised
  by its stand-in and read back after the store rolls.
- **1.7 Threshold crossing alerts** (§11.4, O1). A: per probe target
  the policy thresholds (the console sends them with the probes); a
  metric crossing a threshold over an eval interval raises
  `sdwan-tca` (set, cleared), stateless with damping 1; a damping
  factor over 1 counts intervals. C: thresholds taken from the
  policies' performance criteria and sent; `swvc.tca.damping`. U:
  Faults shows them. T: agent probe test with canned samples. Done
  when a dummynet delay on the lab raises and clears one.
- **1.8 Phase close.** L: the two-jail lab run through 1.1–1.7 and
  written into TODO's verified list; docs and openapi.

### 119-2 The routing domains

- **2.1 Domains in the document.** C: `swvc.domains` (service:
  fib, prefix, rd, rt, label; breakout: fib, rd, rt, label;
  subscriber: rd, rt, label), checked unique across services
  (R15–R20), labels 16–1048575, FIBs distinct from the subscriber's.
  U: Services tab shows them. T: validator cases. Done when the
  example document carries them.
- **2.2 The breakout domain.** C: the apply makes the breakout FIB,
  copies the UNIs' routes into it (R25, R26), puts the default route
  and the NAT there, and the flows' breakout rules `setfib` into it
  instead of a default route in the subscriber FIB; remote breakout
  routes by the tunnel in that FIB. A: nothing new. T: apply test
  rules. L: breakout from the breakout FIB on the two jails. Done
  when the subscriber FIB holds no default route.
- **2.3 The service domain's addresses.** C: tunnel inner addresses
  and (later) CPI addresses allocated from the service domain's
  prefix, kept in the state's alloc; the reserved prefixes stay for
  the UNIs' DHCP pools. T: plan test. Done when the plan shows them.
- **2.4 UCS interfaces addressed and routed** (§12.2.3.2–5). C:
  `ucs_end_points[].addressing: static|dhcp|slaac`, `vrf` (a FIB)
  and `routing` (bgp or ospf with the same shape as a UNI's). A: DHCP
  client on an interface (`dhclient` through rc.conf, `ifconfig_X=
  DHCP`), SLAAC (`inet6 accept_rtadv`); a UCS BIRD instance when
  routed. T: job tests, apply test. Done when the lab jail's UCS gets
  its address by DHCP from the other jail (0.2's dnsmasq).
- **2.5 Phase close.** L, docs, TODO.

### 119-3 Manually keyed IPsec

- **3.1 Manual SAs by the agent.** A: `ipsec-manual` job: `set`
  (reqid, SPIs in and out, algorithms, keys, UDP encapsulation, ESN,
  the ipsec(4) interface) and `clear`, written with setkey(8) from a
  file the agent makes and removes; the keys never in a trace
  (exec_set_secret). T: agent test with a stand-in setkey. L: a root
  test on the VM with real SAs between two jails. Done when ping
  crosses the lab tunnel with manual SAs (R41–R50, R55).
- **3.2 Key pairs and the derivation.** A: an X25519 pair per tunnel
  end, made with OpenSSL, the private half 0600 beside the agent's
  kept files (R51–R53); the public half in the `sdwan` read; the SA
  keys and SPIs derived with HKDF-SHA256 from the agreement and the
  two public halves (NIST SP 800-56A, R54). T: agent test deriving
  the same keys on both sides. Done when two agents derive equal SAs
  from each other's public halves.
- **3.3 The `uswe` tunnel kind.** C: a UCS tunnel of kind `uswe`
  (encrypted always, tunnel mode, ipsec(4) with a reqid, the far
  public key passed as `${uswe:SID:IF}` as wg's is); `lifetime` and
  `algorithms` per UCS; the apply orders key, SAs, interface,
  addresses. T: apply test. Done when the lab tunnel of kind uswe
  carries ping.
- **3.4 Rekeying.** A: a new pair at the half-life, the old kept; the
  new SAs installed beside the old at the activation time, the old
  cleared after (R110, R112, R134, R136). C: the manager schedules
  the activation time (R112), passes the new public halves, and sets
  the switch for both ends at once; a failed rotation is a fault
  (1.6). T: agent test with a short lifetime. L: a rekey on the lab
  while ping runs, no loss. Done when the lab shows none.
- **3.5 Phase close.** tcpdump on the lab: ESP in UDP, ESN; docs,
  TODO.

### 119-4 MPLS in GRE

Not supported: see the summary above. No tasks.

### 119-5 The control plane as RFC 4364

- **5.1 The control plane host.** C: `control_plane: {host, as, md5,
  rd, rt}` per service; the apply runs a BIRD instance on that host
  (an edge or the console's host) as a route reflector with vpn4 and
  vpn6 channels, the domains' RDs, RTs and labels (R14–R20). T: apply
  test with the reflector on a. Done when the stand-in run shows it.
- **5.2 The CPI.** C: a CTVC from each edge to the host (a `uswe`
  tunnel in the service domain, R5, R6) or a virtual interface
  (R2, §12.2.4.2); each edge's instance peers with the reflector by
  it, TCP MD5, four-octet AS, communities and extended communities
  (R9–R13), VPN routes with the domains' labels (R29–R34); the full
  mesh is written only without a control plane host. T: apply test.
  Done when the lab's three jails exchange VPN routes by the
  reflector.
- **5.3 Phase close.** L, docs, TODO, and the conformance notes on
  what RFC 4364 needs that BIRD does not do on FreeBSD.

### 119-6 The management plane's steps

- **6.1 The steps.** C: the apply's phases named and ordered as
  §12.1's steps 1–12, the Edges tab showing them by step. Done when
  the page reads as the document's activity flow.
- **6.2 The mapping and the list.** docs/USING.md: a table from each
  document attribute to R89–R160; a conformance list with what is
  not done (multiple subscriber domains, R96's Ethernet UNI
  attributes, stateful TCA, a NETCONF or REST binding). Done when
  every R of §12 is in one of the two.

### SASE-1 MEF 88 security policies

- **S1.1 The policies in the document.** C: `security_policies:
  [{name, criteria}]` with `ip-block` (allow, deny, lists by name),
  `dns-domain-filter` (deny, lists), `dns-protocol-filter`,
  `rate-limit` (bits per second), `log`; validator. U: a Security tab
  under SD-WAN listing them. T: validator cases. Done when the
  example carries one.
- **S1.2 Addresses and rates in the rules.** C: where a flow's policy
  names a security policy by AF-SECURITY-INGRESS or -EGRESS, the
  rules compiler adds, before the forward, `deny` by the policy's
  tables (allow first, then deny), `log` where asked, and a dummynet
  pipe for its rate limit. T: apply test rules. Done when the lab
  drops a denied prefix.
- **S1.3 DNS filtering.** A: `sdwan-dns` op keeping an Unbound
  instance per service in its FIB (the BIRD instances' pattern), its
  configuration from the console: listen on the UNI's provider
  address, denied domains as local zones, forwarders. C: the apply
  writes it where a policy filters DNS; `fwd` of port 53 from the UNI
  to it where the protocol filter says so. T: agent test with a
  stand-in unbound, apply test. Done when a denied domain fails to
  resolve from the lab host.
- **S1.4 Counts.** A: the rules' counters read (`ipfw -S show` of
  the set) into the `sdwan` read per rule number. C: counts per
  security policy and list. U: the Security tab shows them. T.
  Done when the tab counts the lab's denied packets.
- **S1.5 Phase close.** L, docs, TODO.

### SASE-2 Feeds and the record

- **S2.1 Feeds.** C: settings hold feed URLs and an interval; fetched
  on the console's host only, versioned in the store, named lists
  the policies use; a failed fetch keeps the last. U: Settings tab
  for feeds with each one's version and age. T: console test with a
  local feed. Done when a list from a feed reaches an edge's table.
- **S2.2 Large tables.** A: the rules' tables filled in chunks with
  atomic adds and the limits raised; a table swap on a list change
  without a rules reload. T. Done when a 100k-entry list applies in
  seconds on the VM.
- **S2.3 The record.** A: ipfw's log to the routing socket (logdst rtsock, RTM_IPFWLOG) read into
  `sdwan-security` events with the rule number mapped to flow,
  policy and list; kept 24 hours. C: collected per service. U:
  Security tab shows the record with filters, and exports it as CSV.
  T. Done when a lab deny appears in the record within a second.

### SASE-3 Access by identity

- **S3.1 Remote end points.** C: an end point of kind `remote` (edge,
  interface, prefix, listen port) with `identities: [{name, zone,
  public_key}]`; validator. T. Done when the example carries one.
- **S3.2 The apply.** C: a wg interface in the service FIB, a peer per
  identity with an address from the prefix, the zone table entries
  per identity; policies apply as to a UNI's hosts. T: apply test.
  L: a lab client as an identity reaching the far UNI. Done when it
  does.
- **S3.3 Issuing and revoking.** C: an identity made from a console
  user or a name, its key pair made on the console, the private half
  shown once in a WireGuard configuration and not kept, revocation
  removing the peer within the tick; a re-authorisation interval
  after which a peer is removed until issued again. U: Identities
  tab. T. Done when a revoked lab client loses the tunnel.
- **S3.4 Sessions.** C: the wg read's last handshake and bytes per
  peer, read from each edge with the identities (the agent's
  wireguard read has them already). U: Identities shows sessions. T.
  Done when the tab shows the lab client's handshake.

### SASE-4 The functions that need a proxy

- **S4.1 URL and domain filtering.** A: Squid from packages, an
  instance per service in its FIB with peek-and-splice on 443 and
  plain filtering on 80, lists from the policy; `sdwan-proxy` op. C:
  `url-filter` criterion, `fwd` of 80 and 443 to it. T: agent test
  with a stand-in, apply test. L. Done when a denied domain is
  refused by SNI on the lab.
- **S4.2 Malware.** A: c-icap and ClamAV from packages, Squid's
  ICAP service for cleartext HTTP. C: `malware` criterion. T, L with
  the EICAR file. Done when it is caught.
- **S4.3 Intrusion detection and prevention.** A: Suricata from
  packages on the UNI interface, alerts (eve.json) into events;
  prevention by ipfw divert in a second step. C: `ids: {rules,
  mode}` criterion. T, L. Done when a test rule alerts on the lab.
- **S4.4 Phase close.** L, docs, TODO.

### SASE-5 Zero trust and conformance

- **S5.1 The framework's terms.** C and U: actors (identities and
  UNIs' zones), targets (zones, the Internet), the policy per pair as
  the policy map already is, sessions (S3.4), an audit trail of
  issuances, revocations and denies. Done when the Security tab reads
  in MEF 118's terms.
- **S5.2 Mapping and the list.** With MEF 117 and MEF 88 at hand: each
  attribute mapped, a conformance list. Done when every attribute is
  in one of the two.
