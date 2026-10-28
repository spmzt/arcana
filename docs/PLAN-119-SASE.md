# Plan: Mplify 119 and SASE, what remains

The SD-WAN service is modelled on MEF 70.2, Mplify 119 (the Universal
SD-WAN Edge, USWE) and SASE (Mplify 117.1, MEF 138, MEF 118.1). The
book's conformance pages (sdwan/mplify.md, sdwan/conformance.md) list
each requirement as done, partly done or not done; this is what is
left to build or to decide.

Each task is one commit, reviewed before it goes in, with the agent's
or the console's version bumped, its tests in the suite, and the book
(arcana-docs) and openapi.yaml where it shows. A: the agent, C: the
console, U: the page, T: tests, L: the lab on the VM.

What the lab cannot give: an SD-WAN Vendor Edge of another vendor to
interoperate with. Everything is verified between two Arcana edges in
USWE mode, the format checked against the RFCs with tcpdump.

## Mplify 119

### 119-4 MPLS in GRE: not supported

Inside the IPsec tunnel, Mplify 119 wants every packet as GRE with
protocol type 0x8847 carrying one MPLS label that names the routing
domain (§10, R61–R64, R66, R141–R144). FreeBSD's gre(4) carries IP and
IPv6 only and the kernel has no MPLS: it would take a netgraph node of
our own in the kernel, which Arcana does not take on without the
user's explicit yes. The routing domains are told apart by their own
tunnels instead, and a document's labels stay reserved. A draft node
(ng_mplsgre) exists outside this repository, should that change.

### 119-5 The control plane as RFC 4364: the VPN routes

The reflector and the CPI work with plain IPv4 and IPv6 routes. Left:
VPNv4 and VPNv6 routes with the domains' route distinguishers, route
targets and labels (R14–R20, R29–R34, R121, R123). BIRD's l3vpn
protocol would carry them, and the FreeBSD port of BIRD 3 (net/bird3)
does not build it (no L3VPN option; "protocol l3vpn" is a syntax
error). A port with the protocol built is the way; then the reflector
gets `vpn4` and `vpn6` channels and each edge's instance the domains'
RDs, RTs and labels.

### 119-6 The conformance list's "not done"

Each its own task when taken up:

- R96's MEF 10.4 Ethernet UNI attributes and R97's auto-negotiation
  (the interfaces are what the host has).
- One address per end point where the specification allows both
  families.
- DSCP and PCP marking of the tunnels' outer packets (R114, R138).
- A date and time for a key's activation (R112, R136): the rotation
  runs in step on both ends instead.
- More than one subscriber routing domain per service.
- Stateful threshold crossing alerts (the probes' are stateless, O1).
- RFC 7317's hardware and virtual machine management (§12.7).
- A NETCONF, YANG or REST binding of the management plane (§7.5):
  docs/PLAN-SDN-YANG.md.

## SASE

### SASE-6 MEF 138's model, the rest

The security policies are MEF 138's Security Function Policies. Done
(console 0.327 and after, agent 0.229 and after):

- SEN and SAN (R24–R36): `www/arcana-console/sen.c`. A SEN for each
  deny the edges' rules logged (the record's `sdwan-security` events)
  and each Suricata alert (`sdwan-ids`), with Table 3's items: issuer,
  UTC timestamp, a UUID, the function and its policy, IOC or OTHER,
  the event, source, details, action, and the UNI where known (D2);
  domains and URLs neutralised with `[.]` (R28, D3). A SAN for each
  function policy whose values a kept document changes (R31), with
  Table 4's: who, from where, the values that changed alone, a Block's
  and Quarantine's names neutralised (R34). Both kept in the data
  directory, readable by the console alone (R26, R32), read by
  `GET /api/sdwan/sen` and `/san` (`.csv` too), shown on the Security
  tab, and sent to their recipients (R30, R36): `mail_sen`, `mail_san`,
  `telegram_sen`, `telegram_san` in Settings, Notifications. SENs are
  made from the events the console reads for its alerts: when no
  recipient of any kind is set, none are read and none are made.
- MD+R: the lists are hashes (MD5, SHA-1, SHA-256, `:size` if known),
  written on each edge as ClamAV's hash signatures in its database
  directory (`arcana-sdwan.hdb`, `.hsb`; an Allow's as its false
  positives, `.fp`, `.sfp`) before the services' c-icap starts, which
  reads the directory whole. One ClamAV an edge: a hash on an Allow
  and on a Block or Quarantine of services at one edge is refused.
- DNF: a `*` for a whole label inside a name (`host.*.tld`, R71) on a
  Block or Quarantine; unbound takes none, so such names are ended
  by the zone's Squid at the TLS name and refused by the request's
  host (the zone's HTTP and TLS are forwarded to it as a URLF's are).
  An Allow with one is refused: unbound would still answer it, and
  Squid cannot let through what unbound blocks. `*.name` stays
  unbound's.
- PDNS: CNAME and NS entries (R104) by a response policy zone of each
  zone's (unbound's RPZ, tagged with the zone's prefixes): a CNAME's
  value the name an alias leads to (a QNAME trigger, applied to each
  name of an answer's chain), an NS's a name server's name
  (`rpz-nsdname`) or address (`rpz-nsip`). SOA, MX, SRV and PTR are not
  taken: unbound's RPZ has no trigger on an MX's exchange, an SRV's
  target, a SOA's or a PTR's value. DNS over TLS southbound (D22, port
  853, a certificate of the instance's own the Security tab offers)
  and northbound (D21, `forward-tls-upstream` to the `upstream`
  servers, each `address[@port]#name`). DNS over HTTPS is not taken
  (D19): the base system's unbound is built without it.
- DPF: `message-type` `query` and `response` (Table 6) by the port, a
  query to 53, a response from it; `any` is both. An update or
  another is inside the message, which ipfw does not read.

Left, and why:

- MBSF for IPsec (R38, R45, R50, R63, R65): not done. A middlebox for
  IPsec would impersonate the responder to the initiator with a
  certificate of the edge's CA and initiate to the real responder,
  as Squid does for TLS; neither strongSwan nor the base system is
  such a proxy, and the IKEv2 and IPsec parameters its lists would
  name (Table 9's criteria) are inside IKE_SA_INIT, which ipfw does
  not read. Blocking or allowing IPsec as a protocol is IPPF's
  (`protv4` esp, ah, udp 500 and 4500). TLS alone meets R45.
- DLP: none; FreeBSD has no engine for it, nor do the packages Arcana
  uses (c-icap's modules scan for malware alone).
- The book's conformance rows (arcana-docs, sdwan/conformance.md and
  sdwan/security.md) are to say the above.

To decide (the user's): which of the conformance list's "no" rows come
next: session states, an external IdP with OAuth 2.0, Context
Policies, event-based Continuous Monitoring.
