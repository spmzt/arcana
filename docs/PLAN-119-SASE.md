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

The security policies are MEF 138's Security Function Policies. Left:

- SEN and SAN with their IDs, neutralised domains and recipients
  (R24–R36).
- MD+R: lists of hashes given to ClamAV.
- DNF: wildcards inside a name (host.*.tld, R71).
- PDNS: the other record types (SOA, NS, CNAME, MX, SRV, PTR; R104),
  and DNS over TLS or HTTPS (D19–D22).
- DPF: message types beyond `any`.
- MBSF for IPsec (TLS only today, R45).
- DLP: none; FreeBSD has no engine for it.

To decide (the user's): which of the conformance list's "no" rows come
next: session states, an external IdP with OAuth 2.0, Context
Policies, event-based Continuous Monitoring.
