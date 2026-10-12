# Using the console

The console is described in the book,
https://spmzt.github.io/arcana-docs/, a chapter for each part of
it, with pictures:

| Part | Chapter |
|---|---|
| The tree, the top bar, the activity bar and the queue, tables, phones | [The panel](https://spmzt.github.io/arcana-docs/sections/panel.html) |
| A host's summary, how it is reached, its rollback timer, jails, services | [A host](https://spmzt.github.io/arcana-docs/sections/host.html) |
| Routes, nexthops, interfaces, netgraph, bridges, geneve, a jail's own network, safe mode | [Network](https://spmzt.github.io/arcana-docs/sections/network.html) |
| ipfw, the kept rules, following a packet, tables, NAT and pipes | [Firewall](https://spmzt.github.io/arcana-docs/sections/firewall.html) |
| Packages and the host's jobs | [Packages and jobs](https://spmzt.github.io/arcana-docs/sections/packages-jobs.html) |
| Pools, datasets, snapshots, disks, mounts, health | [Storage](https://spmzt.github.io/arcana-docs/sections/storage.html) |
| Kernel modules, sysctl, processes | [Kernel, sysctl and processes](https://spmzt.github.io/arcana-docs/sections/kernel.html) |
| The log, dmesg and events | [Log and events](https://spmzt.github.io/arcana-docs/sections/log.html) |
| WireGuard, IPsec, BIRD | [The plugins](https://spmzt.github.io/arcana-docs/sections/plugins.html) |
| The fleet's map, route lookup, traceroute | [The network map](https://spmzt.github.io/arcana-docs/sections/map.html) |
| Usage over time, sampling, limits | [Utilization](https://spmzt.github.io/arcana-docs/sections/utilization.html) |
| Workflows, their steps, triggers and runs | [Workflows](https://spmzt.github.io/arcana-docs/sections/workflows.html) |
| Settings, API tokens, What's new | [Settings](https://spmzt.github.io/arcana-docs/sections/settings.html) |

The book's source is https://github.com/spmzt/arcana-docs. SD-WAN is
below until it moves there too.

## SD-WAN

**SD-WAN** in the tree holds the SD-WAN services the console keeps,
named as MEF 70.2 (SD-WAN Service Attributes and Service Framework)
names them. It is one document with three parts:

- `ucs`: the underlays (Underlay Connectivity Services, §12). Each has
  an `id`, a `type` (`public`, an Internet Access, or `private`), a
  `billing` (`flat-rate`, `usage-based` or `other`), and the
  `tunnel` the edges make over it: `kind` `gre`, `gif`, `geneve`, `uswe` or
  `wg`, and for the first three `ipsec`, true for IPsec IKEv2 under
  it.
- `edges`: the hosts that are SD-WAN Edges (§7.8). Each names its
  `server` and lists its `ucs_end_points` (§12.3): an `id`, its
  `ucs`, the `interface` it is on, and maybe an `address`, a
  `gateway`, a `bandwidth` in bits per second, `backup` (used only
  when nothing else is left), `breakout` (traffic for the Internet
  leaves here; only on a public underlay), and, Mplify 119 §12.2.3,
  its `addressing` (`static`, `dhcp` or `slaac`: by the last two the
  address is the host's own, learned when a plan is made), a `vrf`
  (a routing table of the underlay's own) and its `routing` (`bgp`,
  `ospf`, shaped as a UNI's).
- `swvcs`: the services (SD-WAN Virtual Connections, §9). Each has
  an `id`, the `fib` it has on its edges (1 or more; FIB 0 is the
  underlay's), its `ucs`, `reserved_prefixes` (the provider's own
  addresses, tunnels' among them), its `domains` (Mplify 119 §7.3,
  all optional: `service`, with the `prefix` the tunnels' addresses
  come from and a `fib` kept for the control plane; `breakout`, with
  the `fib` the Internet traffic goes by; `subscriber`; each with a
  route distinguisher `rd`, route targets `rt` and an MPLS `label`,
  R15–R20, one service's each), and:
  - `zones` (§9.5): a `name` and `prefixes`, a list or `Default`, and
    `policies`, each an `app` (a flow or a group) and the ingress
    `policy` it gets in the whole zone, or `Block`;
  - `flows` (§9.14), matched in order, the first that matches: a
    `name`, `criteria` that all must match (`sav4`, `dav4`, `sdav4`,
    `sav6`, `dav6`, `sdav6`, `protv4`, `nextheadv6`, `dscp`, `sport`,
    `dport`, `sdport`, `ethertype`, `appid`, or `any` alone) and
    maybe a `group` of `groups`;
  - `policies` (§9.12): a `name`, a `direction`, `ingress` or
    `egress`, and `criteria`. Ingress: `encryption`,
    `public-private`, `internet-breakout`, `backup`,
    `virtual-topology`, `allowed-destination-zones`,
    `billing-method`, `business-importance`, `performance` (a
    `primary` metric, `delay`, `ipdv` or `loss`, with `threshold`,
    `ceiling` and `remediation`, and `secondary` ones with a
    threshold), `bandwidth` (`commit` and `limit`, or a rate
    limiter's name) and `af-security-ingress`. Egress:
    `egress-block` and `af-security-egress`;
  - `topologies` (§9.6): `multipoint-to-multipoint` with
    `end_points`, or `rooted-multipoint` with `roots` and `leaves`;
    `Swvc`, all to all, is always there;
  - `intervals` (§9.7: `eval`, `arrival`, `ir`, in milliseconds),
    `rate_limiters`, `security_policies` (§9.10, each a `name` and
    MEF 88 `criteria`: `ip-block` with `allow` and `deny` lists of
    prefixes, `dns-domain-filter` with the domains in `deny`,
    `dns-protocol-filter`, `rate-limit` in bits per second, `log`;
    a flow's policy names one by `af-security-ingress` or
    `af-security-egress`), `importance` (`levels`, high to low, and a
    `default`) and `probe`, how its tunnels are measured;
  - `end_points` (§10): an `id`, the `edge` it is on, its `uni` (§11:
    an `id`, the `interface`, a `vlan` or 0, `max_frame`, `ipv4` and
    `ipv6` addressing, `none`, `static`, `dhcp` or (IPv6) `slaac`, each
    but none with a `prefix` and the `provider`'s addresses in it,
    `ll-only` for IPv6 too; with dhcp or slaac the `reserved` prefixes
    not given out, the `dns` servers told to the hosts and a `lease`
    (§11.4, §11.5); and static `routes`), its `policy_map` (each a
    `zone` or `Internet`, an `app`, and its `ingress` and `egress`
    policies, over the zone's own) and its `nat`. In place of a `uni`,
    a `remote` (SASE-3, access by identity): a wg `interface` of the
    edge, the `prefix` the identities' addresses come from, the `port`
    it listens on (51820) and its `identities`, each a `name`, a `zone`
    of the service and a WireGuard `public_key`; the policies apply to
    an identity as to a UNI's hosts. On the edge, the apply makes the
    wg interface in the service's table with the prefix's first host
    as its address, listening on the port, and each identity a peer
    allowed its own address, the lowest free from the second, kept
    for it; the zone table sends that address to its zone's block, so
    the identity's flows get the zone's policies and the security
    policies as a UNI's host's do; the other edges route the prefix by
    their tunnels to this one. The far ends tell the prefix's zone by
    the zones' own prefixes, as they do a UNI's, so a zone the
    identities are in is best the Default one, or one whose prefixes
    hold the remote's.

**URL filters** (SASE-4, MEF 88's `url-filter`): a security policy
with `url-filter` (`mode` sni or inspect, `deny` domains, `lists` by
name) has HTTP and TLS from the service's end points forwarded by
ipfw (ports 80 and 443, to 3128 and 3129 on the edge's own address at
each end point) to Squid on the edge, an instance per service in its
table (`sdwan-proxy`, `arcanactl sdwan proxy`). Squid is a plugin:
installed by hand (`pkg install squid`, the package has SSL, SSL_CRTD
and TP_IPFW), never by Arcana, and the apply says so where it is
missing. In mode sni Squid looks at the TLS names (peek) and ends a
connection to a denied domain, the rest let through unopened
(splice); in mode inspect it opens TLS (bump) with a CA of the
instance's own, made once by the agent with `openssl(1)` and kept
beside its files, whose certificate the Security tab offers for the
clients to trust. HTTP to a denied domain is refused outright. The
denied domains, the policy's own and its lists', each cover the
names beneath. The Security tab lists each edge's instances, their
mode and state; the `sdwan` read has them as `proxy`.

**Identities** (SASE-3): the tab lists every remote end point's
identities with the address the plan gave each, when it was issued
and until when it is authorised. **+ identity** issues one at an end
point, for a console user (the name of one of the sign-in keys, with
the box ticked) or any name: the console makes the X25519 key pair,
puts the identity in the document (in place of one of the name: issued
again, with a new key), applies the edges, and shows the WireGuard
configuration once, the private key kept nowhere: the address, the
edge's key, its address on a public UCS and the port, the service's
prefixes, the DNS filter where there is one. **Revoke** takes it out
of the document and applies: its peer goes. A remote end point's
`reauth` (an hour to a year, in seconds) is how long an identity stays
authorised from its `issued` time; past it the manager's tick applies
and the peer is removed until the identity is issued again. `GET`,
`POST` and `DELETE /api/sdwan/identities` do the same. Each identity's
**session** is its peer as the edge's `wg(8)` tells it, read from the
edge with the list: the last handshake, the bytes each way and where
it came from; none when the edge has no peer for it yet.

**Security** lists the service's security policies (MEF 88): the
addresses allowed and denied, the domains denied and whether DNS is
kept to the provider's resolver, the rate limit, the log, and which
policies name each; **+ policy** and the pencil edit one. On the
edges, where a flow's policy names one by `af-security-ingress`, the
rules of that flow's block get, before the forward, a `deny` of what
goes to a prefix of the policy's deny list and one of what comes from
one, each with a `not` for the allow list, `log` where the policy
says, the prefixes in tables of the policy's own (`sw<fib>_s<n>d4`,
`d6`, `a4`, `a6`); a `rate-limit` is a dummynet pipe of the policy's
own, the flow sent through it on the way out by the tunnels. Named by
`af-security-egress`, the same denies stand on the way out by the UNI.
The DNS criteria are the base system's unbound(8), `local-unbound`:
where any policy of a service names a security policy with
`dns-domain-filter` or `dns-protocol-filter`, each edge with a UNI of
the service runs an instance of it in the service's table (`sdwan-dns`;
`arcanactl sdwan dns json` by hand; checked by local-unbound-checkconf
first, its pid file beside the agent's kept files, started again at
the agent's start), listening on the UNIs' provider addresses,
answering the UNIs' subnets, resolving by itself, and answering every
denied domain and the names beneath it with NXDOMAIN (a local zone
each; the domains of all the service's filtering policies together).
With `dns-protocol-filter`, every DNS query from the UNI, UDP or TCP,
is forwarded to that instance by an ipfw rule (`fwd provider,53`),
whatever resolver the host asked. Security lists the instances, and
counts for each policy what its deny rules dropped on every edge
(packets and bytes, as `ipfw -S show` counts them since the rules were
made, which the `sdwan` read carries as `rules.counters`, each rule's
number, packets, bytes and text).

**Lists** (SASE-2): a security policy's `ip-block` and
`dns-domain-filter` may name `lists` beside their own entries. A list
is a feed, a URL the console's host fetches with the base system's
fetch(3) (https, http or file) every `interval` hours (6 unless said),
or entries pasted on the Security tab: one a line, prefixes and domain
names, `#` for a note. Each is kept in `sdwan-lists.json` with a
version that moves when its entries change, when it was fetched, and
the error of a fetch that failed, which keeps the last entries. The
prefixes of a named list go into the policy's deny tables after its
own, the domains into its DNS filter; the document is refused for a
list that is not there.

What IPsec decrypts goes past the firewall on its way in by default
(`net.inet.ipsec.filtertunnel=0`), and a tunnel's payload with it, so
the agent sets that and its IPv6 twin to 1 whenever it loads the
rules: what comes in by an IPsec-carried tunnel is then filtered like
the rest.

**The record** (SASE-2): a policy with `log` has its deny rules log
each packet to the routing socket (ipfw's `logdst rtsock`, a thousand
a rule between resets, which the agent asks for), where the agent
reads them (RTM_IPFWLOG: the rule, its action, the addresses, the
interface and the rule's comment, which names the service and the
policy) into a record it keeps for a day beside its files, each an
event `sdwan-security` as it comes, twenty a second at most. The
`sdwan` read carries the day's count and the latest 500; Security
shows them from every edge, newest first, with a filter, and **CSV**
downloads the day's from every edge (`GET /api/sdwan/record.csv`;
`/api/sdwan/record` as JSON, `?swvc=`, `&policy=`, `&edge=`,
`&since=` to pick). `GET` and `PUT /api/sdwan/lists` carry the
feeds and the interval, `POST /api/sdwan/lists/fetch` fetches now
(`{"name"}` for one); **Fetch now** on the tab does the same. A list
may be large: the agent writes a table's entries 64 to a line as
`table … atomic add`, one call each, all or nothing, and raises
`net.inet.ip.fw.tables_max` when the tables would not fit; and when
only entries changed since the rules were applied (a list fetched
anew), each changed table is filled beside itself and swapped in with
`table … swap`, the rules and the steering left as they are.
`arcanactl sdwan rules @file` reads the JSON from a file.

**Dashboard** counts what there is, each number naming the FreeBSD
piece that does the work (routing tables by setfib, tunnels by gre,
gif, geneve, wg and uswe, IPsec by strongSwan or keyed by the agents,
the rules in an ipfw set),
draws the edges with the tunnels between them as their probes see them
(green up, red down, dashed a backup, a lock encrypted, the delay and
loss on each) or as planned before an apply, and lists the underlays,
the edges and the services in tables, with forms: **+ underlay** (its
type, billing, the tunnel kind over it and IPsec under it), **+ edge**
(a host the console has), **+ WAN link** on an edge (the underlay, the
interface picked from the host's own list with the address it has, the
gateway, bandwidth, breakout and backup), each changed with the pencil
or taken away with the cross, the document kept at each step and
checked as a whole; **Services** has the same for a service and its
parts: **+ service** (id, routing table, reserved prefixes, underlays,
provider AS, evaluation interval, BFD), **+ end point** (an edge, its
interface from the host's list, a VLAN tag, the IPv4 and IPv6 subnets
with the edge's address in each, a NAT prefix), **+ zone** (name and
prefixes, or the Default), **+ flow** (applications from the catalog,
DSCP, protocol, ports, prefixes, or everything), **+ policy** (the
tunnel criteria, breakout, the destination zones, performance by a
metric with threshold, ceiling and remediation, bandwidth by a limiter
or a commit and limit, importance; for egress, the block), and **+
rule** on an end point (zone, flow or group, ingress and egress policy)
or on a zone (flow and policy). What a form does not ask for, as
virtual topologies, rate limiters, secondary subnets or BGP at a UNI,
stays as it is and the Document tab writes. It shows one service's
end points, zones, flows (in the
order they are matched), policies, topologies and rate limiters;
**Document** the whole of it as JSON. **Check** asks the console
whether it is one the standard allows and **Keep** keeps it; what the
console says no to names where, and the requirement:

    swvc office, policy realtime: performance: the ceiling is the
    threshold or above it (R72)

A change is made from the version it was read at; one made from an
older version is refused, so two pages do not undo each other. **Start
from an example** writes one with two of the console's hosts as its
edges.

**Edges** shows what the kept services make on the edges, and makes
it: **Deploy** says first what it will make, make again and take away
and asks, then runs it, each edge's steps done so far shown on its
line while it runs; the table lists each edge's objects by step in
the order they are made, the changes alone until **Show all**; **Past
applies** lists the last fifty, when, how each went and what it did.
Each edge is to have, for each service on it:

- `net.fibs` raised to the highest service FIB on it, and one (never
  lowered). It is per vnet: a fresh vnet has 1. `net.add_addr_allfibs`
  must be 0, the default: at 1 an interface's addresses are routed in
  every table and no service can have one of its own, so the step
  fails and says so.
- strongSwan's key and daemon, when one of its tunnels wants IPsec.
- Its end of each tunnel (a Tunnel Virtual Connection, §7.10): one
  between each two edges of a service, over each two of their UCS End
  Points that a tunnel can join (the same underlay, or two public
  ones), each End Point with its outer `address`. The tunnel is the
  underlay's `tunnel`: gre, gif or geneve, under IPsec IKEv2 in
  transport mode when it says `ipsec` (a public underlay does unless it
  says otherwise; and every tunnel of a service does when one of its
  policies says `encryption` `required-always`, R39, which an underlay
  that says no IPsec cannot meet), or wg. One IKEv2 connection serves
  every tunnel of a kind between the same two outer addresses: in
  transport mode it protects all of them, and two would conflict. It is in the service's FIB, its outer packets
  in FIB 0, its inner addresses a /31 and a /127 of the service's
  reserved prefixes; each end has its own unit (`gre100`, `gre101`),
  since two ends may be one host. The far end is told once both ends
  have a key: the wg peer, or the IKEv2 connection with the far host's
  key, protecting only the tunnel's own packets (GRE, IP-in-IP, or
  UDP for geneve).
- Routes in the service's FIB: each far end point's prefixes by a
  tunnel to its edge, one that is no backup first and a private one
  before a public one; and each UNI's static routes. A prefix no tunnel
  can carry (an IPv6 one with no IPv6 reserved prefix for the tunnels'
  inner addresses, say) is left out, and the plan says so in a note.
- The UNIs, last: the interface, or a VLAN on it, in the service's FIB,
  with the provider's addresses.

Each is a row with the jobs that make it, and whether it is to be
made, made again (its jobs changed), taken away, or is as it is.
**Apply** takes away what goes, last made first, and then makes what
comes in the order of Mplify 119's activity flow (§12.1, steps 1 to
13), each step on every edge before the next; a step that fails takes
away what it made and stops the apply. The Edges tab names each row's
step:

| Step (§12.1) | What Arcana makes |
|---|---|
| 1 VRFs | the services' tables, the domains' and the underlays' (net.fibs raised, setfib); forwarding on |
| 2 Synchronization | ntpd by the edge's servers |
| 3 UCS UNIs | the WAN links' interfaces: their table, addressing, routing with the underlay |
| 4 Control plane | the control tunnels (CTVC), their key pairs and SAs; the iBGP to the host, by BIRD |
| 5 UTVCs | the data tunnels: gre, gif, geneve, wg or uswe, IKEv2 under them or the agents' keys; no GRE with MPLS labels (not supported) |
| 6 SD-WAN UNIs | the UNI interfaces and VLANs, their addresses, router advertisements and DHCP |
| 7 Subscriber routing | the routes written, and BIRD at the UNIs (static, BGP, OSPF) |
| 8 Application flows, 9 Zones | the ipfw tables and rules in set 30 |
| 10 Policy map | the steering: each far prefix by its policy's tunnels in order |
| 11 Fault management | BFD on the tunnels in BIRD; the agents' faults (§11.3) |
| 12 Performance monitoring | the probes, their thresholds |
| 13 Enable SD-WAN UNI | the UNIs come up last (R169) | What was made is
kept in `sdwan-state.json` with the jobs that take it away again, and
the tunnels' units and addresses, so that one added moves none of the
others. **Make all again** takes everything made away first.

A wg tunnel's FIB is set, but not kept across a reboot: wg-quick(8),
which brings wg up at boot, gives its addresses before any table can
be set. gre, gif and geneve keep theirs in `rc.conf`.

**Paths** shows what each edge's probes see of each tunnel. After the
tunnels and their far ends, an apply tells each edge the tunnels to
measure (`sdwan-probes`): the far inner address of each, pinged (ICMP
echo, a raw socket, so the agent must be root) through the service's
table, as Mplify 119 §11.4 has an edge measure its tunnels. Of each
eval interval the agent keeps a sample: the one-way delay, half the
mean round trip (MEF 105); the delay variation, the mean difference
between one round trip and the next; the loss; the least and the
most. So many misses in a row and the tunnel is down, so many answers
and it is up again, each an event (`sdwan-tunnel`) the Faults list
shows. The service's `probe` sets how: `interval` (ms, 100), `size`
(bytes, 64), `count` (0 for without end), `dscp`, `down` and `up` (3
and 3), `timeout` (ms, 1000), `history` (samples kept, 3600) and
`report`; `intervals.eval` is the sample's length. The targets are
kept beside `history.conf` for the agent's next start; `arcanactl
sdwan` reads what they saw, `arcanactl sdwan probes json` sets them.
Under each tunnel's table, its **monitor**: three charts over the last
5, 15 or 60 minutes (the buttons at the top), the delay (each end's
mean a line, its least to most a band), the variation and the loss,
both ends each in a colour, the service's `tca` threshold a dashed
line where set, and the tunnel's faults (tunnel, bfd, tca) as bands of
the time they were open; a column hovered gives its figures. The page
asks each edge only for the samples after the last it gave (`after`)
and keeps the earlier ones, as many as the agent does.

**The rules** (after the probes, before the routes and UNIs): the
console compiles each edge's services into one ipfw ruleset of their
own, in set 30, rules 10 to 99, kept apart from the kept rules and
loaded again at the agent's start (`sdwan-rules`). What comes in at a
UNI goes by its source to its zone's block (`skipto tablearg` by the
zone table; no zone, dropped, R23; a packet with source routing
dropped, D1); the block has the flows in order, each with the ingress
policy the end point's map or the zone gives it (R109–R112): a flow
with none, or Block, is dropped; one with a policy is forwarded by the
policy's table (`fwd tablearg`), which maps each far prefix to the
inner address of the tunnel chosen for it, and what is not in the
table goes on; a packet no flow matches is dropped (R96). A flow's
criteria are said as ipfw says them (addresses, protocols, ports,
DSCP, `appid` by a small catalog: dns, http, https, ssh, sip, ntp,
smtp, imap, pop3, ldap, rdp, snmp, syslog, ike, bgp, quic, dhcp,
icmp); `ethertype` cannot be, and a flow with IPv4 and IPv6 criteria
both matches nothing.

**The steering** (`sdwan-steer`): for each policy's table, each far
prefix the policy may reach (its virtual topology, R47–R51; its
allowed destination zones, R58–R62, Self alone by default) with the
tunnels that fit the policy (encryption, public or private, billing,
backup only when enabled, R63) in order: no backup first, private
before public. The edge takes the first whose far end its probes do
not say is down, fills a second table beside the one in use and swaps
it in, and chooses again the moment a probe's state changes: the local
failover, with no console. Where a policy has `performance`, the
console's manager reads every edge's probes every five seconds and
orders the tunnels by it (R69, R70): those that meet every threshold
first, by the primary metric, and the one in use stays first while it
meets them and is under the ceiling (R73); an order that changed is
sent to the edge. `GET /api/sdwan/steer` says what was sent last;
Paths shows each edge's prefixes, by which tunnel each goes now and
the others' states.

**Beyond the tunnels**, a flow with a policy may reach the hosts of
the edge's own UNIs of the service whose zone it is allowed, and the
Internet where its policy says `internet-breakout: enabled`
(R53–R57): what is not a prefix of the service's UNIs (the table
`sw<fib>_known`) is the Internet. Where it leaves is the edge's own
UCS end point marked `breakout` (local: the service's default route
by its `gateway`, reached by its interface, in the service's table),
else the first edge of the document that has one and a tunnel to it
(remote: the default route by the tunnel). Leaving locally, IPv4 is
translated by an ipfw nat instance (`3000 + fib`) to the first host
of the `nat.public_prefix` of the edge's end point that has one, else
the interface's address, with `nat.exceptions` left as they are; what
comes back in by that interface to the translated address or to the
service's prefixes is forwarded by the service's table (`setfib`),
and when no flow at the edge's UNIs breaks out, what comes in from
the Internet for the service's prefixes is dropped (R56). The nat
instance's output does not go through the kept rules. A flow's
packets that none of this lets through are dropped by the flow's own
last rule, so a later flow never sees them (R96); a policy without
`internet-breakout` drops the flow's Internet traffic (R57).

**Bandwidth** (`bandwidth` in a policy: a rate limiter's name, shared
by every flow naming it, or the policy's own `commit` and `limit`,
R77–R83): each limiter is a dummynet pipe of its `limit` (none: no
limit), each flow in it a queue of that pipe weighted 1 to 100, half
by its commit's share of the pipe's commits and half by its
`business-importance` among the service's `importance.levels`, the
first level the highest (D4). The queue meters the flow after the
policy says it is forwarded (R79): on the way out by the service's
tunnels, and in the flow's rule for its own UNIs' hosts and for
breakout. The pipes and queues are numbered from 3000 and are made
and deleted with the rules; `dummynet` and `ipfw_nat` are loaded as
needed. A packet out of a pipe leaves the firewall (ipfw's one_pass).
**Egress** (`egress` in an end point's policy map, R85, R86): a flow
of the zone whose egress policy says `egress-block: discard` is
dropped leaving by that end point's UNI. Backup and billing are in
the steering above (R63, R64); a rooted-multipoint topology gives a
leaf its roots only, so no edge forwards for another (R50, R51).

**Routing at a UNI** (§11.6): besides its static `routes`, a UNI may
have `bgp` (`family` ipv4, ipv6 or both, the subscriber's `as`, its
`neighbors` at the UNI, within the UNI's prefixes, and maybe a
`password`, a `hold_time`, `communities` as `[as, value]` pairs added
to what the subscriber is sent, and a `distance`) or `ospf` (`family`,
`area`, and maybe `cost`, `hello`, `dead`, a `password` and a
`distance`); one of each, for one family or both (R139). A service
with any such UNI gets a BIRD instance of its own on each of its
edges, named `sw<fib>` and run by the agent in the service's table
(`setfib`, with a control socket and a pid file beside the agent's
kept files; `sdwan-bird`, kept and started again with the agent): the
kernel's table learned and kept, so what the console put there stays
and outranks what BGP brings; the UNIs' and the tunnels' connected
routes; iBGP with every other edge by each tunnel between them (the
service's `as`, 64512 unless said), next hop the tunnel's own address,
advertising the UNIs' routes and what they learn (not the kernel's
own, nor the reserved prefixes: a peer would resolve its next hop by
them in a circle), so what one UNI learns reaches them all; and at each UNI the protocol its entry says, the
`distance` its preference (256 less it, R140–R142). What a UNI learns
goes by the service's table and the tunnel iBGP chose, not by the
policies' tables: steering by performance is of the prefixes written
in the document. With `bfd` in a service (`interval` 100 to 300 ms,
`multiplier`, Mplify 119 §10.5 and R159), the instance watches each
tunnel interface by BFD and the edges' iBGP sessions go by it; the
agent reads the sessions every second into the `sdwan` read, a
session that goes down after it was up, or comes up again, is a fault
(`sdwan-tunnel`, by bfd, R60), and the steering takes BFD's word over the probe's where
there is a session. Paths shows BFD's state beside the probe's. With
`md5` in a service, the edges' iBGP sessions are signed with TCP MD5
(R12). With `control_plane` (`host`, an edge of the service, and maybe
a `cluster_id`), the full mesh gives way to Mplify 119's control plane
(§8.3, R9–R13): every other edge peers with that host alone, by each
tunnel to it, and the host's BIRD reflects their routes to all (RFC
4456, `rr client`, the cluster id its router id unless said); a plan
refuses a topology where an edge has no tunnel to the host. With
`ctvc`, one of the service's UCSs, the control plane gets a tunnel of
its own from each edge to the host over that underlay (the CTVC,
R5, R6: the UCS's tunnel kind, addresses from the service domain's
prefix, BFD and probes like any, steered by no policy), and the iBGP
goes by it and nothing else; without it the sessions ride the data
tunnels (the CPI as a virtual interface, R2). The service form asks
for the host, the cluster id and the control tunnel's underlay. RFC 4364's VPN routes with the
domains' route distinguishers, targets and labels (R14–R20) are not
written: they need BIRD's l3vpn protocol, which the FreeBSD port of
BIRD 3 does not build (known limits). An edge with `ntp` (its servers, in the edge form) gets them
written into its `ntp.conf` and ntpd enabled and restarted, with the
FIBs, so faults line up and keys can turn together (Mplify 119
§12.2.2); the `ntp` job does it, and `arcanactl ntp` by hand.

**The routing domains** (Mplify 119 §7.3, R15–R26): a service's
`domains` name its tables beyond its own. With a `breakout` domain's
`fib`, the apply keeps the Internet apart from the subscriber's table:
the default route (by the local breakout gateway, or by the tunnel to
the edge that breaks out, whose far end gets a route by the tunnel
interface there) goes into the breakout table, the edge's own UNIs'
subnets and static routes are imported into it (R25, R26) once the
UNIs are up, so what comes back finds the hosts, the flows that break
out are sent to it by `setfib` before they leave, and what comes back
in at the breakout interface is set to it too; the service's own table
holds no default route then. net.fibs is raised over the domains'
tables as well. With a `service` domain's `prefix`, the tunnels' inner
addresses are taken from it rather than from the reserved prefixes,
and the edges' iBGP keeps it to themselves like them; its `fib` is
kept for the control plane interface to come. The route
distinguishers, targets and labels are checked and kept for the
tunnel format to come; nothing uses them yet.

**The uswe tunnel** (Mplify 119 §10): a UCS whose `tunnel` is of kind
`uswe` gets, for each pair of edges, an ipsec(4) interface at each end
whose reqid is its unit, ESP in tunnel mode keyed by the agents
themselves: the apply has each end make its X25519 pair (`ipsec-sa
key`), makes the interface with its outer ends, and then has each end
derive the SAs from the far end's public half, which the console reads
from that end's `sdwan` read and passes as `${uswe:SID:IF}` the way it
passes a wg key; `algorithms` picks AES-256-CBC with HMAC-SHA-256 or
AES-256-GCM, `esn` and `encap` (ESP in UDP) are on unless said
otherwise, and `lifetime` (seconds, a day unless said) is what the
keys are good for. No IKEv2 under it. The UCS form asks for it all
under "uswe only".

**The keys turned** (Mplify 119 R110, R112): the console's manager
turns a uswe tunnel's keys at the half-life of their lifetime, both
ends in step and without a packet lost: a next pair made on each end
(`ipsec-sa key next`), its public half read from the sdwan read, the
new SAs from the two pairs put in inbound on both ends, then outbound,
each end's old outbound SA taken out as its new one goes in (`derive …
next install in | out`; the kernel would keep sending on the old one
otherwise, net.key.preferred_oldsa), then committed on both (`commit`:
the old inbound SAs taken out, the next pair made the pair). A rotation that
fails is kept with its step and why, tried again after two minutes,
and the end it failed on raises a `key-rotation` fault until one is
done. The Paths tab's Keys table shows each end's half, when it was
keyed and when it turns, and **turn the keys** does it now
(`POST /api/sdwan/rekey`); an apply waits for a rotation and a
rotation for an apply.

**Manually keyed security associations** (Mplify 119 §10, R41–R50,
R55): the `ipsec-sa` job sets the two SAs of an ipsec(4) interface,
out and in, each its SPI and keys, ESP in tunnel mode on the
interface's reqid, with ESN and ESP in UDP (port 4500) where said,
AES-CBC with HMAC-SHA-1, -256 or -512, or AES-GCM-16 on its own; the
base system's setkey(8) reads them from a file the agent writes 0600
and takes out again, and neither the trace nor the job's title has the
keys. `clear` deletes every SA between the two outer addresses.
`arcanactl ipsec-sa` by hand. Rather than given, the keys are derived
(R51–R54): `key` makes an interface its X25519 pair, the private half
a PEM file 0600 beside the agent's kept files that nothing else reads,
the public half 44 characters of base64 in the `sdwan` read under
`keys`; `derive` takes the far end's public half (`peer`), the
algorithms and the flags, and computes both directions' SPIs and keys
from the agreement by HKDF-SHA256 (the two public halves in order and
an `epoch` number as the context), so the two ends, each with the
other's public half, set the same SAs mirrored; another epoch gives
other keys, for the rotation to come. Every SA gets an anti-replay
window of 1024 packets: without one, the kernel's two ends disagree
on the authenticated data of an AEAD cipher under ESN and every
packet fails its check.

**The UCS End Points, addressed and routed** (Mplify 119 §12.2.3):
with `addressing` dhcp the apply puts the interface on DHCP (the DHCP
word of `ifconfig_<if>` in rc.conf, which dhclient's rc script reads,
and `service dhclient restart <if>`), with slaac on router
advertisements (`inet6 accept_rtadv` and rtsol once, kept in
`ifconfig_<if>_ipv6`); the `if-set` job's `addressing`, `arcanactl
interface <if> addressing` by hand. The end point's `address` may then
be left out: the plan asks the host for the interface's first global
address and uses it as the tunnels' outer one, and an end point whose
host has none yet is left without tunnels, with a note, until the
next apply. With a `vrf` the interface goes into that table and the
tunnels over it send their outer packets by it (`tunnelfib`; IPsec and
WireGuard keep the first table). With `routing` (`bgp` with the
underlay's `as` and `neighbors`, or `ospf`, as a UNI's entry) the edge
runs a BIRD instance of its own for the underlay, `ucs<vrf>`, in that
table, with the kernel's routes learned and kept and the interface's
connected ones; `sdwan-bird` keeps it with the services'.

**The hosts' addresses at a UNI** (§11.4, §11.5): with `static` the
hosts set their own and the edge only has the provider's addresses on
the interface. With `slaac` (IPv6, a /64) the base system's rtadvd
advertises the prefix on the UNI, and the `dns` servers as RDNSS: an
entry for the interface in `rtadvd.conf` between arcana's marks, the
interface on `rtadvd_interfaces`, rtadvd enabled and restarted (the
`rtadvd` job; `arcanactl rtadvd` by hand). With `dhcp` the edge gives
the addresses: the base system has no DHCP server, so dnsmasq from
packages (installed by the apply), an instance of each service on each
edge, run in the service's table by setfib like the BIRD instances,
checked by `dnsmasq --test` first, its pid and lease files beside the
agent's kept files, started again at the agent's start (`sdwan-dhcp`;
`arcanactl sdwan dhcp json`). It serves no DNS; its ranges are the
subnet's hosts less the provider's addresses and the `reserved`
prefixes (for IPv6, ::100 to ::ffff of the /64, less the reserved),
the router the provider's first address, the `dns` servers told, the
`lease` 12h unless said; for IPv6 it sends the router advertisements
that tell the hosts to ask. The apply also turns the kernel's
forwarding on, both families, kept in `sysctl.conf`. Paths lists each
edge's instances and the leases they gave, under Addresses given.

**Faults** (Mplify 119 §11.3): each edge keeps the day's faults, each
with its time, type, severity (Warning, Minor, Major, Critical, and
Cleared), what it is of, who saw it and a line: a tunnel the probes
lost (tunnel), a BFD session down (bfd), a BGP neighbour down after
it was up (bgp-neighbor), a BIRD instance that stopped answering, which
the agent starts again at once (bird-instance), a metric
over a threshold (tca), CPU or memory over the sampler's limit (cpu,
memory). One of a type and object is open at a time; set and cleared
are events (`sdwan-fault`) within the second (R71), and `GET
/api/servers/<id>/sdwan` lists the day's; Paths lists them, open
first, and the dashboard counts the open ones. A service's `tca`
(thresholds for `delay` and `ipdv` in ms and `loss` as a fraction,
and `damping`, intervals in a row, 1 by default) gives the probes the
thresholds: a metric over its threshold for so many intervals is a
fault, cleared when under it again for as many (MEF 105 §7.4,
stateless, O1); the service form asks for them. AS override, damping and extended communities are
refused, BIRD having no word for them. Paths shows each edge's instances and their protocols,
as `birdc show protocols` lists them; `arcanactl sdwan bird json`
sets them by hand.

### Mplify 119 conformance

What the document carries for each of Mplify 119's management plane
requirements (§12, R89–R160), and what is not done. The requirements
are the SD-WAN Vendor Manager's, which the console is; where the
table says a document attribute, the apply passes it to the edge as
jobs.

| Requirement | Document attribute | Done by |
|---|---|---|
| R89–R92 the VRFs of each UCS, the service, breakout and subscriber domains | `ucs_end_points[].vrf`, `swvcs[].domains.service.fib`, `domains.breakout.fib`, `swvcs[].fib` | routing tables by setfib, net.fibs raised |
| R93 NTP server addresses | `edges[].ntp` | ntp.conf, ntpd |
| R94, R95 UCS UNI and End Point interface identifiers | `ucs_end_points[].interface` | the host's interface |
| R96 MEF 10.4 Ethernet attributes (physical links, frame size, EVC EPs, C-tags, token share, envelopes) | — | not done: the interfaces are what the host has |
| R97 auto-negotiation | — | not done: ifconfig media is not written |
| R98–R101 IPv4 and IPv6 address, static or dynamic, prefix, gateway | `ucs_end_points[].address`, `gateway`, `addressing` (static, dhcp, slaac) | the interface's address, dhclient, rtsol; one address per end point, not both families |
| R102 the VRF of each UCS UNI | `ucs_end_points[].vrf` | ifconfig fib, tunnelfib |
| R103 the underlay's routing protocol | `ucs_end_points[].routing` (bgp, ospf) | a BIRD instance per underlay table |
| R104 UCS UNIs put into service | — | the apply's step 3 |
| R105, R106, R113, R115, R116 the CTVC: interface, address and prefix, its underlay interface, the far address, the service VRF | `swvcs[].control_plane.ctvc` (a UCS) | the control tunnel, step 4, in the service's table |
| R107, R110, R111 the key pair made by the edge, its public half told, a new pair at the half-life | — (the agent's) | ipsec-sa key, the sdwan read's keys, the manager's rotation |
| R108, R109, R112 authentication and privacy methods, key length and lifetime, the algorithms, the activation | `ucs[].tunnel` (`kind` uswe, `algorithms`, `esn`, `encap`, `lifetime`) | the derived SAs; the activation is the manager's rotation, in step on both ends, not a date and time |
| R114 DSCP and PCP of the CTVC | — | not done: the tunnels' outer packets are not marked |
| R117–R119 the CPI as a virtual interface | `control_plane` without `ctvc` | the iBGP by the data tunnels |
| R120 BGP router id | — | the edge's tunnel address |
| R121, R123 route distinguishers and MPLS labels per VRF | `domains.*.rd`, `rt`, `label` | kept, not used: VPN routes and MPLS in GRE are not supported (known limits) |
| R122 the BGP AS | `swvcs[].as` | BIRD |
| R124 BGP peer addresses | `control_plane.host` | the host's tunnel addresses |
| R125, R126 static routes to the control plane | — | not needed: the control plane host is an edge at the tunnel's far end |
| R127, R128 TCP MD5 on every control plane iBGP session | `swvcs[].md5` | BIRD's password, the tcp-md5 SAs in the kernel |
| R129, R130, R137, R139, R140 the UTVC: interface, address and prefix, its underlay interface, the far address, the UCS VRF | `ucs[].tunnel`, `ucs_end_points[]` | the data tunnels, step 5, in the service's table, their outer packets by the underlay's |
| R131–R136 encryption of the UTVC: keys, parameters, algorithms, rotation | `ucs[].tunnel` as the CTVC's | the uswe tunnel |
| R138 DSCP and PCP of the UTVC | — | not done |
| R141–R144 GRE of type 0x8847 and the three labels | — | not supported |
| R145, R146 the SD-WAN UNI's interface, VLAN, state, frame size | `end_points[].uni.interface`, `vlan`, `max_frame` | the interface or a vlan(4) on it, disabled until step 13 |
| R147–R150 the UNI's IPv4 and IPv6 addresses, static or dynamic | `uni.ipv4`, `uni.ipv6` (`static`, `dhcp`, `slaac`, `none`) | the provider's addresses, dnsmasq, rtadvd |
| R151 the UNI in the subscriber VRF | `swvcs[].fib` | ifconfig fib |
| R152 static routes | `uni.routes` | route(8) in the table |
| R153 BGP peers at the UNI: address, AS, MD5, password | `uni.routing.bgp` (`neighbors`, `as`, `password`) | BIRD |
| R154 application flows | `swvcs[].flows` | ipfw rules |
| R155 zones | `swvcs[].zones` | ipfw tables |
| R156 the policy map: UNI, flow, zone, the tunnels in order, breakout, allowed destinations, block | `end_points[].policy_map`, `policies` | ipfw rules and the steering |
| R157 irduration | `swvcs[].intervals.ir` | the probes |
| R158 alarm severities Warning to Critical | — | the agents' faults, all severities, in the sdwan read |
| R159 BFD 100 to 300 ms with its multiplier on every tunnel | `swvcs[].bfd` | BIRD's BFD |
| R160 faults retrieved | — | `GET /api/servers/<id>/sdwan` |

Not done, as the table says and beyond it: R96's Ethernet UNI
attributes and R97's auto-negotiation; one address per end point
where the specification allows both families; DSCP and PCP marking of
the tunnels' outer packets (R114, R138); route distinguishers,
targets and labels in the control plane's routes (R121, R123, RFC
4364's VPNv4 and VPNv6 by BIRD's l3vpn, which the FreeBSD port does
not build) and GRE with MPLS labels (R141–R144); a date and time for
a key's activation (R112, R136: the rotation is run in step on both
ends instead); more than one subscriber routing domain per service;
stateful threshold crossing alerts (the probes' are stateless, O1);
RFC 7317's hardware and virtual machine management (§12.7); and a
NETCONF, YANG or REST binding of the management plane (§7.5): the
console's own API and cblink are the management plane.
