# TODO

## To do

- SD-WAN (MEF 70.2 now, Mplify 119 later), step by step. Done: the
  services kept and checked by the console, and shown; the edges made
  from them (a FIB per service, the UNIs and tunnels in it, gre, gif,
  geneve or wg, IPsec IKEv2 in transport mode where asked, routes by
  the tunnels), planned, applied and kept. A wg tunnel's FIB is not
  kept across a reboot (wg-quick gives the addresses first); the
  tunnels measured by the agents (ICMP echo through the service's
  table, the interval, size, count, DSCP and the down and up counts
  set per service), the Paths tab with each end's delay, variation and
  loss, and faults; the flows classified by ipfw in a set of their own
  and steered by the policy tables, the edge taking the first tunnel
  not down (the local failover), the console's manager ordering them
  by the performance criteria; breakout, local by the edge's own
  Internet access with NAT or remote by a tunnel, each flow let to
  its own UNIs' hosts and the Internet by its policy and nothing
  else; bandwidth and importance by dummynet pipes and weighted
  queues; egress blocks. The probes and the rules run where the agent
  runs: an edge that is a vnet jail is not measured or steered yet.
  The bandwidth commit is a weight among the flows of one limiter's
  pipe, not a guarantee against other traffic on the UCS; the pipes
  and nat are verified with ipfw on the lab VM, not under load; BGP
  and OSPF at a UNI by a BIRD instance of each service on each edge,
  in the service's table, iBGP between the edges by the tunnels (what
  a UNI learns goes by the table and the tunnel iBGP chose, not by the
  policy tables). The instances are run by the agent (setfib, a
  socket each) and verified with stand-ins, not yet against a real
  subscriber router; BFD on the tunnels by the same instances, the
  sessions read every second, a change a fault and the steering's
  word (Mplify 119 tasks 1.1 to 1.3 of docs/PLAN-119-SASE.md; BIRD
  has no DSCP for BFD, so R159's DSCP is not set); TCP MD5 on the
  edges' iBGP and NTP as a step (tasks 1.4, 1.5); the faults kept a
  day with Mplify's types and severities, from the probes, BFD, BIRD
  and the sampler, and threshold crossing alerts from the probes
  (1.6, 1.7; storage as a resource fault and interface-down are not
  raised yet); the lab run of 119-1 (1.8, in the verified list); the
  monitor charts of each tunnel on Paths (UX-5); SLAAC at a UNI by
  rtadvd and DHCP by dnsmasq in the service's table, with the kernel's
  forwarding turned on by the apply (0.1, 0.2, in the verified list);
  the routing domains (Mplify 119 §7.3): a service's domains in the
  document, checked and unique, the breakout domain a table of its
  own with the default route, the UNIs' routes imported and the flows
  sent to it by setfib, the tunnels' addresses from the service
  domain's prefix (119-2 tasks 2.1 to 2.3; stand-ins, not the lab:
  the jails have no Internet to break out to); the UCS End Points
  addressed by DHCP or SLAAC (the address learned from the host at
  each plan), in a table of their own, and routed with the underlay by
  a BIRD instance of the edge (2.4; DHCP on the jails, in the verified
  list); manually keyed SAs on an ipsec(4) interface by setkey, the
  keys never in a trace (119-3 task 3.1); a key pair per tunnel end
  and the SAs of both directions derived from the agreement by
  HKDF-SHA256, the same on both ends (3.2); the uswe tunnel kind: an
  ipsec(4) interface each end with its unit as reqid, the pairs made,
  the SAs derived from the far public half the apply reads from that
  end (3.3); the keys turned at the half-life, both ends in step,
  inbound before outbound, by the manager or by hand, a failure a
  fault (3.4); the phase closed on the lab, the packets seen on the
  wire as ESP in UDP under ESN (3.5). MPLS in GRE (119-4) is not
  supported: it would be kernel work, which Arcana does not take on
  (2026-10-11); the domains keep their own tunnels. 119-5: a control
  plane host per service, an edge whose BIRD reflects the others'
  routes, each peering with it alone (5.1); the CTVC, a control
  tunnel of its own from each edge to the host over a UCS the
  service names, the iBGP by it alone (5.2); the phase closed on the
  lab with three jails, the host reflecting between two edges with
  no tunnel between them (5.3; RFC 4364's VPN routes stay out, known
  limits); the Edges tab's steps named as §12.1's activity flow, the
  guide's table from each of R89-R160 to its attribute, and the list
  of what is not done (119-6). Mplify 119 is through. SASE-1: the
  security policies in the document with MEF 88's criteria, checked,
  on a Security tab with a form, the example carrying one (S1.1);
  the ip-block denies and allows, the log and the rate pipe in the
  rules, ingress before the forward and egress by the UNI (S1.2);
  the DNS filter, an unbound instance of the base system per service
  on each edge, the denied domains its local zones, every query from
  the UNI forwarded to it where the protocol filter says so (S1.3);
  the rules' counters in the sdwan read, the Security tab counting
  what each policy denied (S1.4). Next: S1.5, the phase closed on the
  lab.
- A luxuria plugin installed in a vnet jail and not on the host does
  not get its tab (reported 2026-10-11). The agent lists a running
  vnet jail's plugins by access(X_OK) on the program under the jail's
  root, and the page gives the tab to a host one of whose running vnet
  jails has it; to find out: the jail's name, whether the agent runs
  as root (a root 0700 cannot be looked into otherwise), and what the
  host's list read says under that jail's plugins.
- Jails made and changed from the console (asked 2026-10-11), the way
  the user makes them on his servers. A shared `/etc/jail.conf` holds
  the defaults, the user's domain in place of example.net:
  `path = "/usr/jails/${name}"`, `host.hostname =
  "${name}.<domain>"`, `host.domainname = "<domain>"`, `exec.start =
  "/bin/sh /etc/rc"`, `exec.stop = "/bin/sh /etc/rc.shutdown jail"`,
  `exec.consolelog = "/var/log/${name}_console.log"`, `exec.clean`,
  `mount.devfs`. One ZFS dataset per jail, mounted at the path (as
  `<pool>/jails/<name>`, under a dataset for the jails of the host):
  made with the jail from a base jail's snapshot, two ways to choose
  from: `zfs clone` (quick, tied to the snapshot) or `zfs send | zfs
  recv` (a copy of its own, independent of the base); listed with the
  jail, destroyed with it only when asked.
  Each jail is a file of its own,
  `/etc/jail.conf.d/<name>.conf`, that begins with `.include
  "/etc/jail.conf";` and has the jail's block: `devfs_ruleset`,
  `sysvsem = new` and the like, `allow.raw_sockets`, `ip4.addr =
  "bridge0|172.23.1.43"`, `ip6.addr = "bridge0.20|2a01:...:443"` (an
  interface and an address each), and `.include`s of templates kept
  beside it, such as a certbot one that adds `exec.created +=` and
  `exec.poststop +=` lines (directories made, nullfs mounts of another
  jail's certificates, unmounted at stop); a template is written once
  and included by every jail that needs it. The console's forms: the
  shared defaults once per host, a jail (name, dataset, addresses on
  their interfaces, the switches, the templates to include), a
  template (its lines); the agent writes the files (libjailconf
  already parses them), makes the dataset and starts the jail.
- Asked for on 2026-10-11, each a task of its own, in no order yet:
  - Users and groups, roles (RBAC) and tenants in the console: who
    sees and changes which hosts and services.
  - Mail notifications of faults, jobs and runs.
  - The console's CA: one imported, or made and self-signed from the
    panel, given to each agent and trusted there; the console as a CA
    and as an intermediate CA under another.
  - A session's lifetime set in Settings.
  - LDAP for the console's sign-in.
  - The base system's ssh, further: the banner, the users let in,
    authorized keys, host keys and their fingerprints, host keys
    signed by a CA key.
  - IDS/IPS by Snort, a plugin (luxuria) as before: Snort and its
    rules updated and configured from the panel.
  - The console clustered; disaster recovery across console clusters.
  - Agents in an HA pair on identical hardware and ports (CARP, the
    state shared), with CARP on its own for a host.
  - VPN groups and road warrior setups of several clients, policies
    and pools.
  - A Devices page of its own, a table of the hosts (sorted and
    filtered), the rail's host list moved there.
  - A certificates tab per host, by certctl and OpenSSL.
  - Configuration templates: a host's setup exported to one and a
    template applied to a host; YAML where the standard allows,
    UCL otherwise.
  - A span tab: traffic mirrored by a BPF interface, or by ipfw rules
    with BPF.
  - Labels on interfaces, for the UCS they carry.
  - The device's rollback timer (safe mode's wait) set in the console.
  - BIRD's OSPF, BFD and BGP each a tab of its own, with forms.
  - IGMP and MLD configured.
  - NDP and ARP entries added and deleted by hand, temporary or
    permanent.
  - MSS clamping on transports.
  - QoS on ipfw by forms: pipes, schedulers, queues, their masks and
    the rules that use them, beyond what SD-WAN makes.
  - Every table exported as CSV.
  - Prefix lists kept by the console and used on any host.
  - SD-WAN policies by named lists (MEF 70.2, no vendor's model):
    lists of UCS, of prefixes (as the zones hold them), of edges, of
    UCS End Points (the edge's underlay address, the UCS, the tunnel
    kind and a preference) and of services, kept once and called by
    an AFS match or a policy's criteria; and the policy made in
    three steps: the lists, then the flows (the AFS) and the policy
    they get, then the policy map at each SWVC End Point.
- WireGuard: preshared keys; a peer's key rotated.
- Storage, beyond what there is: a key that is typed, for
  a dataset whose keylocation is prompt, without it being kept in a
  job; a key changed; file systems other than UFS made; a disk's
  self-test started; a vnet jail's datasets from the jail's own page.
- To look at (2026-10-06): the test VM (FreeBSD 16-CURRENT, labvm)
  stopped answering, and had to be restarted, right after `ifconfig
  bridge0 maxaddr 500` was run by the agent on a bridge it had just
  made, with one epair member that had learned one address, and whose
  priority had been set to 4096 a moment before. No crash dump was
  written: a hang, not a panic. Not reproduced since; the lab that
  did it is `lab-br.sh` of the session's scratchpad, minus that line.
  Once, in the same lab, the agent's `ifconfig -av` failed with
  "getnameinfo: Address family not recognized" while the bridge and
  its epair were being made; not reproduced either.
- A geneve tunnel's forwarding table: if_geneve keeps one and shows
  no way to read it from userland (no sysctl as vxlan has, no dump
  through netlink); once it does, shown as a bridge's addresses are.
  A learned address of a bridge deleted, and a static one added.
- Workflows, further: the console checks a step's job against
  share/arcana/jobs.yaml, which is apart from arcana.yaml because
  cblink-gen takes no key of its own there: a kind added to the one
  is added to the other by hand. A run's chain is drawn as rows of
  boxes, where a failure goes on written on its box, not drawn as an
  arrow; steps are moved up one at a time, not dragged. What runs at
  an interval counts from when the console's worker began, not from
  its last run, after a restart; the console watches events by asking
  every five seconds, not by subscribing.
- Gula, further: older samples thinned instead of dropped; dmesg for
  an agent that is not root, which the kernel refuses unless
  security.bsd.unprivileged_read_msgbuf is on.
- The mesh: agents joined by SCTP associations, each to at least a
  configured number of others (2 unless set), so that the console
  reaches an agent it has lost through one it still has. SCTP only,
  with no fallback to TCP: a blocked or failed association is a state
  to show and to route around. No module is loaded for it and no
  interface made; an agent on a host without `sctp` in its kernel does
  not try until the console tells it to try again. Who the agents are
  and how they are joined is agreed among them with DNCP (RFC 7787),
  from `libdncp`, which is written and is a repository of its own.
  To be done, in this order:
  - Certificates with a role. An agent's is for a server only, and an
    agent takes any peer the CA signed for the console: agents that
    call each other need certificates that can, and an agent must let
    only the console's ask for anything but the mesh.
  - Arcana's DNCP profile: over cblink on SCTP with DTLS, its own TLVs
    (an agent's name and mesh addresses, when it last heard the
    console), SCTP's heartbeats instead of keep-alives.
  - The mesh listener, the switch and "try again" for each host in the
    console, and the associations drawn on the map and listed, with
    their state, their paths, their round-trip time and their streams.
  - Relaying, and the console falling back to it; the path named by
    the console from the topology the agents hold.
  Not yet decided:
  - How an agent picks its neighbours, which DNCP leaves open: the
    next ones on a ring ordered by node identifier, until enough
    associations work, is what was proposed.
  - Whether a node's data carries its signature. DNCP secures each
    hop, not the data: an agent could publish for another until that
    one publishes again.
  - How a relayed session is carried: end to end, the console's own
    TLS session with the agent inside a stream through the relay,
    which only copies bytes; or hop by hop, the relay reading and
    sending on. End to end needs a cblink connection that runs over a
    cblink stream, which cblink has not got, or a bridge through a
    local socket at both ends.

## Not yet verified

Written and tested with stand-ins, never run for real:

- On a host itself, as root: what of an interface is kept in rc.conf
  (done for real only in a vnet jail, below), and a static route kept
  there. A route in another routing table: the one tried was refused
  by the kernel, its gateway not being reached in that table, which
  came through as route(8) says it. Whether the address named to send
  from is the one a route then uses: route(8) took it.
- Nodes of the map that move away from the pointer, as was reported
  from a browser that is not the one the tests run: not reproduced. A
  real mouse in headless Chromium keeps a host under it for every
  step. What could cause it was changed: the pointer is the drawing's
  while something is dragged, the neighbours outside no longer swing
  about when a host is moved, and the drawing is as large as its room.
- The network map with real tunnels between real hosts: the test has two
  names for one agent, so its links are the networks they share.
- WireGuard and BIRD against the real wg(8), wg-quick(8) and birdc(8):
  the tests use stand-ins. The format of `wg show all dump` is the one
  wg(8) documents; BIRD is not installed on the machine this was written
  on, and what birdc prints was written from its documentation.
- A vnet jail's network. Run for real, against the jail `gateway` of
  one host: its interfaces, routes, route lookup and BIRD read; an
  address added and removed; an interface brought up; a new epair
  given, taken back and destroyed. Not run for real: anything kept
  (the jail's own `rc.conf`, `vnet.interface` in `jail.conf`), BIRD's
  configuration written in a jail, WireGuard in a jail, safe mode in a
  jail, and the map with a real jail as a node (the browser test tells
  the page that a jail runs).
- A jail's share of the CPUs and its memory from rctl_get_racct(2):
  the test VM's kernel has kern.racct.enable off, and turning it on
  needs a reboot; what is read when it is off was run for real.
- Loading and unloading a kernel module for real: reading the kernel
  is real, kldload(8) and kldunload(8) are stand-ins in the tests.
- The switch to SCTP from the page, and SCTP between two machines:
  the API was run for real, between a console and an agent on one
  machine.
- BIRD's safe mode and what is done when BIRD stops answering, against
  a real BIRD: the replies looked for are those in BIRD's source, 2.19
  and 3.3 (`cmd_reconfig_msg()`), and the tests use a stand-in that
  says them, dies or refuses on demand. `show route` was parsed from
  the format in `nest/rt-show.c`.
- Firefox: the console is tested in headless Chromium only.
- The install offer on a real phone: Chrome's prompt on Android, the
  wording for Safari on iOS and for Firefox.
- Notifications on a real phone. A message sent with the console's code
  was delivered to headless Firefox through Mozilla's push service and
  shown; Google's service accepts the console's signature, but the
  Chromium build the tests run cannot receive from it.
- `arcana-enrol -s` on a real host, the container image since the
  rename, and the update check against GitHub's live feed.

## Verified for real

What was once in the list above, and when it was run:

- SD-WAN's probes (2026-10-10, the root test): the loopback pinged
  every 50 ms, up with its samples (a tenth of a millisecond each
  way), and an address in a table with no route to it down after two
  misses, each an event.
- SD-WAN's jobs on two vnet jails joined by an epair (2026-10-10): a
  gre tunnel made in FIB 1 with its /31, its route and the far UNI's
  in FIB 1 and not in FIB 0, IKEv2 in transport mode carrying the GRE
  (ESP AES-GCM-256, the first packet lost to the trap), and a ping
  from one UNI to the other through it; the UNI's address cannot be
  used from FIB 0. net.fibs is per vnet: a new one has 1.
- A security policy's DNS filter on a vnet jail (MEF 88; task S1.3,
  2026-10-11, the lab's dns step): the base system's local-unbound
  started by the agent in FIB 1 on the UNI's address with the denied
  domain a local zone, told running in the sdwan read; asked from the
  other jail over the tunnel, the denied domain and a name beneath it
  answer NXDOMAIN; the instance stopped when not named. The protocol
  filter's forward (fwd 10.10.0.1,53 udp ... in recv gre100) is taken
  by ipfw as the plan writes it; a query from the far jail to a
  foreign resolver through the tunnel could not be sent by drill
  there (a lab routing matter, not the rule's), so the forward itself
  is seen accepted, not exercised: to do with the next lab.
- A security policy's denies on a vnet jail (MEF 88; task S1.2,
  2026-10-11, by hand with arcanactl sdwan rules as the plan writes
  them): the tables of the denied and the allowed prefixes made, the
  two deny log rules taken by ipfw as written, a ping to a denied
  prefix dropped and counted on the rule, the hosts reachable again
  once the rules are cleared. Found: ipfw on 16.0-CURRENT no longer
  takes "valtype legacy" on table create (the plain number is its
  default and the word is gone), which every zone and known-hosts
  table used; the agent leaves the word out for legacy now.
- A control plane host between two edges on three vnet jails (Mplify
  119 §8.3, R5, R6, R9-R13; task 5.3, 2026-10-11, build/lab/rr-lab.sh,
  BIRD 3.3.3 as the console writes it): a control tunnel (gre in FIB
  1) from each edge to the host, no tunnel between the edges; the
  host's two sessions rr client with a cluster id, each edge's one
  session to the host, all Established with TCP MD5 (BIRD puts the
  tcp-md5 SAs in the kernel itself, four of them on the host, the
  tcpmd5 module loaded, no setkey), BFD Up at 100 ms on each
  (BIRD chooses multihop BFD, port 4784, over the point-to-point
  tunnel; it works the same); each edge's UNI prefix reaches the
  other by the reflector with next hop the host, and a ping between
  the two UNIs crosses the host, forwarding on. Found: BIRD's BFD
  binds its sockets to the tunnel addresses at start and gives them
  up for good when they are not there yet ("bind: Can't assign
  requested address", the sessions left Down as multihop), so the
  instance starts after the tunnel interfaces have their addresses,
  as the apply orders it.
- The wire of a derived-SA tunnel between two vnet jails (Mplify 119
  R46, R48; task 3.5, 2026-10-11): tcpdump on the underlay shows the
  ping as UDP-encap ESP on port 4500 both ways, the SPIs the derived
  ones, the sequence numbers climbing; setkey -D shows each SA with
  replay=128 and flags 0x440, NAT-T and ESN, state mature.
- The keys of a derived-SA tunnel turned between two vnet jails
  (Mplify 119 R110, R112; task 3.4, 2026-10-11, the lab's rekey step
  by hand as the console's manager does it): a next pair on each, the
  halves swapped, the new SAs in inbound on both, then outbound, then
  committed, while ping ran at ten a second: 100 of 100 answered,
  the old SAs gone, the next pair the pair. Found: with the old
  outbound SA left in until the commit, three packets were lost,
  since this kernel keeps sending on the old SA
  (net.key.preferred_oldsa=1 on the VM) while the far end's commit
  had taken its old inbound out; so the out step takes the old
  outbound out with it, and none is lost whatever the kernel prefers.
- Derived IPsec keys between two vnet jails (Mplify 119 R51-R54;
  task 3.2, 2026-10-11, the lab's sakey step): a key pair made on
  each by the agent, the public halves read from the sdwan read and
  given to the other side, the SAs derived on each from the
  agreement: setkey -D shows the same two SPIs mirrored on both,
  ping crosses with AES-256-CBC, HMAC-SHA-256, ESN and ESP in UDP.
  Found: AES-GCM-16 with ESN dropped every packet as "bad
  authentication" until the SAs got a replay window: a kernel bug in
  the AAD of AEAD with ESN (known limits); with -r 128 GCM and ESN
  work together.
- Manually keyed IPsec between two vnet jails (Mplify 119 §10; task
  3.1, 2026-10-11, the lab's sa step): an ipsec(4) interface with
  reqid 100 on each, made by the agent's if-create, the two SAs each
  way set by the ipsec-sa job (setkey from a file, AES-256-CBC with
  HMAC-SHA-256, ESN, ESP in UDP): setkey -D shows them esp-udp in
  tunnel mode on the reqid, ping crosses the tunnel, tcpdump on the
  underlay shows UDP-encap ESP on port 4500 both ways, and the trace
  says "not kept: it has keys in it" in place of setkey's output.
- A UCS End Point addressed by DHCP (Mplify 119 §12.2.3.2; task
  2.4, 2026-10-11, the lab's ucsdhcp step): the second edge's dnsmasq
  on the underlay epair, the first edge's interface put on DHCP by
  the if-set job (rc.conf's DHCP word, dhclient restarted): it leased
  10.202.0.142, the agent's interfaces read tells it, which is what
  the console's plan learns, and the lease is listed at the server.
  Found on the way: the agent's queued jobs kept only the first weeks'
  text attributes of their spec; the rest pointed into the freed
  request (agent 0.61.0). Not run in the lab: SLAAC on a UCS, a vrf,
  BGP with the underlay.
- SLAAC and DHCP at a UNI (MEF 70.2 §11.4, §11.5; tasks 0.1 and 0.2,
  2026-10-11, the lab's sub step): a third vnet jail on an epair
  behind the first edge's UNI, the UNI in FIB 1 with the prefixes,
  the agent told as the apply would: rtadvd with the /64 and RDNSS,
  dnsmasq in FIB 1 with a range, the router and the DNS server. The
  host's rtsol got it a 2001:db8:10::/64 address and a default route
  by the edge's link-local; dhclient got it 10.10.0.125 with the
  router; it pinged the far UNI through the edge and the gre tunnel;
  the agent listed the lease with the host's name. Found: a vnet
  jail's devfs hides bpf, which dnsmasq's DHCP and dhclient need
  (no ruleset of this host unhides it; the lab unhides it by hand).
  Not run: DHCPv6 (dnsmasq's enable-ra), the unmake (rtadvd's entry
  removed, dnsmasq stopped), which the stand-ins cover.
- Mplify 119 tasks 1.1 to 1.7 on two vnet jails (2026-10-11, the
  lab build/lab/bfd-lab.sh): an arcana-agent of its own inside each
  jail, a gre tunnel in FIB 1, a BIRD 3.3.3 instance each with BFD on
  the tunnel and iBGP signed by MD5, probes with a threshold, NTP
  written and ntpd enabled. BFD and BGP established, the far UNI's
  prefix installed by BGP, ping UNI to UNI in FIB 1. The epair cut:
  the probe's tunnel fault and the BFD fault within seconds, BGP down
  by BFD; mended: both cleared, BGP back within the error wait time.
  A threshold under the delay: a tca fault; over it: cleared. Found
  and fixed on the way: a peer's kernel-learned host routes exported
  by iBGP made the next hop resolve in a circle (now only the UNIs'
  routes go to the edges, and the console's static routes outrank
  BGP's); BFD and BGP start down, so a fault needs them up once; a
  BFD session that vanishes with its BGP counts as down; BIRD's
  "Reconfiguration in progress" is taken; a running instance is told
  again rather than started; an instance that stops answering is
  started again within five seconds, with a fault saying so. Not done in the
  lab: the steering by BFD (no rules on the jails), resource faults.
- Building the agent as `nobody` when `arcana-agent` runs as root
  (2026-10-04, on the console's host): the clone over SSH with the key
  set for it, make, and the program run with `-V`, each under
  `chroot -u nobody`; the tree it leaves is `nobody`'s, and the program
  sent back is the one built, by its SHA-256.
- The agent's restart after an update, by the real rc(8) service
  (2026-10-04, and on every host at every update since): another
  process within two seconds, the old one stopped by the service.
- An interface created, described, given an MTU, brought down and up
  and destroyed with the real ifconfig(8), and kept in and taken out of
  rc.conf with the real sysrc(8), in a vnet jail (2026-10-04): what was
  kept made keeping it again refused, and what was forgotten did not.

- The agent's tests that need root (2026-10-04, as root on the machine
  this is written on): a jail of their own started, restarted,
  stopped and killed, its addresses added and removed live and kept.
- Storage (2026-10-04, in a lab on the machine this is written on,
  with memory disks and a pool of its own): gpart creating a table,
  adding, labelling, resizing and deleting partitions; zfs creating
  datasets and a volume, setting properties, snapshots, a rollback
  that brought a file back, clone, promote, rename, mount, unmount; a
  pool created as a mirror, a device attached, detached, replaced, a
  cache added and removed, scrub, trim, clear, export, import with the
  list of what can be imported; a UFS file system mounted by an fstab
  written through the agent. What zfs and zpool refuse comes through
  as they say it.
  That lab is also where a guard was found to be too weak: it knew the
  pool of the root file system only, and a test asked for another pool
  of the same machine, one with `/home` on it, to be destroyed and
  exported by force. Neither happened, but zpool unmounted what it
  could before it refused. Since then no pool with a dataset mounted
  where the system lives is destroyed, exported or force-unmounted
  from here, and none by force.

- SCTP (2026-10-04, on a test machine with `sctp` in its kernel): an
  agent listening on TCP also listens on SCTP at the same address and
  port; the console switched to it through its API, asked the jails
  over DTLS on SCTP, kept the association open for the next request,
  saw its own session listed as sctp, and switched back.
- Static routes and netgraph, with the real route(8) and ngctl(8)
  (2026-10-04, on the same machine, in a vnet jail made for it and on
  the host): a route added with a metric and a weight, which
  `route get` then showed, looked up through the agent and deleted;
  what route(8) refuses said as it says it; a bridge node made on an
  interface, named, connected by a second hook, listed, the hook
  removed and the node shut down, on the host and inside the jail.
  In a jail, netgraph needs the jail to allow its sockets
  (`allow.socket_af`) and the node types loaded on the host: a jail
  cannot load a module.
- Sysctl (the same day and machine): read from the kernel, one set
  with the real sysctl(8), and a read-only one refused as sysctl says.
- The agent's tests that need root, on that machine too. They share
  one jail, and are now marked never to run side by side.

- Processes, logs and history (2026-10-05, on the test machine, the
  agent as root): every process read with another user's and a
  jail's among them, and a jail's alone; a busy loop at 100% CPU
  while its WCPU still rose; a nice value lowered, STOP, CONT and
  TERM sent across users, and a jail's process only by its jail;
  init, the agent and the kernel's idle process refused. The real
  `/var/log/messages` read, a line of logger(1) followed from the
  position before it and found by a search. Four samples of history
  with the real swap, network and disk figures. Not done there: the
  page against that agent, and a log turned over by the real
  newsyslog.

- The firewall, bridges and geneve (2026-10-05, on the test machine,
  with the real ipfw(8) and ifconfig(8)): a rule added now and
  deleted; rules kept, and applied through set 1 and the swap, with a
  table of the kept file made in it; in safe mode the old rules
  swapped back by the host when nothing confirmed, and the new ones
  left with set 1 emptied when it was; a text ipfw refuses not kept,
  with ipfw's own words; the firewall turned off and on. A bridge
  with two members: VLAN filtering, an access port and a trunk, both
  in the spanning tree, read back as ifconfig has them, with role and
  state; an address refused on a member, and one put there by hand
  shown. Geneve tunnels made in l2 to a host and in l3 to a multicast
  group with TTL, DF and DSCP inherited, their options set and read
  back. Not run for real: any of it in a vnet jail, what is kept in
  rc.conf for a bridge or a tunnel, NAT and NAT64, a spanning tree
  with more than one bridge in it (every port there was designated
  and forwarding), and traffic through a geneve tunnel.

- IPsec, BIRD and BFD (2026-10-09, on the test VM, in two vnet jails
  with strongSwan 6.1 and BIRD 3.3, everything through the agent):
  each jail's key made, the connections written, GRE in transport mode
  over IPv4 and an ipsec(4) interface with its reqid in tunnel mode
  over IPv6, pings through both and their SAs read back with their
  counters; OSPFv3 Full and BFD Up over both, as the BIRD reading
  says them. The jails had no allow.raw_sockets, and the agent saw
  the kernel's IPsec (ipsec.ko, loaded on the host) from them. A GRE
  or gif tunnel with IPv6 ends was found to have
  been made without its ends before then: ifconfig(8) needs inet6
  before tunnel, and says nothing in its exit status.
- A snapshot sent between hosts (2026-10-09, the same VM, as root): two
  agents with the real zfs on a pool of a file of its own, a full
  send of 20 MiB and an incremental one of 5 MiB relayed between
  their streams as the console relays them, the copy's snapshots and
  files the same as the original's; a receive onto a dataset that is
  there refused with zfs's own words, and a pool's own dataset
  refused before anything ran. The console's relay itself, with
  stand-ins for zfs.
- Thresholds and the kernel's messages (2026-10-09, the same VM): a
  limit on vtnet0 crossed by its traffic made its event; the
  kernel's messages read as root, numbered, followed by their number
  as the kernel wrote more, those beyond twenty in a second told as
  one.

## Known limits

- RFC 4364 VPN routes (Mplify 119 R14-R20: VPNv4 and VPNv6 with the
  domains' route distinguishers, targets and labels) are not written
  for the control plane: BIRD's l3vpn protocol would carry them, and
  the FreeBSD port of BIRD 3 (net/bird3, 3.3.3 on the VM) does not
  build it (no L3VPN option; "protocol l3vpn" is a syntax error). The
  reflector carries plain IPv4 and IPv6 routes. A port with the
  protocol built would be the way (2026-10-11).
- IPsec: a FreeBSD kernel bug found 2026-10-11 (16.0-CURRENT,
  sys/netipsec/xform_esp.c): with an AEAD cipher (AES-GCM, ChaCha20)
  and ESN, esp_input adds the ESN high bits to the separate AAD only
  when the SA has a replay window (wsize != 0), while esp_output adds
  them whenever the SA has replay state; an SA without a window
  (setkey without -r) sends an ICV over four more bytes than the
  receiver checks, and every packet is a bad authentication. The
  agent sets -r 128 on every SA, which is right anyway (R47), and
  then GCM with ESN works; worth a fix upstream (the same test on both
  paths).

- The GitHub workflow (2026-10-11): the images it builds on
  (ghcr.io/spmzt/freebsd-emscripten, cblink) carry a 16.0-CURRENT
  userland, and vmactions/freebsd-vm boots 15.1 at most, so inside the
  container head(1), tail(1) and the like die on casper ("Invalid
  pdflags at fork") and the agent's test suite fails there while it
  passes on a 16.0 host; the same skew is the likely cause of the
  ipsec and vnet cases' garbled arguments. The images need a 15.1
  base, or the tests a kernel of their own. Until then the build
  cannot go green.

From a review of the whole code for flaws of security and design; what
it found and could be fixed was, and this is what stays:

- The build of the agent on a host runs as `nobody`, in a directory
  `nobody` owns and that outlives the build, and `make install` of a
  console update then runs as root from that tree. Any other process
  running as `nobody` on that host can change what is built. A user of
  its own for the build, a fresh directory for each, and the host keys
  and deploy key kept where the build cannot write would close it.
- A security key is asked for its owner's presence, not for a PIN or a
  fingerprint: keys without either still work, and a key found works
  for whoever found it. Sessions are not tied to the key they were made
  with: one made with a key since removed lasts until it ends.
- Somebody who can log in can make the console connect to port 443 of
  any host by naming it as a push service's address; the certificate
  must be valid for the name, and nothing of the answer is shown but a
  status and the start of an error.
- A change made in safe mode that fails half way (the MTU set, the
  description refused) reports the failure and leaves what was done.

- EC keys for the console's own HTTPS certificate: Kore's key manager
  signs with RSA only, so `console.pem` must be RSA until Kore (or a
  patch like the one in `port/www/kore/files`) handles ECDSA.
- A web terminal in the console: it could not be built.
- Luxuria in the agent is the plugins, BIRD and WireGuard's `wg`; what
  reaches outside (the release check, notifications) is the console's.
  A plugin is still built into the agent and the page: what makes it
  one is that it is there only where its program is installed.
