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
  raised yet). Next: the lab run of 119-1 (1.8), DHCP and SLAAC at a
  UNI, the UX tasks. Later: Mplify 119's tunnel (GRE
  carrying an MPLS label inside IPsec, BGP L3VPN), and SASE.
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
