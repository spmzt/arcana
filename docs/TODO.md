# TODO

## To do

- WireGuard: preshared keys; a peer's key rotated.
- Storage, beyond what there is: `zfs send` and `receive` between
  two hosts (on one host it is done; between two it needs the agents
  to reach each other, which is the mesh's); a key that is typed, for
  a dataset whose keylocation is prompt, without it being kept in a
  job; a key changed; file systems other than UFS made; a disk's
  self-test started; a vnet jail's datasets from the jail's own page.
- The firewall, further, in the page: a rule's words offered as they
  are typed; rules moved by dragging; a hit counter drawn over time.
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
- Workflows: a chain of steps kept by the console and run by it on
  several hosts at once. As decided:
  - The spec is the schema the steps are made from: a table in
    `arcana.yaml` of which attributes each kind of job uses and which
    it needs, carried into `schema.json`, so that the editor's forms
    and the console's checks come from it and a new kind is there
    without more code.
  - A step is a job of any kind, with a condition before it (a read
    operation and a test on its reply) and what follows a failure:
    stop, go on, or another step. Values may be parameters asked for
    when it is run, the host, or what an earlier step answered.
  - Triggers: by hand, at an interval, and on events, both asked for
    by the console (a host that stopped or began answering, a
    threshold crossed, a jail's state) and told by the agent (cblink
    notifications).
  - A workflow that runs by itself may hold a destructive kind (a
    pool destroyed, a partition table, an agent replaced) only when
    it is marked so by hand.
  - Runs kept, each host and step with its trace; the chain drawn as
    a graph, and a run as that graph coloured as it goes; the queue
    saved as a workflow.
- Gula, further: older samples thinned instead of dropped; a jail's
  share of the CPUs and memory as rctl accounts it, not only added up
  from its processes; a threshold on a disk, an interface or a
  jail; the kernel's messages followed as they come (not read whole
  each time); dmesg for an agent that is not root, which the kernel
  refuses unless security.bsd.unprivileged_read_msgbuf is on.
- The page on a phone, further: a card's title the column that names
  the row best (a process's command, not its number); the row's
  actions behind one menu when there are many; the map and the
  firewall's chain drawn for a narrow screen.
- SCTP, further: what comes in parts as a cblink stream (each on an
  SCTP stream of its own, flow-controlled by itself) instead of a
  dump, so that it can share the association too; a burst of first
  requests to a host opens an association each until one is shared,
  and the others are closed then.
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
