# Using the console

The console is laid out as a tree and tabs.

- **The first host** is the machine the console runs on. Arcana installs
  the agent beside the console, so nothing is enrolled: start it
  (`sysrc arcana_agent_enable=YES`, `service arcana_agent start`) and
  the console adds it by itself, under the host's name, over the agent's
  local socket. Until then the empty page says what it waits for: no
  agent answering, or one whose socket the console's user may not use.
  The agent's rc script lets the group `arcana`, the console's, use the
  socket when that group exists. Taken off the list, the host is not
  added again; `local_agent` in `web.conf` names another socket, or
  none.
- The **tree** on the left: the fleet, its hosts, and each host's jails.
  What you select decides the page. **Enrol a host** and **Add a server**
  are at its top. A host's jails are folded away until you open them
  with the arrow on the host, and the browser remembers which are open. When the jails do not fit in the space under
  the hosts, each host shows what fits and a **+N more…** row that
  shows the rest.
- **All hosts**: every host as a card with CPU, memory and ZFS, how many
  jails run, and the fleet as a graph from the console through the
  hosts to their jails; nodes are links.
- **Network**: the fleet as a map; see [The network](#the-network).
- **API**, the light in the top bar that says whether the console
  answers, opens the console's own API as `docs/openapi.yaml`
  documents it: every route with what it is for, what it takes and
  what it answers, by group and searched; the document itself is one
  press away, for a client generator or another viewer.
- **All hosts**: the fleet at a glance. Its graph is of what runs: a
  host with its jails that are not stopped; a host's own Summary has
  all of them.
- A **host** has tabs:
  - **Summary**: usage gauges with their recent history, counts, the ZFS
    pools, and the host's jails as a graph; a jail picked in a graph,
    here or on the fleet's page, opens in a box over the page.
  - **Jails**: their state (running, stopped, dying; starting, stopping,
    restarting while something happens to them; unknown when the host
    does not answer), with start, stop, restart and kill. Those running
    come first; **Sort** orders by running or by name.
  - **Services**: the rc.d scripts, enabled or not, running or not, with
    start, stop, restart, reload, enable and disable; a service's drawer
    edits its `rc.conf` variables through `sysrc(8)`. Those running come
    first, then those enabled; **Sort** orders by running, enabled or
    name, and the other way round when pressed again.
  - **Network**: the routing table, nexthops, connections and sockets,
    per address family, as `netstat` and `sockstat` print them
    (`--libxo json`); filter the rows, click a column to sort.
    A routing table too large to send, a full BGP table say, comes as
    its first 2000 rows with how many it has; type a prefix or an
    interface in the filter and press **Search host** to have the host
    search the whole table for it.
    In the routes, **+ route** adds a static route (a destination and
    a gateway, an address or an interface), and the cross on a static
    route deletes it; both run `route(8)`. A route can be given its
    **metric** (its cost: of several routes to one destination the
    lowest is used, the others when it is gone), its **weight** (its
    share among routes of one metric), the **source address** of the
    host that what takes it is sent from, and the **routing table** it
    goes into. **fib** picks the routing table shown and changed, when
    the host has more than one.
    **Look up a route** opens a box that asks for an address and tells
    the route the host would take to it, as `route get` tells it, and
    every other route that covers the address, the most specific
    first.
    **Interfaces** lists the host's interfaces as the agent reads them
    with getifaddrs(3): state and link, addresses, MTU, hardware
    address, a tunnel's two ends, traffic in all and as it is now. An
    address is added with **+ address** and taken off with its cross;
    **Up** and **Down** change the interface's state, **Edit** its MTU
    and description. **+ interface** creates a cloned one: an epair, a
    gif, gre, ipsec or vxlan tunnel with its two ends, a VLAN on its
    parent, a bridge, and the rest; the cross on a cloned interface
    destroys it. These are jobs that run `ifconfig(8)`. A change is
    made live, and with **Keep it in rc.conf** also written there
    through `sysrc(8)`, to be there after a boot: an address as the
    next `ifconfig_<if>_alias<n>`, a route under a name of its own in
    `static_routes`, an interface in `cloned_interfaces`.
    **Netgraph** draws the host's netgraph(4) nodes and the hooks that
    join them, from `ngctl list -l`; a node is picked for its hooks,
    which are removed with their cross, shut down, or given a new peer;
    dragging the dot on a node onto another connects a hook of each.
  - **Storage**, in five views:
    **Pools**: each ZFS pool with how full and how fragmented it is,
    its health, what `zpool status` says of it and of its last scrub,
    and its devices as they are nested, with their error counts. A
    scrub is started and stopped, the pool trimmed, its errors cleared,
    a device taken offline and brought online, replaced by another,
    mirrored by another, detached from its mirror. **+ pool** makes a
    pool of the devices named, each by itself, as a mirror or as
    raidz1, raidz2 or raidz3, with where it is mounted; **+ devices**
    gives a pool more, as data or as a log, a cache, spares or a
    special device; **Import** lists the pools zpool finds on the
    host's devices that are not imported, to be picked; a pool is
    exported, and destroyed once its name is typed.
    A pool with a dataset mounted where the system lives (the root,
    or under `/usr`, `/var`, `/home`, `/tmp` and the like) is never
    destroyed or exported from here, and nothing of it is unmounted
    by force: to do so unmounts what it can, and the host, or who is
    logged in to it, is left standing on nothing. No pool is destroyed
    or exported by force at all: what uses it is stopped first.
    **Datasets**: the file systems and volumes as a tree, with what
    each uses, has available and refers to, its compression ratio and
    where it is mounted. **+ dataset** makes one, a volume when given a
    size, with properties as `name=value`; **Set** changes properties,
    or returns one to what it inherits; a dataset is mounted,
    unmounted, snapshotted, and destroyed once its name is typed. A
    pool's own dataset is not destroyed from here.
    **Snapshots**: the newest first, of all or of one dataset and those
    under it; taken with a name (the time, unless another is given),
    of everything under the dataset too when asked; rolled back to,
    cloned into a new dataset, destroyed once the name is typed.
    **Disks**: every disk as GEOM has it, with what `camcontrol` says
    it is, its partition table drawn to scale and listed. A table is
    made on a disk without one (gpt, mbr, bsd); a partition added in
    the free room, aligned to 1 MiB, labelled, resized, deleted once
    its name is typed; an empty table destroyed. **Rescan** has
    `camcontrol` look for disks that came or went.
    **Mounts**: what is mounted, with how full, and beneath it what
    `fstab` says to mount: an entry that is not mounted is mounted,
    what is mounted unmounted (never the root). **Edit** opens `fstab`
    whole; the host takes it only if every line is an entry and nobody
    changed the file meanwhile, and keeps the one before beside it as
    `fstab.arcana-old`.
    Every table here, as everywhere in the console, is sorted by the
    column picked in its head, the other way when picked again and as
    the host gave it the third time, and the filter above leaves the
    rows that have its text in any column. The datasets are a tree
    until they are sorted.
    Every change is a job, and the host checks each word of it before
    a program sees it: no word is ever an option, `-r` and `-f` are the
    job's own flags, and only the verbs named here exist. Nothing in
    storage is done in safe mode, since the host cannot take it back.
    Sending and receiving, encryption keys and making a file system
    on a partition are not done from here. From
    a shell: `arcanactl storage disks | pools | datasets | snapshots
    [dataset] | mounts`, `arcanactl zfs …`, `zpool …`, `gpart …`,
    `mount path`, `umount [-f] path`, `cam rescan`, `fstab [-w file]`.
  - **Kernel**: every file linked into the kernel, the kernel itself
    first, with its size, how many references hold it, and the modules
    in it; read from the kernel, as `kldstat -v` has it. **Load** takes
    a module's name as `kldload` finds it, without a path, and offers
    those of the module path that are not in; **Unload** asks for the
    name to be typed, since what a module does stops with it, and the
    kernel refuses one that is still used. With **at boot too** a
    module loaded is put into `rc.conf`'s `kld_list`; one unloaded
    that was there is taken out of it; and what `kld_list` names that
    is not in the kernel now is said. Arcana loads no module by
    itself: what a feature needs and is missing is said, and loaded
    here. Above the list: what the kernel and its modules take, and
    how much of the kernel's memory is in use. Below it, **Kernel
    memory**: the largest `malloc(9)` types and `uma(9)` zones, as
    `vmstat -m` and `vmstat -z` count them, which is where a module's
    own memory shows. From a shell: `arcanactl kmod`, `arcanactl [-p]
    kmod load | unload module`.
  - **Sysctl**: the kernel's state, a part of the tree at a time
    (**kern**, **vm**, **net** and the others, or from a name typed),
    read from the kernel as `sysctl -a` has it: each name with its
    value, its type, whether it is a loader tunable, and what it is
    said to be. Values that are neither numbers nor text are left
    out. The values come in parts and the table fills as they arrive,
    so **all**, the whole tree, is all of it: the agent sends the next
    part only when the one before was taken. **Set**, on a value that
    can be, puts it into a field in its row; it is set with
    `sysctl name=value` by a job, and with **at boot too** also
    written to `/etc/sysctl.conf`, where the line that set the name
    before is replaced and the rest is left as it was. What
    `sysctl.conf` sets is listed above the table, whichever part of
    the tree is shown. A jail's sysctls are not set from here. From a
    shell: `arcanactl sysctl [name]`, `arcanactl [-p] sysctl
    name=value`.
  - **How it is reached**, at the foot of the summary: the agent's
    listeners, the one the console uses, and the connections open to
    the agent now, each with its transport, where it comes from and
    the name in its certificate, read again every few seconds. The
    console keeps its connection to an agent open and sends the next
    request over it; several requests at once have one each. An agent
    that listens on TCP listens on SCTP as well, at the same address
    and port, where the kernel has SCTP. It never loads the module:
    where it is missing the listener is shown as down with the reason,
    and once `sctp` is loaded from the Kernel tab, **Try SCTP again**
    has the agent start it. **Switch to SCTP** asks the agent over
    SCTP first and changes the server only when it answers; **Switch
    to TCP** goes back the same way. Nothing falls back by itself:
    where SCTP is blocked on the way, the host does not answer until
    it is switched back. From a shell: `arcanactl transport [retry]`.
  - **Plugins** are what works through a program that has to be
    installed, not the base system's: **BIRD** (`birdc`) and
    **WireGuard** (`wg`; the interface itself, `if_wg` made by
    `ifconfig`, is the base system's and is among the interfaces).
    Each has a tab of its own, after the others and marked ◆, on a
    host where its program is installed, and none where it is not;
    on the page of a jail with a network of its own they follow that
    network's views, apart, when the program is installed in the
    jail. Nothing is asked of BIRD or `wg` on a host without them.
    **WireGuard** lists the `wg` interfaces with their peers: endpoint,
    allowed addresses, last handshake, traffic. **Make its key** has
    the host make the interface's private key, which stays on the host:
    the console is told, and shows, public keys only, and what `wg`
    prints with keys in it is kept out of the trace. **+ peer** adds a
    peer by its public key; the cross removes one. Kept for a boot, an
    interface is written with its key, addresses and peers to
    `/usr/local/etc/wireguard/<if>.conf` for `wg-quick`, readable by
    root alone, and named in `wireguard_interfaces`: that needs the
    `wireguard-tools` package on the host.
    **BIRD** draws the routing daemon in the middle and around it its
    BGP neighbours (their AS and address), its OSPF neighbours and its
    RPKI caches, each coloured by its state. A neighbour picked, in the
    drawing or in the table under it, opens in a box: what the daemon
    says of it (session, timers, each channel's table, its import and
    export filters, how many routes came and went, and all the rest
    `show protocols all` prints), **restart**, **reload**, **disable**
    and **enable**, and the part of the configuration that makes it, to
    be changed there.
    Under it, what the configuration is made of, read from the host:
    **filters and functions**, what BGP and OSPF take in and give out,
    each edited as it is written; **communities and sets**, the named
    lists filters test against, edited as a list, one entry a line, a
    community as `(AS, value)` and a large one as `(AS, a, b)`;
    **RPKI**, the caches with their state and the ROA tables with how
    many origins each holds, and **+ cache**, which adds the tables,
    the protocol and a function `rpki_invalid()` for filters to ask;
    and the protocols and the rest, with **+ BGP neighbour** and
    **+ OSPF** to start one from an outline. **Configuration** edits
    the whole file; a configuration in several files has a list to
    pick from.
    A change is put back as the whole file with that part changed.
    The host has `bird -p` parse the whole configuration first: what
    it refuses does not stay, the box says what bird said, and what
    was typed is kept. Then BIRD is told to read it. The file as it
    was is kept beside it as `<file>.arcana-old`.
    A change is made in **safe mode** unless that is turned off beside
    **Configuration**: BIRD is told to take the new configuration back
    by itself (`configure timeout`), and a few seconds later the page
    says that it stays (`configure confirm`), which it can only do if
    the console still reaches the host. If it cannot, BIRD goes back to
    what it ran when the time is up, and the host puts the file back as
    it was. While a change waits, another is not taken, and BIRD is not
    told to read its configuration by hand: that would stop its timer.
    A BIRD that answers and does not take a configuration leaves the
    file as it was. One that stops answering while it is told, or
    after, is not undone: the file parses, bird said so, and stays in
    place for BIRD to read when it is started again; the host starts
    nothing by itself. A BIRD that does not run gets the file all the
    same, though not in safe mode, which is BIRD's own.
    In a neighbour's box each channel's **import and export filter is
    chosen from a list** of the filters the file has, with `all` and
    `none`; the choice is written into the neighbour's part of the
    configuration when it is saved. A filter written out in place, or
    a condition, is left to be changed in the text.
    **Routes** shows what BIRD's tables hold: for a prefix, or for an
    address the route that covers it; those learned from a neighbour
    or sent to it (also from the neighbour's box); those of one table;
    and with what they carry, a BGP route's path and communities. The
    host counts first: more than 2000 routes are not fetched, and the
    count is said instead. From a shell: `arcanactl bird routes …`,
    `arcanactl -s bird config -w file`, `arcanactl bird confirm`.
    Changes to interfaces, routes, a jail's address made here and
    service variables are made in **safe mode** where they can be: once
    the change is made, the host waits a minute to hear from the
    console again, which the console does by reading the job. If the
    change cut the host off, nothing arrives, and the host undoes it by
    itself, and only what the change changed (an interface that was up
    already is not brought down for having been told to come up): the address is put back with its prefix length, the
    interface brought back up, the route added or deleted again. The
    job then reads "not confirmed within 60 s: undone". Only a route
    deleted without a gateway cannot be put back, and the console says
    so before it does it.
  - **Packages**: what `pkg` can upgrade on the host or in a running
    jail, with **Check**, a dry run, and **Upgrade** of the selected
    packages or of all.
  - **Jobs**: the host's own record of what it was asked to change, by
    this console or with `arcanactl -q`; a row opens its workflow.
    Above the list it says what the agent is doing now that is not a
    job, a request somebody waits for such as a check of the packages,
    since when, and whether the agent was told to stop and waits for
    it: the same as its log says.
- A **jail with a network of its own** (vnet) has that network on its
  page, under **Network**: the same views as a host's network tab
  (interfaces, routes with lookup, connections, sockets, netgraph,
  WireGuard, BIRD with its neighbours and its configuration), for the
  jail. It is read and changed from the host: there is no agent in the
  jail, and nothing is installed there for it. `ifconfig`, `route`,
  `netstat`, `sockstat` and `ngctl` are the host's, run for the jail;
  `birdc`, `bird` and `wg` are the jail's own, run in it, so that what
  parses a configuration is the version that runs it. What is kept for
  the jail's next start is kept in the jail's own `rc.conf`, its BIRD
  configuration and WireGuard files are the jail's, and they are never
  followed out of the jail through a link. Safe mode works there as on
  the host. From a shell: `arcanactl -j jail net …`, `interface …`,
  `route …`, `wg …`, `bird …`.
- **An interface gets into such a jail from its host**: **+ from host**
  above the jail's interfaces gives it one the host has (`ifconfig
  vlan100 vnet jail`), or, with the field left empty, a new `epair`
  made for it: the `a` end stays on the host, to be put in a bridge or
  given an address there, the `b` end goes to the jail. The host's
  interfaces are offered in a list, and so are its bridges, for the
  pair's end on the host to be made a member of one. **To host** on
  a row takes that interface back. Kept, it is the jail's
  `vnet.interface` in `jail.conf`, and a new pair is in the host's
  `rc.conf`, so the jail has them again after a boot. The host refuses
  to give away the interface the console reaches it by, unless asked in
  safe mode. From a shell: `arcanactl [-p] interface name give | take
  jail`, `arcanactl [-p] interface epair give jail [bridge]`.
- A **jail** has its page: actions, addresses (changed live with
  jail_setv(3) and the interface alias, persistently in its `jail.conf`
  block with a diff to preview, or both), its configuration as jail(8)
  reads it, and its history.
- **Activity** at the bottom: every call to a host, with its workflow as
  a graph from the API call through the session check and the cblink
  request to each call the agent made; a box picked in the graph shows
  its details in a pane beside the graph, which stays in view while the
  graph scrolls. The same pane shows the operation's **CBOR schema**:
  its request and reply as maps keyed by attribute number, in CDDL, with
  the attribute sets they nest, taken from the family's own description
  (`share/arcana/arcana.yaml`); **{ } Schema** turns it off and on. When
  a program ran, **Raw output** shows its argv, exit status and output. Changes are jobs the
  host runs on its own: the graph fills in stage by stage, and a change
  that cuts the console off still completes. An entry still under way
  has a cross: for a job, it takes the job out of the host's queue if
  it has not started (one that runs is left to finish: stopping a
  change half way is what would not be safe); for a reading, it stops
  waiting for it. A reading that takes long, such as the packages, is
  asked for once: leaving its tab and coming back waits for the same
  answer. **Queue** is on unless
  you turn it off in that browser: a change waits in the activity bar
  until you press **Run**, and what waits is sent to each host as one
  batch, run in order, whichever host is selected then; a change can be
  taken out of the queue with its cross; off, a change is sent at once.
- The tree, the activity bar, the list of tasks in it and the service
  drawer are resized by dragging their edge; the browser keeps the
  sizes, and a double click on the edge goes back to the usual one.
- **Settings** has the console's version, and under **Look** its
  themes: Tron, Amber, Matrix, Synth, Slate, Onyx (black, white and one
  red, in a plain face, without glow) and the light ones: Paper,
  the warm Sand, the cool Mist and the green Mint. The one
  picked takes at once and is kept in that browser. A theme is a set of
  colours in `web/style.css` (`html[data-theme="…"]`): the accent, the
  surfaces and the text, which everything else is drawn from.
- On a phone the tree is one line under the top bar, showing what is
  selected; a tap unfolds it, and picking something folds it again. The
  top bar's buttons are a row of their own, tables scroll inside
  themselves, and notifications appear above the activity bar.
- **Settings** in the top bar changes the console's own settings: the
  name keys show, the release check and its feed, the `arcana-agent` it
  sends, and the repository and branch a host builds it from. They are
  kept in `settings.json` in the data directory and override `web.conf`;
  a field put back to `web.conf`'s value follows it again. The relying
  party, the origin, the data directory and the certificates are shown
  there and changed only in `web.conf`: keys are bound to the first two,
  and all are read once, at the start. Whoever can log in can set the
  repository, and so decides what is built and sent to every host as
  root.
- In the top bar: **FX** turns the blur and idle animations off for this
  browser, **Notify** allows a notification when a task that
  took more than ten seconds ends, and has this browser told of changes
  made in the others (below), **Keys** manages security keys and
  passkeys.
- **Notifications on other devices**: a change asked for in one browser
  is told, when it ends, to every other browser where **Notify** was
  allowed, whether or not the console is open there: the phone hears of
  what was done at the desk. It is Web Push: the browser subscribes with
  its vendor's push service (Google's for Chrome, Mozilla's for Firefox,
  Apple's for Safari, where the console must be installed to the home
  screen first), and the console posts the message there, encrypted for
  that browser alone (RFC 8291) and signed with the console's own key
  (VAPID; `vapid.pem` in the data directory). The push service sees who
  sends and to whom, not what. The console must be able to reach those
  services over HTTPS, port 443, and the page must be served over HTTPS
  for a browser to subscribe. **Settings** lists the devices
  (`push.json`) and removes one; a device whose browser dropped the
  subscription is forgotten by itself. Up to 16 devices.

- **On a phone** the tree of hosts is a drawer that slides in from the
  left (☰), the top bar is one row with the rest behind **⋮**, a
  dialog is a sheet from the bottom, a row of choices is one line that
  is scrolled, and a table keeps its first column in sight while the
  others are scrolled.
- On a phone that has no theme chosen the plain **Slate** is used;
  Tron and the others are chosen in Settings as anywhere.
- **Recent tasks** along the bottom: the last few, each with its host,
  how it ended and how long it took, always in sight; one picked opens
  the list at it, where each also has the time it began. The tasks
  that ended are kept in the browser and are still there when the
  page is opened again, without their traces.
- **Connections** and **Sockets**, in a host's network, are read again
  every two seconds while they are shown, without a task of their own
  in the activity; **Live** pauses that.

## The network

**Network** in the tree shows the fleet as a map. Nothing is configured
for it: the console reads each host's interfaces every few seconds and
works the links out.

- A **link** is drawn only between hosts of this console: a tunnel
  whose far end is an address of another host, a point-to-point address
  whose peer is one, or two hosts with addresses in the same network.
  Three or more hosts in one network join a node of its own. A link
  carries its traffic: its width and the dots that run along it follow
  the rate of the interface behind it.
- **Routing** is drawn too, from what each host's BIRD says: a BGP
  session or an OSPF adjacency between two hosts as a link of its own
  kind, and a neighbour that is not a host of this console as a small
  node beside the host that speaks to it, with its AS or router ID;
  picking one opens that host's BIRD. **Peers** hides them.
- With nothing picked, the panel lists every **WireGuard session**: each
  peer of each host, by the other host's name when it is one, with its
  endpoint and when it last shook hands.
- A **host** is dragged to where it should be, and stays there in that
  browser; the map is dragged to move it, the wheel zooms, and on a
  phone two fingers do. **Fit** shows every host, **Arrange** puts them
  back on a circle. Once the map was moved or zoomed it is not fitted
  again unasked, so nothing shifts under the hand.
- The **legend** names the kinds of lines, and each is picked to take
  that kind out of the map and to put it back: tunnels, point to point
  links, shared networks, BGP and OSPF with their neighbours outside,
  jails' ties to their hosts, and the route traced with its
  alternatives.
- A host the console reaches by a **local socket**, its own, is not on
  the map when there are hosts reached over the network.
- A host or a link is picked for its **details** beside the map: the
  host's interfaces with their addresses and a chart of each one's
  traffic, in above the line and out below it; a link's two ends.
  With nothing picked, what the whole fleet receives and sends over
  time, and its busiest interfaces. **Jails** hangs each host's running
  jails under it.
- A **running jail with a network of its own** (vnet) is a node itself,
  drawn with a dashed edge under its host and tied to it: it has its
  interfaces and their traffic, its tunnels, its BGP and OSPF sessions
  and its neighbours outside, as a host has. A tunnel is drawn from or
  to it as with a host, a route is traced from it and through it, and
  **Its network** opens the jail's page. All of it is done by the
  jail's host.
- A **tunnel is made by drawing it**: drag the dot on a host's edge
  onto another host. The console offers the outer addresses the two
  reach each other by and a free pair of inner ones, asks for the kind
  (gif, gre, WireGuard, vxlan), and creates an interface on each host,
  the two ends of one tunnel. For WireGuard each host makes its own key;
  once both have one, each is given the other as its peer, by its
  public key, at its outer address. WireGuard peers that are interfaces
  of two hosts of the console are drawn as a tunnel. Each is made in safe mode, and kept in `rc.conf`
  unless told otherwise. A tunnel picked on the map is destroyed with
  one button, both ends.
- **Route between hosts** asks each host on the way which route it
  takes to an address (the agent's `route-lookup`), follows the gateway
  to the host that has its address, and draws the way over the map hop
  by hop, until the address is reached, the way leaves the hosts of this
  console, or it comes back to where it was. Beside each hop are the
  routes that would be taken in its place when the best one goes, drawn
  dashed.

