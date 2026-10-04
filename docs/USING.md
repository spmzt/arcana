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
    route deletes it; both run `route(8)`. **fib** picks the routing
    table shown and changed, when the host has more than one.
    **Lookup** asks the host for the route to the address typed in the
    filter: what it would take, as `route get` tells it, and every
    other route that covers the address, the most specific first.
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
  red, in a plain face, without glow) and the light Paper. The one
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
  browser; the map is dragged to move it and the wheel zooms. **Fit**
  shows every host, **Arrange** puts them back on a circle.
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

