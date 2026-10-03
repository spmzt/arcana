# Using the console

The console is laid out as a tree and tabs.

- The **tree** on the left: the fleet, its hosts, and each host's jails.
  What you select decides the page. **Enrol a host** and **Add a server**
  are at its top. A host's jails are folded away until you open them
  with the arrow on the host, and the browser remembers which are open. When the jails do not fit in the space under
  the hosts, each host shows what fits and a **+N more…** row that
  shows the rest.
- **All hosts**: every host as a card with CPU, memory and ZFS, how many
  jails run, and the fleet as a graph from the console through the
  hosts to their jails; nodes are links.
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
    route deletes it; both run `route(8)`, live only.
    **Interfaces** lists the host's interfaces as the agent reads them
    with getifaddrs(3): state and link, addresses, MTU, hardware
    address, a tunnel's two ends, and traffic. An address is added
    with **+ address** and taken off with its cross; **Up** and
    **Down** change the interface's state. These are jobs that run
    `ifconfig(8)`, live only: `rc.conf` is not touched, so they do not
    survive a boot.
    Changes to interfaces and routes are made in **safe mode**: once
    the change is made, the host waits a minute to hear from the
    console again, which the console does by reading the job. If the
    change cut the host off, nothing arrives, and the host undoes it by
    itself: the address is put back with its prefix length, the
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
  themes: Tron, Amber, Matrix, Synth, Slate and the light Paper. The one
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
  browser, **Notify** allows a desktop notification when a task that
  took more than ten seconds ends, **Keys** manages security keys and
  passkeys.
