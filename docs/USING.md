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
- **Workflows**: chains of steps the console keeps and runs on
  several hosts at once. A step is a job of any kind, its fields
  those `share/arcana/jobs.yaml` says the kind needs (marked) and
  uses, with a choice where a field is one of a few; or a read of the
  host (hello, jails, services, stats, events, history, packages)
  whose answer a later step looks at; or one of Arcana's own, from
  the repository the console builds from (`agent_source`): **is its
  repository newer** asks the step's host for the commit at its head
  (`git ls-remote`, nothing cloned) and answers `new_agents`,
  `new_console` and `new` (either), each true when the head is not
  what the agents, or the console, were last updated to; **build the
  agent** has the host build arcana-agent, kept by the console;
  **update every host's agent** sends it to every host, each
  restarted with it; **update the console** builds and installs all
  of Arcana on the host the console runs on (a server added by its
  local socket), the console restarting once the step has ended. What
  was built and updated to is kept in `arcana-source.json`. **Only
  when…** puts a condition
  before a step: a read made then, or what an earlier step answered,
  a path in it (`jails[name=web].state`, `host.hostname`) and a test
  (eq, ne, contains, gt, lt, exists, missing); a step whose condition
  fails is skipped. **When it fails** the host's run stops, goes on,
  or goes on at a later step, those between not run. A value may be
  `${param.NAME}`, asked for when it runs with its default offered,
  `${host.id}` or `${host.name}`, `${step.ID.PATH}`, what an earlier
  step answered, or `${event.PATH}`, of the event that began the run.
  A workflow runs by hand (**Run**, on the hosts picked), **every** so
  many seconds, or **on** events: those the console sees itself, a
  host that stopped answering (`host-down`), that answers again
  (`host-up`), a jail whose state changed (`jail-state`), and those the
  host tells (`threshold`, `kmsg`, `link` and the rest), each with what
  it must match (`what=mem`); an event's run is on the host it happened
  on. One that runs by itself may hold a step that destroys (a dataset
  destroyed, an interface, a partition table) only when **It may
  destroy, by itself** says so. Each run is listed with what began it
  and how each host's went; a run is drawn as its chain, a row for each
  host, each step coloured by how it went, and a step picked shows its
  trace. What waits in the queue becomes a workflow with **As a
  workflow**, and **From a template…** starts one made already, to be
  looked over and saved: Arcana kept up to date from its repository
  (every hour: the check, then the agent built, sent to every host,
  and the console updated, each only when the head is newer), a jail
  started again when it stops, packages upgraded every week, and a
  service restarted when its host answers again. The console keeps the workflows in `workflows.json` and
  the last 30 runs in `runs.json`; what runs by itself is started by
  one worker of the console's, the one holding `workflows.lock`.
- **SD-WAN**: the SD-WAN services the console keeps, as MEF 70.2
  says them; see [SD-WAN](#sd-wan).
- **Utilization**: how busy every host has been, as lines over the
  last five minutes, quarter of an hour, hour, or all that is kept.
  Each agent looks at its host by itself, every five seconds and an
  hour of it until it is told otherwise, so the lines are there when
  the page is opened; while it is open, what came since is added.
  **Sampling**, at a host's name, says how often its agent looks and
  how many samples it keeps, with what that takes of the agent's
  memory (about 70 KiB for the hour, on a host with five interfaces
  and three disks: 8 bytes a sample and 4 for each figure in it), and
  sets both; with 0 kept the agent does not sample at all and holds
  nothing. The agent keeps what it was told in
  `/usr/local/etc/arcana/history.conf`, and the samples themselves
  beside it when it stops and every five minutes, so that a restart
  of the agent keeps the graphs. The same form sets the limits: a
  CPU, memory or swap figure over its limit makes an event, and
  another when it is back under (five points lower), listed under
  events in the Log tab; the defaults are 90, 90 and 50 percent, and
  0 is no limit. **Limits of an interface, a disk or a jail**, a line
  each, do the same for one of them: `net:igb0=125000000` (bytes a
  second, in and out together), `disk:ada0=50000000` (bytes a second,
  read and written), `jail-cpu:web=80` (percent of one CPU) and
  `jail-mem:web=1073741824` (bytes); back under is a tenth lower. Each
  running jail's share of the CPUs and its memory are drawn under the
  disks, a jail picked at a time, as the kernel's resource accounting
  has them: that needs `kern.racct.enable=1` in `/boot/loader.conf`
  and a reboot, which the page says when it is off. Under **Network** are the
  host's interfaces, without the loopback, each with what goes over
  it now: **all** draws them added up, one pressed draws that one;
  a bridge and its members are each counted, so **all** counts a
  bridged packet more than once. Under **Disks** the same for each
  disk. From a shell: `arcanactl history`, `arcanactl history set
  seconds samples`. With more than one host, their CPU, memory and
  load are first drawn over one another, a colour each. Then each host
  has a box of its own, which folds: the CPUs' busy share, the memory
  in use with the swap as a dashed line, the load, what the network
  received and sent, and what the disks read and wrote, each with its
  average or peak over what is shown. A gap in a line is when the
  host was not sampled. The host's name opens the host.
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
    per address family; filter the rows, click a column to sort. The
    routes are asked of the kernel itself, through netlink, so each
    comes with what the kernel knows of it: its metric, its weight,
    the address it sends from, its table. The connections and sockets
    come from the kernel's own lists of them, as netstat and sockstat
    read them, with the same columns: who holds a socket, its command
    and descriptor, and `?` for one nobody holds any more. A host's
    own are read by the agent itself, a jail's by its helper inside
    the jail; netstat and sockstat are not run for them.
    **Neighbours** are ARP's and NDP's, asked of the kernel through
    netlink as the routes are: each with its link-level address,
    interface, state (reachable, stale, delay, probe, incomplete, or
    permanent for one set by hand) and whether it is a router; read
    again every two seconds while Live is lit. `arcanactl net
    neighbours [-4 | -6] [text]`.
    The routes, connections and sockets come in parts over the
    console's stream as the host reads them, so a table of any size,
    a full BGP table say, arrives whole: the first time the table
    fills as the parts come, and read again (as connections and
    sockets are every two seconds while **Live** is lit) the table
    shown stays until the new one is whole. Where the page has no
    stream, a table of more than 2000 routes comes as its first 2000
    rows with how many it has, and **More** reads on; type a prefix or an
    interface in the filter and press **Search host** to have the host
    search the whole table for it.
    In the routes, **+ route** adds a static route (a destination and
    a gateway, an address or an interface), and the cross on a static
    route deletes it; both are asked of the kernel through netlink. A
    gateway may be several addresses with commas between, each with
    its share after an `@` (`10.0.0.1@2,10.0.0.2`): that is one route
    with as many next hops (ECMP), which the table shows as a row for
    each, **Path** saying which of how many; a route's **Nhop** opens
    its next hop in a box (its type, gateway, interface, MTU, flags
    and how many routes use it), or for a route of several ways the
    group they share with what each way carried, and **Nexthops**, in
    **Groups**, as the group the kernel made of them: each
    group a row, its next hops one under the other, each with its
    gateway, interface and a bar of its share. Under each group, what
    it carried, from the samples the agents keep (the history): on
    the left what the host **sent** by each next hop's interface, on
    the right what the gateways **received**, on the interface with
    the gateway's address, where the gateway is a host of this
    console. Each is a chart of columns over the last 5, 15 or 60
    minutes, every column the shares of that moment stacked to the
    whole, with the weights dashed across where the shares would
    meet if they were kept; beside it each next hop's share against
    its weight, and its rate. An interface's traffic is all of it,
    not only the group's, and next hops by one interface are one
    share: the samples cannot tell them apart. A jail's groups have
    no chart, its interfaces not being sampled. A second route to a
    destination that has one makes such a group too; one way of it
    is deleted by its gateway. A route of several gateways is not
    kept in `rc.conf` from here. A route can be given its
    **metric** (its cost: of several routes to one destination the
    lowest is used, the others when it is gone), its **weight** (its
    share among routes of one metric), the **source address** of the
    host that what takes it is sent from, and the **routing table** it
    goes into. **fib** picks the routing table shown and changed, when
    the host has more than one.
    **Look up a route** opens a box that asks for an address and tells
    the route the host would take to it, as the kernel tells it, and
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
  - **Storage**, in six views:
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
    An encrypted dataset says so, and whether its key is loaded:
    **Load key** reads the key from where the dataset's `keylocation`
    says (a file, a URL), **Unload key** forgets it; a key that is
    asked for at a prompt is never typed into the console, and is
    loaded on the host. One is made encrypted with the properties
    `encryption=on`, `keyformat=` and `keylocation=file:///...`.
    **Jail** gives a dataset to a running jail to manage as its own
    (`zfs jail`), **Unjail** takes it back.
    **Health**: how each disk says it is: well or failing, its
    temperature, how long it has been powered on, how worn it is, and
    the errors it counts. An NVMe disk is asked with `nvmecontrol`,
    any other with `smartctl` when the host has smartmontools.
    **Snapshots**: the newest first, of all or of one dataset and those
    under it; taken with a name (the time, unless another is given),
    of everything under the dataset too when asked; rolled back to,
    cloned into a new dataset, destroyed once it is confirmed (a
    snapshot's name is not typed: a dataset's still is). Each row has
    a box to pick it, and **All** picks every snapshot shown, as the
    filter leaves them (a dataset's name, a date in the name):
    **Destroy N** destroys those picked at once, after one question,
    as a batch of jobs, one each, so that one refused (a clone was made
    of it) leaves the others destroyed.
    **Resnapshot**, on the newest snapshot of a dataset, takes it
    again, now, under the same name, and lets the old one go: the new
    one is taken first under a name of its own, the old one destroyed,
    and the new one renamed, so that there is a snapshot all along;
    one zfs will not destroy (held, cloned) stays as it was.
    **Resnapshot N**, beside Destroy N, does it to every picked
    snapshot that is the newest of its dataset, in one batch, a job
    each; **Pick the newest** picks the newest snapshot of each
    dataset shown. From a shell: `arcanactl zfs resnapshot [-r]
    dataset@snapshot`.
    **Replicate** sends a snapshot into a dataset that is not there
    yet, on the same host (another pool, say): `zfs send` into `zfs
    receive`, all of it or what changed since a snapshot both have,
    with the datasets under it when asked. What arrives is not
    mounted. **To** another host sends it there: `zfs send` on this
    host and `zfs receive -u` on that one, each as a stream on the
    connection the console has with it, the console carrying the
    bytes at the pace the slower of the two takes them; never with
    `-F`, so nothing there is overwritten, and never into a pool's own
    dataset. What is sent between hosts is listed above the snapshots,
    on both hosts' pages, with what it carried, how it ended, what zfs
    said when it did not, and **Stop** while it runs; the console
    keeps the last 32 in `transfers.json`, and one its restart cut is
    said to be interrupted.
    **Disks**: every disk as GEOM has it, with what `camcontrol` says
    it is, its partition table drawn to scale and listed. A table is
    made on a disk without one (gpt, mbr, bsd); a partition added in
    the free room, aligned to 1 MiB, labelled, resized, deleted once
    its name is typed; an empty table destroyed. **Rescan** has
    `camcontrol` look for disks that came or went. On a partition
    of type freebsd-ufs, **newfs** makes a UFS file system, with a
    label when given one, and **growfs** grows the file system to the
    partition's size. The host refuses newfs while the partition is
    mounted, swapped on or a pool's device, and, unless told that it
    may, while it has a file system on it.
    **Mounts**: what is mounted, with how full, and beneath it what
    `fstab` says to mount: an entry that is not mounted is mounted,
    what is mounted unmounted (never the root). **Edit** opens `fstab`
    whole; the host takes it only if every line is an entry and nobody
    changed the file meanwhile, and keeps the one before beside it as
    `fstab.arcana-old`.
    **Swap**, beneath: the devices the host swaps on, with how much of
    each is used; **+ swap** swaps on a device more and **Swap off**
    takes one away, until the next start, for which swap is a line
    of `fstab`.
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
  - **Firewall**: ipfw(8), laid out as a ruleset is written here. A
    main chain that every packet walks in the order of the numbers,
    and the parts it calls, each ending in its return; **Layout**
    lists them, and each has a tab of its own with the rules whose
    numbers are its:

    | Numbers | Part |
    |---|---|
    | 1–8 | Outgoing jump |
    | 9–99 | Before incoming NAT |
    | 100–199 | Incoming NAT |
    | 200–299 | Check-state after incoming NAT |
    | 300–399 | Incoming NAT64 |
    | 400–499 | After incoming NAT |
    | 500–599 | Before outgoing NAT |
    | 600–699 | Outgoing NAT |
    | 700–799 | Check-state after outgoing NAT |
    | 800–999 | After outgoing NAT |
    | 1000–8999 | IPv6 and IPv4, to me and from me, before and after NAT: eight parts of a thousand each |
    | 9000–9099 | IPv6 link-locals only |
    | 9100–9199 | Silent drop |
    | 9200–9999 | Dangerous packets |
    | 10000–13999 | IPv6 and IPv4, incoming and outgoing forward |

    A part's table has each rule with its counters and where it is:
    in the kernel now, kept, or both. A rule is added with its number
    and its words as ipfw takes them, **now** (into what the kernel
    has), **keep** (into the kept rules), or both, and deleted the
    same ways. The kept rules are a file of ipfw's own commands, one a
    line (`add 01001 allow tcp from any to me6 22 in`, and `table`,
    `nat` and `nat64…` lines), which the host loads when it starts;
    **Kept rules as text** shows it to be changed as a whole, checked
    by ipfw without being done, and for a host that has none **Start
    from the layout** fills it with the chain, its calls and returns.
    When rc.conf's `firewall_type` names a file of the host's own,
    which the firewall loads now, **Load the current file** puts that
    file in the text as kept rules: what applying does itself
    (`flush`, `set`, `delete`) left in as comments and the options
    before a command (`-q`, `-f`) taken off, nothing kept until
    **Keep**.
    **Apply the kept rules** makes them the whole ruleset without a
    gap: they are loaded into set 1 while it is disabled, and set 1
    is swapped with set 0, so no packet meets half a ruleset. The
    rules that were there wait in set 1: if the console does not
    reach the host afterwards, the host swaps them back by itself.
    **Turn on** is taken back the same way. A rule's words are
    checked to be ipfw's, with nothing a shell would read, and the
    sets are not a rule's to name. ipfw must be in the kernel; Arcana
    does not load it. From a shell: `arcanactl net ipfw`, `arcanactl
    [-p] ipfw add number rule…`, `ipfw keep add …`, `ipfw [keep]
    delete number`, `[-s] ipfw apply`, `ipfw enable | disable`,
    `ipfw rules [-r | -w file [-n]]`, `ipfw trace address [seconds
    [packets]]`.
    While the Firewall tab is shown its parts are in the side bar, in
    place of the hosts: **Overview**, **Dynamic states**, **Kept rules
    as text**, then a line for each part with how many rules it has;
    **‹ Hosts** brings the tree back, and **Layout ›** the parts. The
    light beside the counts is the switch: it shows whether the
    firewall is on, and pressed turns it off or on. A rule is pressed
    to change it in its own row: its number, its words as they are
    kept, now and keep; saved, the old one is deleted where it was and
    the new one added where it is to be. As a rule is typed, the words
    that may come next are offered in ipfw's order: the action, what
    the packet is, `from` and an address (the host's tables among
    them), `to`, and the options. **Dynamic states** are the
    connections the stateful rules let through, as `ipfw -D show` has
    them: the rule that made each, its flow, counters and how long it
    still lives, read again every two seconds; one pressed leads to
    its rule.
    **What Apply would change** sets the kept rules beside those of
    the kernel: the rules Apply would add, those it would remove, and
    those whose words differ, which may be only how ipfw writes a
    rule back. **Follow a packet** asks for a protocol, where from,
    where to, a port, a direction and an interface, and walks the
    first packet of such a connection through the kernel's rules:
    each rule it meets, each jump, call and return, and what becomes
    of it. A rule the page cannot judge (`me`, a state, an option it
    does not know) is taken as met and marked; it is a reading of the
    rules, not the kernel's own answer. The kernel's own answer is
    **What the kernel decides**, below the page's reading, or
    `arcanactl [-j jail] ipfw trace address`: for some seconds the
    packets to or from the address that really cross the firewall,
    each with the rule that decided it and what it decided, its
    interface and direction, as ipfw's `rule-matched` probe tells
    dtrace(1); the host needs dtrace (`kldload dtraceall`). In a part, a rule's packets
    are followed by how many a second it took since the look before,
    and a line of what it took a second at the last looks (the last
    five minutes: a part shown is read again every five seconds while
    **Live** is lit), and **never** when none has matched it; a rule being changed has
    ▲ and ▼, which put a number before the rule above or after the
    one below into its field, for Save to move it there; a rule
    dragged and dropped before or after another of its part opens
    the same way, with a number between the two.
    **Tables** lists each table with its type and what is in it: an
    entry is added and taken out, a table created and destroyed.
    **NAT and pipes** shows the NAT instances and dummynet's pipes as
    ipfw shows them. A NAT instance is asked for by what it is: its
    number, the interface or address it hides behind, its options
    (same ports, private only, reset, deny in, log) and the ports it
    sends on, one a line (`tcp 10.0.0.5:80 8080`); a pipe by its
    number, bandwidth, delay, loss in percent, queue and whether each
    source or destination address has a pipe of its own. One line
    more makes, changes or deletes anything else (NAT64, NPTv6, a
    queue, a scheduler, a delete) in ipfw's own words. With **keep**, what is done to a table or an
    instance is also a line at the head of the kept rules; and what
    undoes it takes its lines out again: a table or an instance
    deleted (`destroy`, `delete`) all of its lines, a table flushed
    its entries, an entry deleted its own. **Logged
    packets** reads what the rules with `log` wrote into
    `/var/log/security`. A running jail with a network of its own is
    listed under the host in the side bar: its firewall is its own,
    ipfw is run inside it, its rules are kept in the jail, and on or
    off is as the jail's own network has it.
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
  - **Processes**: what runs on the host, as `top` shows it: each
    process with its user, jail, state, nice value, threads, the
    memory it holds (Res) and has mapped (Size), CPU, WCPU, I/O, the
    CPU time it has used, and its command. **CPU** is what it used
    between the two last looks, in percent of one CPU; **WCPU** is
    the kernel's own, slower figure; **I/O** is blocks read and
    written a second. **by CPU / WCPU / Memory / I/O** puts the most
    first, and any column's head sorts by it; the table is read again
    every three seconds while **Live** is lit. **all** or a jail's
    name picks whose processes; **kernel** shows the kernel's own
    too. A process pressed opens under its row: its whole command
    line, its parent, what it waits on, and a **Signal** to send
    (TERM, KILL, HUP, INT, QUIT, STOP, CONT, USR1, USR2, ABRT), which
    is asked about first, and a **Nice** value to give it, -20 to 20.
    Both are jobs. The agent checks that the process is still the one
    that was shown, by when it started, and refuses init, the
    kernel's own and itself. Above the table, each jail's processes
    are added up (how many, their CPU, their memory); one pressed
    shows that jail's alone. A process opened also lists what it has
    open (files, sockets with their addresses, pipes) and its threads
    with what each waits on; another user's files are shown to a
    root agent only. From a shell: `arcanactl [-j jail] ps [pid]`,
    `arcanactl signal pid [name]`, `arcanactl renice pid nice`.
  - **Events**, the last entry of the Log tab's list of logs: every
    route, interface, address and neighbour of the host that came,
    went or changed, as the kernel told the agent of it through netlink the
    moment it happened, the last 512 kept. A storm of routes (a BGP
    session coming up) is counted for each second and not listed. A
    jail with a network of its own (vnet) is watched as the host is,
    from the moment it is made or the agent starts, and its events
    say its name (in the Host column); removed, it is let go at once,
    not held. Each is shown the moment the
    agent tells it: the console subscribes to the host's events
    while they are shown, and passes each to the page over its
    stream; asked for every few seconds only where there is no
    stream. This is what the workflows' triggers will be made of.
    From a shell: `arcanactl events [after]`, or `arcanactl events
    -f` to follow them as they happen.
  - **Log**: what syslogd wrote, a file of `/var/log` at a time,
    `messages` first, the newest line on top. A line of syslog's is
    taken apart into its time, host, program, PID and message, in
    either form syslogd writes. While **Live** is lit, what is
    written is read every three seconds and added, as `tail -f`
    would; a file turned over by newsyslog is read from its start.
    **Search** looks for a text in the end of the file on the host,
    in either case; the filter narrows what is on the page.
    **Older** reads further back. **host** or a running jail's name
    picks whose `/var/log` is read. A packed log (`.bz2`, `.gz`,
    `.xz`, `.zst`) is unpacked to be read, whole. **dmesg** is the
    kernel's message buffer, followed as it comes: the agent reads it
    every second and numbers each new line, which the page shows the
    moment it is told, none twice and none missed (a second with more
    than twenty has the rest read at once). **audit** is the audit trail of now,
    where the host keeps one. Where syslogd writes a level (`-v`),
    it is a column. A line with a word of trouble in
    it (error, fail, denied, panic) is marked red, one of doubt
    (warn, invalid, cannot) amber: the file itself has no level.
    Files newsyslog has packed are not read. From a shell:
    `arcanactl log [-o lines] [-f position] [name [text]]`.
  - **Over SCTP**, the requests the console makes of a host at once
    all go over one association, which a thread of the console runs,
    each waiting for its own answer: the agent sees one session where
    over TCP it would see one for each. The first requests to a host,
    when they come at once, make one association: the first makes it
    and the others wait for it, a while. What comes in parts (the
    kernel's state, the routes, connections and sockets) is a cblink
    stream over that same association, flow-controlled by itself: the
    host sends a part only while the page has room for it, which the
    page gives back as it takes them, so a slow page holds its own
    stream and nothing else. cblink sends requests and replies on SCTP
    stream 0, and its own streams on the others.
  - **How it is reached**, at the foot of the summary: the agent's
    listeners and the connections open to the agent now, each with its
    transport, where it comes from and the name in its certificate,
    read again every few seconds. A green light is before the way the
    console itself gets in, which is the one it knows to work; another
    the agent listens on has an empty one, until it is tried; the
    agent's local socket is listed only when it is the console's way.
    The console keeps its connection to an agent open and sends the
    next request over it; several requests at once have one each. An
    agent that listens on TCP listens on SCTP as well, at the same
    address and port, where the kernel has SCTP. It never loads the
    module: where it is missing the listener is shown as down with the
    reason, and once `sctp` is loaded from the Kernel tab, **Try SCTP
    again** has the agent start it. **Switch to SCTP** has the console
    ask the agent over SCTP first, and only when it answers is the
    host reached that way from then on; when it does not, nothing is
    changed. **Go back to TCP** does the same the other way, and is
    also offered when a host reached over SCTP stops answering. From a
    shell: `arcanactl transport [retry]`.
  - **Plugins** are what works through a program that has to be
    installed, not the base system's: **BIRD** (`birdc`),
    **WireGuard** (`wg`; the interface itself, `if_wg` made by
    `ifconfig`, is the base system's and is among the interfaces) and
    **IPsec** (strongSwan's `swanctl`; an `ipsec` interface is the base
    system's).
    Each has a tab of its own, after the others and marked ◆, on a
    host where its program is installed or one of its running vnet
    jails has it installed, and none where neither does; the picker
    at the left of the tab's toolbar offers only those that have it.
    Nothing is asked of BIRD or `wg` on a host without them.
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
    **IPsec** is strongSwan, IKEv2 only, every connection arcana writes
    saying `version = 2`. **Make its key** has the host make a key of
    its own, ECDSA P-256, whose private half stays on the host; the tab
    shows the public half, which is what a peer is given: two hosts
    know each other by their keys, no CA between them. **At boot**
    keeps strongSwan started with the host (`strongswan_enable`), and
    **Start** starts it when it is not running. **+ connection** joins
    this host to another between two addresses, in **tunnel** mode or
    in **transport** mode, where what is sent between the two addresses
    is protected as it is: a gre, gif or WireGuard tunnel between them,
    with the traffic named as `192.0.2.1[gre]`. With a **reqid** a
    connection serves the `ipsec` interface made with that reqid
    (**+ interface**, type ipsec): tunnel mode, the interface's routes
    deciding what goes through it. A connection is written as
    `swanctl/conf.d/arcana-<name>.conf` with the peer's key beside it,
    and strongSwan reads them all again; if it refuses, the files are
    put back as they were. The table has each connection with its
    child, its SA's state and algorithm, and its traffic; **Up**,
    **Down**, and the cross, for arcana's, takes it away, its SAs ended
    first. A connection that is not IKEv2 is marked so. From a shell:
    `arcanactl ipsec init | start | conn | unconn | up | down`.
    In a vnet jail, strongSwan is the jail's own, installed in it
    (`pkg -r` or **+ packages** for the jail): its key, its
    `swanctl/conf.d` and its `strongswan_enable` are beneath the jail's
    root, and `swanctl` and the rc.d script run in it. The kernel's
    IPsec is the host's: built in, or `ipsec.ko` loaded on the host
    (`ipsec_load="YES"` in its `loader.conf`), since a jail cannot load
    a module; the tab says so when it is not there. The jail needs no
    `allow.raw_sockets`.
    **BIRD** draws the routing daemon in the middle and around it its
    BGP neighbours (their AS and address), its OSPF neighbours and its
    RPKI caches, each coloured by its state. Under the protocols, the
    **BFD sessions**: each neighbour that asked for BFD, on which
    interface, and whether it still answers. A neighbour picked, in the
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
  - **Packages**: of the host or a running jail. **Installed**, at
    first, lists what is installed, from the host's own database
    without asking the repository: each package's version, whether it
    was asked for by hand or came automatically as what another needs,
    its size, its port and what it is. **Upgrades** asks the repository
    what is newer, with **Check** (pkg update first), a dry run, and
    **Upgrade** of the selected packages or of all. **IPv4** or
    **IPv6** has pkg reach the repository over that only (`pkg -4`,
    `pkg -6`), kept in the browser; **either** lets pkg choose.
    **Clean** deletes the downloaded packages no longer needed, or no
    longer in the repository (`pkg clean`), **Clean all** the whole
    cache (`pkg clean -a`), each a job once it is confirmed. **Clean
    the jails**, on the host's page, does it in every running jail at
    once: one batch of a job each, so that a jail whose pkg refuses
    fails alone. **Install…** installs packages by name, on the host or
    in the jail whose page it is, over IPv4 or IPv6 as chosen
    (`pkg install -y`). From a shell: `arcanactl packages [-i] [-4 |
    -6] [jail]`, `pkg-upgrade [-O] …`, `pkg-clean [-a] [-j jail | -J]`,
    `pkg-install [-O] [-4 | -6] [-j jail] package …`. When pkg refuses packages built for a newer
    FreeBSD than the host's (OSVERSION), the console asks whether to
    go on anyway, and approved, does it again with
    `IGNORE_OSVERSION=yes` (a job of kind pkg-upgrade with force).
  - **Jobs**: the host's own record of what it was asked to change, by
    this console or with `arcanactl -q`; a row opens its workflow.
    Above the list it says what the agent is doing now that is not a
    job, a request somebody waits for such as a check of the packages,
    since when, and whether the agent was told to stop and waits for
    it: the same as its log says.
- A **jail with a network of its own** (vnet) has that network in its
  host's **Network** tab, and in each plugin's: the picker at the left
  of the toolbar names the host or one of its running vnet jails, and
  every view (interfaces, routes with lookup, connections, sockets,
  netgraph, bridges, geneve, neighbours; WireGuard, BIRD with its
  neighbours and its configuration, IPsec) is then of that jail. The
  jail's page has **Open it in the Network tab**, and the map's **Its
  network** opens the same. It is read and changed from the host: there is no agent in the
  jail, and nothing is installed there for it. `ifconfig`, `route`,
  `netstat`, `sockstat` and `ngctl` are the host's, run for the jail;
  `birdc`, `bird`, `wg` and `swanctl` are the jail's own, run in it, so that what
  parses a configuration is the version that runs it. What is kept for
  the jail's next start is kept in the jail's own `rc.conf`, its BIRD
  configuration and WireGuard files are the jail's, and they are never
  followed out of the jail through a link. Safe mode works there as on
  the host. From a shell: `arcanactl -j jail net …`, `interface …`,
  `route …`, `wg …`, `bird …`, `ipsec …`.
- **An interface gets into such a jail from its host**: **+ from host**
  above the jail's interfaces, with the jail picked, gives it one the host has (`ifconfig
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
- **Settings** is a section of its own, at the foot of the tree, with
  a tab for each part: **Look**, **Notifications**, **API tokens**,
  **Sign-in keys**, **Console** and **web.conf**. It opens with no host
  as well.
- **Settings**, **API tokens**: read-only tokens for a program to
  look at the hosts through the API without a passkey, sent as
  `Authorization: Bearer arcr_…`. One is made with a name and its
  value is shown that once; the console keeps only its SHA-256, and
  when it was last used. It reads what is said of the hosts (GET under
  `/api/servers`) and nothing else: it changes nothing, and does not
  read the console's settings, sign-in, push or enrolment. Deleted, it
  opens nothing at once.
- **Settings** has the console's version, and under **Look** its
  themes. **Graphite**, the default everywhere, is calm: surfaces of
  one hue, one blue for what can be acted on, green, amber and red for
  how things are, a plain face for reading and the fixed one for what
  is read character by character (addresses, keys, code), words as they
  are written and nothing glowing. Slate, Onyx (black, white and one
  red) and the light ones, Paper, the warm Sand, the cool Mist and the
  green Mint, are drawn the same way in their colours. The neon ones,
  Tron, Amber, Matrix and Synth, are the console on a dark grid it began
  as: glow, a display face, capitals spaced out. The one picked takes
  at once and is kept in that browser. A theme is a set of colours in
  `web/style.css` (`html[data-theme="…"]`): the accent, the surfaces
  and the text, which everything else is drawn from. A browser that
  kept another theme before Graphite was the default is moved to
  Graphite once. **Motion**, under **Look** too, turns the blur and the
  idle animations off or on.
- On a phone the tree is one line under the top bar, showing what is
  selected; a tap unfolds it, and picking something folds it again. The
  top bar's buttons are a row of their own, tables scroll inside
  themselves, and notifications appear above the activity bar.
- **Settings**, **Console**, changes the console's own settings: the
  name keys show, the release check and its feed, the `arcana-agent` it
  sends, and the repository and branch a host builds it from. They are
  kept in `settings.json` in the data directory and override `web.conf`;
  a field put back to `web.conf`'s value follows it again. The relying
  party, the origin, the data directory and the certificates are shown
  under **web.conf** and changed only there: keys are bound to the first two,
  and all are read once, at the start. Whoever can log in can set the
  repository, and so decides what is built and sent to every host as
  root.
- In the top bar: **Notify** allows a notification when a task that
  took more than ten seconds ends, and has this browser told of changes
  made in the others (below); once the browser has allowed them, the
  same button turns them off and on again for this browser, which also
  stops what is pushed to it. **Settings**, **Sign-in keys**, manages
  security keys and passkeys.
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
  for a browser to subscribe. **Settings**, **Notifications**, lists the
  devices
  (`push.json`) and removes one; a device whose browser dropped the
  subscription is forgotten by itself. Up to 16 devices.

- **A table on a phone** is a card for each row: its title is the
  column that names the row (a process's command, an interface's or a
  jail's name, a firewall's part), or the first column where none
  does; each other value has its column's name beside it, and what is
  done to the row is along the card's foot, behind one **⋯** when
  there are more than two. The table's head
  stays above the cards as a row of buttons to sort by. Every table,
  the older ones too (routes, sockets, interfaces, BIRD's protocols,
  WireGuard's peers, netgraph's nodes, packages, jobs), sorts by the
  column picked, numbers as numbers whether they came as numbers or
  as text, and is narrowed by the filter.
- **On a phone** the tree of hosts is a drawer that slides in from the
  left (☰), the top bar is one row with the rest behind **⋮**, a
  dialog is a sheet from the bottom, a row of choices is one line that
  is scrolled, and a table keeps its first column in sight while the
  others are scrolled. The firewall's parts, a side bar elsewhere, are
  a strip above its rules. On the network map the tools are one line
  along the top and the legend one along the foot, each scrolled
  sideways, and **Arrange** puts the hosts on a tall ellipse that the
  screen holds.
- Choices of one kind (the views of a tab, a family, a range of time)
  are one joined row that does not break into a grid, and scrolls
  sideways where there is no room; a page's tabs too. A table row with
  more than three actions shows two and **…**, which shows the rest.
- **Every table's columns** are as wide as their borders are dragged
  in the head; a double click on a border lets the column be as wide
  as what is in it again. A box with a mark before its name (a
  bridge, how a host is reached) folds when its head is pressed, and
  stays as it was left.
- A task that **failed** has **Retry** in the list: the same job, sent
  again to the same host.
- A routing table too large for one reply ends in **More**, which
  reads the next two thousand routes and puts them after those that
  are there.
- On the **Network** map a host's bridges stand above it: a box for
  each, with a dot for every member in the colour the spanning tree
  gave it, and a dashed line to the jail whose end of an epair is in
  the bridge; pressed, it opens the host's bridges.
- **Recent tasks** along the bottom: the last few, each with its host,
  how it ended and how long it took, always in sight; one picked opens
  the list at it, where each also has the time it began. The tasks
  that ended are kept in the browser and are still there when the
  page is opened again, without their traces.
- **Bridges**, in a host's network or a jail's: each bridge drawn as
  the switch it is, a port for each member, coloured by what the
  spanning tree made of it (forwarding, on its way, held back, or not
  in the tree), with its role, and the VLAN it is in untagged or those
  it carries tagged. Above them: whether the bridge filters VLANs,
  which bridge is the root of the tree and through which port and at
  what cost it is reached. A port picked is made an **access port**
  (one VLAN untagged, none tagged) or a **trunk** (a list of VLANs
  tagged, and perhaps one untagged), put into or taken out of the
  spanning tree, made an edge port, or taken out of the bridge; kept
  in `rc.conf` when asked. A member of a bridge takes no address
  here: its addresses belong on the bridge. One that has some is
  marked, and they can be removed. From a shell: `arcanactl net
  bridges`, `arcanactl [-p] bridge name access member vlan`, `bridge
  name trunk member vlans [untagged]`, `bridge name vlanfilter on |
  off`, `bridge name flag member [-]flag`, `bridge name set option
  value`, `bridge name addm | deletem member`.
- **A bridge's own options and what it has learned**, at the foot of
  its box: the spanning tree's protocol, priority and timers, how
  many addresses it keeps and for how long, each in a field with what
  the bridge has now, of which **Set what was changed** sets those
  that differ; and the addresses it has learned, each with its VLAN,
  the member it is behind and when it is forgotten.
- **Geneve**: the geneve(4) tunnels, each with its mode (l2, Ethernet
  frames for a bridge; l3, IP packets that are routed), its
  identifier, its local address and the host or the multicast group
  it leads to. **+ geneve tunnel** makes one, in the mode it will
  keep; a tunnel picked has every option to be set: identifier,
  addresses, group and its device, TTL and don't-fragment (each also
  inherited from the packet inside), DSCP inherited, the port range,
  learning and its table's size and timeout, external control.
  **Flush** empties its forwarding table. From a shell: `arcanactl net
  geneve`, `arcanactl [-p] geneve name create | set option value …`,
  `geneve name flush [all]`.
- **Connections** and **Sockets**, in a host's network, are read again
  every two seconds while they are shown, without a task of their own
  in the activity; **Live** pauses that.

## The network

**Network** in the tree shows the fleet as a map, its first tab. Nothing
is configured for it: the console reads each host's interfaces every
few seconds and works the links out. Its second tab, **Nexthop
groups**, has every host's routes of several next hops with what each
next hop sent and what its gateway received, as a host's Nexthops tab
draws them (above).

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
- On a tunnel or a point to point link, each end's interface is
  written at its own end, just past the host, and what it carries in
  the middle; another kind of line has its name above the middle and
  its rate below.
- **Labels** opens the switches of what is written: **Names** and
  **Rates** apart, and one for each kind of line (tunnels, point to
  point links, shared networks, BGP, OSPF and jails). Until a kind is
  switched, a kind with more than six lines has its labels left out,
  and a line then shows its own when the pointer is on it or it is
  picked.
- A line is **dragged** to bend it away from the lines beside it; the
  browser keeps the bend, and **Arrange** straightens every line
  again. A BGP or OSPF neighbour outside the console is dragged the
  same way to put it elsewhere: it keeps its place beside its host,
  following it when the host moves, until **Arrange**; picked, it
  opens its host's BIRD.
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
  **Its network** opens its host's Network tab with the jail picked.
  All of it is done by the
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
- **Look up the route** asks each host on the way which route it
  takes to an address (the agent's `route-lookup`), follows the gateway
  to the host that has its address, and draws the way over the map hop
  by hop, until the address is reached, the way leaves the hosts of this
  console, or it comes back to where it was. Beside each hop are the
  routes that would be taken in its place when the best one goes, drawn
  dashed.
- **Traceroute**, the section's third tab, is the way the packets take
  in fact, as `mtr` shows it: from a host of this console to an address
  or another host, a round of `traceroute` every second, a probe a hop,
  each hop with what it lost and its last, average, best and worst
  times and their deviation, and a bar from the best to the worst
  with the average marked. A hop that answers differently over the
  rounds, a way of several, says how many more answered. Where a hop is
  a host of this console it is named, with the interface the probe came
  in by; and of the host it starts from and each of ours on the way,
  the interface it sends on towards the address, by which gateway, and
  that interface's MTU: the smallest of them is as large as the path's
  MTU can be. From a shell: `arcanactl traceroute address`.

## SD-WAN

**SD-WAN** in the tree holds the SD-WAN services the console keeps,
named as MEF 70.2 (SD-WAN Service Attributes and Service Framework)
names them. It is one document with three parts:

- `ucs`: the underlays (Underlay Connectivity Services, §12). Each has
  an `id`, a `type` (`public`, an Internet Access, or `private`), a
  `billing` (`flat-rate`, `usage-based` or `other`), and the
  `tunnel` the edges make over it: `kind` `gre`, `gif`, `geneve` or
  `wg`, and for the first three `ipsec`, true for IPsec IKEv2 under
  it.
- `edges`: the hosts that are SD-WAN Edges (§7.8). Each names its
  `server` and lists its `ucs_end_points` (§12.3): an `id`, its
  `ucs`, the `interface` it is on, and maybe an `address`, a
  `gateway`, a `bandwidth` in bits per second, `backup` (used only
  when nothing else is left) and `breakout` (traffic for the Internet
  leaves here; only on a public underlay).
- `swvcs`: the services (SD-WAN Virtual Connections, §9). Each has
  an `id`, the `fib` it has on its edges (1 or more; FIB 0 is the
  underlay's), its `ucs`, `reserved_prefixes` (the provider's own
  addresses, tunnels' among them), and:
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
    `rate_limiters`, `security_policies`, `importance` (`levels`,
    high to low, and a `default`) and `probe`, how its tunnels are
    measured;
  - `end_points` (§10): an `id`, the `edge` it is on, its `uni` (§11:
    an `id`, the `interface`, a `vlan` or 0, `max_frame`, `ipv4` and
    `ipv6` addressing, `none` or `static` with a `prefix` and the
    `provider`'s addresses in it, `ll-only` for IPv6 too, and static
    `routes`), its `policy_map` (each a `zone` or `Internet`, an `app`,
    and its `ingress` and `egress` policies, over the zone's own) and
    its `nat`.

**Overview** shows the underlays, the edges and the services in
tables; **Services** one service's end points, zones, flows (in the
order they are matched), policies, topologies and rate limiters;
**Document** the whole of it as JSON. **Check** asks the console
whether it is one the standard allows and **Keep** keeps it; what the
console says no to names where, and the requirement:

    swvc office, policy realtime: performance: the ceiling is the
    threshold or above it (R72)

A change is made from the version it was read at; one made from an
older version is refused, so two pages do not undo each other. **Start
from an example** writes one with two of the console's hosts as its
edges. Nothing is sent to the hosts yet: what the edges are to do is
the next part.
