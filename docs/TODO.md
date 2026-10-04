# TODO

## To do

- Routes through netlink, with its attributes mapped to CBOR, instead of
  running route(8) and netstat(1).
- WireGuard: preshared keys; a peer's key rotated.
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

- Building the agent as `nobody` when `arcana-agent` runs as root
  (`chroot -u nobody`); only the unprivileged build was run with the
  real git and make.
- The agent's restart after an update against a real rc(8)-managed
  service; the tests use a stand-in for service(8).
- The agent's tests that need root, since the rename to Arcana.
- Creating, setting and destroying interfaces, routing tables, what is
  kept in rc.conf, and netgraph, against a real ifconfig(8), route(8),
  sysrc(8) and ngctl(8) as root; the tests use stand-ins. The interfaces
  themselves and the route lookup's parsing were checked against this
  machine's real output.
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
