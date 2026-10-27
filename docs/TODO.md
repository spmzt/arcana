# TODO

## To do

- FEC relays: the overhead kept in the history beside the tunnel's
  rate.  Several relays a host, and SD-WAN's relays with `plugin:
  speederv2`, need an integration of the port's rc script with
  `_svcj` and `_svcj_ipaddrs`.

- IPFIX export in ng_netflow(4), kernel work and the user's:
  ng_netflow exports NetFlow v5 and v9 only (both hooks at once,
  nothing else); pflow(4) has IPFIX but serves pf.
  docs/PLAN-SDN-YANG.md's flow telemetry (5.6) waits on it or takes v9.
  An expired flow also waits in a partly filled export datagram until
  it fills or the node shuts down, with no timer to send it; a flush
  belongs to the same work.
- The SDN and YANG redesign: docs/PLAN-SDN-YANG.md. Open decisions:
  D-5, D-6, D-11, D-12.
  To do, the datastores first, their safety design the user's to
  review before an EDIT of running is served: 2.3.x (candidate and
  running, with-origin 2.3.9, report-all-tagged), 2.3.5 the rc.conf.d
  fragments rendered (the agent edits rc.conf through sysrc(8)), the
  running datastore's use of rtadvd.conf (2.5.1), syslog.conf written
  from ietf-syslog; 2.6.2 (the vrf-root mount) and parent-reference;
  2.7.2 to 2.7.4; the rest of 3.2's subscriptions (suspension, modify,
  replay, configured, on-change from the event sources rather than a
  read each second) and NACM (3.3); 3.4's streams (the JSON stays on
  the wire until then); RESTCONF (Y-4); and Y-3's conversions of the
  interim module's operations onto the standard models, a module at a
  time.  Each operation converted to YANG shows its YANG model beside
  the CBOR schema in its task's { } Schema panel, in the same commit.
  For the user: the CORECONF draft's examples number some
  ietf-interfaces items otherwise than SIDS.md.
- MEF 138's model, the rest: docs/PLAN-119-SASE.md, SASE-6.
- Game mode: the console used on a Steam Deck in its Game Mode, by its
  controls alone. The page reads the controller through the Gamepad
  API (navigator.getGamepads(), which Steam's browser and a PWA added
  as a non-Steam game both give): the D-pad and left stick move a
  visible focus between the controls of the page, A presses, B goes
  back or closes a dialog, the bumpers go between tabs and the side
  bar's pages, the right stick scrolls a page or pans the network map,
  the triggers zoom it; a key on the screen's keyboard (Steam + X) for
  the inputs. A layout for 1280x800 with targets large enough for it,
  and the console's own words for each button shown while a controller
  is in use.
- Each a task of its own, in no order yet:
  - Disaster recovery across console clusters.
  - Agents in an HA pair on identical hardware and ports, the pair's
    state shared; ipfw has no pfsync, which is pf's: how the state is
    shared is the user's to decide.
- A geneve tunnel's forwarding table: if_geneve keeps one and shows
  no way to read it from userland (no sysctl as vxlan has, no dump
  through netlink); once it does, shown as a bridge's addresses are.
- The mesh: agents joined by SCTP associations, each to at least a
  configured number of others (2 unless set), so that the console
  reaches an agent it has lost through one it still has. SCTP only,
  with no fallback to TCP: a blocked or failed association is a state
  to show and to route around. No module is loaded for it and no
  interface made; an agent on a host without `sctp` in its kernel does
  not try until the console tells it to try again. Who the agents are
  and how they are joined is agreed among them with DNCP (RFC 7787),
  from `libdncp`, a repository of its own.
  To be done, in this order:
  - Certificates with a role: joining the events group, which cblink
    admits below the handlers, is not covered; to be closed in cblink
    with the mesh.
  - Arcana's DNCP profile: over cblink on SCTP with DTLS, its own TLVs
    (an agent's name and mesh addresses, when it last heard the
    console), SCTP's heartbeats instead of keep-alives.
  - The mesh listener, the switch and "try again" for each host in the
    console, and the associations drawn on the map and listed, with
    their state, their paths, their round-trip time and their streams.
  - Relaying, and the console falling back to it; the path named by
    the console from the topology the agents hold.
  Not decided:
  - How an agent picks its neighbours, which DNCP leaves open. The
    proposal: the next ones on a ring ordered by node identifier,
    until enough associations work.
  - Whether a node's data carries its signature. DNCP secures each
    hop, not the data: an agent could publish for another until that
    one publishes again.
  - How a relayed session is carried: end to end, the console's own
    TLS session with the agent inside a stream through the relay,
    which only copies bytes; or hop by hop, the relay reading and
    sending on. End to end needs a cblink connection that runs over a
    cblink stream, which cblink has not got, or a bridge through a
    local socket at both ends.
- The console's descriptors and threads:
  - store_write() can get EBADF on the descriptor mkstemp(3) just gave
    it, which means another thread closed a number it did not own (a
    double close, the number reused meanwhile).  Not reproduced; look
    for a close(2) of a descriptor already closed in the console's
    threads (the SD-WAN manager, the subscriptions, the pool).
  - apply_begin() (sdwan_edge.c) reads the run after pthread_detach,
    when run_main may have freed it.
  - Descriptors leaked on error paths in pki.c, nodes.c, auth.c,
    push.c and mail.c.
  - A retried request in hosts.c keeps the dropped connection's steps
    box, so the retry never subscribes to steps.
- Squid, c-icap, unbound, dnsmasq and BIRD are written by the console
  with places the agent fills; to be rendered on the agent from a
  form, as Suricata's YAML and smtpd.conf are.
- OpenSMTPD (the Mail tab):
  - its counters (`smtpctl show stats`) kept in a ring and graphed;
  - a fault when the queue grows past a size or smtpd stops;
  - smtpd restarted when a listener's `pki` is the host's certificate
    and that certificate is renewed, and the certificate's dates shown;
  - `db:` tables written by the tab (makemap), not only `file:` ones.
- Suricata (IDS/IPS):
  - ruleset rules set a group at a time (by classtype or source file,
    suricata-update's `group:` lines), and `modify.conf` to change a
    shipped rule;
  - rules reloaded live (`reload-rules` over the instance's socket)
    instead of a restart;
  - packet profiling (Suricata built with `--enable-profiling`): ticks
    per protocol and per stage;
  - `autofp-scheduler: hash` for the autofp runmode;
  - the NIC queues' interrupt binding (cpuset -x) shown beside the
    threads' CPU sets;
  - a netmap IPS pair refused when an interface of it is a bridge
    member;
  - a capture uploaded from the browser for replay (only a file the
    host has is taken), and the pcap-log files downloaded from an
    alert's row.
- To decide (the user's): BIRD that stops answering while a safe
  change waits leaves the unconfirmed file in place, as bird.c says
  ("one that died is not undone after"), so BIRD's next start reads a
  change nobody confirmed.  Safe mode takes an unconfirmed change back
  elsewhere: put the file back here too?
- FIBs and link-local routes: whether the agent's if-create and if-set
  jobs always set an interface's FIB before its addresses (see Known
  limits).

## Not yet run for real

Written and tested with stand-ins only:

- A route in another routing table that the kernel takes (the one
  tried was refused, its gateway not reached in that table); and
  whether the source address route(8) takes is the one the route then
  uses.
- The map with a real vnet jail as a node.
- A jail's share of the CPUs and its memory from rctl_get_racct(2): the
  lab VM's kernel has kern.racct.enable off, and turning it on needs a
  reboot; what is read when it is off is run for real.
- The switch to SCTP from the page (the API is run for real, between a
  console and an agent on one machine).
- The firewall, bridges and geneve: any of it in a vnet jail; what is
  kept in rc.conf for a bridge or a tunnel; NAT and NAT64; a spanning
  tree of more than one bridge; traffic through a geneve tunnel.
- Logs: one turned over by the real newsyslog while it is followed.
- SD-WAN: the steering by BFD on the lab, resource faults; DNS sent to
  the service's resolver by ipfw `fwd` (ipfw takes the rule; no query
  has gone through it); DHCPv6 at a UNI (dnsmasq's enable-ra) and the
  unmake of rtadvd and dnsmasq; SLAAC on a UCS, a UCS in a VRF, BGP
  with the underlay.
- The Security section (URL filters, Antivirus, IDS/IPS) without
  SD-WAN, with the real plugins.
- Firefox: the console is tested in headless Chromium only.
- The install offer on a real phone: Chrome's prompt on Android, the
  wording for Safari on iOS and for Firefox.
- A login from an Android app named in web.conf's android block, on a
  real phone: the tests sign as Credential Manager would, with its
  origin (android:apk-key-hash:...), and read
  /.well-known/assetlinks.json, but Android has not been seen to accept
  the file or to sign for the console's rp_id.
- Notifications on a real phone. A message sent with the console's code
  is delivered to headless Firefox through Mozilla's push service;
  Google's service accepts the console's signature, but the Chromium
  build the tests run cannot receive from it.
- `arcana-enrol -s` on a real host, the container image, and the update
  check against GitHub's live feed.

## Known limits

- A query argument's value with an "=" in it (encoded %3D, or even
  %253D) comes to the console cut at it: libwebsockets' argument
  parsing.  So /api/servers/<id>/data takes node names, not an XPath
  filter; the filter is arcanactl get -x's and cblink's.  To look at
  in lws's parser, or read the raw query from :path ourselves.

- FreeBSD 16-CURRENT: an interface given an IPv6 address in FIB 0,
  moved to another FIB (ifconfig fib), then destroyed, leaves its
  link-local prefix route (fe80::%N/64) in FIB 0 on an interface index
  that no longer exists (netstat shows "---"); route(8) cannot delete
  it, the index not resolving.  The detach purges the interface's FIB
  at that time, not the one its routes were added in.  The collectors
  show such a route with no interface.  A FIB set before the addresses
  avoids it.  For a kernel fix (in6_ifdetach / rt_flushifroutes over
  every FIB).

- RFC 4364 VPN routes are not written for the control plane: the
  FreeBSD port of BIRD 3 does not build its l3vpn protocol
  (docs/PLAN-119-SASE.md, 119-5).
- IPsec: a FreeBSD kernel bug (sys/netipsec/xform_esp.c): with an AEAD
  cipher (AES-GCM, ChaCha20) and ESN, esp_input adds the ESN high bits
  to the separate AAD only when the SA has a replay window (wsize !=
  0), while esp_output adds them whenever the SA has replay state; an
  SA without a window (setkey without -r) sends an ICV over four more
  bytes than the receiver checks, and every packet is a bad
  authentication. The agent sets -r 128 on every SA, which is right
  anyway (R47), and then GCM with ESN works; worth a fix upstream (the
  same test on both paths).
- SCTP to an address on lo0 from another host is answered only by a
  kernel that scopes SCTP by address (net.inet.sctp.ignore_loopback_iftype,
  a patch not upstream); a stock kernel counts such an address out of
  a non-loopback peer's scope (sctp_is_address_in_scope()) and sends
  no INIT-ACK.  That is the kernel, not Arcana.
- The standard models have no place for a vxlan's or geneve's VNI and
  ends.  ifconfig(8) does not set an ipsec(4) interface's ends from
  addresses that are not the host's, and says nothing (exit 0).
- In a vnet jail, devfs hides bpf, which dnsmasq's DHCP and dhclient
  need; no default ruleset unhides it.  Netgraph in a jail needs the
  jail to allow its sockets (`allow.socket_af`) and the node types
  loaded on the host: a jail cannot load a module.

- The GitHub workflow: the images it builds on
  (ghcr.io/spmzt/freebsd-emscripten, cblink) carry a 16.0-CURRENT
  userland, and vmactions/freebsd-vm boots 15.1 at most, so inside the
  container head(1), tail(1) and the like die on casper ("Invalid
  pdflags at fork") and the agent's test suite fails there while it
  passes on a 16.0 host; the same skew is the likely cause of the
  ipsec and vnet cases' garbled arguments.  Until the images' userland
  and the VM's kernel match, or the tests have a kernel of their own,
  the build cannot go green; it runs by hand only.

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

- There is no web terminal in the console.
- Luxuria in the agent is the plugins, BIRD among them (WireGuard's
  `wg` is the base system's and Invidia's); what reaches outside (the
  release check, notifications) is the console's.  A plugin is still
  built into the agent and the page: what makes it one is that it is
  there only where its program is installed.
- jls stays a program the tests can fake, where libjail could not be.
