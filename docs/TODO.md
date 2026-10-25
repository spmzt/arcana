# TODO

## To do

- FEC relays, the rest: the overhead kept in the history beside the
  tunnel's rate.  Several relays a host are read and set by profile
  (agent 0.210.0), and SD-WAN's relays with `plugin: speederv2` are
  made at both ends by the apply (console 0.312.0); both need the
  port's rc script with `speederv2_profiles`, the user's to commit to
  net/udpspeeder (a draft given 2026-10-25).

- For the user to do (2026-10-13): IPFIX export in ng_netflow(4),
  which exports NetFlow v5 and v9 only (seen on the lab, 16-CURRENT,
  2026-10-13: both hooks at once, nothing else); pflow(4) has IPFIX
  but serves pf. docs/PLAN-SDN-YANG.md's flow telemetry (5.6) waits on
  it or takes v9. Also seen: an expired flow waits in a partly filled
  export datagram until it fills or the node shuts down, with no timer
  to send it; a flush would be part of the same kernel work.
- The SDN and YANG redesign: docs/PLAN-SDN-YANG.md, with its notes
  under docs/notes/. Open: D-5, D-6, D-11, D-12. Still to do: 1.11,
  the first GET (the collectors it serves are in git's history before
  agent 0.159.0), and what waits on it: 2.3.4; 2.3.5, the rc.conf.d
  fragments rendered (the agent still edits rc.conf through sysrc(8));
  the running datastore's use of rtadvd.conf (2.5.1); 2.6.2 (the
  vrf-root mount) and parent-reference; 2.7.2 to 2.7.4; 2.8,
  yang-library. With the datastores, with-origin (2.3.9) and
  report-all-tagged. Writing syslog.conf from ietf-syslog. The disks
  of arcana-storage also as ietf-hardware's components (3.1.9). 3.2,
  notifications (faults as ietf-alarms), 3.4's streams (the JSON
  stays on the wire until then), and Y-3's conversions of the interim
  module's operations onto the standard models, a module at a time.
  For the user: the CORECONF draft's examples number some
  ietf-interfaces items otherwise (SIDS.md). As each operation is
  converted to YANG (the user, 2026-10-13: with each conversion, not
  after all of them), its task's { } Schema panel shows its YANG model
  beside the CBOR schema.
- To decide (the user's): whether the security policies move to MEF
  138's model (Security Function Policies each with Block, Allow and
  Quarantine lists, No-match, Duration; PDNS and DLP added), and which
  of the conformance list's "no" rows come next (session states, an
  external IdP with OAuth 2.0, Context Policies, SAAN/SSEN as
  notifications, event-based Continuous Monitoring).
- Game mode (asked 2026-10-25): the console used on a Steam Deck in
  its Game Mode, by its controls alone. The page reads the controller
  through the Gamepad API (navigator.getGamepads(), which Steam's
  browser and a PWA added as a non-Steam game both give): the D-pad
  and left stick move a visible focus between the controls of the
  page, A presses, B goes back or closes a dialog, the bumpers go
  between tabs and the side bar's pages, the right stick scrolls a
  page or pans the network map, the triggers zoom it; a key on the
  screen's keyboard (Steam + X) for the inputs. A layout for 1280x800
  with targets large enough for it, and the console's own words for
  each button shown while a controller is in use. Not started.
- Asked for on 2026-10-17:
  - poudriere as a plugin, a Builder page in the side bar with Jails,
    Ports and Bulk tabs: tested with a stand-in poudriere
    (agent_test:poudriere, pwa_test:pwa_flows), not yet against a real
    one.
- Asked for on 2026-10-16:
  - A Security section in the side bar (URL filters, Antivirus,
    IDS/IPS), usable without SD-WAN: not tried with the real plugins
    yet: stand-ins in the tests.
- Alert management (asked 2026-10-16): Telegram not tried against the
  real Bot API: a sink in the tests.

- Asked for on 2026-10-11, each a task of its own, in no order yet:
  - Disaster recovery across console clusters.
  - Agents in an HA pair on identical hardware and ports: the pair's
    state shared; ipfw has no pfsync, which is pf's: the user's to
    decide.
  - IGMP and MLD: a querier or a multicast router (pimd, mrouted) is
    not done: ask.
  - QoS on ipfw by forms: masks are each address or all; prefixes and
    ports in a mask still by ipfw's words.
- Storage: a disk's self-test started. Only NVMe has one in the base
  system (nvmecontrol selftest; ATA and SCSI need smartctl, a
  package), and the lab has no NVMe disk to try it on: left until one
  is there.
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
  - Certificates with a role: joining the events group, which cblink
    admits below the handlers, is not covered; to be closed in cblink
    when the mesh comes.
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

  - Seen once on a console 0.275.0, in its log: "writing
    sdwan-state.json: Bad file descriptor".  store_write's own
    descriptor comes from mkstemp(3) just before, so EBADF there means
    another thread closed a number it did not own (a double close
    somewhere, with the number reused meanwhile).  Not reproduced; look
    for a close(2) of a descriptor already closed, in the console's
    threads (the SD-WAN manager, the subscriptions, the pool).
    A review of every close in the console (2026-10-22) found none;
    what it found instead, to do: apply_begin() reads the run after
    pthread_detach,
    when run_main may have freed it; descriptors leaked on error paths
    in pki.c, nodes.c, auth.c, push.c and mail.c; a retried request in
    hosts.c keeps the dropped connection's steps box, so the retry never
    subscribes to steps.

Written and tested with stand-ins, never run for real:

- A route in another routing table: the one tried was refused by the
  kernel, its gateway not being reached in that table, which came
  through as route(8) says it. Whether the address named to send from
  is the one a route then uses: route(8) took it.
- A vnet jail's network. Run for real, against the jail `gateway` of
  one host: its interfaces, routes, route lookup and BIRD read; an
  address added and removed; an interface brought up; a new epair
  given, taken back and destroyed. Not run for real: the map with a
  real jail as a node (the browser test tells the page that a jail
  runs).
- A jail's share of the CPUs and its memory from rctl_get_racct(2):
  the test VM's kernel has kern.racct.enable off, and turning it on
  needs a reboot; what is read when it is off was run for real.
- The switch to SCTP from the page: the API was run for real, between
  a console and an agent on one machine.  (SCTP between two network
  stacks, in the verified list.)
- For the user to say (2026-10-13): BIRD that stops answering while a
  safe change waits (run for real: birdc down) leaves the unconfirmed
  file in place, as bird.c says it should ("one that died is not
  undone after"), so BIRD's next start reads a change nobody
  confirmed.  Safe mode's word is that an unconfirmed change is taken
  back: put the file back there too?
- Firefox: the console is tested in headless Chromium only.
- The install offer on a real phone: Chrome's prompt on Android, the
  wording for Safari on iOS and for Firefox.
- A login from an Android app named in web.conf's android block, on a
  real phone: the tests sign as Credential Manager would, with its
  origin (android:apk-key-hash:...), and read
  /.well-known/assetlinks.json, but Android has not been seen to accept
  the file or to sign for the console's rp_id.
- Notifications on a real phone. A message sent with the console's code
  was delivered to headless Firefox through Mozilla's push service and
  shown; Google's service accepts the console's signature, but the
  Chromium build the tests run cannot receive from it.
- `arcana-enrol -s` on a real host, the container image since the
  rename, and the update check against GitHub's live feed.

## Verified for real

What was once in the list above, and when it was run:

- Kept in rc.conf on a host itself, and wg-quick(8) for real
  (2026-10-17, the lab VM as root, its /etc/rc.conf kept first and put
  back byte for byte): an interface's address and a static route kept
  by -p (ifconfig_<if>_alias0, static_routes and its route_), taken
  off by hand and put back by the base system's own rc.d netif and
  routing; a WireGuard interface made, keyed, addressed and peered
  with -p, a ping through it to a vnet jail's end, rc.conf with
  wireguard_enable and wireguard_interfaces and no ifconfig_ of its
  own, and the file written for wg-quick with its Address, MTU, port,
  key and peer.  The interface destroyed as at a boot, the real
  wg-quick (wireguard-tools 1.0.20260223, fetched, not installed)
  made it again from that file, its route to the peer too, and the
  ping went through.  wg-quick on FreeBSD leaves a route monitor
  running in the background, as it should.
- SCTP to an agent listening on a router's loopback address
  (2026-10-17): it times out while TCP to the same address works.
  FreeBSD's SCTP counts an address on a loopback interface out of a
  non-loopback peer's scope (sctp_is_address_in_scope()), so no
  INIT-ACK is sent: reproduced between two vnet jails (the root test
  sctp_loopback), and SCTP to an address of a real interface, bound
  too with --sctp-also, answered.  The transport read and the host
  page said so of such a listener until 2026-10-21, when the kernel
  learnt to scope by the address rather than the interface's type
  (net.inet.sctp.ignore_loopback_iftype); the warnings went, and
  sctp_loopback now has SCTP to the lo0 address answered.
- BIRD's forms against the real BIRD (2026-10-17): every
  configuration the console's BIRD forms and SD-WAN write is taken or
  refused by BIRD 3.3.2's own parser (bird -p) in the tests where the
  host has BIRD; it found that SD-WAN put a route's preference on the
  protocol, which BIRD 3 has on the channel only, a BGP password without
  its authentication, the RPKI function without its return type, and a
  session from a template that names no peer type refused as it should
  be.  And live (the root test bird_live): two vnet jails, BIRD in each,
  eBGP over an epair as the BGP form writes a session; Established, a
  route of each learned by the other, and the agent read the session's
  state and the routes through the real birdc.
- SCTP multi-homed between two network stacks (2026-10-17, the root
  test sctp_multihome): the agent in one vnet jail bound to two
  addresses (--sctp-also), arcanactl in another with two of its own,
  an epair for each pair; the association had a path to each of the
  client's addresses, both active.  One epair end taken down: the
  client took its address out of the association (ASCONF, FreeBSD's
  auto_asconf), the other path became primary, and events kept coming
  on the same association; back up, the address was added again and
  its path active.  SCTP's timers shortened in each jail's own stack
  (net.inet.sctp is per vnet) to find a failure in a second.
- SCTP between two network stacks (2026-10-13): the agent in one vnet
  jail and arcanactl in another (both rooted at /, nothing installed
  in either), an epair between them; over sctp://, mutual TLS, the
  agent named the session sctp from the other jail's address and its
  kernel held the association; TCP to the same listener too.
- User certificates against the real sshd (2026-10-13, the lab jail
  arcsub1, its own lo0 in a vnet): a CA's public key given by
  `arcanactl -j arcsub1 sshd user-cas`, a user's key signed by it, and
  the user signed in by ssh with the certificate alone; the CA taken
  away, the same certificate refused.  Found there: `service sshd
  reload` says it cannot for an sshd not enabled in rc.conf, and exits
  0, so the change was not taken; the agent runs onereload now.
- An interface given to a jail and kept (2026-10-13, a lab jail of a
  jail.conf of its own): vnet.interface = "epair2b" written into the
  jail's block, read back by jail(8), and taken out when the interface
  was taken back.
- BIRD not answering, against BIRD 3.3.2 (2026-10-13, a vnet jail):
  the read says so in birdc's words; a configuration written is put in
  place once it parses, and said to be read when BIRD is started; one
  in safe mode when BIRD stops answering is left in place (see the
  question above).
- A jail's own rc.conf and safe mode in a jail, for real (2026-10-13,
  a vnet jail): an address kept as ifconfig_lo0_alias0 in the jail's
  rc.conf by sysrc -R and taken out again; an address added in safe
  mode, left unconfirmed, and undone after the 2 s it was given.
- BIRD's configuration written in a jail and its safe mode, against
  BIRD 3.3.2 (2026-10-13, a vnet jail): a file put in place and BIRD
  told (its new route there); one BIRD refuses said in BIRD's words
  and not put in place; one in safe mode left unconfirmed, taken back
  (the route gone, the file as it was).
- A kernel module loaded and unloaded for real (2026-10-13, the lab
  VM, as root): if_disc by the kmod job, listed with its references,
  disc0 made and destroyed with it, unloaded, and the kernel itself
  refused before anything ran.
- WireGuard against the real wg(8), in a vnet jail (2026-10-13): wg0
  made with its address, given a key and a port (init), a peer with
  an endpoint, IPv4 and IPv6 allowed-ips and a keepalive, read back
  through `wg show all dump` as wg(8) printed it, and taken away.
- BIRD 3.3.2 against the real birdc(8), in a vnet jail (2026-10-13):
  device, direct, kernel, static, BFD, OSPF and BGP protocols each read
  with its state and info (BGP start/Active, OSPF Alone), and `show
  route` parsed with its type, protocol, since and preference.

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
- A 100000-entry table on a vnet jail (SASE-2 task S2.2, 2026-10-12,
  arcanactl sdwan rules @file against the jail's agent): the rules
  with the table loaded in 0.23 s, ipfw table info 100000 items; the
  same rules with one entry changed swapped the table in place in
  2.1 s (1563 atomic adds of 64, a process each) with no rules
  reload, the changed entry found by lookup; cleared after.
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

- A web terminal in the console: it could not be built.
- Luxuria in the agent is the plugins, BIRD among them (WireGuard's
  `wg` is the base system's and Invidia's since 2026-10-19); what
  reaches outside (the release check, notifications) is the console's.
  A plugin is still built into the agent and the page: what makes it
  one is that it is there only where its program is installed.

- Asked for on 2026-10-20, after a review of the whole code:
  - Squid, c-icap, unbound, dnsmasq and BIRD are still written by the
    console with the agent's places in them; jls stays a program the
    tests can fake, where libjail could not be.
  - OpenSMTPD: the plan is docs/notes/opensmtpd.md; not yet: counters
    as graphs, db: tables, a fault when the queue grows.
