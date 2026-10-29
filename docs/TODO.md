# TODO

## To do

- IPFIX export in ng_netflow(4), kernel work and the user's:
  ng_netflow exports NetFlow v5 and v9 only (both hooks at once,
  nothing else); pflow(4) has IPFIX but serves pf.
  docs/PLAN-SDN-YANG.md's flow telemetry (5.6) waits on it or takes v9.
  An expired flow also waits in a partly filled export datagram until
  it fills or the node shuts down, with no timer to send it; a flush
  belongs to the same work.
- The SDN and YANG redesign: docs/PLAN-SDN-YANG.md. Open decisions:
  D-5, D-11, D-12 (D-6 taken: a FIB per vpn-node).
  To do, the datastores first, to the safety design decided on
  2026-10-28 (in the plan, 2.3): 2.3.x (candidate and
  running), 2.3.5 the rc.conf.d
  fragments rendered (the agent edits rc.conf through sysrc(8)), the
  running datastore's use of rtadvd.conf (2.5.1); RESTCONF (Y-4).
  The interim family is gone (3.8, 0.238.0/0.336.0): every operation
  is a YANG module's, its task's { } Schema panel showing the
  module's tree.
  For the user: the CORECONF draft's examples number some
  ietf-interfaces items otherwise than SIDS.md.
- MEF 138's model, what stays undone and why (docs/PLAN-119-SASE.md,
  SASE-6): the middlebox for IPsec (no IPsec proxy on FreeBSD) and
  DLP (no engine). The book's conformance rows are to be brought up to
  SASE-6: SEN and SAN, MD+R hashes, DNF's inner wildcards, PDNS's
  CNAME and NS entries and DNS over TLS, DPF's message types.
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
- The console's store_write() got EBADF once, on the descriptor
  mkstemp(3) had just given it (console 0.275.0, on Kore): another
  thread closed a number it did not own.  Looked for again on
  2026-10-28 and not found in the console as it is now:
  - every console_test case under `ktrace -i -t c`: no system call of
    arcana-console or arcana-agent failed with EBADF;
  - every case again, and console_test:churn twenty times, with a
    preload in the console that reports a close(2) or libc's _close()
    of a descriptor mkstemp(3) gave another thread, any close that
    fails with EBADF, and libwebsockets called off the thread of
    lws_service(): none;
  - read: cblink closes a connection's descriptor in cbl_conn_fail()
    alone, once (its state under the lock), on the loop's thread for a
    connection on a loop; its TLS and DTLS BIOs are BIO_NOCLOSE.
    libwebsockets is built LWS_MAX_SMP 1 and the console calls it
    from the service thread only, lws_cancel_service() aside.
  The likeliest cause was Kore's: kore_log() from threads that were
  not the worker queued on the worker's message connection with no
  lock (the 2026-10-22 review), gone with Kore on 2026-10-25.  Seen
  again, store_write() now says which step failed and on which
  number, and does not close a descriptor EBADF says is no longer
  its own; start from that line, ktrace and the preload.
- arcana-sdwan's instances (the grouping instance, ysd.c) still have
  their configuration as text (conf), as the console wrote it before;
  BIRD's, dnsmasq's, unbound's and Squid's are forms now (spec), which
  the agent renders (luxuria/sdconf.c), as Suricata's already were.
  The module to say the form, or the text the agent rendered.
- To decide (the user's): BIRD that stops answering while a safe
  change waits leaves the unconfirmed file in place, as bird.c says
  ("one that died is not undone after"), so BIRD's next start reads a
  change nobody confirmed.  Safe mode takes an unconfirmed change back
  elsewhere: put the file back here too?

## Not yet run for real

Written and tested with stand-ins only:

- The map with a real vnet jail as a node.
- Suricata's packet profiling: the VM's Suricata is the port's, built
  without `--enable-profiling`; packet_stats.log is parsed from its
  format as util-profiling.c writes it (8.0), with files written by
  hand.
- A jail's share of the CPUs and its memory from rctl_get_racct(2): the
  lab VM's kernel has kern.racct.enable off, and turning it on needs a
  reboot; what is read when it is off is run for real.
- The switch to SCTP from the page (the API is run for real, between a
  console and an agent on one machine).
- SD-WAN: the steering by BFD on the lab, resource faults; DNS sent to
  the service's resolver by ipfw `fwd` (ipfw takes the rule; no query
  has gone through it); DHCPv6 at a UNI (dnsmasq's enable-ra) and the
  unmake of rtadvd and dnsmasq; SLAAC on a UCS, a UCS in a VRF, BGP
  with the underlay.
- The Security section (URL filters, Antivirus, IDS/IPS) without
  SD-WAN, with the real plugins.
- Suricata's interfaces' queue interrupts (hw.intrnames, cpuset -x) on
  a NIC with RSS queues: the lab VM's interrupts are virtio's, named by
  no interface.
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
  in lws's parser, or read the raw query from :path ourselves. The
  same parser decodes the path's %-escapes before the console sees it,
  so RESTCONF cannot name a list entry whose key has "/" or "," in it
  (RFC 8040 escapes them as %2F and %2C).

- FreeBSD 16-CURRENT: an interface given an IPv6 address in FIB 0,
  moved to another FIB (ifconfig fib), then destroyed, leaves its
  link-local prefix route (fe80::%N/64) in FIB 0 on an interface index
  that no longer exists (netstat shows "---"); route(8) cannot delete
  it, the index not resolving.  The detach purges the interface's FIB
  at that time, not the one its routes were added in.  The collectors
  show such a route with no interface.  A FIB set before the addresses
  avoids it.  For a kernel fix (in6_ifdetach / rt_flushifroutes over
  every FIB).

- NAT64 (nat64lsn) through a vnet jail answered only with
  net.inet.ip.fw.nat64_direct_output=1: with 0, the translated replies
  are counted as "discarded due to some errors" and go nowhere.  Not
  looked into further.  With the well-known prefix 64:ff9b::/96 an
  IPv4 address that is not global (RFC 1918, the documentation
  ranges) is translated only with allow_private.

- FreeBSD 16-CURRENT, if_geneve: geneve_init() marks the softc
  running (geneve_init_complete()) even when it failed to set up its
  socket, so a failed start is never retried until the interface goes
  down and up again.  The first geneve of a network started by an
  address given to it (SIOCSIFADDR, under in_control) fails so; one
  brought up first does not.  The agent brings a geneve up as it makes
  it, and keeps "up" in its rc.conf line.  For a kernel fix.

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
- The agent runs no jls(8): a jail by name is read with jail_getv(3),
  every jail with jailparam_get(3).  The unprivileged tests preload
  libfakejail.so into the agent they start, whose jail_getv answers a
  lookup by name or jid from a file of the test's; the list of every
  jail is still the host's.
