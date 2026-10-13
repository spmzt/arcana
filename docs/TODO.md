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
  raised yet); the lab run of 119-1 (1.8, in the verified list); the
  monitor charts of each tunnel on Paths (UX-5); SLAAC at a UNI by
  rtadvd and DHCP by dnsmasq in the service's table, with the kernel's
  forwarding turned on by the apply (0.1, 0.2, in the verified list);
  the routing domains (Mplify 119 §7.3): a service's domains in the
  document, checked and unique, the breakout domain a table of its
  own with the default route, the UNIs' routes imported and the flows
  sent to it by setfib, the tunnels' addresses from the service
  domain's prefix (119-2 tasks 2.1 to 2.3; stand-ins, not the lab:
  the jails have no Internet to break out to); the UCS End Points
  addressed by DHCP or SLAAC (the address learned from the host at
  each plan), in a table of their own, and routed with the underlay by
  a BIRD instance of the edge (2.4; DHCP on the jails, in the verified
  list); manually keyed SAs on an ipsec(4) interface by setkey, the
  keys never in a trace (119-3 task 3.1); a key pair per tunnel end
  and the SAs of both directions derived from the agreement by
  HKDF-SHA256, the same on both ends (3.2); the uswe tunnel kind: an
  ipsec(4) interface each end with its unit as reqid, the pairs made,
  the SAs derived from the far public half the apply reads from that
  end (3.3); the keys turned at the half-life, both ends in step,
  inbound before outbound, by the manager or by hand, a failure a
  fault (3.4); the phase closed on the lab, the packets seen on the
  wire as ESP in UDP under ESN (3.5). MPLS in GRE (119-4) is not
  supported: it would be kernel work, which Arcana does not take on
  (2026-10-11); the domains keep their own tunnels. 119-5: a control
  plane host per service, an edge whose BIRD reflects the others'
  routes, each peering with it alone (5.1); the CTVC, a control
  tunnel of its own from each edge to the host over a UCS the
  service names, the iBGP by it alone (5.2); the phase closed on the
  lab with three jails, the host reflecting between two edges with
  no tunnel between them (5.3; RFC 4364's VPN routes stay out, known
  limits); the Edges tab's steps named as §12.1's activity flow, the
  guide's table from each of R89-R160 to its attribute, and the list
  of what is not done (119-6). Mplify 119 is through. SASE-1: the
  security policies in the document with MEF 88's criteria, checked,
  on a Security tab with a form, the example carrying one (S1.1);
  the ip-block denies and allows, the log and the rate pipe in the
  rules, ingress before the forward and egress by the UNI (S1.2);
  the DNS filter, an unbound instance of the base system per service
  on each edge, the denied domains its local zones, every query from
  the UNI forwarded to it where the protocol filter says so (S1.3);
  the rules' counters in the sdwan read, the Security tab counting
  what each policy denied (S1.4); the phase closed (S1.5): of MEF 88's
  policy criteria, ip-block, dns-domain-filter, dns-protocol-filter,
  rate-limit and log are done; lists by name come with the feeds
  (SASE-2), and url-filtering, malware detection and intrusion
  detection with the proxy (SASE-4). SASE-2: the lists, feeds the
  console's host fetches with the base system's libfetch and pasted
  ones, versioned, named by the policies into their tables and DNS
  filter (S2.1); large tables: the entries in chunks of atomic adds,
  a changed table swapped in place without the rules reloaded, the
  limit raised (S2.2); the record: the denies logged to the routing
  socket, read by the agent into a day's record and events, shown and
  exported (S2.3). SASE-3: the remote end point in the document, an
  edge's wg interface, a prefix, a port and the identities, each a
  name, a zone and a key, the example carrying one (S3.1); the apply,
  the wg interface in the service's table, a peer per identity with
  an address of the prefix kept for it, the zone table's entries
  (S3.2); identities issued and revoked from the console, the key
  pair made there and the configuration shown once, a
  re-authorisation interval after which the peer goes (S3.3); each
  identity's session from the edge's wg read, the handshake and the
  bytes, on the tab (S3.4); SASE-3 closed. SASE-4: the URL filter,
  Squid as a plugin, an instance per service, the TLS names looked at
  or TLS opened with the agent's CA, HTTP and TLS forwarded to it
  (S4.1); malware scanned, by c-icap and ClamAV behind the same Squid,
  c-icap on the edge's own address in the service and taking Squid's
  alone, plugins all (S4.2, in the verified list); intrusion
  detected by Suricata on the UNIs, a plugin, its alerts events and
  in the read (S4.3, detect; in the verified list); prevented, mode
  prevent, ipfw divert(4) to Suricata as packets come in, fail-closed
  with a Critical fault (S4.3, in the verified list).  Not inspected
  where it prevents: IPv6 (divert's IPv6 is not trusted), and what
  comes back from local breakout (after NAT, past the divert); SASE-4
  closed (S4.4): the URL filter, malware scanning and prevention on one
  service together on the lab, what the edge is sent for itself not
  diverted, Suricata taking one-sided flows where the edge answers.
  SASE-5: the Security tab in MEF 118.1's terms, Access Control
  Policies Subject Actor to Target Actor from the policy map, Policy
  End Points, Continuous Monitoring, and the audit trail, Audit Events
  for what the console does, HMAC-chained (S5.1); the conformance list
  against the current documents, Mplify 117.1, MEF 138 and MEF 118.1,
  each attribute in it (S5.2, the book's Conformance: SASE).  Found
  there: Mplify 117.1 takes its Security Functions from MEF 138, which
  replaces MEF 88, and none of them has intrusion detection (ids is
  Arcana's own, mislabelled MEF 88's until now).  SASE-5 closed.
- To decide (the user's): whether the security policies move to MEF
  138's model (Security Function Policies each with Block, Allow and
  Quarantine lists, No-match, Duration; PDNS and DLP added), and which
  of the conformance list's "no" rows come next (session states, an
  external IdP with OAuth 2.0, Context Policies, SAAN/SSEN as
  notifications, event-based Continuous Monitoring).
- Verified on the lab 2026-10-12 (S4.4, SASE-4 closed): one service
  on arcswan1 for the road end point with Suricata preventing (divert
  9, setfib 10), HTTP and TLS forwarded to Squid (denied.example), and
  c-icap with ClamAV behind it, the rules as the console writes them,
  three runs alike: a harmless page served, the denied name refused by
  HTTP and by TLS's SNI, the EICAR file refused (403, VIRUS DETECTED),
  /attack dropped and told blocked.  Found there: (1) the replies to
  Squid's own fetches, addressed to the edge in the UNI's subnet, were
  diverted while Squid's packets out were not, so Suricata saw half of
  those flows and cut them, and no page came back; what is for the
  edge itself is not diverted now (not dst-ip me); (2) the end point's
  flows to Squid are seen from its side alone (Squid answers from the
  edge, not diverted), and Suricata in IPS mode dropped them as invalid
  and parsed no HTTP: for such a service Suricata takes one-sided flows
  (stream.async-oneside, midstream) and does not drop for invalid
  (drop-invalid: no).  In one prevent run of seven made with those
  settings, before they were kept to such services, a request matched
  by a drop rule was told blocked yet reached the far end; the eleven
  prevent runs after it (with those settings and without) dropped it
  every time.  They are kept to services the edge answers for.
- Verified on the lab 2026-10-12 (S4.3, prevent): Suricata on divert
  port 8001 for wg5, a drop rule for /attack: a harmless request
  passed, the request for /attack went nowhere and was told blocked;
  Suricata killed, a ping through the UNI got nothing back and a
  Critical fault (ids) was raised, cleared when applied again.  Found
  there: (1) ipfw takes up after a divert at the next rule number, so
  the diverts are rule 9, before the way in at 10; (2) divert(4) gives
  back in routing table 0 whatever table its process is in (a
  PF_DIVERT socket takes none, nor SO_SETFIB), so a packet given back
  on its way out was routed in table 0 and lost (no route), and
  Suricata's TX thread died of the error, taking Suricata with it;
  both directions are diverted as they come in now, and setfib puts
  them back in the service's table.
- Verified on the lab 2026-10-12 (S4.3): Suricata 8 added into
  arcswan1 from fetched packages, an instance on wg5 (the road end
  point's UNI) with the configuration the console writes and one rule
  of the service's own (http.uri /attack): the client's request
  alerted, the alert in the sdwan read and as an sdwan-ids event, 13 s
  after (Suricata tells of a short flow once done with it).  Found
  there: a new instance read its log directory's old eve.json from the
  start, so alerts were told again; one new to the agent is read from
  where the file ends.
- Verified on the lab 2026-10-12 (S4.2): Squid, c-icap 0.6.5 with
  c-icap-modules 0.5.7 and ClamAV 1.5.4 added into arcswan1 from
  fetched packages, signatures only EICAR's (a one-line eicar.hdb):
  the client's fetch of the EICAR file over HTTP refused, 403, c-icap
  logging VIRUS DETECTED: Eicar-Test-Signature with the client's
  address; a harmless file served (204 from c-icap); the client
  asking c-icap itself refused, 403, the edge answered.  Found there:
  in a service's table c-icap could not bind 127.0.0.1 (with
  bind_all_fibs 0 a socket binds only its table's addresses, and lo0
  is the host's), so it listens on the edge's own address in the
  service, with client_access for that address alone.
- 2026-10-12: the plugins' tabs on every host: where the plugin is
  not installed (host or the jail picked), the tab names its program
  and package with a button that installs it by pkg-install, the host's
  list read again when the job ends and the agent's kept answer for
  the jails forgotten; a workflow template installing a plugin's
  package. Squid has no tab, so its package is installed by the
  template or the Packages tab.
- 2026-10-12: workflows, further: jobs.yaml checked against
  arcana.yaml's job-kind and job-spec by jobs.awk at the build, which
  stops where they differ (a field the API names otherwise says its
  attribute); a failure that goes on at a later step drawn as an
  arrow under the run's row; steps dragged to another place; an
  interval counted from when the workflow last ran by it, kept in
  every.json across restarts; each host waited on subscribed to, a
  thread each, its events running what they begin as they come and
  what was missed read when it answers again, host-down known when
  the connection drops. jail-state is still a read of the jails at
  each tick: the agent tells no event of a jail's state.
- 2026-10-12: a vnet jail's plugins looked for as the jail sees its
  files: a child of the agent attaches to the jail and asks there, so
  that a link inside it (a /usr/local leading to /opt/local) leads
  where it does for the jail and not on the host, where it found
  nothing; beneath the jail's root without following a link out of it
  when the agent may not attach; kept ten seconds. wg(8) is found in
  /usr/bin as well, the base system's since FreeBSD 15, where it is
  run from then: the VM's own host had no WireGuard tab for that.
  Verified on the VM by agent_root_test:jail_plugins.
- 2026-10-12: each host's rollback timer, set on its Summary: the
  seconds a change made in safe mode waits there to be confirmed,
  kept with the server and sent with every safe job and BIRD
  configuration (safe-wait), the agent's own -w when not set;
  arcanactl -W does the same.
- 2026-10-11: what is new, in the update boxes and Settings' last
  tab: the agent's source-log (a bare blob:none clone in the build
  directory), the console's /api/update/notes (the tags' messages as
  release notes when any, else the commit messages, new until the
  running version's own commit). Found on the way: Kore hands a
  handler only the query parameters its route declares, so the
  record API's filters (swvc, policy, edge, since) were never seen;
  declared now with a validator.
- Lab hygiene, 2026-10-12: a lab jail left dying (squid, unbound or
  the client's processes still in it) shows up in the console's web
  tests as extra tree leaves, so the cases wait in vain for four; the
  down step kills them now, and `jls -d` tells when one lingers.
- Verified on the lab 2026-10-12 (S4.1): Squid 7.7 added into
  arcswan1 from fetched packages (a plugin; the agent refused the
  instance while it was missing, naming pkg install squid), an
  instance in FIB 1 on the road end point's own address with the
  service's DNS filter beside it, HTTP and TLS from the client
  forwarded by the rules: an allowed name served through it, a denied
  one 403 over HTTP, and over TLS refused by its SNI (TCP_DENIED at
  the peek, then the proxy's own 403 page); `bfd-lab.sh proxy`. Two
  lessons kept in the code: Squid's certificate maker and its cache
  are needed in mode sni too, and an intercepting Squid resolves every
  name it is asked for, so the configuration names the service's DNS
  filter as its resolver where there is one.
- Verified on the lab 2026-10-12 (S3.3): the client's peer removed at
  arcswan1 as the console's apply does it for a revoked identity: the
  ping to the far UNI that answered 3 of 3 loses all, no peer left on
  wg5 (`bfd-lab.sh road`, its end).
- Verified on the lab 2026-10-11 (S3.2): a client jail arcroad as an
  identity, arcswan1's wg5 in FIB 1 with 10.30.0.1/24 and the client
  its peer by the agent as the console's plan has it; the client,
  10.30.0.2, pinged the far UNI 10.20.0.1 through arcswan1's tunnel,
  3 of 3, the handshake and bytes in wg's dump (`bfd-lab.sh road`).
  On this VM `pkg -r <root> install` hangs on the kmods catalogue as
  root, so the step fetches wireguard-tools with -U and adds the
  files, IGNORE_OSVERSION for the newer package.
- Verified on the lab 2026-10-11 (S2.3): a deny rule with `log logdst
  rtsock` on arcswan1 as the console compiles one, a web connection
  from arcswan2 by the tunnel: the entry (rule 12, deny, 10.20.0.1 to
  10.10.0.1, gre100, "security office guard src") and its event in
  the agent's record in the try's own second; the record read back
  after the agent's restart (`bfd-lab.sh record`).
- Found on the lab 2026-10-11 (S2.3): nothing coming in by the
  IPsec-carried GRE tunnel ever reached the SD-WAN rules, since
  `net.inet.ipsec.filtertunnel=0` (the default) lets what IPsec
  decrypted bypass the firewall, the GRE payload included. The agent
  now sets it and `net.inet6.ipsec6.filtertunnel` when it loads the
  rules. This is why S1.3's protocol-filter forward did not answer
  on the lab (drill's network error): the forward rule is `in recv
  gre100` and never saw the query.
- Jails made and changed from the console (asked 2026-10-11), the way
  the user makes them on his servers. A shared `/etc/jail.conf` holds
  the defaults, the user's domain in place of example.net:
  `path = "/usr/jails/${name}"`, `host.hostname =
  "${name}.<domain>"`, `host.domainname = "<domain>"`, `exec.start =
  "/bin/sh /etc/rc"`, `exec.stop = "/bin/sh /etc/rc.shutdown jail"`,
  `exec.consolelog = "/var/log/${name}_console.log"`, `exec.clean`,
  `mount.devfs`. One ZFS dataset per jail, mounted at the path (as
  `<pool>/jails/<name>`, under a dataset for the jails of the host):
  made with the jail from a base jail's snapshot, two ways to choose
  from: `zfs clone` (quick, tied to the snapshot) or `zfs send | zfs
  recv` (a copy of its own, independent of the base); listed with the
  jail, destroyed with it only when asked.
  Each jail is a file of its own,
  `/etc/jail.conf.d/<name>.conf`, that begins with `.include
  "/etc/jail.conf";` and has the jail's block: `devfs_ruleset`,
  `sysvsem = new` and the like, `allow.raw_sockets`, `ip4.addr =
  "bridge0|172.23.1.43"`, `ip6.addr = "bridge0.20|2a01:...:443"` (an
  interface and an address each), and `.include`s of templates kept
  beside it, such as a certbot one that adds `exec.created +=` and
  `exec.poststop +=` lines (directories made, nullfs mounts of another
  jail's certificates, unmounted at stop); a template is written once
  and included by every jail that needs it. The console's forms: the
  shared defaults once per host, a jail (name, dataset, addresses on
  their interfaces, the switches, the templates to include), a
  template (its lines); the agent writes the files (libjailconf
  already parses them), makes the dataset and starts the jail.
  Done 2026-10-12: the jail-conf job (make, remove, defaults,
  template, untemplate) and the jail-files read; the page's + jail,
  Defaults and Templates; verified as root on a pool of a memory disk
  (agent_root_test:jail_make): a jail by clone and one by send, started,
  their datasets at their paths, the base untouched; a removal with a
  dataset not the jail's refused with the jail left running (found
  there: it was stopped before the dataset was asked about), then each
  taken away with its own.  Not yet: changing a made jail's file from
  the page (it is made and taken away; its block is edited as any
  jail's is).  The datasets above a jail's that are not there are made
  (canmount=off), and taken away again when the make fails; a pool is
  never made nor taken away.  The IPFW tab's Load the current file
  verified in a jail with its own rc.conf and script (the lab's
  arcswan1 root).
- Asked for on 2026-10-11, each a task of its own, in no order yet:
  - Users and groups, roles (RBAC) and tenants in the console: who
    sees and changes which hosts and services.
  - Mail notifications of faults, jobs and runs. (Done 2026-10-12:
    Settings, Notifications, By mail; one worker reads each host's
    events, the agent's job ends among them now, and the console's
    host's sendmail(8) sends them, twenty an hour at most.)  The page
    tests that failed with mail_tick at 1 s (2026-10-13): the page
    tests waited for a button and clicked it in two calls, and a page
    drawn anew between them left the click on nothing (a safe job
    never confirmed, the queue never run).  They wait and click in one
    call now (click_when); with 1 s in every test's console the whole
    suite passed twice.
  - The console's CA: one imported, or made and self-signed from the
    panel, given to each agent and trusted there; the console as a CA
    and as an intermediate CA under another.
  - A session's lifetime set in Settings. (Done 2026-10-12: idle
    minutes and the longest, in hours.)
  - LDAP for the console's sign-in.
  - The base system's ssh, further: the banner, the users let in,
    authorized keys, host keys and their fingerprints, host keys
    signed by a CA key.
    (Done 2026-10-12: the SSH tab, of a host or a jail; sshd -T read,
    each change read by sshd -t first and kept beside, undone in safe
    mode; verified with the real sshd and ssh-keygen in a lab jail.
    Not yet: TrustedUserCAKeys (user certificates) set from the page.)
  - IDS/IPS by Snort, a plugin (luxuria) as before: Snort and its
    rules updated and configured from the panel.
  - The console clustered; disaster recovery across console clusters.
  - Agents in an HA pair on identical hardware and ports (CARP, the
    state shared), with CARP on its own for a host.
  - VPN groups and road warrior setups of several clients, policies
    and pools.
  - A Devices page of its own, a table of the hosts (sorted and
    filtered), the rail's host list moved there. (The page done
    2026-10-12.  The rail's list not moved yet: it is the way to each
    host's jails, so what the rail keeps after (the open host and its
    jails?) is the user's to say.)
  - To ask the user what is meant: MSS clamping "on transports" (the
    SD-WAN tunnels by ipfw tcp-setmss, an interface's, or the agent's
    links?), labels on interfaces (a console-side tag, or the
    interface's description?), prefix lists (used by what: ipfw
    tables, BIRD filters, SD-WAN zones?), IGMP and MLD (what to set).
  - A certificates tab per host, by certctl and OpenSSL. (Done
    2026-10-12: trusted and untrusted, read with OpenSSL; a CA given,
    one distrusted and trusted again, kept where certctl rehash finds
    them; a jail's too.  Verified with the real certctl in a lab jail.)
  - Configuration templates: a host's setup exported to one and a
    template applied to a host; YAML where the standard allows,
    UCL otherwise.
  - A span tab: traffic mirrored by a BPF interface, or by ipfw rules
    with BPF.
    (Done 2026-10-12: Network, Span: a bridge's span ports; rules with
    log logdst bpf, each a tap ipfw<n> (FreeBSD 16), made and listed;
    capture by tcpdump from any of them, the lines and the pcap.
    Verified in a vnet jail with devfs's bpf unhidden.)
  - Labels on interfaces, for the UCS they carry.
  - BIRD's OSPF, BFD and BGP each a tab of its own, with forms.
  - IGMP and MLD configured.
  - NDP and ARP entries added and deleted by hand, temporary or
    permanent. (Done 2026-10-12: the neighbour job, kept as rc.conf's
    static pairs; verified in a vnet jail with arp(8) and ndp(8).)
  - MSS clamping on transports.
  - QoS on ipfw by forms: pipes, schedulers, queues, their masks and
    the rules that use them, beyond what SD-WAN makes.
    (Done 2026-10-12: the Firewall tab's QoS; dummynet read as
    objects, each made, changed and taken away by a form and kept as
    one line; a rule that sends to a pipe or queue.  Masks are each
    address or all; prefixes and ports in a mask still by ipfw's
    words.)
  - Flaky under the whole suite's load (2026-10-12): agent_test:observe
    expected "samples":[] after the last sample, and under load the
    sampler looked again first.  (Done 2026-10-13: what comes after
    the last is checked to be only newer.)
  - Every table exported as CSV. (Done 2026-10-12: ⤓ in every
    table's head, the rows as shown.)
  - Prefix lists kept by the console and used on any host.
  - SD-WAN policies by named lists (MEF 70.2, no vendor's model):
    lists of UCS, of prefixes (as the zones hold them), of edges, of
    UCS End Points (the edge's underlay address, the UCS, the tunnel
    kind and a preference) and of services, kept once and called by
    an AFS match or a policy's criteria; and the policy made in
    three steps: the lists, then the flows (the AFS) and the policy
    they get, then the policy map at each SWVC End Point.
- WireGuard, done 2026-10-12: a client made from the page (its
  configuration and QR code, the key pair made by the console and kept
  nowhere), with a preshared key (a job's preshared-key, given to wg in
  a file there only while it is read), and a client's key turned (↻:
  the new peer in, then the old one out).
- Storage, beyond what there is: a key that is typed, for
  a dataset whose keylocation is prompt, without it being kept in a
  job; a key changed; file systems other than UFS made; a disk's
  self-test started; a vnet jail's datasets from the jail's own page.
  (A key typed and a key changed done 2026-10-12: zfs-key, a call
  and not a job, verified as root on a pool of a memory disk.  FAT by
  newfs_msdos done too, verified on memory disks.  A self-test: only
  NVMe has one in the base system (nvmecontrol selftest; ATA and SCSI
  need smartctl, a package), and the lab has no NVMe disk to try it
  on: left until one is there.  A jail's datasets on its page done
  too: the storage read with jail, its own zfs list by jexec; verified
  with a dataset given to a vnet jail on a pool of a memory disk.)
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
  (Done 2026-10-13: deladdr, static and flush, static kept in rc.conf;
  verified in a vnet jail.  Found there: run_exec scopes what it runs,
  so a caller that scoped ifconfig too gave it -j twice, and a bridge
  in a jail could be neither read nor changed: scope_argv leaves what
  is scoped already.)
- Gula, further: older samples thinned instead of dropped; dmesg for
  an agent that is not root, which the kernel refuses unless
  security.bsd.unprivileged_read_msgbuf is on.
  (Done 2026-10-13: the older half thinned, the oldest kept until the
  older half is 64 looks apart; a refused dmesg says what lets it.)
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
- wg-quick(8): the tests use stand-ins (wg(8) and birdc(8) were run
  for real, below).
- A vnet jail's network. Run for real, against the jail `gateway` of
  one host: its interfaces, routes, route lookup and BIRD read; an
  address added and removed; an interface brought up; a new epair
  given, taken back and destroyed. Not run for real: the map with a
  real jail as a node (the browser test tells the page that a jail
  runs).
- A jail's share of the CPUs and its memory from rctl_get_racct(2):
  the test VM's kernel has kern.racct.enable off, and turning it on
  needs a reboot; what is read when it is off was run for real.
- The switch to SCTP from the page, and SCTP between two machines:
  the API was run for real, between a console and an agent on one
  machine.
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

- EC keys for the console's own HTTPS certificate: Kore's key manager
  signs with RSA only, so `console.pem` must be RSA until Kore (or a
  patch like the one in `port/www/kore/files`) handles ECDSA.
- A web terminal in the console: it could not be built.
- Luxuria in the agent is the plugins, BIRD and WireGuard's `wg`; what
  reaches outside (the release check, notifications) is the console's.
  A plugin is still built into the agent and the page: what makes it
  one is that it is there only where its program is installed.
