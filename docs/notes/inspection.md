# SSL/TLS and SSH inspection: a plan

Not built. TLS is inspected transparently by SSLproxy: clients set no
proxy, they trust one root and nothing else. FreeBSD 16.0 and later
only; Arcana installs nothing by itself (a button the admin presses is
fine); no pf.

## What there is today

**TLS, by Squid's ssl-bump.** A URL filter of the Security page, and the
url-filter criterion of an SD-WAN security policy, run Squid in one of
two modes:

- `sni`: the ClientHello is peeked at (`ssl_bump peek step1`), a denied
  name is ended (`terminate`), the rest passes unopened (`splice`).
- `inspect`: the rest is opened (`bump`) with a CA of the instance's own,
  made once on the agent by openssl(1) and kept there; its certificate
  is told in the sdwan read for the clients to trust. What a bumped
  connection carries can be scanned by c-icap with ClamAV (ICAP on the
  loopback, the Antivirus tab).

The Security page's filter is an explicit proxy; SD-WAN's intercepts
(`https_port … intercept ssl-bump`, the traffic sent to it by an ipfw
`fwd` rule, in the service's routing table by setfib(2)).

**TLS and SSH, seen but not opened, by Suricata.** Its EVE log has, for
TLS, the SNI, the server certificate's subject, issuer, validity and
fingerprint, and the JA3/JA4 fingerprints of client and server; for SSH,
the client's and server's version banners and their hassh fingerprints.
Arcana reads Suricata's alerts, not these records.

## What is missing

1. **The inspection CA is the instance's own.** Each Squid makes one, so
   every edge has a different root to trust, nothing rotates it, and the
   console does not know them. Its private key lives on the edge.
2. **No "do not open" list** beside allow and deny: banking, health,
   pinned applications, the hosts' own update servers.
3. **What fails to bump is not told.** A pinned client fails silently;
   nothing says which connections were opened, passed or ended.
4. **What is opened is not given to Suricata.** It sees TLS as encrypted
   even where Squid opened it.
5. **SSH: nothing** beyond what Suricata would log, and Arcana does not
   read it.

## The plan, for TLS: SSLproxy, transparent

The engine is SSLproxy (security/sslproxy), a plugin with an install
button as BIRD is.

### 0. How the traffic reaches it

- An ipfw `fwd` rule sends the clients' TLS to SSLproxy on the
  loopback, in its own range of the kept rules (an Arcana part, so the
  admin's rules are never touched, see the firewall's care rule):
  `fwd 127.0.0.1,8443 tcp from <clients> to not me 443 in recv <lan>`,
  and the same with `::1` for IPv6. `fwd` keeps the destination, so
  SSLproxy's `ipfw` NAT engine reads it with getsockname(2); no NAT, no
  divert, no pf.
- On an SD-WAN edge the rule lives in the service's routing table
  (setfib(2)) as the Squid intercept does today.
- SSLproxy's proxyspec: `https 127.0.0.1 8443` (and `::1`), with
  `natengine ipfw`; plain HTTP on 80 can go the same way (`http`), for
  the same filter and log.
- What SSLproxy does with a connection, per its filter rules (by SNI,
  certificate CN, host, URI, source address): **Pass** (spliced, not
  opened), **Block**, **Split** (opened and re-encrypted, logged), or
  **Divert** (opened and handed to a listening program).

### 1. Inspection CAs, the console's (first)

The console already makes and rotates its own CA (pki.c, Settings ›
Certificate authority). Beside it, **inspection CAs**, apart from the
CA the agents trust (that one must never be trusted by browsers):

- one root **per tenant fleet**, made by the console, its key kept
  there and never sent to an edge: a tenant's clients trust only its
  own root;
- for each edge that inspects, an **intermediate** signed by its
  fleet's root, its key made on the edge (a request, as enrolment
  does): SSLproxy's `CACert`/`CAKey`/`CAChain`, so an edge lost gives
  away its own intermediate alone, which is then revoked by issuing a
  new one;
- each root's certificate to download (PEM and DER) from Settings and
  the inspection page: what the fleet's clients install once, for
  every edge;
- rotated as the console's CA is.

### 2. What is not opened

- A **do-not-decrypt list**: domains and destination prefixes (the
  console's prefix lists), as SSLproxy `Pass` rules (`PassSite`):
  Arcana's small default list (the FreeBSD update and package servers,
  the console itself) and the admin's own; no category feed (a third
  party's).
- **Source classes**: the clients inspected (a prefix list, the guests'
  network); the rest never reach SSLproxy, the `fwd` rule names them.
- **Pinned or failing**: SSLproxy passes a connection whose handshake
  fails (`PassUnsupported`-like behaviour by its options), and it is
  told (3.).

### 3. What happened, told

SSLproxy's connect log (`ConnectLog`) and certificate log, read by the
agent as it reads eve.json: each connection's outcome (opened, passed,
blocked, failed) counted, a failure an event (`tls-inspect`), shown on
the Security page and in the event log.

### 4. Opened traffic to the IDS and the scanners

- **Suricata**: SSLproxy's mirror (`MirrorIf`, `MirrorTarget`) sends
  what it opened as emulated packets to an interface; an epair(4) pair
  whose other end Suricata reads (in IDS mode) gives it the plaintext.
- **Content logs and pcap** per connection (`ContentLogDir`,
  `PcapLogDir`): off by default; a troubleshooting switch, kept a short
  while.
- **Divert to a program**: SSLproxy inserts its `SSLproxy:` line for
  the program, which neither Squid nor c-icap read; not planned unless a
  program of Arcana's own is wanted.

### 5. Squid beside it

The explicit-proxy URL filter of the Security page and its ICAP/ClamAV
scanning stay Squid's (clients that do set a proxy). The transparent TLS
of SD-WAN's url-filter criterion moves from Squid's
`https_port intercept ssl-bump` to SSLproxy, so there is one way to
open TLS without a proxy setting.

### Where it shows

- Security › TLS inspection (new tab, a plugin's): on or off, the
  clients and interfaces, the do-not-decrypt list, the root to
  download, the mirror to Suricata, and what was opened, passed,
  blocked and failed.
- SD-WAN: the url-filter criterion of a security policy says
  "inspected" and names the same lists.
- Settings › Certificate authority: the inspection CAs beside the
  console's, with their edges' intermediates.

## The plan, for SSH

Opening SSH as TLS is opened would mean a proxy that ends every session
with a host key of its own: every client's known_hosts would warn, keys
and agent forwarding break, and no such proxy is in base or a well kept
port. Not planned. SSH sessions are seen and logged; they are not
recorded, and there is no bastion.

### 1. Seen, not opened (first)

Suricata's SSH records read by the agent like its alerts: each session's
client and server, banners, hassh and hasshServer, and its length.
Shown on the IDS/IPS tab as SSH sessions, with rules on them (an
unknown client fingerprint, a server banner that is not OpenSSH, SSH on
a port that is not 22). ET Open has SSH rules already.

### 2. Logged where Arcana runs the server

The hosts' own sshd is already Arcana's to configure (the SSH tab: keys,
user CAs, options). For SSH into the fleet:

- **certificates**, as now, with the principals, `source-address` and
  `force-command` of each user's certificate set by the console's RBAC
  role (who may log in where, from where);
- **every session logged**: sshd's `LogLevel VERBOSE` (which key and
  certificate), read by the agent as an event (`ssh-session`: who, from
  where, how long).

## Order

1. SSLproxy as a plugin: installed by a button, its rc.d service, its
   conf rendered on the agent from a form (as smtpd.conf and
   suricata.yaml are), the `fwd` rules in an Arcana range of the kept
   rules (0.).
2. The inspection CAs, their intermediates, their download (1.).
3. The do-not-decrypt and source lists (2.).
4. The connect log read, and Suricata's TLS and SSH records (3., SSH
   1.), one reader of the logs.
5. The mirror to Suricata (4.).
6. SD-WAN's transparent TLS moved from Squid to SSLproxy (5.).
7. SSH sessions logged (SSH 2.).

Each step is tested with stand-ins for sslproxy and ipfw in agent_test,
and a lab run with the real SSLproxy in a vnet jail before it is called
done.
