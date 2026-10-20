# SSL/TLS and SSH inspection: a plan

Asked for on 2026-10-19 ("Plan for supporting the ssl/ssh inspection
too"), after the decisions of 2026-10-18 said SSL inspection is wanted.
Nothing here is built yet. FreeBSD 15.1 and later only; Arcana installs
nothing by itself (a button the admin presses is fine); no pf.

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
Arcana reads Suricata's alerts today, not these records.

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

## The plan, for TLS

### 1. One inspection CA, the console's (first)

The console already makes and rotates its own CA (pki.c, Settings ›
Certificate authority). Beside it, an **inspection CA**, apart from the
CA the agents trust (that one must never be trusted by browsers):

- a root made by the console, its key kept there, and never sent to an
  edge;
- for each edge that inspects, an **intermediate** signed by that root,
  its key made on the edge (a request, as enrolment does), so an edge
  lost gives away its own intermediate alone, which is then revoked by
  issuing the edge a new one;
- the root's certificate to download (PEM and DER) from Settings, and
  shown in the URL filter's form: what the clients install once, for
  every edge;
- rotated as the console's CA is: the next root made, both trusted for a
  while, the edges given new intermediates, the old root retired.

Squid then bumps with `tls-cert=` the intermediate and its chain, so
every edge is trusted by one root.

### 2. What is not opened

- A **do-not-decrypt list** for each filter and each SD-WAN policy:
  domains (`ssl::server_name`) and destination prefixes, the second
  reusing the console's prefix lists. They are `splice`d after the peek.
- **Source classes**: a prefix list of clients that are inspected (the
  guests' network), the rest spliced.
- **Pinned or unsupported**: `on_unsupported_protocol tunnel all`, and a
  bump that fails its handshake is spliced the next time for that name
  (kept by the agent for a day), and said (3.).
- No category feed: a list of categories would be a third party's.
  Arcana offers a small default list (the FreeBSD update servers, the
  hosts' package mirrors, the console itself), editable.

### 3. What happened, told

Squid's access log, in a format of Arcana's own with `%ssl::bump_mode`,
`%ssl::>sni`, `%ssl::<cert_subject` and `%ssl::<cert_errors`, read by
the agent as it reads eve.json: each connection's outcome (opened,
passed, ended, failed) counted in the read, and a failed bump an event
(`tls-inspect`), shown on the Security page and in the event log.

### 4. Opened traffic to an IDS (later, and an open question)

Squid encrypts again towards the server, so there is no plaintext on a
wire for Suricata to read. The ways open:

- **ICAP**: c-icap already gets the requests and responses of a bumped
  connection. A c-icap service of Arcana's own that hands them to
  Suricata as files (Suricata's file inspection) or runs its HTTP rules
  is possible, but new code in C against c-icap's API.
- **Leave it**: ClamAV on what is opened, Suricata on everything else,
  and Suricata's TLS rules (by SNI, JA3/JA4, certificate) on what is
  not opened.

Recommended: leave it for now, and decide after 1.–3.

### Where it shows

- Security › URL filter: in `inspect` mode, the do-not-decrypt list,
  the source classes, the root to download, and what was opened,
  passed, ended and failed.
- SD-WAN: the url-filter criterion of a security policy gets the same
  lists (named lists of the SD-WAN document).
- Settings › Certificate authority: the inspection CA beside the
  console's, with its edges' intermediates.

## The plan, for SSH

Opening SSH as TLS is opened would mean a proxy that ends every session
with a host key of its own: every client's known_hosts would warn, keys
and agent forwarding break, and no such proxy is in base or a well kept
port. Not planned. What can be done:

### 1. Seen, not opened (first)

Suricata's SSH records read by the agent like its alerts: each session's
client and server, banners, hassh and hasshServer, and its length.
Shown on the IDS/IPS tab as SSH sessions, with rules on them (an
unknown client fingerprint, a server banner that is not OpenSSH, SSH on
a port that is not 22). ET Open has SSH rules already.

### 2. Controlled where Arcana runs the server

The hosts' own sshd is already Arcana's to configure (the SSH tab: keys,
user CAs, options). For SSH into the fleet:

- **certificates**, as now, with the principals, `source-address` and
  `force-command` of each user's certificate set by the console's RBAC
  role (who may log in where, from where);
- **every session logged**: sshd's `LogLevel VERBOSE` (which key and
  certificate), read by the agent as an event (`ssh-session`: who, from
  where, how long);
- optionally **a session recorded**: `ForceCommand` running script(1)
  with timing (`script -r -T`), the recording kept on the host and
  played back from the console. It is visible to the user, and their
  interactive session only (not scp or forwarding).

### 3. A bastion (if wanted)

A jump host that records every session (sshpiper, Teleport) is a third
party's program: possible as a plugin the admin installs with a button,
as BIRD is, but not planned unless asked.

## Order

1. The inspection CA, its intermediates, its download (TLS 1.).
2. The do-not-decrypt and source lists (TLS 2.).
3. What happened, told (TLS 3.), and Suricata's TLS and SSH records read
   (SSH 1.), as one reader of the logs.
4. SSH sessions logged, and recorded if wanted (SSH 2.).
5. Then decide on TLS 4. and SSH 3.

Each step is tested as the URL filter is today: stand-ins for Squid and
Suricata in agent_test, and a lab run against the real Squid and
Suricata in a vnet jail before it is called done.

## For the user to decide

1. One inspection root for the console, or one for each tenant fleet?
   (One a fleet keeps a customer's clients from trusting another's.)
2. Per-edge intermediates with the root key on the console only
   (recommended), or one key shared by every edge (simpler, worse when
   an edge is lost)?
3. The default do-not-decrypt list: Arcana's small one and the admin's
   own, with no category feed — enough?
4. SSH: sessions seen (Suricata) and logged (sshd) only, or also
   recorded (script(1)), or a bastion plugin?
5. A notice page for inspected clients (Squid's `deny_info` and a first
   visit page), wanted?
