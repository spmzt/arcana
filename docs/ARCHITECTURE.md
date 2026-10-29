# Arcana architecture

Arcana manages a fleet of FreeBSD hosts: an agent on each host, and a
console that coordinates them for its users.  The vocabulary of Archives,
Agent and Orchestrator is in [NAMING.md](NAMING.md).

## Programs

Each program does one thing.  There is one daemon per role.

| Program | Runs on | Does |
|---|---|---|
| `arcana-agent(8)` | every host, as root | Serves the host's YANG models over cblink's YANG family: reports jails and the rest and changes them. The only privileged component. |
| `arcana-console(8)` | the console host, unprivileged | Its own HTTP server on libwebsockets: serves the PWA and its JSON API, authenticates you with WebAuthn, talks to `arcana-agent` instances as a cblink client. |
| PWA (C → wasm) | the browser | The console. |
| `jailconf(8)` | anywhere | Adds or removes a value of one jail's parameter in jail.conf, in place, like sysrc(8) does for rc.conf. |
| `arcanactl(8)` | anywhere | Command-line client for `arcana-agent`. |
| `arcana-enrol(8)` | a host, once | Gets the host a certificate from the console's CA with a one-time token, and starts `arcana-agent` with it. |

```
 browser                 console host                         hosts
┌──────────┐  HTTPS   ┌──────────────────────┐  cblink     ┌──────────────────────┐
│ PWA      │ ───────▶ │ arcana-console       │ ──────────▶ │ arcana-agent         │
│ C → wasm │   JSON   │ WebAuthn, sessions,  │ TCP, mTLS   │ libjail, libprocstat │
│          │ ◀─────── │ server registry      │ ◀────────── │ jail(8) -e / -c / -r │
└──────────┘  cookie  └──────────────────────┘    CBOR     │ libjailconf          │
                                                           └──────────────────────┘
                                         arcanactl ─────▶ (the same models, for admins and tests)
```

When the console host also has jails it runs both: the web-facing
process stays unprivileged and reaches the local `arcana-agent` over an
AF_UNIX socket.

## The wire: YANG

The contract between `arcana-agent` and its clients is its YANG models
(`share/yang`): the standard ones (RFC 8343's interfaces, RFC 8349's
routing, RFC 8341's NACM...) with Arcana's augments, and a module of
Arcana's where none exists, each with its SIDs (RFC 9595,
`share/yang/SIDS.md`).  They travel as YANG-CBOR (RFC 9254) on cblink's
YANG family: GET of a datastore, EDIT of the candidate and a confirmed
commit, an rpc or an action, RFC 8639 subscriptions; cblink-gen(1)
writes the C structures, the schema tables and the server's
trampolines from the modules (`share/mk/arcana.yang.mk`).  Beside it
the agent has two families of its own, for streams alone: `arcana-
stream` (a snapshot sent or received, a capture put or a pcap-log
file got) and `arcana-parts` (a network table in parts).  The steps a
request takes are told to its peer as it runs, arcana-jobs' `steps`
notification.

`share/arcana/arcana.yaml` is no family any more: what the programs
keep for their own use (a jail, a service, a job and the change it
makes, the kinds of job), from which `share/arcana/wire.awk` writes the
module `arcana@<rev>` of structures alone and the header that names
them (`arcana.h`); `share/arcana/jobs.awk` makes arcana-jobs' kinds of
it and `jobs.yaml`.  The consoles' own family, `cluster.yaml`, is a
family as it was.

The core operations, and what each runs on the host (the rest are in
`share/arcana/yang-ops`, each with its module):

| Operation | Does | Mechanism in `arcana-agent` |
|---|---|---|
| arcana-host `host` | host facts, the agent's features | uname(3), sysctl(3) |
| arcana-jails `jails` | running and configured jails | jail_getv(3), procstat_getprocs(3), `jail -f scope -e sep` |
| arcana-jails' `start`, `stop`, `restart`, `kill` | a jail's actions | jail(8) `-c`, `-r`, `-rc`; jail_remove(2) for kill |
| arcana-network's `address` | add or remove an IP, live and/or persistent | jail_setv(3), SIOCAIFADDR ioctls, libjailconf |
| arcana-services `services` | the host's rc.d scripts, enabled and running; in running, each one's rcvar and variables | the rc.d directories, `<name>_enable` in `sysrc -A`, `service <name> status`; the files rc(8) reads (libvarconf) |
| arcana-services' `start`, `stop`, `restart`, `reload`, `read` | a service's actions; one read as it is now | `service <name> <verb>`; `service <name> enabled`, `describe`, `extracommands` |
| arcana-services, committed | enabled or not, its rc.conf variables | Arcana's rc.conf file (`/usr/local/etc/rc.conf.d/arcana`), yours commented out where accepted |
| arcana-network's read actions | routes, nexthops, connections, sockets | `netstat --libxo json -rnW / -onW / -nW -f <family>`, `sockstat --libxo json -w -4/-6`; one run per family, joined |
| arcana-host `stats` | CPU, load, memory, swap, ZFS pools | `kern.cp_time` between requests, `vm.loadavg`, `vm.stats.vm.*`, `swapinfo -k`, `zpool list -Hp` |
| arcana-packages `packages` | pending upgrades of the host or a running jail | `pkg [-j jail] update -q`, `pkg [-j jail] version -vRl '<'` |
| arcana-packages' `upgrade` | upgrade all or named packages, or show what would be | `pkg [-j jail] upgrade -y|-n [names]`, then `pkg version` again |
| arcana-jobs `submit` | queue a batch of changes | the job queue, below |
| arcana-jobs `jobs`, its `read`, `cancel`, `confirm` | list jobs, read one with its trace so far, take a queued one back, keep a safe change | the job queue |

Every request requires an authenticated peer: a client certificate
from the arcana CA over TCP, or access to the 0600 AF_UNIX socket; a
host's certificate (urn:arcana:role:agent) asks nothing.  What it may
do is NACM's (RFC 8341): what changes the host, or gives out what
should stay on it, is `nacm:default-deny-all`, run only by a rule that
permits it.  A refusal comes back with its words, and the steps told
while it ran, so a failed jail(8) run still comes back with its output.

Reading configuration goes through jail(8) itself (`-e`), so variables,
includes, `*` blocks and per-jail `jail.conf.d/<name>.conf` files mean
exactly what they mean to jail(8).  libjailconf exists only for the one
thing jail(8) cannot do: change a value in place.  It parses a file only
to find the jail's block and the bytes to change; what the jail already
has or inherits it is told, from `jail -e`.  After writing,
`arcana-agent` reads the file back with `jail -e` and restores the previous
version if jail(8) disagrees with the edit.

## Library choices

Base system first; packages only where they remove real work.

| Need | Library |
|---|---|
| Jail state and changes | libjail(3) (base) |
| Per-jail processes | libprocstat(3) (base) |
| Interface aliases | ioctl(2); libifconfig is internal to base, with no header |
| JSON (backend, frontend) | libucl (base, `libprivateucl`); the frontend compiles the same sources to wasm |
| Text sanitising | vis(3) (base) |
| WebAuthn signatures | libcrypto (base OpenSSL); browsers hand the public key over as SPKI DER, so no CBOR decoding is needed |
| Host transport | cblink (libcblink, needs the libcbor package) |
| Tests | ATF: atf-c(3), atf-sh(3), kyua(1) (base) |

## Trust boundaries

| Component | Privilege | Holds |
|---|---|---|
| Browser | none | an HttpOnly, SameSite=Strict session cookie |
| `arcana-console` | unprivileged user (its supervisor root, to listen and read the HTTPS key) | the users, their roles and WebAuthn public keys, its cblink client certificate and key, and the CA's key when it runs its own CA |
| `arcana-agent` | root | its server certificate and key, the CA certificate |

## Authentication (browser to console)

Users, each with one or more WebAuthn credentials (a security key and
a spare), and roles that say what each may do on the console and on
which hosts (`users.json` in the data directory).  A user may belong to
a tenant, a fleet of its own, and then sees that tenant's hosts alone.

* **Enrolment.**  With no credential stored, the backend writes a random
  one-time setup token to `<datadir>/setup-token` (mode 0600).  The first
  registration needs it and makes the built-in owner; an invited user
  registers with the invitation's token; adding a key needs a logged-in
  session.
* **Ceremonies.**  32-byte single-use challenges, valid two minutes.  The
  backend checks `clientDataJSON` (type, challenge, origin) and the
  authenticator data (RP ID hash, flags, counter) and verifies the
  signature with libcrypto.  ES256, EdDSA and RS256.
* **Passwords.**  A user may also sign in with a password of the
  console's own (bcrypt) or, when **Settings** name a directory, by LDAP
  over TLS.  A session opened so cannot change sign-ins, tokens, users,
  the CA or the settings; that takes a key.
* **Sessions.**  32 random bytes in a cookie; only its SHA-256 is kept.
  Idle timeout 30 min, absolute 12 h.  One guard checks every protected
  route; state-changing requests also need the console's own `Origin`
  (a browser sends it), or `X-Arcana: 1` from a client that sends no
  `Origin`.  A GET changes nothing, so it needs neither, even where a
  read is kept to the roles that may change (a host's system files).
* **Headers.**  Every reply, the page's and the API's: a
  Content-Security-Policy (only the console's own scripts, styles, images
  and connections; WebAssembly; no framing), `X-Frame-Options: DENY`,
  `Cross-Origin-Resource-Policy` and `Cross-Origin-Opener-Policy`
  `same-origin`, `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`, a Permissions-Policy allowing passkeys, fullscreen and
  the clipboard alone, and over TLS `Strict-Transport-Security` for
  this host only, as many days as the setting `hsts_days` says (365
  unless set; 0 sends none).

## Console plugins

Extensions of the console's page, served by the console from its own
origin (`cplug.c`); not the hosts' plugins (BIRD, Suricata and the
others), which run on the hosts.  A console plugin's script runs with
the page's full rights, the signed-in user's, so only what the console
host's administrator installed and a console owner enabled is served.

* **Where.**  A directory each under web.conf's `plugins_dir`
  (`/usr/local/share/arcana-console/plugins` unless set; `""`, or no
  such directory, for none), named by the plugin's id.  A link to a
  directory elsewhere is not a plugin.
* **Format.**  `plugin.json` in it: `id` (`[a-z0-9-]{1,40}`, the
  directory's name), `name`, `version`, `arcana` (the least console
  version, `a.b.c`; an older console lists the plugin with why and
  serves none of it), optional `description`, `author`, `entry` (the
  `.js` files, in order), `styles` (`.css`), `assets` (files or
  glob(3) patterns of `.png`, `.svg`, `.webp`, `.json`, `.woff2`) and
  `provides` (words: `guide-pack`, `theme`, ...).  Anything else, a key
  the format does not have, a path that is absolute, hidden or has
  `..`, a file larger than 8 MB, a file whose real path is out of the
  plugin's directory (a link out), and the plugin is listed with the
  reason and none of it served.
* **Hashes.**  Each listed file's size and SHA-384 are kept; the page
  loads exactly these, with `integrity="sha384-..."`.  The directory is
  looked at again at most once a second, on `GET /api/plugins` and on a
  plugin's file asked for: rescanned when it, a plugin's directory,
  its `plugin.json` or the directory of a listed file changed, and a
  listed file whose time or size changed is hashed again.  No restart.
* **Enabled** by a console owner alone (`POST /api/plugins/<id>`
  `{"enabled": bool}`), kept in `console-plugins.json` in the data
  directory, written in the audit trail.  An enabled plugin is served
  to every signed-in user.
* **Served** at `/plugins/<id>/<file>`: a file the plugin lists, of an
  enabled plugin, to a session (not to an API token), with the
  headers every reply has (above), `Cache-Control: no-cache` and the hash as the
  ETag; read and hashed again as it is sent, its real path checked to
  be in the plugin's directory.  Anything else is not found.
* **Loaded** by the page (`bridge.js`, `plugins.c`) once signed in:
  the list is read then and again with the health (every 15 s while
  the page is looked at), and each enabled plugin with no error that
  the page has not loaded yet gets its styles (`<link rel=stylesheet
  integrity crossorigin>`) and its scripts (`<script integrity>`, in
  `entry` order).  A file the browser refuses (its bytes not what was
  listed), a script that throws, a plugin function that throws: the
  plugin's error, shown in Settings, Plugins and in a toast; the page
  goes on without it.  Enabled, a plugin is loaded at once; disabled,
  it stays in a page until that page is loaded again (Settings says
  so).  Settings, Plugins lists them (name, version, author, provides,
  enabled, and what the page made of each) and has Enable and Disable
  for a console owner.

The page gives a plugin's scripts `window.Arcana`:

| Member | What |
|---|---|
| `version` | the console's version |
| `user` | `{name, role}` of who is signed in |
| `registerPlugin({id, screens, menu, on})` | once, from the plugin's own script, `id` its own; `on` as `Arcana.on` for each key |
| `api(method, url, body)` | a request to the console as the page makes them (its session, `X-Arcana`), a path of the console's alone; `body` sent as JSON; a Promise of the reply's JSON, rejected with an `Error` (`status`, `body`) unless 2xx |
| `navigate(hash)` | goes to an address of the page (`#/...`) |
| `toast(text, bad)` | a toast, an error's when `bad` |
| `fullscreen(on)` | the page over the whole screen, or not, where the browser lets it |
| `on(event, fn)` | `route` (`{hash}`, each address), `theme` (`{theme}`), `servers` (`[{id, name, local}]`, when the hosts change, and at once with them as they are), `signed-out`, `gamepad-first` (`{id}`, a controller's first press on the console's pages; a handler that returns `true` takes it, and the page does nothing with that press) |

`screens: {<name>: {title, enter(root, ctx), leave()}}` are the
plugin's screens, at `#/p/<plugin>/<name>[/<rest>]`: shown, the page's
own regions are put away and its controller overlay is off (the screen
reads the Gamepad API itself), `enter` gets a root element over the
whole page and `ctx` (`plugin`, `screen`, `rest`, `exit()` back to the
page as it was); `leave` is called when another address is gone to.
The rest of the address is the plugin's: `route` tells it when it
changes.  `menu: [{label, screen}]` adds entries to the account menu
that open a screen of the plugin's.

## Enrolment (host to console)

Without a `tls { }` block the console runs its own CA (`pki.c`): EC
P-256, made at first start in the data directory, with the console's
client certificate signed by it.  A logged-in user asks for a token for
a host (`POST /api/enrol/tokens`: name, host, port); it is 32 random
bytes, single use, valid an hour.  `arcana-enrol(8)` on the host makes
a key and a certificate request and sends them with the token (`POST
/api/enrol`, no session).  The console signs a certificate for the
token's host, whatever the request's subject says, with `serverAuth` and
a SAN for the host, returns it with the CA, and adds `tcp://host:port`
to its servers.  The host's key never leaves the host.

## Trace model

Every reply that touched a host carries a trace: steps with a parent,
forming a tree.  `arcana-agent` records its own steps; the backend adds the
API, session check and cblink request steps above them.

```
POST /api/servers/s1/jails/web/restart          api
├─ session check                                auth
└─ libcblink YANG action tcp://host:4310      lib   libcblink, mTLS
   └─ arcana-agent jail web restart               daemon
      ├─ /usr/sbin/jail -f … -e \037            exec  (read configuration)
      ├─ jail_getid(3)                          lib
      ├─ /usr/sbin/jail -f … -rc web            exec  (the restart)
      └─ jailparam_get(3)                       lib
```

`kind` is `api`, `auth`, `daemon`, `lib`, `syscall`, `file` or `exec`.
Only `exec` steps carry `argv`, `exit`, `output` and `error-output`; the
UI shows its raw-output button exactly when a trace has one.  Because
configuration is read through `jail -e`, any request that reads
configuration has one.  Program output reaches the browser with
unprintable characters as vis(3) escapes (the `-e` separator shows as
`\037`).

## Jobs

A change that is asked for and waited on dies with its connection. That
is wrong for exactly the changes that matter most: restarting the jail
the console runs in, or the interface it is reached through. So every
change can instead be **queued as a job** (arcana-jobs' `submit`, one or a batch
of up to 64).

The daemon keeps a queue and one thread that runs it, in the order
given, under the same lock as direct changes. A job belongs to the
daemon, not to the connection that queued it: the client may leave, and
the job and those behind it still run to their end. Each job has its own
trace, changed under a lock, so `job` returns the steps done so far
while it runs; a step that has begun and not ended has the status
`incomplete`. A queued job can be cancelled; a running one cannot. The
last 64 finished jobs are kept in memory, and all are forgotten when
the daemon restarts.

The console sends every change as a job and reads it once a second, so
the workflow graph grows stage by stage; when the host stops answering,
the entry says so and keeps trying, and shows the outcome when the host
is back. With **Queue** on, changes are held in the browser and sent
together as one batch. Reads (lists, tables, dry runs, previews) stay
direct calls.

## What the console holds by subscription

Beside the pool of connections its requests take (over SCTP one
association every request shares), the console keeps one more
connection to each agent a page reads from, on a thread of its own
(`watch.c`), for RFC 8639's dynamic subscriptions over cblink's
SUBSCRIBE streams.  A topic is subscribed the first time a read of it
is asked, for the user it is asked for, whose access rules (NACM, RFC
8341) the agent holds the subscription to, and let go when no read
asked for it for two minutes:

| Topic | Subscription | Answers |
|-------|--------------|---------|
| jobs | arcana-jobs, on-change (the agent tells each job's change; RFC 8641) | `GET jobs`; a job's read while it is queued |
| stats | arcana-host's stats, periodic, 5 s | `GET stats` |
| jails | arcana-jails, periodic, 5 s | `GET jails` (the host by its hello, asked each time) |
| sdwan | arcana-sdwan, periodic, 2 s; arcana-probe read by the thread at that period, as the user | `GET sdwan?after=` (subscribed for those alone; the samples after a time held, ten minutes of them) |
| events | the NETCONF stream | every page following the host's events |

A push-update is the whole of a topic, a push-change-update a YANG
Patch applied to a copy of the last; each is made the module's struct
the read's JSON is built from, so a read answered from what is held has
the shape the host's own answer has, its trace saying how old it is.
The first read of a topic, a read a page asks with its steps shown, and
every read while nothing is held go to the host as before; a change the
console makes to a host, or a job's there, lets go of what is pushed
periodically until its next push, so a read after a change is never
answered with the state before it.  A running
job's trace is its read action's alone: the console reads it at most
once a second whatever number of pages poll it, and keeps a finished
job's read.  The connection lost, what is held goes with it; it is made
again one second on, doubling to a minute, and the topics still asked
for are subscribed anew.  An agent that has no such subscription (one
of the release before) refuses it, and its reads, and the pages that
follow its events, go to it as they did.  `GET
/api/servers/<id>/watch` says the connection's state, each topic's,
and how often the console went to the agents and answered without them.

## Services

The daemon never reads or writes `rc.conf` itself.  It lists the
executable scripts of `/etc/rc.d` and `/usr/local/etc/rc.d`, reads
`<name>_enable` from `sysrc -A` (which evaluates the configuration
without running any script; `service -e` runs every one, and scripts
with no default for their rcvar warn each time) and asks `service
<name> status` whether the enabled ones run, and changes things with `service <name> <verb>` and
`sysrc(8)`, so quoting, `rc.conf.d` and `rc.conf.local` mean what they
mean to the system.  A service's variables are those `sysrc -a` lists
whose names start with the script's name or its rcvar's stem; only such
names can be set, and nothing is passed through a shell.  Every program
run is a step in the trace with its output; listing a host with many
enabled services takes one `status` run per service, so the console
fetches the list only when the Services tab is opened or refreshed.

## Addresses and aliases

A live address change sets the running jail's `ip4.addr`/`ip6.addr` with
jail_setv(3) and, when the jail has an `interface` parameter, adds or
removes the alias with SIOCAIFADDR/SIOCDIFADDR, as ifconfig(8) would.
jail(8) only removes the aliases of configured addresses when a jail
stops, so arcana-agent removes the ones that were added live after a stop or
restart, and all of them after a kill, which bypasses jail(8).

A persistent change edits the jail's own block in the file that defines
it, keeping every other byte; values inherited from global statements or
`*` blocks are left alone.

## Jail states

`running`, `stopped`, `dying` and `absent` come from the host.  The UI
adds `starting`, `stopping` and `restarting` while an action is in
flight, `error` after a failed one, and `unknown` when data is stale or
the host is unreachable.

## Offline behaviour

The service worker precaches the application shell (HTML, CSS, the wasm
and its glue, fonts, icons) under a name derived from a checksum of the
shell; `/api/` is never cached, and nothing about jails is kept in browser
storage.  The top bar shows three signals: NET (`navigator.onLine`), API
(`/api/health`, every 15 s) and HOST (the last request to the selected
arcana-agent).  Jail data older than 30 s, or from a failed refresh, is
dimmed and marked stale with its age; jails of an unreachable host show
as unknown.  Started offline, the app says that it is there but jail data
is not, and reconnects by itself.

## Layout

```
cblink/                 the transport, a submodule
share/arcana/           the kept structures, the jobs, the cluster's family
share/mk/               build settings shared by every Makefile
share/yang/             the YANG modules and their SIDs
lib/libjailconf/        in-place jail.conf editing
lib/libvarconf/         in-place rc.conf, loader.conf, sysctl.conf editing
usr.sbin/jailconf/      jailconf(8)
usr.sbin/arcana-agent/  arcana-agent(8)
usr.sbin/arcanactl/     arcanactl(8)
usr.sbin/arcana-enrol/  arcana-enrol(8)
www/arcana-console/     arcana-console(8)
www/arcana-ui/          the PWA
docs/                   this file, the other guides, openapi.yaml
tests/                  the top of the installed test suite
```

Each directory has a `tests/` with atf-c or atf-sh tests; `make check`
runs them with kyua(1), and they install to `${TESTSBASE}/arcana`.

| Suite | Kind | Covers |
|---|---|---|
| `libjailconf` | atf-c | edits, quoting, inherited values, includes, diff, atomic writes |
| `jailconf` | atf-sh | the command line, dry runs, errors |
| `arcana-agent` | atf-sh | listing through jail(8) -e, actions and address changes with a stand-in jail(8), traces, mutual TLS; as root, a real throwaway jail, live addresses and alias cleanup |
| `console` | atf-c | WebAuthn as an authenticator would do it (ES256, Ed25519, wrong origin, RP, challenge, signature, counter), CSRF, servers, jails through arcana-agent over a socket and over mutual TLS |
| `console/pwa` | atf-c | the PWA in Chromium with a virtual authenticator: enrolment, an action, the workflow and raw output, an address preview, login, offline reload |
