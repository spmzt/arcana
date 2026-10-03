# Jailgrid architecture

Jailgrid is a single-user console for FreeBSD jails on several hosts.

## Programs

Each program does one thing.  There is one daemon per role.

| Program | Runs on | Does |
|---|---|---|
| `jailgridd(8)` | every jail host, as root | Serves the `jailgrid` cblink family: reports jails and changes them. The only privileged component. |
| Kore module `jailgrid.so` | the console host, unprivileged | Serves the PWA and its JSON API, authenticates you with WebAuthn, talks to `jailgridd` instances as a cblink client. |
| PWA (C → wasm) | the browser | The console. |
| `jailconf(8)` | anywhere | Adds or removes a value of one jail's parameter in jail.conf, in place, like sysrc(8) does for rc.conf. |
| `jailgridctl(8)` | anywhere | Command-line client for `jailgridd`. |
| `jailgrid-enrol(8)` | a jail host, once | Gets the host a certificate from the console's CA with a one-time token, and starts `jailgridd` with it. |

```
 browser                 console host                         jail hosts
┌──────────┐  HTTPS   ┌──────────────────────┐  cblink     ┌──────────────────────┐
│ PWA      │ ───────▶ │ kore + jailgrid.so   │ ──────────▶ │ jailgridd            │
│ C → wasm │   JSON   │ WebAuthn, sessions,  │ TCP, mTLS   │ libjail, libprocstat │
│          │ ◀─────── │ server registry      │ ◀────────── │ jail(8) -e / -c / -r │
└──────────┘  cookie  └──────────────────────┘    CBOR     │ libjailconf          │
                                                           └──────────────────────┘
                                         jailgridctl ─────▶ (same family, for admins and tests)
```

When the console host also has jails it runs both: the web-facing
process stays unprivileged and reaches the local `jailgridd` over an
AF_UNIX socket.

## The jailgrid family

`share/jailgrid/jailgrid.yaml` is the contract between `jailgridd` and
its clients; cblink-gen(1) generates the C structures, validation
policies, client wrappers and server glue from it.

| Operation | Does | Mechanism in `jailgridd` |
|---|---|---|
| `hello` | host facts | uname(3), sysctl(3) |
| `list` | running and configured jails | jail_getv(3), procstat_getprocs(3), `jail -f scope -e sep` |
| `action` | start, stop, restart, kill | jail(8) `-c`, `-r`, `-rc`; jail_remove(2) for kill |
| `address` | add or remove an IP, live and/or persistent | jail_setv(3), SIOCAIFADDR ioctls, libjailconf |
| `services` | the host's rc.d scripts, enabled and running | the rc.d directories, `<name>_enable` in `sysrc -A`, `service <name> status` |
| `service-action` | start, stop, restart, reload, enable, disable | `service <name> <verb>`; `sysrc <rcvar>=YES/NO` |
| `service-config` | a service's rc.conf variables, read and set | `sysrc -a`, `sysrc key=value`, `sysrc -x key`, `service <name> describe` |
| `network` | routes, nexthops, connections, sockets | `netstat --libxo json -rnW / -onW / -nW -f <family>`, `sockstat --libxo json -w -4/-6`; one run per family, joined |
| `stats` | CPU, load, memory, swap, ZFS pools | `kern.cp_time` between requests, `vm.loadavg`, `vm.stats.vm.*`, `swapinfo -k`, `zpool list -Hp` |
| `packages` | pending upgrades of the host or a running jail | `pkg [-j jail] update -q`, `pkg [-j jail] version -vRl '<'` |
| `pkg-upgrade` | upgrade all or named packages, or show what would be | `pkg [-j jail] upgrade -y|-n [names]`, then `pkg version` again |

Every operation requires an authenticated peer: a client certificate
from the jailgrid CA over TCP, or access to the 0600 AF_UNIX socket.
Replies carry `ok`, `error` and a `trace`, so a failed jail(8) run still
comes back with its output.

Reading configuration goes through jail(8) itself (`-e`), so variables,
includes, `*` blocks and per-jail `jail.conf.d/<name>.conf` files mean
exactly what they mean to jail(8).  libjailconf exists only for the one
thing jail(8) cannot do: change a value in place.  After writing,
`jailgridd` reads the file back with `jail -e` and restores the previous
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
| Kore module | unprivileged user | WebAuthn public key, its cblink client certificate and key, and the CA's key when it runs its own CA |
| `jailgridd` | root | its server certificate and key, the CA certificate |

## Authentication (browser to console)

One user, one or more WebAuthn credentials (a YubiKey and a spare).

* **Enrolment.**  With no credential stored, the backend writes a random
  one-time setup token to `<datadir>/setup-token` (mode 0600).  The first
  registration needs it; later ones need a logged-in session.
* **Ceremonies.**  32-byte single-use challenges, valid two minutes.  The
  backend checks `clientDataJSON` (type, challenge, origin) and the
  authenticator data (RP ID hash, flags, counter) and verifies the
  signature with libcrypto.  ES256 and EdDSA, which covers YubiKey 5.
* **Sessions.**  32 random bytes in a cookie; only its SHA-256 is kept.
  Idle timeout 30 min, absolute 12 h.  One guard checks every protected
  route; state-changing requests also need `X-Jailgrid: 1` and a matching
  `Origin`.

## Enrolment (jail host to console)

Without a `tls { }` block the console runs its own CA (`pki.c`): EC
P-256, made at first start in the data directory, with the console's
client certificate signed by it.  A logged-in user asks for a token for
a host (`POST /api/enrol/tokens`: name, host, port); it is 32 random
bytes, single use, valid an hour.  `jailgrid-enrol(8)` on the host makes
a key and a certificate request and sends them with the token (`POST
/api/enrol`, no session).  The console signs a certificate for the
token's host, whatever the request's subject says, with `serverAuth` and
a SAN for the host, returns it with the CA, and adds `tcp://host:port`
to its servers.  The host's key never leaves the host.

## Trace model

Every reply that touched a host carries a trace: steps with a parent,
forming a tree.  `jailgridd` records its own steps; the backend adds the
API, session check and cblink request steps above them.

```
POST /api/servers/s1/jails/web/restart          api
├─ session check                                auth
└─ cblink jailgrid.action tcp://host:4310       lib   libcblink, mTLS
   └─ jailgridd action restart web              daemon
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
stops, so jailgridd removes the ones that were added live after a stop or
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
jailgridd).  Jail data older than 30 s, or from a failed refresh, is
dimmed and marked stale with its age; jails of an unreachable host show
as unknown.  Started offline, the app says that it is there but jail data
is not, and reconnects by itself.

## Layout

```
share/jailgrid/      the cblink family spec
share/mk/            build settings shared by every Makefile
lib/libjailconf/     in-place jail.conf editing
usr.sbin/jailconf/   jailconf(8)
usr.sbin/jailgridd/  jailgridd(8)
usr.sbin/jailgridctl/ jailgridctl(8)
usr.sbin/jailgrid-enrol/ jailgrid-enrol(8)
www/jailgrid/        Kore module
www/jailgrid-ui/     the PWA
docs/                this file, TOOLS.md, NAMING.md, openapi.yaml
tests/               the top of the installed test suite
```

Each directory has a `tests/` with atf-c or atf-sh tests; `make check`
runs them with kyua(1), and they install to `${TESTSBASE}/jailgrid`.

| Suite | Kind | Covers |
|---|---|---|
| `libjailconf` | atf-c | edits, quoting, inherited values, includes, diff, atomic writes |
| `jailconf` | atf-sh | the command line, dry runs, errors |
| `jailgridd` | atf-sh | listing through jail(8) -e, actions and address changes with a stand-in jail(8), traces, mutual TLS; as root, a real throwaway jail, live addresses and alias cleanup |
| `console` | atf-c | WebAuthn as an authenticator would do it (ES256, Ed25519, wrong origin, RP, challenge, signature, counter), CSRF, servers, jails through jailgridd over a socket and over mutual TLS |
| `console/pwa` | atf-c | the PWA in Chromium with a virtual authenticator: enrolment, an action, the workflow and raw output, an address preview, login, offline reload |
