# Arcana

**The Seven Archives of FreeBSD.** A FreeBSD-native fleet manager: an
agent on every host, and a console you log in to with a security key or
a passkey. It shows every host's jails, services, packages, network
tables and resource usage, changes them, and shows exactly which
library calls, system calls and programs each change used. Its
vocabulary, and where it is going, are in
[docs/NAMING.md](docs/NAMING.md).

Home: <https://github.com/spmzt/arcana>

```
 browser (PWA, C → wasm) ──HTTPS──▶ kore + arcana-console.so ──cblink/mTLS──▶ arcana-agent ──▶ jails
                                      (console host)                     (each host)
```

| | |
|---|---|
| `usr.sbin/arcana-agent` | The daemon on each host: libjail(3), libprocstat(3), jail(8), served over cblink with mutual TLS. The only privileged part. |
| `www/arcana-console` | The console: a Kore module with WebAuthn login (libcrypto), the server list, and the JSON API ([OpenAPI](docs/openapi.yaml)). |
| `www/arcana-ui` | The PWA: C compiled with Emscripten, base libucl for JSON, installable and usable offline as a shell. |
| `usr.sbin/jailconf` | `jailconf(8)`: change one value of a jail parameter in `jail.conf` in place, like `sysrc(8)` for `rc.conf`. |
| `usr.sbin/arcanactl` | `arcanactl(8)`: talk to an arcana-agent from a shell, with libxo(3) output. |
| `usr.sbin/arcana-enrol` | `arcana-enrol(8)`: join a host to the console with a one-time token; it gets its certificate from the console's CA. |
| `lib/libjailconf` | The in-place editor behind both. |
| `share/arcana/arcana.yaml` | The cblink family: the contract between arcana-agent and its clients. |

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains the design and the
trust boundaries; [docs/NAMING.md](docs/NAMING.md) is the naming design
the project is growing into; [docs/TOOLS.md](docs/TOOLS.md) describes
every program
with its options and examples, and each has a man page: `arcana-agent(8)`,
`arcanactl(8)`, `arcana-enrol(8)`, `jailconf(8)` and `arcana-console(8)`
for the console.

## Building

Base `make(1)` and `bsd.*.mk`, on FreeBSD 14 or later.

For the host's programs (arcana-agent, arcanactl, arcana-enrol,
jailconf):

- [cblink](https://github.com/spmzt/cblink): libcblink, `cblink-gen` and
  `cblink.mk`, from its port `devel/cblink` or its own tree;
- `devel/libcbor`, which cblink needs.

```sh
pkg install libcbor
```

For the console as well:

- Kore 4.3, built with `TASKS=1`: its headers to build, `kore(1)` to run.
  The ports tree has no Kore; the port shipped here in `port/www/kore`
  builds it with tasks on, as does `Containerfile` from the release
  tarball;
- `devel/emscripten`, for the PWA;
- a libucl source tree, which the PWA compiles to wasm:
  `/usr/src/contrib/libucl` when the system sources are installed, or a
  checkout of the [0.9.4 release](https://github.com/vstakhov/libucl)
  named with `LIBUCL_SRC`;
- optionally `www/chromium`, which includes chromedriver, for the browser
  test.

```sh
pkg install emscripten chromium
```

Then:

```sh
cp config.mk.sample config.mk     # where cblink and Kore are, if not /usr/local
make                              # LIBUCL_SRC=/path/to/libucl without /usr/src
make check                        # the test suite, with kyua(1)
make install                      # PREFIX=/usr/local by default
```

`make WITHOUT_CONSOLE=yes` builds only what a host runs, without
Kore, emscripten or libucl's sources. The ports,
`port/sysutils/arcana` (with a `CONSOLE` option) and `port/www/kore`,
build the same way; `devel/cblink` comes from cblink's own tree.

`make check` skips the tests that need root; run it as root to drive a
throwaway jail (`arcana-test`, on `127.0.10.0/24` on `lo0`) through
jail(8) for real.

## Setting it up

### Certificates

The console talks to every arcana-agent over TLS 1.3 with client
certificates. Without a `tls { }` block in `web.conf` the console runs
a CA of its own: at first start it writes `ca.pem`, `ca.key`,
`console.pem` and `console.key` to its data directory, and hosts
get their certificates from it by enrolling (below). Nothing else is
needed.

To use a CA of your own instead, name its certificate and the console's
client certificate in `web.conf`'s `tls { }` block; add `ca_key` there
if the console is still to enrol hosts. With base `openssl(1)`:

```sh
cd /usr/local/etc/arcana
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout ca.key -out ca.pem -days 3650 -subj "/CN=arcana CA" \
    -addext basicConstraints=critical,CA:TRUE

# One per host, named as the console will reach it.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout host1.key -out host1.csr -subj "/CN=host1.example"
printf 'subjectAltName=DNS:host1.example\nextendedKeyUsage=serverAuth\n' \
    > host1.ext
openssl x509 -req -in host1.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 825 -extfile host1.ext -out host1.pem

# The console's client certificate, the same way, with
# extendedKeyUsage=clientAuth, as client.pem and client.key.
```

Keep `ca.key` off the hosts.

### On each host

Install the host's programs, then enrol the host from the console:
**Enrol a host** (also offered when adding a server) takes a name and
the host name or address the console reaches it by, and shows a
one-time command. Run it on the host as root:

```sh
make install WITHOUT_CONSOLE=yes           # arcana-agent, jailconf, arcanactl, arcana-enrol
arcana-enrol -s https://console.example 3f1c…   # from the console
arcanactl list                           # over the local socket
```

`arcana-enrol(8)` makes a key, has the console's CA sign a certificate
for the host, writes both and the CA to `/usr/local/etc/arcana`, and
with `-s` enables and starts `arcana-agent` on port 4310 with them; the
console adds the host to its servers at the same time. The token works
once and for an hour. Without `-s` it prints the `rc.conf` lines
instead:

```sh
sysrc arcana_agent_enable=YES
sysrc arcana_agent_listen="tcp://0.0.0.0:4310 tcp://[::]:4310"
service arcana_agent start
```

The service always listens on its local socket,
`/var/run/arcana-agent.sock`; `arcana_agent_listen` adds network
listeners. Their certificate files are `ca.pem`, `host.pem` and
`host.key` in `/usr/local/etc/arcana` unless `arcana_agent_ca`,
`arcana_agent_cert` or `arcana_agent_key` say otherwise, and
`arcana_agent_flags` is added to all of that.

A host with certificates from your own CA is added as a server by name
and URI, with no enrolment.

### On the console host

Kore serves the PWA and the API. WebAuthn and PWA installation on Android
need HTTPS with a certificate the phone trusts, such as one from Let's
Encrypt. The certificate must be RSA: Kore's key manager, which keeps
the private key out of the worker, signs with nothing else.

```sh
pw useradd arcana -d /var/db/arcana -s /usr/sbin/nologin
install -d -o arcana -m 0700 /var/db/arcana
cd /usr/local/etc/arcana
cp kore.conf.sample kore.conf      # domain, certificate, bind address
cp web.conf.sample web.conf        # rp_id, origin, client certificate
sysrc arcana_console_enable=YES
service arcana_console start
```

If the console host has jails too, run its arcana-agent with
`-g arcana -l unix:/var/run/arcana-agent.sock` and add it as
`unix:/var/run/arcana-agent.sock`: the console stays unprivileged and reaches
it through a socket only its group can open.

### The console in a container

`Containerfile` builds the console on `ghcr.io/spmzt/freebsd-emscripten`
(the base toolchain and emscripten, from
[spmzt/images](https://github.com/spmzt/images)) and ships it on the
cblink image; the workflow in `.github/workflows` publishes it as
`ghcr.io/spmzt/arcana`. It runs Kore unprivileged (uid 4310) on port 8443:
HTTPS with an RSA certificate mounted as `console.pem` and `console.key`
in `/usr/local/etc/arcana`, plain HTTP for a reverse proxy without one.

```sh
podman run -d --name arcana -p 8443:8443 \
    -e ARCANA_RP_ID=console.example \
    -v arcana:/var/db/arcana \
    ghcr.io/spmzt/arcana
podman exec arcana cat /var/db/arcana/setup-token
```

`ARCANA_ORIGIN` (default `https://` and the RP ID) and `ARCANA_PORT`
change the rest; a mounted `web.conf` or `kore.conf` replaces the
generated one. The CA lives in the `arcana` volume; to use your own
instead, mount `ca.pem`, `client.pem` and `client.key` into
`/usr/local/etc/arcana`, readable by uid 4310.

### First login

With no key registered, the console writes a one-time token to
`/var/db/arcana/setup-token` and logs that it did. Open the console,
paste the token, touch your security key: that registers it and logs you
in, and the token is gone. Add a spare key from **Keys** afterwards. Opened
in the browser of a phone or tablet, the console offers to install
itself as an app: with the browser's own prompt on Android, and with
where to tap in Safari on iOS and in Firefox. **Not now** stops the
offer in that browser.

A phone's passkey works as a second key: open the console on the phone,
log in once with the security key (Chrome can use it over USB or NFC, or
the passkey of another device nearby), and register from **Keys**;
Android stores a synced passkey. From then on **Use a passkey** on the
login screen logs in with it, on the phone or, through the phone, on
any browser. Registration asks for a discoverable credential where the
authenticator offers one, so security keys keep working as before.

Security keys work only at the address the console is configured for:
`rp_id` must be the host name in the address bar (or a parent domain of
it), `origin` the exact origin, and the page HTTPS unless it is on
localhost. Anywhere else the browser refuses with "SecurityError" ("The
operation is insecure" in Firefox), and the login screen says which
address the console is set up for. Keys are bound to the `rp_id` they
were registered under: after changing it, remove
`/var/db/arcana/credentials.json` and enrol again with the new setup
token.

## Using it

The console is laid out as a tree and tabs.

- The **tree** on the left: the fleet, its hosts, and each host's jails.
  What you select decides the page. **Enrol a host** and **Add a server**
  are at its top. A host's jails are folded away until you open them
  with the arrow on the host, and the browser remembers which are open. When the jails do not fit in the space under
  the hosts, each host shows what fits and a **+N more…** row that
  shows the rest.
- **All hosts**: every host as a card with CPU, memory and ZFS, how many
  jails run, and the fleet as a graph from the console through the
  hosts to their jails; nodes are links.
- A **host** has tabs:
  - **Summary**: usage gauges with their recent history, counts, the ZFS
    pools, and the host's jails as a graph.
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
    per address family, as `netstat` and `sockstat` print them
    (`--libxo json`); filter the rows, click a column to sort.
  - **Packages**: what `pkg` can upgrade on the host or in a running
    jail, with **Check**, a dry run, and **Upgrade** of the selected
    packages or of all.
  - **Jobs**: the host's own record of what it was asked to change, by
    this console or with `arcanactl -q`; a row opens its workflow.
- A **jail** has its page: actions, addresses (changed live with
  jail_setv(3) and the interface alias, persistently in its `jail.conf`
  block with a diff to preview, or both), its configuration as jail(8)
  reads it, and its history.
- **Activity** at the bottom: every call to a host, with its workflow as
  a graph from the API call through the session check and the cblink
  request to each call the agent made; a box picked in the graph shows
  its details in a pane beside the graph, which stays in view while the
  graph scrolls. When a program ran, **Raw output** shows its argv, exit
  status and output. Changes are jobs the
  host runs on its own: the graph fills in stage by stage, and a change
  that cuts the console off still completes. **Queue** is on unless
  you turn it off in that browser: a change waits in the activity bar
  until you press **Run**, and what waits is sent as one batch, run in
  order; off, a change is sent at once.
- The tree, the activity bar, the list of tasks in it and the service
  drawer are resized by dragging their edge; the browser keeps the
  sizes, and a double click on the edge goes back to the usual one.
- In the top bar: **FX** turns the blur and idle animations off for this
  browser, **Notify** allows a desktop notification when a task that
  took more than ten seconds ends, **Keys** manages security keys and
  passkeys.

## Updating

The console asks GitHub's release feed every six hours and shows a
banner when a newer version is out; `update_check = false` in `web.conf`
turns that off. It does not replace itself, since it runs unprivileged:

- the container image carries `io.containers.autoupdate=registry`, so
  `podman auto-update` (from cron, say) pulls a newer `ghcr.io/spmzt/arcana`
  and restarts the container;
- a native install is updated with `pkg upgrade arcana`, or
  `make install` from a newer tree, then `service arcana_console restart`.

Certificates stay valid across updates.

### Updating the agents

The console marks a host whose `arcana-agent` is not the one it has,
and can update it: **Update agent** beside the version on the host's
page, or **Update N agents** on the fleet page for every such host.
Builds are told apart by the program's SHA-256, which each agent
reports, so a rebuilt agent of the same version counts as another. The console sends the `arcana-agent` installed with it
(`agent_binary` in `web.conf` names another). Each host

1. checks the program against the SHA-256 sent with it,
2. writes it beside the installed one and runs it with `-V`: a program
   built for another machine or FreeBSD version does not run, and is
   dropped,
3. puts it in place of the installed one, which stays as
   `arcana-agent.old`.

With **Restart the agent now**, on by default, the host then restarts
its `arcana_agent` service, and shows the new version at the next
refresh; without it, the new program runs from the next start of the
service. A restart drops jobs still queued on the host; one that is
running finishes first. From a shell, `arcanactl agent-update [-r]
program` does the same for one host.

The program has to suit the host: the same architecture and a FreeBSD
version it runs on, with `libcblink` there as before. Hosts that differ
from the console's machine are updated with `pkg upgrade arcana`
instead, which the Packages tab can do. If an update goes wrong, put
`arcana-agent.old` back and restart the service.

### Building the agent on a host

The console need not have the agent it sends: it can have a host build
it. Name the repository in `web.conf`,

```
agent_source = "https://github.com/spmzt/arcana.git";
agent_ref = "main";            # a branch or tag; optional
```

and each host's header gets **Build agent here**. That host clones the
repository afresh into `/var/cache/arcana-build`, builds `libjailconf`
and `arcana-agent` with `make`, and sends the program back; nothing is
installed there. The console checks it against its SHA-256, keeps it in
`agent/` under its data directory, and sends that one from then on, so
the hosts that run another build are offered the update. The build is
in the activity bar with the output of git and make.

The host that builds needs what the build needs: `git`, the base
compiler, and `devel/cblink` with its `libcbor`. If cblink or the linker
are somewhere else on it, `/usr/local/etc/arcana/config.mk` there is
copied into the tree as its `config.mk`. When the agent is root, git
and make run as `nobody`. From a shell, `arcanactl agent-build [-o
file] repository [ref]` builds and saves the program.

### Versions

The agent and the console have versions of their own, and every change
to one bumps it: `ARCANA_AGENT_VERSION` in
`usr.sbin/arcana-agent/agent.h`, `ARCW_VERSION` in
`www/arcana-console/console.h`. A host's header and the tree show the
agent's; the update dialog shows the one the console would send.

## TODO

Planned, in rough order:

- The agent's sources organised by Archive, after
  [docs/NAMING.md](docs/NAMING.md).

Waiting for approval before any work:

- Managing interfaces and their addresses.
- BIRD: neighbours and protocols, status, restart, clear.
- Route management, possibly through netlink with its attributes mapped
  to CBOR.
- A safe mode that rolls a configuration change back when the daemon
  loses the console, for the changes that can be rolled back.

Known limits:

- EC keys for the console's own HTTPS certificate: Kore's key manager
  signs with RSA only, so `console.pem` must be RSA until Kore (or a
  patch like the one in `port/www/kore/files`) handles ECDSA.

## Licence

BSD-2-Clause. The fonts in `www/arcana-ui/vendor/fonts` are under the
SIL Open Font License 1.1 and morphdom under the MIT licence; see
`www/arcana-ui/vendor/README`.
