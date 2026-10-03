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
sysrc arcana_agent_flags="-l unix:/var/run/arcana-agent.sock \
    -l tcp://0.0.0.0:4310 -l 'tcp://[::]:4310' -A /usr/local/etc/arcana/ca.pem \
    -C /usr/local/etc/arcana/host.pem -K /usr/local/etc/arcana/host.key"
service arcana_agent start
```

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
in, and the token is gone. Add a spare key from **Keys** afterwards. On
Android, Chrome offers to install the console as an app.

A phone's passkey works as a second key: open the console on the phone,
log in once with the security key (Chrome can use it over USB or NFC, or
the passkey of another device nearby), and register from **Keys**;
Android stores a synced passkey. From then on **Use a passkey** on the
login screen logs in with it, on the phone or, through the phone, on
any browser. Registration asks for a discoverable credential where the
authenticator offers one, so security keys keep working as before.

## Using it

- **Servers** on the left: add one by name and URI
  (`tcp://host1.example:4310`).
- **Jails** in the middle, with their state: running, stopped, dying,
  and, while something happens to them, starting, stopping, restarting;
  unknown when the host does not answer, and dimmed when the data is
  stale.
- **Services**, the second tab of a server: its rc.d scripts, enabled or
  not, running or not, with start, stop, restart, reload, enable and
  disable; a service's drawer edits its `rc.conf` variables through
  `sysrc(8)` and shows what the script says of itself.
- **Gauges** under the host bar: CPU, memory in use and ZFS allocation,
  each with its recent history, sampled every 10 s while the server is
  selected. CPU is `kern.cp_time` between samples, memory the active,
  wired and laundry pages, ZFS the pools' allocation from `zpool list`.
- **Network**, the third tab: the routing table, the nexthops, active
  connections and open sockets, per address family, as `netstat -rnW`,
  `netstat -onW`, `netstat -nW` and `sockstat -w` print them on the host
  (through `--libxo json`); filter the rows, click a column to sort.
- **Notify**, in the top bar: a desktop notification when a task that
  took more than ten seconds ends.
- **Packages**, the fourth tab: what `pkg` can upgrade on the host or in
  any running jail (`pkg -j`), with **Check** (`pkg update` first), a
  dry run, and **Upgrade** of the selected packages or of all; the
  output of `pkg upgrade` is in the activity trace.
- A jail's **drawer** has its actions, addresses, configuration as jail(8)
  reads it, and its history. Addresses change live (jail_setv(3) and the
  interface alias), persistently (its block in `jail.conf`, edited in
  place, previewed as a diff first), or both.
- Changes are **jobs** the host runs on its own: the activity graph
  fills in stage by stage while one runs, and a change that cuts the
  console off (restarting its own jail) still completes; the entry shows
  the outcome when the host answers again. **Queue** in the activity
  bar holds changes and sends them as one batch, run in order.
- **Activity** at the bottom: every action and manual refresh, with its
  workflow as a graph, from the API call through the session check and
  the cblink request to each call arcana-agent made. When a program ran, a
  **Raw output** button shows its argv, exit status and output.

## Updating

The console asks GitHub's release feed every six hours and shows a
banner when a newer version is out; `update_check = false` in `web.conf`
turns that off. It does not replace itself, since it runs unprivileged:

- the container image carries `io.containers.autoupdate=registry`, so
  `podman auto-update` (from cron, say) pulls a newer `ghcr.io/spmzt/arcana`
  and restarts the container;
- a native install is updated with `pkg upgrade arcana`, or
  `make install` from a newer tree, then `service arcana_console restart`.

Hosts update `arcana-agent` the same way; the console marks a host
whose `arcana-agent` is not its own version. Certificates stay valid across
updates.

## TODO

Planned, in rough order:

- A console laid out for a fleet: a tree of hosts and jails, summary
  pages with graphs, more use of the workflow graph.
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
