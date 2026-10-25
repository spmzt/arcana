# Arcana

**The Seven Archives of FreeBSD.** A FreeBSD-native fleet manager: an
agent on every host, and a console you log in to with a security key or
a passkey. It shows every host's jails, services, packages, network
tables and resource usage, changes them, and shows exactly which
library calls, system calls and programs each change used. Its
vocabulary, and where it is going, are in
[docs/NAMING.md](docs/NAMING.md).

Home: <https://github.com/spmzt/arcana>. The manual, a book of its
own: <https://spmzt.github.io/arcana-docs/> (its source is
<https://github.com/spmzt/arcana-docs>).

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
| `share/arcana/arcana.yaml` | The cblink family: the contract between arcana-agent and its clients; `share/yang/arcana@<rev>.yang` is its wire, the YANG module `share/arcana/wire.awk` writes from it. |

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains the design and the
trust boundaries; [docs/NAMING.md](docs/NAMING.md) is the naming design
the project is growing into; [docs/TOOLS.md](docs/TOOLS.md) describes
every program
with its options and examples, and each has a man page: `arcana-agent(8)`,
`arcanactl(8)`, `arcana-enrol(8)`, `jailconf(8)` and `arcana-console(8)`
for the console.

## Building

Base `make(1)` and `bsd.*.mk`, on FreeBSD 16.0 or later (16-CURRENT
until 16.0 is released); FreeBSD 15 is not supported.

```sh
git clone --recurse-submodules https://github.com/spmzt/arcana.git
cd arcana
make check-deps                   # what the build needs, and what is missing
make install-missing-packages     # as root: pkg install what is missing
make install-kore                 # as root, once, for the console: Kore
make                              # it checks the same first, and says
make check                        # the test suite, with kyua(1)
make install                      # PREFIX=/usr/local by default
```

`make check-deps` asks pkg(8) what is installed and lists what is not,
as packages; `make install-missing-packages` installs those with
`pkg install` (`WITH_TEST_TOOLS=yes` adds the tests' tools). `make`
itself checks first and stops with that list, not a compiler's error.

What it needs:

- for the host's programs (arcana-agent, arcanactl, arcana-enrol,
  jailconf): `devel/libcbor`, and `net/libyang3` for `cblink-gen` (a
  build dependency only). [cblink](https://github.com/spmzt/cblink) is
  the submodule `cblink/`, built by `make` first and installed with the
  rest; a tree without it (a release tarball, the port) uses an
  installed `devel/cblink`;
- for the console as well: `devel/emscripten` for the page; Kore 4.3
  built with `TASKS=1`, which is no package: `make install-kore` builds
  the port shipped here, `port/www/kore`, with the ports framework (the
  ports tree in `/usr/ports`), and `config.mk.sample` says how to use a
  copy elsewhere;
- the sources of libucl and libyaml, which the page compiles to
  WebAssembly (a built library cannot be): the system's in `/usr/src`,
  which pkgbase's `FreeBSD-src` installs (`make
  install-missing-packages` lists it where `/usr/src` is missing), or
  trees named with `LIBUCL_SRC` and `LIBYAML_SRC` (the releases base
  imports, libucl 0.9.4 and libyaml 0.2.5, as the port fetches them);
- for the tests: `devel/git`, `ftp/curl`, `lang/python3`, and
  `www/chromium` (with chromedriver) for the browser test.

`make WITHOUT_CONSOLE=yes` builds only what a host runs, without Kore,
emscripten or the libraries' sources. The ports, `port/sysutils/arcana`
(with a `CONSOLE` option) and `port/www/kore`, build the same way;
`devel/cblink` comes from cblink's own tree.

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

An Android app can log in with the same keys once `web.conf` names it
in an `android { }` block, its package and the SHA-256 fingerprints of
its signing certificates: the console then serves
`/.well-known/assetlinks.json` for Android to check, and takes the
app's WebAuthn origin (`android:apk-key-hash:…`) beside its own. See
`arcana-console(8)`.

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

The console is a tree and tabs: the fleet, its hosts and their jails on
the left; a host's Summary, Jails, Services, Network, Packages and Jobs;
and an activity bar that shows each call as a graph, with its CBOR
schema. [The book](https://spmzt.github.io/arcana-docs/) goes through
all of it, SD-WAN included; [docs/USING.md](docs/USING.md) lists its
chapters.

## Updating

The console says when a newer release is out, and can update the agents
itself: it sends its own `arcana-agent` to the hosts that run another
build, or has a host build one from a git repository first.
[docs/UPDATING.md](docs/UPDATING.md) has the details, and how versions
are numbered.

## TODO

What is planned, what waits for approval, what is known not to work and
what has never been run for real is in [docs/TODO.md](docs/TODO.md).

## Licence

BSD-2-Clause. The fonts in `www/arcana-ui/vendor/fonts` are under the
SIL Open Font License 1.1 and morphdom under the MIT licence; see
`www/arcana-ui/vendor/README`.

## Disclosure

Claude Fable 5.1 and Claude Opus 5.5 were used during Arcana's
development.