# Arcana tools

Every program arcana installs, what it is for, how it is run, and
where its manual is. The man pages are the reference; this is the map.

| Program | Runs on | Manual |
|---|---|---|
| [`arcana-agent`](#arcana-agent) | every host, as root | `arcana-agent(8)` |
| [`arcana-enrol`](#arcana-enrol) | a host, once, as root | `arcana-enrol(8)` |
| [`arcanactl`](#arcanactl) | anywhere | `arcanactl(8)` |
| [`jailconf`](#jailconf) | anywhere | `jailconf(8)` |
| [`arcana`](#arcana-the-console) (the console) | the console host, unprivileged | `arcana-console(8)` |
| [`arcana-container`](#arcana-container) | the container image | below |

`make install WITHOUT_CONSOLE=yes` installs the first four; a full
`make install` adds the console.

## arcana-agent

The daemon on each host, and the only privileged part: it reports
and changes that host's jails, services, packages and network tables
for the console and for `arcanactl`, over cblink.

```sh
sysrc arcana_agent_enable=YES
sysrc arcana_agent_listen="tcp://0.0.0.0:4310 tcp://[::]:4310"
service arcana_agent start
```

Stopping it (`service arcana_agent stop`, SIGTERM or SIGINT) does not
cut a change short: the agent logs what is under way and which jobs wait
behind it, starts nothing more, and stops when that change has ended.
Jobs that had not started are lost. A second signal stops it at once.

| `rc.conf` variable | Meaning | Default |
|---|---|---|
| `arcana_agent_enable` | Run the agent. | `NO` |
| `arcana_agent_socket` | The local socket, always listened on. | `/var/run/arcana-agent.sock` |
| `arcana_agent_group` | A group whose members may use the socket. | none, root only |
| `arcana_agent_listen` | Network listeners, separated by spaces. | none |
| `arcana_agent_ca` | The CA of client certificates, for network listeners. | `/usr/local/etc/arcana/ca.pem` |
| `arcana_agent_cert` | The host's certificate. | `/usr/local/etc/arcana/host.pem` |
| `arcana_agent_key` | Its key. | `/usr/local/etc/arcana/host.key` |
| `arcana_agent_flags` | More flags, added to those above. | none |

`arcana-enrol -s` writes those flags for you. Without `-l` it listens
only on `unix:/var/run/arcana-agent.sock`, mode 0600 (0660 with `-g
group`). Network listeners need `-A`, `-C` and `-K`: peers must present a
certificate from that CA.

| Option | Meaning |
|---|---|
| `-l uri` | A listener: `unix:/path`, `tcp://addr:port`, `sctp://addr:port`; up to eight. |
| `-A`, `-C`, `-K` | CA, certificate and key for network listeners. |
| `-g group` | Local sockets 0660 and owned by the group (for a console on the same host). |
| `-F`, `-d` | Stay in the foreground; debug logging. |
| `-f`, `-D` | `jail.conf` and `jail.conf.d`, if not in `/etc`. |
| `-p pidfile` | Default `/var/run/arcana-agent.pid`. |
| `-j`, `-s`, `-y`, `-N`, `-X`, `-W`, `-Z`, `-P` | The `jail`, `service`, `sysrc`, `netstat`, `sockstat`, `swapinfo`, `zpool` and `pkg` programs, if not the system's; `-R` the rc.d directories. Used by the tests. |
| `-U` *program* | The file an update replaces, if not the running program. |
| `-B` *dir*, `-c` *config.mk* | Where a tree is cloned and built when the console asks for a build (`/var/cache/arcana-build`), and this host's settings for it (`/usr/local/etc/arcana/config.mk`). `-G` and `-M` name `git` and `make`. |
| `-V` | Print the version and exit. |

What each operation runs on the host is in
[ARCHITECTURE.md](ARCHITECTURE.md#the-arcana-family).

## arcana-enrol

Joins a host to a console without handling certificates by hand.
In the console, **Enrol a host** gives a one-time command:

```sh
arcana-enrol -s https://console.example 3f1c…
```

It makes an EC key, has the console's CA sign a certificate for the
host, writes `host.key`, `host.pem` and `ca.pem` to
`/usr/local/etc/arcana`, and with `-s` enables and starts `arcana-agent`
with them; the console adds the host to its servers. The token works
once, for an hour. Options go before the URL.

| Option | Meaning |
|---|---|
| `-s` | Set `arcana_agent_enable` and `arcana_agent_listen` with `sysrc(8)` and restart the service. Without it the `rc.conf` lines are printed. |
| `-a address` | An address for `arcana-agent` to listen on; repeatable. Default `0.0.0.0` and `::`. |
| `-p port` | Default 4310. |
| `-d directory` | Where the files go. |
| `-n name` | The name in the request; the console names the certificate after the token's host regardless. |

The console's HTTPS certificate is verified against the system's trusted
CAs; over plain HTTP the tool warns, because the token could be read.

## arcanactl

A command-line client for one `arcana-agent`: everything the console can
ask a host, from a shell. Output goes through libxo, so `--libxo json`
works; `-t` prints the trace of what the host did.

```sh
arcanactl list                         # the local socket
arcanactl -c tcp://host1.example:4310 \
    -A ca.pem -C client.pem -K client.key list
```

| Command | Does |
|---|---|
| `hello` | The host: system, CPUs, memory, arcana-agent version. |
| `list [-c]` | Running and configured jails; `-c` configured only. |
| `start`, `stop`, `restart`, `kill` *jail* | Change a jail's state; `kill` skips its stop scripts. |
| `address add\|remove [-lnp] [-i if]` *jail addr* | An address, live (`-l`), in `jail.conf` (`-p`), or previewed (`-n`). |
| `services` | rc.d scripts: enabled, running, pid. |
| `service` *name* `start\|stop\|restart\|reload\|enable\|disable` | Through `service(8)`; enable and disable through `sysrc(8)`. |
| `service` *name* `config [-x key] [key=value]` | The service's `rc.conf` variables; set or unset some first. |
| `net routes\|nexthops\|connections\|sockets [-4\|-6]` | `netstat`/`sockstat` output as libxo JSON. |
| `stats` | CPU, load, memory, swap, ZFS pools. |
| `packages [-r]` [*jail*] | Packages with newer versions; `-r` runs `pkg update` first. |
| `pkg-upgrade [-n] [-j jail]` [*package* …] | `pkg upgrade -y`, of all or of the named ones; `-n` a dry run. |
| `jobs` | Queued, running and recent jobs. |
| `job [-w]` *id* | A job with its trace so far; `-w` waits for the end. |
| `job-cancel` *id* | Take a queued job back. |
| `agent-build` [`-o` *file*] *repository* [*ref*] | Have the host clone the repository, build `arcana-agent` there and send it back; it is saved as *file* (`arcana-agent`). |
| `agent-update` [`-r`] *program* | Put a new `arcana-agent` in place on the host, checked there by running it with `-V`; `-r` restarts the service. The one before stays as `arcana-agent.old`. |

Global options: `-c uri` (default the local socket), `-A`/`-C`/`-K` for
TCP, `-N name` when the certificate's name is not the URI's host, `-t`,
and `-q`: queue the change as a job and return its number instead of
waiting. The host runs jobs in order whether or not the client stays,
which is what `arcanactl -q restart <the jail you are in>` needs.
Exit status 0 on success, 1 when the host refused or failed, 2 for
usage.

## jailconf

Adds or removes one value of one jail's parameter in `jail.conf`, in
place, leaving every other byte as it was: what `sysrc(8)` is for
`rc.conf`. `arcana-agent` uses the same library for persistent address
changes.

```sh
jailconf web ip4.addr+=10.0.0.12        # add
jailconf -n web ip4.addr-=10.0.0.10     # show the diff, write nothing
jailconf -f /etc/jail.conf.d/db.conf db allow.mount+=zfs
```

`-n` shows the change as a unified diff without writing; `-v` shows it
and writes; `-f file` names the file (default
`/etc/jail.conf.d/<jail>.conf` if it exists, else `/etc/jail.conf`).
Values the jail inherits from global statements or `*` blocks are not
touched.

## arcana, the console

Not a program of its own: `kore(1)` with the module `arcana-console.so`,
started by the `arcana` rc script.

```sh
cd /usr/local/etc/arcana
cp kore.conf.sample kore.conf      # bind addresses, RSA certificate, user
cp web.conf.sample web.conf        # rp_id, origin
sysrc arcana_console_enable=YES
service arcana_console start
cat /var/db/arcana/setup-token   # for the first login
```

`web.conf` (UCL), named by `ARCANA_WEB_CONF`:

| Key | Meaning | Default |
|---|---|---|
| `rp_id` | The console's host name, as the browser sees it, or a parent domain. Keys are bound to it. | required |
| `origin` | The exact origin, `https://console.example`. Opened anywhere else, security keys fail with "SecurityError"; the login screen says so. | required |
| `rp_name` | The name security keys show. | `Arcana` |
| `datadir` | Keys, servers, setup token, the console's own CA. | `/var/db/arcana` |
| `cookie_secure` | Mark the session cookie Secure. | `true` |
| `tls { ca, cert, key, ca_key }` | Your own CA for arcana-agent over TCP; `ca_key` to enrol hosts with it. Without the block the console runs its own CA. | none |
| `update_check`, `update_url` | Ask the release feed for newer versions. | on, GitHub |
| `agent_binary` | The `arcana-agent` the console sends to hosts when asked to update them. | `/usr/local/sbin/arcana-agent` |
| `settings.json` in `datadir` | What **Settings** in the console changed: `rp_name`, `update_check`, `update_url`, `agent_binary`, `agent_source`, `agent_ref`. It overrides `web.conf` for those. | none |
| `agent_source`, `agent_ref` | A git repository, and a branch or tag, a host can be asked to build `arcana-agent` from; what it builds is sent instead of `agent_binary`. | none |

rc.conf variables: `arcana_console_enable`, `arcana_console_config` (the
`kore.conf`), `arcana_console_web_conf`. The HTTP API is in
[openapi.yaml](openapi.yaml).

## arcana-container

The entry point of the container image (`ghcr.io/spmzt/arcana`): it
writes `web.conf` and `kore.conf` from the environment unless they are
mounted in `/usr/local/etc/arcana`, and starts Kore in the foreground
as the image's unprivileged user.

| Variable | Meaning |
|---|---|
| `ARCANA_RP_ID` | The console's host name. Required without a mounted `web.conf`. |
| `ARCANA_ORIGIN` | Default `https://` and the RP ID. |
| `ARCANA_PORT` | Default 8443. |
| `ARCANA_AGENT_SOURCE`, `ARCANA_AGENT_REF` | A git repository, and a branch or tag, a host can be asked to build `arcana-agent` from. |

With `console.pem` and `console.key` (RSA) mounted it serves HTTPS,
otherwise plain HTTP for a reverse proxy. The console's CA and data
live in the volume at `/var/db/arcana`.
