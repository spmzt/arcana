# Jailgrid tools

Every program jailgrid installs, what it is for, how it is run, and
where its manual is. The man pages are the reference; this is the map.

| Program | Runs on | Manual |
|---|---|---|
| [`jailgridd`](#jailgridd) | every jail host, as root | `jailgridd(8)` |
| [`jailgrid-enrol`](#jailgrid-enrol) | a jail host, once, as root | `jailgrid-enrol(8)` |
| [`jailgridctl`](#jailgridctl) | anywhere | `jailgridctl(8)` |
| [`jailconf`](#jailconf) | anywhere | `jailconf(8)` |
| [`jailgrid`](#jailgrid-the-console) (the console) | the console host, unprivileged | `jailgrid(8)` |
| [`jailgrid-container`](#jailgrid-container) | the container image | below |

`make install WITHOUT_CONSOLE=yes` installs the first four; a full
`make install` adds the console.

## jailgridd

The daemon on each jail host, and the only privileged part: it reports
and changes that host's jails, services, packages and network tables
for the console and for `jailgridctl`, over cblink.

```sh
sysrc jailgridd_enable=YES
sysrc jailgridd_flags="-l unix:/var/run/jailgridd.sock \
    -l tcp://0.0.0.0:4310 -l 'tcp://[::]:4310' \
    -A /usr/local/etc/jailgrid/ca.pem \
    -C /usr/local/etc/jailgrid/host.pem -K /usr/local/etc/jailgrid/host.key"
service jailgridd start
```

`jailgrid-enrol -s` writes those flags for you. Without `-l` it listens
only on `unix:/var/run/jailgridd.sock`, mode 0600 (0660 with `-g
group`). Network listeners need `-A`, `-C` and `-K`: peers must present a
certificate from that CA.

| Option | Meaning |
|---|---|
| `-l uri` | A listener: `unix:/path`, `tcp://addr:port`, `sctp://addr:port`; up to eight. |
| `-A`, `-C`, `-K` | CA, certificate and key for network listeners. |
| `-g group` | Local sockets 0660 and owned by the group (for a console on the same host). |
| `-F`, `-d` | Stay in the foreground; debug logging. |
| `-f`, `-D` | `jail.conf` and `jail.conf.d`, if not in `/etc`. |
| `-p pidfile` | Default `/var/run/jailgridd.pid`. |
| `-j`, `-s`, `-y`, `-N`, `-X`, `-W`, `-Z`, `-P` | The `jail`, `service`, `sysrc`, `netstat`, `sockstat`, `swapinfo`, `zpool` and `pkg` programs, if not the system's; `-R` the rc.d directories. Used by the tests. |

What each operation runs on the host is in
[ARCHITECTURE.md](ARCHITECTURE.md#the-jailgrid-family).

## jailgrid-enrol

Joins a jail host to a console without handling certificates by hand.
In the console, **Enrol a host** gives a one-time command:

```sh
jailgrid-enrol -s https://console.example 3f1c…
```

It makes an EC key, has the console's CA sign a certificate for the
host, writes `host.key`, `host.pem` and `ca.pem` to
`/usr/local/etc/jailgrid`, and with `-s` enables and starts `jailgridd`
with them; the console adds the host to its servers. The token works
once, for an hour. Options go before the URL.

| Option | Meaning |
|---|---|
| `-s` | Set `jailgridd_enable` and `jailgridd_flags` with `sysrc(8)` and restart the service. Without it the `rc.conf` lines are printed. |
| `-a address` | An address for `jailgridd` to listen on; repeatable. Default `0.0.0.0` and `::`. |
| `-p port` | Default 4310. |
| `-d directory` | Where the files go. |
| `-n name` | The name in the request; the console names the certificate after the token's host regardless. |

The console's HTTPS certificate is verified against the system's trusted
CAs; over plain HTTP the tool warns, because the token could be read.

## jailgridctl

A command-line client for one `jailgridd`: everything the console can
ask a host, from a shell. Output goes through libxo, so `--libxo json`
works; `-t` prints the trace of what the host did.

```sh
jailgridctl list                         # the local socket
jailgridctl -c tcp://host1.example:4310 \
    -A ca.pem -C client.pem -K client.key list
```

| Command | Does |
|---|---|
| `hello` | The host: system, CPUs, memory, jailgridd version. |
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

Global options: `-c uri` (default the local socket), `-A`/`-C`/`-K` for
TCP, `-N name` when the certificate's name is not the URI's host, `-t`,
and `-q`: queue the change as a job and return its number instead of
waiting. The host runs jobs in order whether or not the client stays,
which is what `jailgridctl -q restart <the jail you are in>` needs.
Exit status 0 on success, 1 when the host refused or failed, 2 for
usage.

## jailconf

Adds or removes one value of one jail's parameter in `jail.conf`, in
place, leaving every other byte as it was: what `sysrc(8)` is for
`rc.conf`. `jailgridd` uses the same library for persistent address
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

## jailgrid, the console

Not a program of its own: `kore(1)` with the module `jailgrid.so`,
started by the `jailgrid` rc script.

```sh
cd /usr/local/etc/jailgrid
cp kore.conf.sample kore.conf      # bind addresses, RSA certificate, user
cp web.conf.sample web.conf        # rp_id, origin
sysrc jailgrid_enable=YES
service jailgrid start
cat /var/db/jailgrid/setup-token   # for the first login
```

`web.conf` (UCL), named by `JAILGRID_WEB_CONF`:

| Key | Meaning | Default |
|---|---|---|
| `rp_id` | The console's host name, as the browser sees it. | required |
| `origin` | The exact origin, `https://console.example`. | required |
| `rp_name` | The name security keys show. | `Jailgrid` |
| `datadir` | Keys, servers, setup token, the console's own CA. | `/var/db/jailgrid` |
| `cookie_secure` | Mark the session cookie Secure. | `true` |
| `tls { ca, cert, key, ca_key }` | Your own CA for jailgridd over TCP; `ca_key` to enrol hosts with it. Without the block the console runs its own CA. | none |
| `update_check`, `update_url` | Ask the release feed for newer versions. | on, GitHub |

rc.conf variables: `jailgrid_enable`, `jailgrid_config` (the
`kore.conf`), `jailgrid_web_conf`. The HTTP API is in
[openapi.yaml](openapi.yaml).

## jailgrid-container

The entry point of the container image (`ghcr.io/spmzt/geass`): it
writes `web.conf` and `kore.conf` from the environment unless they are
mounted in `/usr/local/etc/jailgrid`, and starts Kore in the foreground
as the image's unprivileged user.

| Variable | Meaning |
|---|---|
| `JAILGRID_RP_ID` | The console's host name. Required without a mounted `web.conf`. |
| `JAILGRID_ORIGIN` | Default `https://` and the RP ID. |
| `JAILGRID_PORT` | Default 8443. |

With `console.pem` and `console.key` (RSA) mounted it serves HTTPS,
otherwise plain HTTP for a reverse proxy. The console's CA and data
live in the volume at `/var/db/jailgrid`.
