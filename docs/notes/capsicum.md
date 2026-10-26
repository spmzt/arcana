# Capsicum in Arcana

Asked for on 2026-10-20: "adding capsicum support in all of the
modules, agent, console, ctl, conf, anything you know as much as you
can."  This note says what runs in capability mode (capsicum(4)) now,
what does not and why, measured on the lab VM (FreeBSD 16.0-CURRENT),
and the shape of what would make the rest possible.

## What capability mode refuses

A small program on the VM (`cap_enter()` and then each call):

| call                                   | in capability mode              |
|----------------------------------------|---------------------------------|
| `sendto` with an address               | refused (ECAPMODE)              |
| `connect`                              | refused                         |
| `sysctlbyname("net.inet.ip.forwarding")` | refused (only CTLFLAG_CAPRD sysctls pass) |
| `socket(AF_NETLINK, ...)`              | refused                         |
| `fexecve` of a `#!` script             | refused (the interpreter is looked up by path) |
| `open`, `stat`, `unlink`, `rename` by path | refused; `*at` with a directory descriptor and no `..` work |

So a process in capability mode keeps the descriptors it has, and
reaches anything else through Casper services (`libcasper`: cap_net,
cap_dns, cap_sysctl, cap_fileargs, ...) or through a helper it forked
before entering.

## Done (2026-10-20)

- **arcanactl(8)**: capability mode once the agent is connected and TLS
  is up (`cbl_conn_connect` resolves and connects before; the TLS
  files are loaded before).  The files named on the command line,
  and the file behind an `@word`, are opened through Casper's
  `cap_fileargs` service (read: `CAP_READ|CAP_FSTAT|CAP_SEEK`); for
  `agent-build` alone a second fileargs instance opens the output
  program to write (`O_CREAT|O_TRUNC`, 0755).  The time zone and the
  message catalogs are cached first (`caph_cache_tzdata`,
  `caph_cache_catpages`).  Every reply the agent sends is decoded and
  printed in the sandbox.  Links `-lcasper -lcap_fileargs -lnv`.
- **arcana-enrol(8)**: the directory for the files is opened first,
  the runner of `sysrc` and `service` is forked first (a child that
  waits for a `g` on a pipe, since capability mode cannot run
  programs: scripts cannot even be `fexecve`d), the request goes to
  the console (libfetch: DNS and the connection), then capability
  mode: the console's answer is parsed (JSON from the network, in the
  sandbox), the key, certificate and CA are written by name in the
  directory (`mkostempsat`, `renameat`), and the runner is told to go.
- **jailconf(8)**: `jail.conf` and its includes are read (includes are
  opened by path and globbed, so before), the directory of the file to
  change is opened, then capability mode: the edit, its check (the
  parser over the edited text) and the write (`jc_write_at` in
  libjailconf: `fstatat`, `mkostempsat`, `renameat`).  `jc_write(path)`
  stays for the agent and wraps it.
- **cblink-gen** (in cblink) was in capability mode already.

## Not done, and why

### arcana-agent

The agent's work is naming global things: it runs programs by path
(`posix_spawn` of `service`, `sysrc`, `zfs`, `jexec`, rc.d scripts,
most of them `#!` scripts), opens files by path on the host and in
jails, reads sysctls, makes netlink and raw sockets, attaches to jails.
None of that passes in capability mode, and Casper has no service for
running programs or attaching to jails.  Its helper children
(`--scope-helper`: routes by netlink, pcb by sysctl, carp by ioctl,
the ICMP socket, `sysctl-int`, `zfs-pipe`) exist precisely to do these
things inside a jail, so they cannot enter either.

What would make a sandbox real for the agent is the split FreeBSD's
own daemons use (sshd, ntpd, dhclient): a **privilege-separated
frontend** that owns the listening sockets and TLS, decodes cblink
frames and parses JSON, in capability mode; and a **privileged
backend** that runs programs and touches files, taking typed requests
over a socketpair.  The frontend would hold the untrusted input (the
network, OpenSSL, the decoder); the backend would see only decoded,
checked requests.  Two things stand in the way today: cblink's loop
runs listener, TLS and dispatch in one process (the split needs a
frame proxy in cblink or the backend to re-decode), and each of the
agent's ~200 operations would need its request carried over the
socketpair.  A smaller first step with the same shape: the **prober**
(gula/probe.c), which parses ICMP replies from anyone on the network
in the root process; moved to a child in capability mode, it would
need Casper's cap_net (`cap_connect` on a per-target connected raw
socket, since `sendto` with an address is refused) and a pipe for
targets and states.

### The console

The console is its own server on libwebsockets (web.c): a root
supervisor that listens, and a worker that serves as the console's
user.  The worker opens the web root's files by path on every request
(lws_serve_http_file), and opens its settings, tokens, PKI and the Raft
log by path, connects to agents (cblink: `connect`, DNS), and runs
`sendmail`.  Capability mode would need: the web root served from a
directory descriptor (`openat` before lws_serve_http_file's own open,
or the files read whole), every file of the console's opened `*at` a
data-directory descriptor, cblink taught to connect through Casper's
cap_net, and a forked runner for sendmail.  That is a project of its
own; the design would follow the agent's split.  The HTTPS private key
is out of the worker already (console 0.316.0, keymgr.c): a key manager
the worker forks as root reads it, becomes the console's user, enters
capability mode with its socket pair limited to CAP_READ|CAP_WRITE, and
signs the digests the worker's TLS handshakes send it; the worker's
OpenSSL key is a provider's public half.

## Order of work, if the split is wanted

1. cblink: a client connector hook (so the console can use
   `cap_connect`), and a server frame proxy (listener+TLS in one
   process, dispatch in another).
2. The prober as a sandboxed child of the agent (smallest real gain:
   it is the one parser of input from arbitrary hosts).
3. The agent's frontend/backend split, operation by operation,
   generated from the IDL as the job parser is.
4. The console: files `*at`, the web root by descriptor, cap_net, the
   sendmail runner.
