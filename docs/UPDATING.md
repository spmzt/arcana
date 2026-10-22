# Updating Arcana

The console asks GitHub's release feed every six hours and shows a
banner when a newer version is out; `update_check = false` in `web.conf`
turns that off. It does not replace itself, since it runs unprivileged:

- the container image carries `io.containers.autoupdate=registry`, so
  `podman auto-update` (from cron, say) pulls a newer `ghcr.io/spmzt/arcana`
  and restarts the container;
- a native install is updated with `pkg upgrade arcana`, or
  `make install` from a newer tree, then `service arcana_console restart`.

Certificates stay valid across updates.

## The page and the installed app

The page keeps its files in the browser, through a service worker, so
that it opens without a network. It looks for a newer set on the
console whenever it comes back into view, which for the app installed
on a phone is every time it is opened, and every half hour while it
stays open. When there is one it takes it and loads itself again; there
is nothing to reinstall. The new files are fetched from the console
itself, past the browser's own cache.

## Updating the console from the repository

With a repository set (`agent_source`, under **Settings**), the header
of the host the console runs on, the one added by its local socket
(`unix:/var/run/arcana-agent.sock`), has **Update console**. The agent
there clones the repository, builds all of Arcana as `nobody`, runs
`make install` as root over what is installed (the console's module,
the page, the agent and the tools), and restarts the `arcana_console`
service and then itself, `arcana_agent`: the console and the agent of
one host are of one version, and read each other. Updating by hand,
restart both too. The agent the console then sends to the other hosts
is the one installed with it, when that is newer than the one a host
built for it earlier. The page reconnects by itself, still logged in: the
console keeps its sessions over a restart. When the console answers with another version
than the page was loaded from, the page loads itself again, after
letting its service worker take the new files. A repository over SSH asks for
its host key as a build does. From a shell: `arcanactl console-update
[-y] [-i key] repository [ref]`.

The build's programs run with the build directory
(`/var/cache/arcana-build`) as their home: emcc keeps its cache there,
and builds its system libraries into it the first time, which takes a
few minutes more.

It needs on that host what building Arcana needs (see the README),
Emscripten included, and its settings in
`/usr/local/etc/arcana/config.mk`. A console in a container is updated
with its image instead. The agent on that host is installed too, and
runs from its next restart.

## Updating the agents

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
its `arcana_agent` service. The console watches for it to answer as the
new build and says when it does; if it has not after 45 seconds, it
says the service did not restart, which is what happens when
`arcana_agent_enable` is not set or the agent was started by hand (the
host's log says which); without it, the new program runs from the next start of the
service. A restart drops jobs still queued on the host; one that is
running finishes first. From a shell, `arcanactl agent-update [-r]
program` does the same for one host.

The program has to suit the host: the same architecture and a FreeBSD
version it runs on, with `libcblink` there as before. Hosts that differ
from the console's machine are updated with `pkg upgrade arcana`
instead, which the Packages tab can do. If an update goes wrong, put
`arcana-agent.old` back and restart the service.

## Building the agent on a host

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

When git fails, the entry in the activity bar says everything git said
(its last line alone is only the end of its advice), and **Raw output**
has it verbatim.

A repository reached over SSH (`git@host:path`, `ssh://…`) takes two
more things, since git runs there as a user with no known hosts and no
key:

- **The server's host key.** The host that builds never takes it on
  trust. The first build stops and the console shows the fingerprints
  of the keys the server presented; compare one with what the server's
  administrator gives, and confirm. The host keeps the confirmed keys
  in `known_hosts` in its build directory and checks the server against
  them from then on. If the server later shows another key, the build
  fails and says so in capitals, and the dialog asks again.
- **A key for the host.** By default the host makes one for itself
  (`id_ed25519` in the build directory) and the dialog shows its public
  half: add it to the repository's server as a read-only deploy key.
  To use a key of your own instead, put its path on the build host in
  **Settings**, "SSH key for git" (`agent_ssh_key`); it has to be
  readable by `nobody`, whom git runs as.

From a shell, `arcanactl agent-build -y` confirms the keys shown, and
`-i key` names the key.

The host that builds needs what the build needs: `git`, the base
compiler, `devel/libcbor` and `net/libyang3` (for cblink-gen, which
reads the wire's YANG modules); cblink is cloned with the tree, a
submodule, and built with it. If the linker
are somewhere else on it, `/usr/local/etc/arcana/config.mk` there is
copied into the tree as its `config.mk`. When the agent is root, git
and make run as `nobody`. From a shell, `arcanactl agent-build [-o
file] repository [ref]` builds and saves the program.

## The wire of cblink 0.2

Since agent 0.195.0 and console 0.276.0 the agent, arcanactl and the
console speak cblink's wire version 2 alone (YANG-CBOR bodies keyed by
SID, `share/yang/arcana@<rev>.yang`), on `libcblink.so.2`; a version-2
program and a version-1 one do not understand each other.  Moving a
fleet over, in an order that never leaves you without a working
arcanactl:

1. Push the tree; on the console host pull and `make` (build only).
2. Install `devel/cblink` 0.2 on every host (`pkg upgrade cblink` from
   the console's Packages tab): `libcblink.so.2` installs beside
   `.so.1`; nothing uses it yet.
3. From the console's fleet page, update every agent but the console
   host's own.  Each becomes version 2 and the old console can no
   longer reach it: expected.  Check each with the new arcanactl from
   the build tree (`obj/usr.sbin/arcanactl/arcanactl`, which finds
   the submodule's library by its rpath): `hello` shows the version.
4. Last, the console host: `make install`, `service arcana_console
   restart`, `service arcana_agent restart`.  Then `arcanactl hello`
   locally and to each host; the fleet page green.
5. Before step 4 a host goes back by `arcana-agent.old` and a restart.

## Versions

The agent and the console have versions of their own, and every change
to one bumps it: `ARCANA_AGENT_VERSION` in
`usr.sbin/arcana-agent/agent.h`, `ARCW_VERSION` in
`www/arcana-console/console.h`. A host's header and the tree show the
agent's; the update dialog shows the one the console would send.
