# Trinity Seven naming and architecture guide

This is the project's naming design: how the components of a
FreeBSD-native fleet orchestration and agent-based management system
are named. The project and its programs carry the names; see
[Programs](#programs) and [The agent's sources](#the-agents-sources)
at the end.

## Purpose

The project manages a fleet of FreeBSD machines, and stays extensible
enough to coordinate things outside a single host: routing between servers, network services, scheduled
tasks, deployments, system services, jails, storage, resource
management, monitoring and telemetry, notifications, external APIs,
Telegram and other integrations, and future plugins and automation.

It is deliberately inspired by the *Trinity Seven* setting. The seven
major architectural domains are named after the seven Archives:

```
Superbia   Invidia   Ira   Acedia   Avaritia   Gula   Luxuria
```

These are an architectural vocabulary, not cosmetic names: the system
should feel like a coherent world with its own terminology while the
software architecture underneath stays technically sensible.

## The most important principle

Do not try to map every FreeBSD subsystem directly to one of the seven.
The seven are high-level conceptual domains. FreeBSD is the substrate.
The **Agent** is the host-local execution layer. The **Orchestrator** is
the fleet-wide coordination layer.

```
                         ORCHESTRATOR
                              │
                    fleet-wide coordination
                              │
                              ▼
                            AGENT
                              │
                   host-local system boundary
                              │
          ┌──────────┬────────┼────────┬──────────┐
          │          │        │        │          │
       Superbia   Invidia    Ira     Acedia   Avaritia
          │          │        │        │          │
          └──────────┴────────┼────────┴──────────┘
                              │
                         Gula / Luxuria
                              │
                              ▼
                           FreeBSD
                              │
                           hardware
```

The exact boundaries may evolve. Do not sacrifice a good technical
architecture merely to make the mythology fit.

## The seven Archives

The English meanings are broad hints; the *Trinity Seven* themes
(Thema) of each Archive matter more when naming individual components.
Names are chosen by conceptual affinity, not literal translation.

### Superbia: identity, truth, authority, policy

Pride. Themes: Verum, Arbiter, Justitia, Impero, Caritas, Missionis,
Idea, Benignitas, Regius, Amor, Sensus.

Covers identity, authority, policy, configuration, desired state, trust,
authorization, governance, judgement, system intent. It answers: *what
should this system be, what is true about it, and what is it allowed or
expected to do?*

Possible affinities: Verum (truth, state, facts), Arbiter (decisions,
policy), Justitia (authorization, enforcement), Impero (control),
Missionis (tasks, objectives), Idea (desired state, intent).

### Invidia: network, reachability, relationships

Envy. Themes: Spero, Perfectus, Expecto, Ridic, Studium. A more
dynamic, active, competitive feeling.

Covers networking, communication paths, routing, connectivity, topology,
reachability, protocol state, network relationships and optimisation.
The FreeBSD networking substrate belongs here (sockets, protocols,
interfaces, routing, FIBs, nexthops, drivers), with room for
higher-level systems: BGP, OSPF, WireGuard, tunnels, firewall, NAT, DNS.

Names inside Invidia need not mean "network": pick by the component's
role. Something about expected state might relate to Expecto.

### Ira: action, execution, change

Wrath. Themes: Victoria, Concordia, Analysis, Partum, Cultura, Ruina,
Auxilium, Invicta, Determinatio.

Ira acts: processes, services, jails, commands, jobs, deployments,
lifecycle operations, scheduled execution, remediation. Start a jail,
stop a service, restart a daemon, run a command, deploy, run a scheduled
task.

Possible affinities: Victoria (successful completion), Concordia
(coordinated execution), Analysis (decomposing a task), Partum
(producing, delivering), Auxilium (assistance), Ruina (teardown,
failure, destructive lifecycle), Determinatio (persistent execution).

### Acedia: persistence, stability, storage

Sloth. Themes: Stagna, Obsidis, Confuto, Infrequentia, Ligare, Fixing,
Moderatio, Asylum, Pax.

Things that persist, remain, hold, or provide a stable substrate:
storage, filesystems, disks, datasets, mounts, snapshots, persistent
state, pools, backups, possibly caches. Not "slow": persistence,
stability, restraint, the things that remain.

### Avaritia: resources, allocation, scarcity

Greed. Themes: Contineo, Retreat, Frux, Amicitia, Cupiditas, Venusta,
Sympathia, Sapientia, Flaccus.

Resources that can be accumulated, allocated, consumed, limited or
exchanged: CPU, memory, VM resources, swap, quotas, capacity,
reservations, limits, accounting, scheduling of scarce resources. Not a
duplicate of telemetry: Avaritia is allocation, quota and capacity;
Gula is utilisation, measurements and events.

Possible affinities: Cupiditas (demand, accumulation), Frux (successful
utilisation), Sapientia (resource policy), Flaccus (changing state).

### Gula: observation, information, telemetry

Gluttony. Themes: Fides, Felicitas, Voluntas, Sanctus.

Gula consumes information from the rest of the system: metrics, logs,
events, health, state observation, monitoring, history, diagnostics,
event streams. It observes the other domains rather than owning their
actions: *Ira performs an action; Gula observes the result.* "em0 went
down", "jail web01 stopped", "the pool is 82% full", "a BGP session
changed state".

### Luxuria: boundaries, interfaces, the outside world

Lust. Themes: Terminus, Vanitas, Sileo, Diligo, Fall, Everlasting,
Abies, Origo.

The boundary between the system and things beyond it: plugins, external
APIs, Telegram, email, webhooks, cloud services, GitHub, external DNS
providers, ticket systems, notification systems, other infrastructure.
Affinities: Terminus (boundaries), Sileo (waiting, cycles), Everlasting
(persistent external systems), Abies (lifecycle), Origo (source,
origin), Diligo (communication). Not literally "communication":
interfaces, boundaries, stages, interaction with external entities.

## Agent

Not one of the seven: an architectural role. The Agent lives on each
managed FreeBSD host and is the controlled boundary through which the
platform interacts with that host.

```
Orchestrator ─▶ Agent ─▶ Superbia, Invidia, Ira, Acedia, Avaritia, Gula, Luxuria ─▶ FreeBSD
```

It must not become a "miscellaneous" module: when implementing
something, first decide which Archive conceptually owns it. The Agent
communicates with the Orchestrator, executes operations locally,
exposes the seven domains, collects results, reports state, enforces
local boundaries, and interacts with FreeBSD.

## Orchestrator

Also outside the seven. The seven are capabilities; the Orchestrator
coordinates them across the fleet: workflows, desired-state
reconciliation, multi-host operations, dependency management, rollouts,
fleet-level scheduling, recovery, cross-host coordination.

```
Orchestrator: "what should happen?"  ─▶  Agent: "do it here"  ─▶  Archives  ─▶  FreeBSD
```

"Restart nginx on all web servers and notify me if any host fails":
Superbia authorises, Ira restarts nginx, Gula observes the result,
Luxuria notifies Telegram, the Orchestrator coordinates the workflow.

## Naming philosophy

- **Do not exhaust the vocabulary.** The themes are a reserved
  namespace; assign one only when a concept naturally appears.
- **Do not force one-to-one mapping.** One Thema need not be one
  subsystem, and one feature may involve several Archives. Deploying a
  jail involves Superbia (permission, desired state), Avaritia
  (resources), Acedia (storage), Invidia (network), Ira (the lifecycle
  operation), Gula (monitoring) and Luxuria (notification). The seven
  describe aspects of an operation, not exclusive implementation boxes.

### How to name a new component

1. Determine its technical responsibility: *what is the fundamental
   concept behind it?*, not which FreeBSD subsystem implements it.
2. Determine which Archive has the strongest conceptual relationship.
3. Check whether an unused Thema naturally describes the concept.
4. Prefer that Thema when the relationship is strong.
5. Otherwise use a descriptive technical name and keep the thematic
   namespace reserved.

Never force a thematic name because it exists, and never consume all
the names at the beginning. A technically clear name beats a strained
reference.

### Priority

1. Correct architecture
2. Clear responsibility
3. Strong conceptual relationship
4. Trinity Seven thematic consistency
5. Aesthetic appeal

The mythology should make the architecture memorable, never confusing.

## FreeBSD relationship

FreeBSD is the foundation. Roughly, and intentionally approximately:

| FreeBSD | Archive |
|---|---|
| networking | Invidia |
| processes, services, tty, execution | Ira |
| filesystem, VFS, storage, devices | Acedia |
| VM, memory, swap, finite resources | Avaritia |
| observation of all of the above | Gula |
| communication outside the system | Luxuria |
| identity, policy, configuration | Superbia |

The project is FreeBSD-native, not a reimplementation of the kernel's
architecture.

## Overall philosophy

FreeBSD provides the substrate; the Agent a controlled presence on one
host; the seven Archives the major capabilities; the Orchestrator
coordinates them across the fleet. The definitions are guiding
concepts, not rigid ones: build a coherent technical system first and
let the terminology emerge around it.

## Programs

Programs are named for what the operator does with them, under one
prefix; Archives name what is *inside* them. A tool called
`superbia-enrol` would make you recall which Archive owns a task before
you could type it, and seven families of tools would multiply that. So:

| Program | Role |
|---|---|
| `arcana-agent` | the Agent: the daemon on every host, the only privileged part |
| `arcana-console` | the Orchestrator: the web console, its users, many hosts |
| `arcanactl` | a shell's way to one agent |
| `arcana-enrol` | joins a host to the console; a Superbia task (identity, trust) |
| `jailconf` | a general `jail.conf` editor; not Arcana-specific, so without the prefix |

Each stays a small tool that does one thing. The Archive a tool or an
operation belongs to is said in its manual and here, and is the name to
reach for when a module, an operation group or a log tag inside the
system needs one.

The service names are `arcana_agent` and `arcana_console` (rc.d names
take no hyphen), the configuration lives in `/usr/local/etc/arcana`, the
console's data in `/var/db/arcana`, and the cblink family is `arcana`.

## The agent's sources

The agent's sources are laid out by Archive, in
`usr.sbin/arcana-agent`; the main files of each:

| Directory | Archive | What is in it |
|---|---|---|
| (top) | the Agent | `main.c` (start, listeners, stopping), `handlers.c` (the family's requests, one thread each), `work.c` (a request's memory) |
| `superbia/` | Superbia | `host.c` (what the host is), `confread.c` (the jails as configured, as jail(8) resolves them), `confedit.c` (changing a jail's configuration, with a backup and a read-back), `kernel.c` (the kernel's modules, loaded and unloaded, and its memory), `sysctl.c` (the kernel's state, read, set and kept) |
| `invidia/` | Invidia | `network.c` (routes, nexthops, connections, sockets), `wireguard.c` and `ywg.c` (WireGuard's keys and peers, through the base system's wg(8)), `interfaces.c` (the interfaces, read and changed live), `routes.c` (static routes), `netdump.c` (a network table in parts, from a thread of its own), `pcb.c` (the connections and sockets, from the kernel's lists), `nlroute.c` (the routing tables through netlink: read, changed, and watched for what changes), `address.c` (a jail's addresses, live and persistent), `transport.c` (the agent's own listeners, SCTP beside TCP, and the connections open to it), `l2.c` (bridges with their spanning tree and VLANs, geneve tunnels), `ipfw.c` (the firewall: its rules, the kept ones, and applying them through set 1) |
| `ira/` | Ira | `lifecycle.c` (list, start, stop, restart, kill), `jails.c`, `jail.c` (running jails), `services.c`, `packages.c`, `jobs.c` (the queue), `exec.c` (running a program), `update.c`, `build.c` (the agent's own program) |
| `acedia/` | Acedia | `pools.c` (ZFS pools, for the host's figures), `storage.c` (disks and partitions from GEOM, pools, datasets, snapshots, mounts and fstab; the zfs, zpool, mount, gpart and camcontrol jobs) |
| `avaritia/` | Avaritia | `resources.c` (CPU, memory, swap) |
| `gula/` | Gula | `trace.c` (the steps of every request), `stats.c` (the host's figures, gathered), `procs.c` (what runs, and a signal or a nice value for one), `log.c` (what syslogd wrote, read from its end and followed), `events.c` (what happened, numbered and kept, to be asked for from a number), `history.c` (an hour of how busy the host was, sampled by a thread of its own) |
| `luxuria/` | Luxuria | the plugins, what works through a program that is installed and not the base system's: `plugins.c` (which a host or a vnet jail has), `bird.c` (BIRD, through birdc(8) and bird(8)) |

One feature can touch several: changing a jail's address is Invidia's
operation, done live through the kernel and persistently through
Superbia's edit of the configuration, and traced by Gula. A file is
where its main concern lives; the `y*.c` files in each directory fill
that Archive's YANG modules.

How the operations (the cblink family in `share/arcana/arcana.yaml`,
its wire the YANG module written from it) fall under the Archives:

| Operations | Archive |
|---|---|
| `list`, `action` (jails), `services`, `service-action`, `pkg-upgrade`, `packages`, the job queue, `agent-update`, `agent-build` | Ira |
| `service-config`, `address` with persist, enrolment and certificates (`arcana-enrol`, the console's CA) | Superbia |
| `network` (routes, nexthops, connections, sockets), `address` live | Invidia |
| `stats`: memory, swap, CPU | Avaritia for what is allocated, Gula for what is measured |
| `stats`: ZFS pools | Acedia |
| the trace of every call, the activity log, job traces | Gula |
| update check, browser notifications (in the console) | Luxuria |
| arcana-bird (the `network` operation's bird kinds and `bird-config` before it), the bird job: the plugins | Luxuria |
| arcana-wireguard (the `network` operation's wireguard kind before it), the wireguard job: WireGuard, through the base system's wg(8) | Invidia |
