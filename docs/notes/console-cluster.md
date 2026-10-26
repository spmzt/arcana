# Console clustering, active/active: a design to decide on

Decided 2026-10-18: the console is to be clustered active/active, and
a database is allowed only where it is required.  This note lays out
what active/active means for Arcana's console as it is, the three
ways to get there, and a recommendation.  Nothing here is built yet.

## What the console keeps today

One arcana-console process (a supervisor and its one worker), one data directory.  Everything
durable is a JSON document written whole by `store_save()` under a
lock file where several writers may meet (`templates.c` pattern):

| store | written by | how often |
| --- | --- | --- |
| `servers.json`, `settings.json`, `users.json`, `credentials.json`, `tokens.json`, `labels.json`, `prefix-lists.json`, `templates.json`, `sdwan.json`, `sdwan-lists.json`, `push.json`, `ca-state.json`, `arcana-source.json` | an admin's change | rarely |
| `sessions.json` | sign-in, sign-out, every `SESSION_SAVE` seconds of use | often, small |
| `workflows.json`, `runs.json`, `every.json`, `transfers.json`, `sdwan-state.json` | the schedulers and the manager loop | continuously |
| `sdwan-audit.jsonl` | each Policy Action; an HMAC chain | append only |

Beside the stores: the **workflow scheduler** runs on the one process
holding `workflows.lock` (flock); the **SD-WAN manager loop** likewise;
the **live stream** (WebSocket) and **job tracking** (the console asks
a host's agent for a job's state) are per process; **push**
subscriptions are a store.  The agents trust the console by its
certificate (`urn:arcana:role:console`), so a second console with the
same CA and client certificate is a console to them.

## What active/active needs

1. Every store readable and writable from every node, with a change
   on one seen by the others before the next request lands anywhere
   (an admin's two clicks may go to two nodes).
2. The schedulers and the manager loop running once in the cluster at
   a time, with another node taking over when the holder dies.
3. Sessions valid on every node: a cookie set by one accepted by all.
4. The audit chain appended in one order.
5. Each node reaching every agent (they are IPv6/TCP with client
   certificates; nothing to change), and the hosts' events followed by
   whichever node a browser is on.

## Three ways

### A. Shared file system (NFS, or a replicated ZFS dataset is not it)

The data directory on NFS, `flock` for the locks.  Nothing in the
console changes but the lock file paths and a cache invalidation: a
node must re-read a store it has in memory (`creds`, `udoc`, the
servers table, settings) when another node wrote it.  `store_save()`
writes a temporary file and renames; a reader on another node sees
either the old or the new document, never a torn one.

For: no new dependency, no new protocol, the smallest change (a
"modified since" check on `store_load()`, locks that work over NFS).
Against: NFS is a single point of failure itself unless it is HA
(which FreeBSD gives with HAST + CARP, or a filer); `flock` over NFSv4
works, over NFSv3 needs `rpc.lockd`; the audit chain's append needs
the lock too.  Latency on every store read unless cached.

### B. A database (PostgreSQL, or SQLite is not it)

Stores become rows (one JSON document a row keeps the code's shape:
`store_load()`/`store_save()` read and write a `documents(name,
version, body jsonb)` table), sessions a table, the audit trail a
table with the chain, the scheduler lock an advisory lock
(`pg_try_advisory_lock`) that a dead node's connection releases.
PostgreSQL itself made HA with Patroni or `repmgr`, or a managed one.

For: the strongest consistency, the simplest take-over, the right
answer at scale.  Against: the complexity the user named: a database
to install, run, back up and make HA, `libpq` as a dependency, and
Arcana installs nothing by itself (an Install button is fine).  Also a
second system of record beside the hosts' own configuration.

### C. Replication of the console's own (Raft over cblink)

The console nodes talk cblink to each other (it is already the
transport to the agents) and replicate a log of store writes with
Raft: the leader orders writes, every node applies them to its own
data directory, the leader runs the schedulers and the manager loop;
a browser talks to any node, which forwards writes to the leader and
answers reads from its own copy (reads of a store just written by this
browser go to the leader too, so a user sees their own change).

For: no dependency, no shared storage, true active/active for reads,
one leader for writes which is what the schedulers want anyway; the
audit chain is the Raft log's order; `libdncp`'s mesh thinking is
nearby.  Against: Raft in C is 1500–2500 lines to get right (log,
snapshots as the stores themselves, membership change, leader lease
for reads); it is new code in the security path.  Three nodes at
least for a majority.

## Recommendation

**C, in two steps**, since the database is to be avoided when not
required and shared NFS moves the single point of failure instead of
removing it:

1. **Leader election and forwarding first (no replication yet).**  A
   node list in `settings` (`cluster_peers`), a lease held through
   cblink heartbeats, one leader at a time; the followers forward
   every `guard(req, true)` request to the leader and proxy the live
   stream; the stores stay on the leader's disk, the followers read
   them through the leader with a short cache.  This alone gives
   several entry points, one brain, take-over by election, and the
   schedulers in one place, with the console's code almost unchanged:
   `store_load()`/`store_save()` grow a "through the leader" path and
   `guard()` a "forward".  Loss of the leader's disk loses the stores:
   that is step 2's problem, and it is today's problem too.
2. **Replicate the stores.**  Each `store_save()` on the leader becomes
   a log entry the followers apply; a follower with the whole log can
   be elected.  This is where Raft's log and snapshots come in; with
   step 1 in place the surface is small (the stores are whole
   documents, so a snapshot is the data directory).

If the user prefers B, step 1 is still the right first move: it makes
one writer, and the database then only replaces the leader's disk.

## Decided 2026-10-18: C, and its shape

The user chose C. One change to the two steps above: a leader that
alone holds the stores gives no availability, since nothing can take
over when it stops. Every store is a whole document (`store_save` writes
the file whole), so the stores replicate without a log of operations:

- **Membership.** Each node is named in `cluster { node … }` of web.conf
  with its cblink URI; three nodes at least, or two and a witness. Nodes
  talk over a family of their own, `arcana-cluster` (its own IDL,
  `share/arcana/cluster.yaml`), on a listener of each console's, with
  mutual TLS by certificates of the console's CA that say
  `URI:urn:arcana:role:console` and serve as well as dial.
- **Terms and votes.** A node that hears no leader for an election
  timeout asks the others for their votes for the next term; a node
  votes once a term, and only for a candidate whose stores are as new
  as its own (the highest version it holds). A majority makes a leader,
  which says so to the others every heartbeat.
- **Versioned documents.** The leader numbers every write
  `(term, seq)`. A follower's `store_save` is sent to the leader, which
  numbers it, writes it, sends it to every follower and answers once a
  majority holds it. Every node reads its own copy: reads stay local,
  active/active. A node behind (restarted, cut off) is sent what is
  newer than its versions when the leader next hears it.
- **Locks.** The read-change-write stores (labels, templates, prefix
  lists, users' sign-ins) take their lock from the leader, so that two
  nodes do not each write their own change over the other's.
- **Caches.** What a subsystem keeps in memory (keys, sessions, users,
  servers, push subscriptions) is read again when a replicated write of
  its store lands.
- **What runs once.** The workflow scheduler, the SD-WAN manager loop
  and the mail watcher run on the leader alone, started when a node
  becomes one and stopped when it is not.
- **Sessions** become a document each (`sessions/<hash>`), so that two
  nodes signing people in never write over each other's.
- **The browser.** Each node keeps its own origin; the WebAuthn RP ID
  is a name the nodes share (`console.example` for
  `a.console.example`, `b.console.example`), and the origin check takes
  the list of the nodes' origins.

A write needs a majority; a node cut off from it still reads, and
refuses changes, saying the cluster has no majority here.

## What the user decides

- A, B or C (C recommended).
- Node count: 2 with a witness, or 3.
- Whether the followers may answer reads from their own cached copy
  (fast, a second stale at worst) or always through the leader.
- Whether browsers go to any node directly (DNS round robin, each
  node its own certificate name) or through CARP's one address, which
  makes the cluster active/passive at the door and active/active
  behind it.

## Built (console 0.215.0)

- `craft.c`: Raft as a state machine without I/O, with a simulation test
  (`tests/raft_test.c`) of three and five nodes through drops, delays,
  duplicates, partitions, crashes and compaction; two of Raft's rules
  broken by hand are caught by it.  A node with an empty log never
  stands: the seed alone leads first.
- `nodes.c`: the I/O.  web.conf's `cluster` block; the arcana-cluster
  family (`share/arcana/cluster.yaml`) on a listener of the node's own;
  a thread a peer; the term, the vote and the log in `cluster/`,
  fsync'ed before anything is said; committed writes applied with
  `store_write()`; the documents sent whole (snapshot) to a node too far
  behind.  `store_save()` goes through `cluster_save()`; a follower's
  write is forwarded to the leader, which answers once it is committed.
- The scheduler, the SD-WAN manager and mail run on the leader alone.
- What the worker keeps of credentials, sessions, users, servers and
  push subscriptions is read again when another node's write lands.
- Every node's origin is taken by the WebAuthn, CSRF and stream checks.
- Settings › Cluster, `GET /api/cluster`; console_test:cluster runs
  three consoles over unix sockets.
- The read-change-write stores (labels, templates, prefix lists) take
  the leader's lock besides their flock(2), and wait to have written
  every write the leader had committed when it gave the lock before
  they read (console 0.216.2): two nodes labelling at once lose
  nothing, where without it half the labels were written over.
- Each session is a document of its own, `sessions/<hash>.json`
  (console 0.216.2): a sign-in, an end, a time of use each its own
  write, so sign-ins on two nodes at once are both kept and an end is
  not undone by another node.

## Not yet

- Files written besides `store_save()`: `vapid.pem` (push), the audit
  chain, `arcana-source.json`, the CA's next state.  The audit chain
  wants appends through the log.
- Membership changes: the nodes are web.conf's; adding one is a restart
  of each with the new block.
