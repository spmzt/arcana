# Console clustering, active/active

The console runs as a cluster of nodes, active/active, by Raft over
cblink between the consoles: no database and no shared file system.
Every store is a whole JSON document (`store_save()` writes the file
whole), so the stores replicate as documents, without a log of
operations.

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
   whichever node a browser is on.  The agents trust the console by its
   certificate (`urn:arcana:role:console`), so every node with the
   same CA and a console certificate is a console to them.

## How it works

- **Membership.** Each node is named in `cluster { node … }` of web.conf
  with its cblink URI and its origin; three nodes at least. Nodes talk
  over a family of their own, `arcana-cluster` (its own IDL,
  `share/arcana/cluster.yaml`), on a listener of each console's, with
  mutual TLS by certificates of the console's CA that say
  `URI:urn:arcana:role:console` and serve as well as dial.
- **Raft.** `craft.c` is Raft as a state machine without I/O, tested
  by simulation (`tests/raft_test.c`: three and five nodes through
  drops, delays, duplicates, partitions, crashes and compaction).  A
  node votes once a term, only for a candidate whose log is as new as
  its own; a majority makes a leader, which holds a lease and says so
  every heartbeat; a leader cut off from the majority steps down.  A
  node with an empty log never stands: the seed (the first node
  named) leads first, from the documents it has.
- **Writes.** `nodes.c` is the I/O: the term, the vote and the log in
  `<datadir>/cluster`, fsync'ed before anything is said; a thread a
  peer.  `store_save()` is `cluster_save()`: the leader numbers the
  document, sends it to every follower and answers once a majority
  holds it and it is written; a follower forwards its write to the
  leader and waits for the same.  Committed writes are applied with
  `store_write()` on every node alike; a node too far behind is sent
  the documents whole.
- **Reads** are each node's own files: active/active.
- **Locks.** The read-change-write stores (labels, templates, prefix
  lists) take the leader's lock besides their flock(2).  A lock is a
  write of the log, applied by every node to its table, so a new
  leader knows the locks of the one before; the holder waits to have
  written every write the leader had committed when it gave the lock
  before it reads.
- **Caches.** What the worker keeps in memory (credentials, sessions,
  users, servers, push subscriptions) is read again when another
  node's write of its store lands.
- **What runs once.** The workflow scheduler, the SD-WAN manager loop
  and the mail watcher run on the leader alone, started when a node
  becomes one and stopped when it is not.
- **Sessions** are a document each (`sessions/<hash>.json`): a
  sign-in, an end, a time of use each its own write, so sign-ins on
  two nodes at once are both kept and an end is not undone by another
  node.
- **The browser.** Each node keeps its own origin; the WebAuthn RP ID
  is a name the nodes share (`console.example` for
  `a.console.example`, `b.console.example`), and the WebAuthn, CSRF
  and stream checks take every node's origin.
- **Without a majority** a node still reads, and refuses changes,
  saying the cluster has no majority here.
- Settings › Cluster and `GET /api/cluster` show it; console_test:cluster
  runs three consoles over unix sockets.

## Not yet

- Files written besides `store_save()`: `vapid.pem` (push), the audit
  chain, `arcana-source.json`, the CA's next state.  The audit chain
  wants appends through the log.
- Membership changes: the nodes are web.conf's; adding one is a restart
  of each with the new block.
- A cluster of two nodes and a witness.
