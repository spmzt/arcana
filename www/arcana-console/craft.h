/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The consoles' consensus (Raft), as a state machine without I/O: what
 * comes in (a message, the time, a write proposed) changes it, and what
 * it says (messages to send, writes now committed to apply, its term and
 * vote and log to be kept on disk first) is taken out by the caller,
 * which owns the network, the disk and the clock.  Each write is a whole
 * document: the log is the writes not yet in every node's documents, and
 * the documents on disk are the snapshot.
 */

#ifndef CRAFT_H
#define CRAFT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	CRAFT_NODES_MAX		9
#define	CRAFT_NAME_MAX		64
#define	CRAFT_BATCH_MAX		64	/* writes in one append */
#define	CRAFT_ELECTION_MIN_MS	1500	/* a follower's patience, at least */
#define	CRAFT_ELECTION_SPAN_MS	1500	/* and a random part above it */
#define	CRAFT_HEARTBEAT_MS	400
/* A leader's lease: heard from a majority this recently, it is the one
 * (less than CRAFT_ELECTION_MIN_MS: no other is elected before it
 * stops saying so).  Longer silent, it steps down. */
#define	CRAFT_LEASE_MS		(2 * CRAFT_HEARTBEAT_MS)

enum craft_role { CRAFT_FOLLOWER, CRAFT_CANDIDATE, CRAFT_LEADER };

/* A write: a document as it is to be, or taken away. */
struct craft_entry {
	uint64_t	 term;
	uint64_t	 seq;
	char		*name;
	uint8_t		*body;
	size_t		 len;
	bool		 gone;
};

enum craft_msg_type {
	CRAFT_VOTE, CRAFT_VOTE_REPLY,
	CRAFT_APPEND, CRAFT_APPEND_REPLY,
	CRAFT_SNAPSHOT_NEEDED,		/* to the caller: send this one the docs */
};

struct craft_msg {
	enum craft_msg_type	 type;
	char			 from[CRAFT_NAME_MAX];
	char			 to[CRAFT_NAME_MAX];
	uint64_t		 term;
	/* vote: the candidate's newest write; append reply: the
	 * follower's newest write that agrees with the leader. */
	uint64_t		 last_term;
	uint64_t		 last_seq;
	bool			 granted;	/* vote reply */
	bool			 ok;		/* append reply */
	/* append */
	uint64_t		 prev_term;
	uint64_t		 prev_seq;
	uint64_t		 commit;
	struct craft_entry	*entries;	/* the node's own, not copied */
	size_t			 nentries;
};

struct craft_peer {
	char		 name[CRAFT_NAME_MAX];
	uint64_t	 next;		/* the next write to send it */
	uint64_t	 match;		/* the newest it holds that agrees */
	bool		 voted;		/* gave its vote this term */
	bool		 inflight;	/* an append is out, unanswered */
	uint64_t	 sent_ms;
	uint64_t	 heard_ms;	/* its last answer, this term */
};

struct craft {
	char			 self[CRAFT_NAME_MAX];
	struct craft_peer	 peers[CRAFT_NODES_MAX - 1];
	int			 npeers;
	enum craft_role		 role;
	uint64_t		 term;
	char			 voted_for[CRAFT_NAME_MAX];
	char			 leader[CRAFT_NAME_MAX];
	/* The log: the writes after base_seq (of base_term), in order. */
	struct craft_entry	*log;
	size_t			 nlog;
	size_t			 cap;
	uint64_t		 base_term;
	uint64_t		 base_seq;
	uint64_t		 commit;	/* the newest a majority holds */
	uint64_t		 applied;	/* the newest taken out to apply */
	uint64_t		 now_ms;
	uint64_t		 election_at;	/* a follower's deadline */
	uint64_t		 heartbeat_at;	/* a leader's next beat */
	uint64_t		 led_at;	/* when it became the leader */
	uint32_t		 rnd;
	/* What the caller takes out. */
	struct craft_msg	*out;
	size_t			 nout;
	size_t			 outcap;
	bool			 state_dirty;	/* term or vote to be kept */
	uint64_t		 log_dirty_from; /* writes from here to keep; 0 none */
	bool			 log_truncated;	/* and the log cut before them */
};

void	 craft_init(struct craft *, const char *, const char *const *, int,
	    uint64_t, uint32_t);
void	 craft_restore(struct craft *, uint64_t, const char *, uint64_t,
	    uint64_t);
int	 craft_restore_entry(struct craft *, uint64_t, uint64_t, const char *,
	    const uint8_t *, size_t, bool);
void	 craft_free(struct craft *);
void	 craft_tick(struct craft *, uint64_t);
bool	 craft_quorum_heard(const struct craft *, uint64_t);
void	 craft_recv(struct craft *, const struct craft_msg *);
int	 craft_propose(struct craft *, const char *, const uint8_t *, size_t,
	    bool, uint64_t *, uint64_t *);
void	 craft_snapshot_done(struct craft *, const char *, uint64_t);
void	 craft_install_snapshot(struct craft *, uint64_t, uint64_t, uint64_t,
	    const char *);
const struct craft_entry *craft_next_apply(struct craft *);
void	 craft_compact(struct craft *, size_t);
const struct craft_entry *craft_entry_at(const struct craft *, uint64_t);
uint64_t craft_last_seq(const struct craft *);
uint64_t craft_last_term(const struct craft *);
void	 craft_out_clear(struct craft *);
int	 craft_quorum(const struct craft *);

#endif
