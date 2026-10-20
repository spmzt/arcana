/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Raft (Ongaro and Ousterhout, "In Search of an Understandable Consensus
 * Algorithm"), for the consoles of a cluster, as a state machine without
 * I/O (craft.h).  Its rules, as the paper's Figure 2 has them:
 *
 * - a node votes once a term, for a candidate whose log is at least as
 *   new as its own (the last write's term, then its sequence);
 * - a leader sends each follower the writes after the one both hold,
 *   and the follower takes them only when it holds that one (its term
 *   and sequence alike), cutting away what of its own disagrees;
 * - a write is committed once a majority holds it and it is of the
 *   leader's own term (those before it then are too), and only then
 *   applied: what was never committed can be lost, never what was.
 *
 * Writes are whole documents, so a follower too far behind for the log
 * the leader keeps is sent the documents instead (the caller's), and
 * the log is compacted to what may still be needed.
 *
 * The caller keeps on disk, before it sends what craft says: the term
 * and vote when state_dirty, the log from log_dirty_from on (the whole
 * of it when log_truncated).  Messages taken out point into the log,
 * and are good until the next call that changes it.
 */

#include <stdlib.h>
#include <string.h>

#include "craft.h"

static uint32_t
rnd_next(struct craft *c)
{

	/* xorshift32: enough to spread the elections apart. */
	c->rnd ^= c->rnd << 13;
	c->rnd ^= c->rnd >> 17;
	c->rnd ^= c->rnd << 5;
	return (c->rnd);
}

static void
election_reset(struct craft *c)
{

	c->election_at = c->now_ms + CRAFT_ELECTION_MIN_MS + rnd_next(c) %
	    CRAFT_ELECTION_SPAN_MS;
}

int
craft_quorum(const struct craft *c)
{

	return ((c->npeers + 1) / 2 + 1);
}

uint64_t
craft_last_seq(const struct craft *c)
{

	return (c->base_seq + c->nlog);
}

uint64_t
craft_last_term(const struct craft *c)
{

	return (c->nlog > 0 ? c->log[c->nlog - 1].term : c->base_term);
}

/* The term of the write at seq; 0 when it is not known here. */
static uint64_t
term_at(const struct craft *c, uint64_t seq)
{

	if (seq == c->base_seq)
		return (c->base_term);
	if (seq < c->base_seq || seq > craft_last_seq(c))
		return (0);
	return (c->log[seq - c->base_seq - 1].term);
}

const struct craft_entry *
craft_entry_at(const struct craft *c, uint64_t seq)
{

	if (seq <= c->base_seq || seq > craft_last_seq(c))
		return (NULL);
	return (&c->log[seq - c->base_seq - 1]);
}

static void
entry_free(struct craft_entry *e)
{

	free(e->name);
	free(e->body);
	memset(e, 0, sizeof(*e));
}

static int
log_push(struct craft *c, uint64_t term, const char *name, const uint8_t *body,
    size_t len, bool gone)
{
	struct craft_entry	*e, *nl;
	size_t			 cap;

	if (c->nlog == c->cap) {
		cap = c->cap == 0 ? 64 : c->cap * 2;
		if ((nl = realloc(c->log, cap * sizeof(*nl))) == NULL)
			return (-1);
		c->log = nl;
		c->cap = cap;
	}
	e = &c->log[c->nlog];
	memset(e, 0, sizeof(*e));
	e->term = term;
	e->seq = craft_last_seq(c) + 1;
	e->gone = gone;
	if ((e->name = strdup(name != NULL ? name : "")) == NULL)
		return (-1);
	if (len > 0) {
		if ((e->body = malloc(len)) == NULL) {
			free(e->name);
			return (-1);
		}
		memcpy(e->body, body, len);
		e->len = len;
	}
	c->nlog++;
	if (c->log_dirty_from == 0 || e->seq < c->log_dirty_from)
		c->log_dirty_from = e->seq;
	return (0);
}

/* The log from seq on, taken away: it disagrees with the leader's. */
static void
log_cut(struct craft *c, uint64_t seq)
{

	while (c->nlog > 0 && craft_last_seq(c) >= seq)
		entry_free(&c->log[--c->nlog]);
	c->log_truncated = true;
}

static struct craft_msg *
out_new(struct craft *c, enum craft_msg_type type, const char *to)
{
	struct craft_msg	*m, *no;
	size_t			 cap;

	if (c->nout == c->outcap) {
		cap = c->outcap == 0 ? 16 : c->outcap * 2;
		if ((no = realloc(c->out, cap * sizeof(*no))) == NULL)
			return (NULL);
		c->out = no;
		c->outcap = cap;
	}
	m = &c->out[c->nout++];
	memset(m, 0, sizeof(*m));
	m->type = type;
	m->term = c->term;
	strlcpy(m->from, c->self, sizeof(m->from));
	strlcpy(m->to, to, sizeof(m->to));
	return (m);
}

void
craft_out_clear(struct craft *c)
{

	c->nout = 0;
}

static struct craft_peer *
peer_of(struct craft *c, const char *name)
{
	int	i;

	for (i = 0; i < c->npeers; i++)
		if (strcmp(c->peers[i].name, name) == 0)
			return (&c->peers[i]);
	return (NULL);
}

void
craft_init(struct craft *c, const char *self, const char *const *peers,
    int npeers, uint64_t now_ms, uint32_t seed)
{
	int	i;

	memset(c, 0, sizeof(*c));
	strlcpy(c->self, self, sizeof(c->self));
	for (i = 0; i < npeers && i < CRAFT_NODES_MAX - 1; i++)
		strlcpy(c->peers[i].name, peers[i], sizeof(c->peers[i].name));
	c->npeers = i;
	c->role = CRAFT_FOLLOWER;
	c->now_ms = now_ms;
	c->rnd = seed != 0 ? seed : 0x9e3779b9;
	election_reset(c);
}

/* What was kept on disk: the term, the vote, the log's base. */
void
craft_restore(struct craft *c, uint64_t term, const char *voted_for,
    uint64_t base_term, uint64_t base_seq)
{

	c->term = term;
	strlcpy(c->voted_for, voted_for != NULL ? voted_for : "",
	    sizeof(c->voted_for));
	c->base_term = base_term;
	c->base_seq = base_seq;
	/* The documents hold what was applied, at least up to the base;
	 * what comes after is applied again when it is committed again,
	 * which a document's version makes harmless. */
	c->commit = c->applied = base_seq;
}

int
craft_restore_entry(struct craft *c, uint64_t term, uint64_t seq,
    const char *name, const uint8_t *body, size_t len, bool gone)
{

	if (seq != craft_last_seq(c) + 1)
		return (-1);
	if (log_push(c, term, name, body, len, gone) != 0)
		return (-1);
	c->log_dirty_from = 0;
	return (0);
}

void
craft_free(struct craft *c)
{

	while (c->nlog > 0)
		entry_free(&c->log[--c->nlog]);
	free(c->log);
	free(c->out);
	memset(c, 0, sizeof(*c));
}

static void
become_follower(struct craft *c, uint64_t term, const char *leader)
{

	if (term > c->term) {
		c->term = term;
		c->voted_for[0] = '\0';
		c->state_dirty = true;
	}
	c->role = CRAFT_FOLLOWER;
	strlcpy(c->leader, leader != NULL ? leader : "", sizeof(c->leader));
	election_reset(c);
}

/* The writes a peer lacks, or what the caller must send it instead. */
static void
send_append(struct craft *c, struct craft_peer *p)
{
	struct craft_msg	*m;
	uint64_t		 prev, n;

	if (p->next == 0)
		p->next = 1;
	prev = p->next - 1;
	if (prev < c->base_seq) {
		/* Compacted away: the documents, as they are applied. */
		if ((m = out_new(c, CRAFT_SNAPSHOT_NEEDED, p->name)) == NULL)
			return;
		m->last_seq = c->applied;
		m->last_term = term_at(c, c->applied);
		p->inflight = true;
		p->sent_ms = c->now_ms;
		return;
	}
	if ((m = out_new(c, CRAFT_APPEND, p->name)) == NULL)
		return;
	m->prev_seq = prev;
	m->prev_term = term_at(c, prev);
	m->commit = c->commit;
	n = craft_last_seq(c) - prev;
	if (n > CRAFT_BATCH_MAX)
		n = CRAFT_BATCH_MAX;
	m->nentries = (size_t)n;
	m->entries = n > 0 ? &c->log[prev - c->base_seq] : NULL;
	p->inflight = true;
	p->sent_ms = c->now_ms;
}

static void
advance_commit(struct craft *c)
{
	uint64_t	n;
	int		i, have;

	for (n = craft_last_seq(c); n > c->commit; n--) {
		/* Only one of its own term commits by counting. */
		if (term_at(c, n) != c->term)
			break;
		have = 1;
		for (i = 0; i < c->npeers; i++)
			if (c->peers[i].match >= n)
				have++;
		if (have >= craft_quorum(c)) {
			c->commit = n;
			break;
		}
	}
}

static void
become_leader(struct craft *c)
{
	int	i;

	c->role = CRAFT_LEADER;
	c->led_at = c->now_ms;
	strlcpy(c->leader, c->self, sizeof(c->leader));
	for (i = 0; i < c->npeers; i++) {
		c->peers[i].next = craft_last_seq(c) + 1;
		c->peers[i].match = 0;
		c->peers[i].inflight = false;
		/* Its vote, or not: the lease starts whole, and the first
		 * beat's answers keep it. */
		c->peers[i].heard_ms = c->now_ms;
	}
	/* A write of its own term, with nothing in it: what came before
	 * is committed by it (Raft's section 5.4.2). */
	(void)log_push(c, c->term, "", NULL, 0, false);
	if (c->npeers == 0)
		c->commit = craft_last_seq(c);
	for (i = 0; i < c->npeers; i++)
		send_append(c, &c->peers[i]);
	c->heartbeat_at = c->now_ms + CRAFT_HEARTBEAT_MS;
}

static void
start_election(struct craft *c)
{
	struct craft_msg	*m;
	int			 i;

	c->term++;
	c->role = CRAFT_CANDIDATE;
	strlcpy(c->voted_for, c->self, sizeof(c->voted_for));
	c->leader[0] = '\0';
	c->state_dirty = true;
	election_reset(c);
	for (i = 0; i < c->npeers; i++)
		c->peers[i].voted = false;
	if (craft_quorum(c) <= 1) {
		become_leader(c);
		return;
	}
	for (i = 0; i < c->npeers; i++) {
		if ((m = out_new(c, CRAFT_VOTE, c->peers[i].name)) == NULL)
			continue;
		m->last_term = craft_last_term(c);
		m->last_seq = craft_last_seq(c);
	}
}

void
craft_tick(struct craft *c, uint64_t now_ms)
{
	struct craft_peer	*p;
	int			 i;

	c->now_ms = now_ms;
	/* A leader no majority answers any more (cut off, or alone) is
	 * one no longer: it steps down, lest it keep saying it leads while
	 * the others elect another (Raft's check-quorum). */
	if (c->role == CRAFT_LEADER && !craft_quorum_heard(c,
	    CRAFT_ELECTION_MIN_MS))
		become_follower(c, c->term, NULL);
	if (c->role == CRAFT_LEADER) {
		if (now_ms < c->heartbeat_at)
			return;
		for (i = 0; i < c->npeers; i++) {
			p = &c->peers[i];
			/* An answer lost is asked again, at the beat. */
			if (!p->inflight || now_ms - p->sent_ms >=
			    CRAFT_HEARTBEAT_MS)
				send_append(c, p);
		}
		c->heartbeat_at = now_ms + CRAFT_HEARTBEAT_MS;
		return;
	}
	/* A node that holds nothing yet waits to be sent it: the first
	 * leader is the seed, whose base is the documents it had, so two
	 * empty nodes never elect each other over them. */
	if (craft_last_seq(c) == 0) {
		election_reset(c);
		return;
	}
	if (now_ms >= c->election_at)
		start_election(c);
}

/*
 * Has the leader heard from a majority (itself counted) within this
 * long?  What it grants on its own word (locks, the schedulers' turn)
 * is granted on this alone: a lease shorter than an election.
 */
bool
craft_quorum_heard(const struct craft *c, uint64_t within_ms)
{
	int	i, have;

	if (c->role != CRAFT_LEADER)
		return (false);
	have = 1;
	for (i = 0; i < c->npeers; i++)
		if (c->peers[i].heard_ms != 0 && c->now_ms - c->peers[i].heard_ms
		    <= within_ms)
			have++;
	return (have >= craft_quorum(c));
}

/* Is a candidate's log at least as new as this node's? */
static bool
up_to_date(const struct craft *c, uint64_t last_term, uint64_t last_seq)
{

	if (last_term != craft_last_term(c))
		return (last_term > craft_last_term(c));
	return (last_seq >= craft_last_seq(c));
}

static void
on_append(struct craft *c, const struct craft_msg *m)
{
	struct craft_msg	*r;
	const struct craft_entry *e;
	uint64_t		 match;
	size_t			 i;

	if ((r = out_new(c, CRAFT_APPEND_REPLY, m->from)) == NULL)
		return;
	if (m->term < c->term) {
		r->ok = false;
		return;
	}
	c->role = CRAFT_FOLLOWER;
	strlcpy(c->leader, m->from, sizeof(c->leader));
	election_reset(c);
	/* The write before: held here, and of the same term? */
	if (m->prev_seq > craft_last_seq(c)) {
		r->ok = false;
		r->last_seq = craft_last_seq(c);
		return;
	}
	if (m->prev_seq >= c->base_seq && term_at(c, m->prev_seq) !=
	    m->prev_term) {
		r->ok = false;
		r->last_seq = m->prev_seq > 0 ? m->prev_seq - 1 : 0;
		if (r->last_seq < c->base_seq)
			r->last_seq = c->base_seq;
		return;
	}
	for (i = 0; i < m->nentries; i++) {
		e = &m->entries[i];
		if (e->seq <= c->base_seq)
			continue;	/* in the snapshot: committed, agreed */
		if (e->seq <= craft_last_seq(c)) {
			if (term_at(c, e->seq) == e->term)
				continue;
			log_cut(c, e->seq);
		}
		if (log_push(c, e->term, e->name, e->body, e->len, e->gone) !=
		    0) {
			r->ok = false;
			r->last_seq = craft_last_seq(c);
			return;
		}
	}
	match = m->prev_seq + m->nentries;
	if (match < c->base_seq)
		match = c->base_seq;
	/* Committed: what the leader says is, as far as this node agrees,
	 * never less than it knew. */
	if (m->commit > c->commit && match > c->commit)
		c->commit = m->commit < match ? m->commit : match;
	r->ok = true;
	r->last_seq = match;
	r->last_term = term_at(c, match);
}

void
craft_recv(struct craft *c, const struct craft_msg *m)
{
	struct craft_msg	*r;
	struct craft_peer	*p;
	int			 i, votes;

	if (m->term > c->term)
		become_follower(c, m->term, m->type == CRAFT_APPEND ? m->from :
		    NULL);
	switch (m->type) {
	case CRAFT_VOTE:
		if ((r = out_new(c, CRAFT_VOTE_REPLY, m->from)) == NULL)
			return;
		r->granted = m->term == c->term && (c->voted_for[0] == '\0' ||
		    strcmp(c->voted_for, m->from) == 0) && up_to_date(c,
		    m->last_term, m->last_seq);
		if (r->granted) {
			strlcpy(c->voted_for, m->from, sizeof(c->voted_for));
			c->state_dirty = true;
			election_reset(c);
		}
		break;
	case CRAFT_VOTE_REPLY:
		if (c->role != CRAFT_CANDIDATE || m->term != c->term ||
		    !m->granted || (p = peer_of(c, m->from)) == NULL)
			return;
		p->voted = true;
		votes = 1;
		for (i = 0; i < c->npeers; i++)
			if (c->peers[i].voted)
				votes++;
		if (votes >= craft_quorum(c))
			become_leader(c);
		break;
	case CRAFT_APPEND:
		on_append(c, m);
		break;
	case CRAFT_APPEND_REPLY:
		if (c->role != CRAFT_LEADER || m->term != c->term ||
		    (p = peer_of(c, m->from)) == NULL)
			return;
		p->inflight = false;
		p->heard_ms = c->now_ms;
		if (m->ok) {
			uint64_t	was = c->commit;

			if (m->last_seq > p->match)
				p->match = m->last_seq;
			p->next = p->match + 1;
			advance_commit(c);
			if (p->next <= craft_last_seq(c))
				send_append(c, p);
			/* Committed now: the others told at once, not at the
			 * next beat, so that they apply it too. */
			if (c->commit > was)
				for (i = 0; i < c->npeers; i++)
					if (&c->peers[i] != p &&
					    !c->peers[i].inflight)
						send_append(c, &c->peers[i]);
		} else {
			/* Back to where it may agree, and again. */
			if (m->last_seq + 1 < p->next)
				p->next = m->last_seq + 1;
			else if (p->next > 1)
				p->next--;
			send_append(c, p);
		}
		break;
	case CRAFT_SNAPSHOT_NEEDED:
		break;
	}
}

/* A write, as the leader proposes it: its term and sequence, to wait
 * for until it is committed (and still of that term at that place). */
int
craft_propose(struct craft *c, const char *name, const uint8_t *body,
    size_t len, bool gone, uint64_t *termp, uint64_t *seqp)
{
	int	i;

	if (c->role != CRAFT_LEADER || name == NULL || name[0] == '\0')
		return (-1);
	if (log_push(c, c->term, name, body, len, gone) != 0)
		return (-1);
	*termp = c->term;
	*seqp = craft_last_seq(c);
	if (c->npeers == 0)
		c->commit = *seqp;
	for (i = 0; i < c->npeers; i++)
		if (!c->peers[i].inflight)
			send_append(c, &c->peers[i]);
	return (0);
}

/* The caller sent a peer the documents as they were at seq. */
void
craft_snapshot_done(struct craft *c, const char *peer, uint64_t seq)
{
	struct craft_peer	*p;

	if (c->role != CRAFT_LEADER || (p = peer_of(c, peer)) == NULL)
		return;
	p->inflight = false;
	if (seq > p->match)
		p->match = seq;
	p->next = p->match + 1;
	advance_commit(c);
	if (p->next <= craft_last_seq(c))
		send_append(c, p);
}

/* The leader's documents, as of last_seq, are this node's now. */
void
craft_install_snapshot(struct craft *c, uint64_t term, uint64_t last_term,
    uint64_t last_seq, const char *leader)
{

	if (term < c->term)
		return;
	become_follower(c, term, leader);
	while (c->nlog > 0)
		entry_free(&c->log[--c->nlog]);
	c->base_term = last_term;
	c->base_seq = last_seq;
	c->commit = c->applied = last_seq;
	c->log_truncated = true;
	c->log_dirty_from = 0;
}

/* The next committed write to apply, or NULL: good until the next call
 * that changes the log. */
const struct craft_entry *
craft_next_apply(struct craft *c)
{
	const struct craft_entry *e;

	while (c->applied < c->commit) {
		c->applied++;
		if ((e = craft_entry_at(c, c->applied)) != NULL)
			return (e);
	}
	return (NULL);
}

/* The log kept to keep writes after the applied ones, keep of those
 * before; the rest is in the documents. */
void
craft_compact(struct craft *c, size_t keep)
{
	uint64_t	upto, n;
	size_t		i;

	if (c->applied <= c->base_seq + keep)
		return;
	upto = c->applied - keep;
	n = upto - c->base_seq;
	c->base_term = term_at(c, upto);
	for (i = 0; i < n; i++)
		entry_free(&c->log[i]);
	memmove(c->log, c->log + n, (c->nlog - n) * sizeof(*c->log));
	c->nlog -= n;
	c->base_seq = upto;
	c->log_truncated = true;
}
