/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The consoles of a cluster, web.conf's cluster block:
 *
 *	cluster {
 *		self = "a";
 *		listen = "tcp://[::]:4311";
 *		nodes {
 *			a { uri = "tcp://a.console.example:4311";
 *			    origin = "https://a.console.example"; }
 *			b { ... }
 *			c { ... }
 *		}
 *	}
 *
 * Each node serves the arcana-cluster family (share/arcana/cluster.yaml)
 * on its listener, by TLS with a certificate of the console's CA that
 * says urn:arcana:role:console and the node's host, and asks the others
 * by the same.  craft.c decides, as Raft has it: who leads, which
 * writes are committed.  This is its I/O: the term, the vote and the
 * log kept in <datadir>/cluster before anything is said; messages sent
 * by a thread for each other node; committed writes applied to the data
 * directory, each a whole document, on every node alike.
 *
 * store_save() of a node is cluster_save(): the leader numbers the
 * document and answers once a majority holds it and it is written here;
 * a follower sends it to the leader and waits for the same.  Reads are
 * each node's own files.  The first node named, the seed, starts from
 * the documents it has; the others are sent them.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "console.h"
#include "craft.h"
#include "cluster.h"

#define	CL_DIR		"cluster"
#define	CL_TICK_MS	50
#define	CL_WAIT_MS	5000	/* a write waits for its commit at most */
#define	CL_DEFER_MS	10000	/* a follower's write, at the leader */
#define	CL_FRAME	(32 * 1024 * 1024)
#define	CL_BATCH_BYTES	(8 * 1024 * 1024)
#define	CL_SNAP_PART	(4 * 1024 * 1024)
#define	CL_LOG_MAX	1024	/* writes kept before the log is cut */
#define	CL_LOG_KEEP	256	/* and those kept after */
#define	CL_QUEUE	16
#define	CL_PENDING	64
#define	CL_RING		1024
#define	CL_LOCKS	64
#define	CL_LOCK_TTL_MS	30000	/* a lock held this long, unless renewed */
#define	ROLE_CONSOLE	"URI:urn:arcana:role:console"

struct node {
	char		 name[CRAFT_NAME_MAX];
	char		 uri[256];
	char		 host[256];
	char		 origin[256];
};

struct peer {
	int			 idx;
	pthread_t		 thread;
	pthread_cond_t		 cv;
	struct craft_msg	 q[CL_QUEUE];
	int			 nq;
	cbl_conn		*conn;
	cbl_tls			*tls;
	struct acl_client	 cl;
	bool			 up;
	char			 why[256];	/* the last failure said */
};

struct pending {
	cbl_req		*req;
	uint64_t	 term;
	uint64_t	 seq;
	uint64_t	 since;
	char		 name[256];
};

static struct {
	bool			 on;
	bool			 started;	/* the worker's start is over */
	pthread_mutex_t		 mu;
	pthread_cond_t		 cv;	/* applied, or the leader known */
	struct craft		 c;
	struct node		 nodes[CRAFT_NODES_MAX];
	int			 nn;
	int			 self;
	char			 listen[256];
	struct peer		 peers[CRAFT_NODES_MAX];
	cbl_ctx			*ctx;
	cbl_loop		*loop;
	cbl_listener		*ls;
	char			 dir[MAXPATHLEN];
	char			 cert[MAXPATHLEN];
	char			 key[MAXPATHLEN];
	struct pending		 pend[CL_PENDING];
	struct {
		uint64_t	 seq;
		uint64_t	 term;
	}			 ring[CL_RING];
	uint64_t		 gen;
	/* What was written since the worker last read it again. */
	char			 changed[32][256];
	int			 nchanged;
	bool			 changed_all;
	/* A snapshot being received. */
	bool			 staging;
	/* A follower's own writes, to the leader. */
	pthread_mutex_t		 wmu;
	cbl_conn		*wconn;
	cbl_tls			*wtls;
	struct acl_client	 wcl;
	int			 wnode;
	/* The leader's locks. */
	struct {
		char		 name[256];
		char		 holder[128];
		uint64_t	 until;
	}			 locks[CL_LOCKS];
} cl = {
	.mu = PTHREAD_MUTEX_INITIALIZER,
	.cv = PTHREAD_COND_INITIALIZER,
	.wmu = PTHREAD_MUTEX_INITIALIZER,
	.wnode = -1,
};

static uint64_t
now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

bool
cluster_on(void)
{

	return (cl.on);
}

/* Does this node run what runs once in the cluster (the schedulers)? */
bool
cluster_leads(void)
{
	bool	leads;

	if (!cl.on)
		return (true);
	pthread_mutex_lock(&cl.mu);
	/* The leader on its lease: cut off, it leads nothing, and the
	 * one elected instead runs them. */
	leads = craft_quorum_heard(&cl.c, CRAFT_LEASE_MS);
	pthread_mutex_unlock(&cl.mu);
	return (leads);
}

/* How many committed writes this node applied: a cache compares it. */
uint64_t
cluster_gen(void)
{
	uint64_t	g;

	pthread_mutex_lock(&cl.mu);
	g = cl.gen;
	pthread_mutex_unlock(&cl.mu);
	return (g);
}

static int
node_of(const char *name)
{
	int	i;

	for (i = 0; i < cl.nn; i++)
		if (name != NULL && strcmp(cl.nodes[i].name, name) == 0)
			return (i);
	return (-1);
}

/* ---- web.conf ----------------------------------------------------- */

/* The host of a cblink URI: tcp://host:port, tcp://[v6]:port. */
static bool
uri_host(const char *uri, char *host, size_t len)
{
	const char	*p, *e;

	if ((p = strstr(uri, "://")) == NULL)
		return (false);
	p += 3;
	if (*p == '[') {
		if ((e = strchr(++p, ']')) == NULL)
			return (false);
	} else if ((e = strrchr(p, ':')) == NULL)
		e = p + strcspn(p, "/");
	if (e == p || (size_t)(e - p) >= len)
		return (false);
	snprintf(host, len, "%.*s", (int)(e - p), p);
	return (true);
}

int
cluster_config(const ucl_object_t *top, const char *path)
{
	const ucl_object_t	*c, *ns, *n, *o;
	ucl_object_iter_t	 it;
	struct node		*nd;
	const char		*self;

	if ((c = ucl_object_lookup(top, "cluster")) == NULL)
		return (0);
	if ((o = ucl_object_lookup(c, "self")) == NULL ||
	    (self = ucl_object_tostring(o)) == NULL ||
	    (o = ucl_object_lookup(c, "listen")) == NULL ||
	    ucl_object_tostring(o) == NULL ||
	    (ns = ucl_object_lookup(c, "nodes")) == NULL) {
		log_msg(LOG_ERR, "%s: cluster needs self, listen and nodes",
		    path);
		return (-1);
	}
	strlcpy(cl.listen, ucl_object_tostring(o), sizeof(cl.listen));
	it = NULL;
	while ((n = ucl_object_iterate(ns, &it, true)) != NULL) {
		if (cl.nn == CRAFT_NODES_MAX) {
			log_msg(LOG_ERR, "%s: %d nodes at most", path,
			    CRAFT_NODES_MAX);
			return (-1);
		}
		nd = &cl.nodes[cl.nn];
		if (strlcpy(nd->name, ucl_object_key(n), sizeof(nd->name)) >=
		    sizeof(nd->name) || (o = ucl_object_lookup(n, "uri")) ==
		    NULL || strlcpy(nd->uri, ucl_object_tostring(o),
		    sizeof(nd->uri)) >= sizeof(nd->uri) || (strncmp(nd->uri,
		    "unix:", 5) != 0 && !uri_host(nd->uri, nd->host,
		    sizeof(nd->host)))) {
			log_msg(LOG_ERR, "%s: cluster node %s: a uri, "
			    "tcp://host:port", path, ucl_object_key(n));
			return (-1);
		}
		if ((o = ucl_object_lookup(n, "origin")) != NULL)
			strlcpy(nd->origin, ucl_object_tostring(o),
			    sizeof(nd->origin));
		cl.nn++;
	}
	if ((cl.self = node_of(self)) == -1) {
		log_msg(LOG_ERR, "%s: cluster self %s is not one of its nodes",
		    path, self);
		return (-1);
	}
	cl.on = true;
	return (0);
}

/* ---- What is kept --------------------------------------------------- */

static int
write_file(const char *path, const void *p, size_t len, mode_t mode)
{
	char	tmp[MAXPATHLEN];
	int	fd;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
	if ((fd = mkstemp(tmp)) == -1)
		return (-1);
	if ((len > 0 && write(fd, p, len) != (ssize_t)len) || fchmod(fd,
	    mode) == -1 || fsync(fd) == -1 || close(fd) == -1 ||
	    rename(tmp, path) == -1) {
		log_msg(LOG_ERR, "writing %s: %s", path, strerror(errno));
		unlink(tmp);
		return (-1);
	}
	return (0);
}

/* The term, the vote and the log's base. */
static void
state_save(void)
{
	char	buf[256], path[MAXPATHLEN];
	int	n;

	n = snprintf(buf, sizeof(buf), "%ju %s %ju %ju\n",
	    (uintmax_t)cl.c.term, cl.c.voted_for[0] != '\0' ?
	    cl.c.voted_for : "-", (uintmax_t)cl.c.base_term,
	    (uintmax_t)cl.c.base_seq);
	snprintf(path, sizeof(path), "%s/state", cl.dir);
	if (write_file(path, buf, (size_t)n, 0600) == -1)
		fatalx("cluster: cannot keep its state");
}

struct rec {
	uint64_t	term;
	uint64_t	seq;
	uint32_t	nlen;
	uint32_t	blen;
	uint32_t	gone;
	uint32_t	pad;
};

static int
rec_write(int fd, const struct craft_entry *e)
{
	struct rec	r;

	memset(&r, 0, sizeof(r));
	r.term = e->term;
	r.seq = e->seq;
	r.nlen = (uint32_t)strlen(e->name);
	r.blen = (uint32_t)e->len;
	r.gone = e->gone;
	if (write(fd, &r, sizeof(r)) != (ssize_t)sizeof(r) ||
	    write(fd, e->name, r.nlen) != (ssize_t)r.nlen ||
	    (r.blen > 0 && write(fd, e->body, r.blen) != (ssize_t)r.blen))
		return (-1);
	return (0);
}

/* What craft says to keep, before anything is sent: the log whole when
 * it was cut, else what was added to it. */
static void
persist(void)
{
	char		 path[MAXPATHLEN], tmp[MAXPATHLEN];
	size_t		 i;
	int		 fd;

	snprintf(path, sizeof(path), "%s/log", cl.dir);
	if (cl.c.log_truncated) {
		snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
		if ((fd = mkstemp(tmp)) == -1)
			fatalx("cluster: mkstemp %s: %s", tmp, strerror(errno));
		for (i = 0; i < cl.c.nlog; i++)
			if (rec_write(fd, &cl.c.log[i]) == -1)
				fatalx("cluster: writing its log: %s",
				    strerror(errno));
		if (fsync(fd) == -1 || close(fd) == -1 || rename(tmp, path) ==
		    -1)
			fatalx("cluster: its log: %s", strerror(errno));
		cl.c.state_dirty = true;	/* the base with it */
	} else if (cl.c.log_dirty_from != 0) {
		if ((fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
		    0600)) == -1)
			fatalx("cluster: %s: %s", path, strerror(errno));
		for (i = cl.c.log_dirty_from - cl.c.base_seq - 1; i <
		    cl.c.nlog; i++)
			if (rec_write(fd, &cl.c.log[i]) == -1)
				fatalx("cluster: writing its log: %s",
				    strerror(errno));
		if (fsync(fd) == -1 || close(fd) == -1)
			fatalx("cluster: its log: %s", strerror(errno));
	}
	if (cl.c.state_dirty)
		state_save();
	cl.c.state_dirty = false;
	cl.c.log_truncated = false;
	cl.c.log_dirty_from = 0;
}

static void
restore(void)
{
	char		 path[MAXPATHLEN], vote[CRAFT_NAME_MAX];
	struct rec	 r;
	uintmax_t	 term, bt, bs;
	FILE		*fp;
	char		*name;
	uint8_t		*body;

	snprintf(path, sizeof(path), "%s/state", cl.dir);
	if ((fp = fopen(path, "r")) == NULL) {
		/* None yet: the seed starts from the documents it has,
		 * the base the others are sent; they wait for it. */
		if (cl.self == 0) {
			craft_restore(&cl.c, 1, "", 1, 1);
			state_save();
		}
		return;
	}
	if (fscanf(fp, "%ju %63s %ju %ju", &term, vote, &bt, &bs) != 4)
		fatalx("cluster: %s does not read", path);
	fclose(fp);
	craft_restore(&cl.c, term, strcmp(vote, "-") == 0 ? "" : vote, bt,
	    bs);
	snprintf(path, sizeof(path), "%s/log", cl.dir);
	if ((fp = fopen(path, "r")) == NULL)
		return;
	while (fread(&r, sizeof(r), 1, fp) == 1) {
		name = calloc(1, (size_t)r.nlen + 1);
		body = r.blen > 0 ? malloc(r.blen) : NULL;
		if (name == NULL || (r.blen > 0 && body == NULL) ||
		    fread(name, 1, r.nlen, fp) != r.nlen || (r.blen > 0 &&
		    fread(body, 1, r.blen, fp) != r.blen)) {
			free(name);
			free(body);
			break;		/* cut short: what came before stands */
		}
		if (r.seq > cl.c.base_seq)
			(void)craft_restore_entry(&cl.c, r.term, r.seq, name,
			    body, r.blen, r.gone != 0);
		free(name);
		free(body);
	}
	fclose(fp);
}

/* ---- The documents ---------------------------------------------------- */

/* A document's name: in the data directory, not in cluster/. */
static bool
doc_name_ok(const char *n)
{
	size_t	i;

	if (n == NULL || n[0] == '\0' || n[0] == '/' || n[0] == '.' ||
	    strlen(n) > 255 || strstr(n, "..") != NULL || strstr(n, "//") !=
	    NULL || strncmp(n, CL_DIR "/", sizeof(CL_DIR)) == 0)
		return (false);
	for (i = 0; n[i] != '\0'; i++)
		if (!(n[i] >= 'a' && n[i] <= 'z') && !(n[i] >= 'A' && n[i] <=
		    'Z') && !(n[i] >= '0' && n[i] <= '9') && n[i] != '.' &&
		    n[i] != '-' && n[i] != '_' && n[i] != '/')
			return (false);
	return (true);
}

/* One the cluster keeps: a JSON document, at the top, in runs/ or in
 * sessions/. */
static bool
replicated(const char *n)
{
	size_t	len;

	len = strlen(n);
	return (doc_name_ok(n) && len > 5 && strcmp(n + len - 5, ".json") ==
	    0 && (strchr(n, '/') == NULL || (strncmp(n, "runs/", 5) == 0 &&
	    strchr(n + 5, '/') == NULL) || (strncmp(n, SESSIONS_DIR "/",
	    sizeof(SESSIONS_DIR)) == 0 && strchr(n + sizeof(SESSIONS_DIR),
	    '/') == NULL)));
}

/* A document the worker reads again: what it keeps of it is stale. */
static void
changed(const char *name)
{
	int	i;

	if (name == NULL) {
		cl.changed_all = true;
		return;
	}
	for (i = 0; i < cl.nchanged; i++)
		if (strcmp(cl.changed[i], name) == 0)
			return;
	if (cl.nchanged == (int)nitems(cl.changed))
		cl.changed_all = true;
	else
		strlcpy(cl.changed[cl.nchanged++], name,
		    sizeof(cl.changed[0]));
}

/* Each document written since the last call, or NULL for every one. */
void
cluster_changes(void (*fn)(const char *))
{
	char	names[32][256];
	int	i, n;
	bool	all;

	pthread_mutex_lock(&cl.mu);
	all = cl.changed_all;
	n = cl.nchanged;
	memcpy(names, cl.changed, sizeof(names));
	cl.nchanged = 0;
	cl.changed_all = false;
	pthread_mutex_unlock(&cl.mu);
	if (all) {
		fn(NULL);
		return;
	}
	for (i = 0; i < n; i++)
		fn(names[i]);
}

/*
 * A lock as a write of the log: its name with LOCK_PREFIX, its body
 * the holder and when it runs out; gone when let go.  Every node
 * applies it to its table, so that a new leader knows the locks the
 * one before granted, and grants none twice.
 */
#define	LOCK_PREFIX	"\001lock\001"

static void
lock_apply(const char *name, const uint8_t *body, size_t len, bool gone)
{
	char		holder[128], *nl;
	uint64_t	until;
	int		i, free_i;

	snprintf(holder, sizeof(holder), "%.*s", (int)(len > sizeof(holder) -
	    1 ? sizeof(holder) - 1 : len), (const char *)body);
	if ((nl = strchr(holder, '\n')) == NULL)
		return;
	*nl = '\0';
	until = strtoull(nl + 1, NULL, 10);
	/* Let go by its holder: another's, granted since, stays. */
	if (gone) {
		for (i = 0; i < CL_LOCKS; i++)
			if (strcmp(cl.locks[i].name, name) == 0 &&
			    strcmp(cl.locks[i].holder, holder) == 0)
				cl.locks[i].name[0] = '\0';
		return;
	}
	free_i = -1;
	for (i = 0; i < CL_LOCKS; i++) {
		if (strcmp(cl.locks[i].name, name) == 0) {
			strlcpy(cl.locks[i].holder, holder,
			    sizeof(cl.locks[i].holder));
			cl.locks[i].until = until;
			return;
		}
		if (free_i == -1 && (cl.locks[i].name[0] == '\0' ||
		    cl.locks[i].until <= now_ms()))
			free_i = i;
	}
	if (free_i == -1)
		return;
	strlcpy(cl.locks[free_i].name, name, sizeof(cl.locks[free_i].name));
	strlcpy(cl.locks[free_i].holder, holder, sizeof(cl.locks[free_i].holder));
	cl.locks[free_i].until = until;
}

static void
apply_one(const struct craft_entry *e)
{
	char	path[MAXPATHLEN];

	cl.ring[e->seq % CL_RING].seq = e->seq;
	cl.ring[e->seq % CL_RING].term = e->term;
	if (strncmp(e->name, LOCK_PREFIX, strlen(LOCK_PREFIX)) == 0) {
		/* The leader's own writes were in its table as it granted
		 * them: applied again late, an old grant would take a newer
		 * holder's place.  The followers', and a new leader's, from
		 * the log. */
		if (cl.c.role != CRAFT_LEADER || e->term != cl.c.term)
			lock_apply(e->name + strlen(LOCK_PREFIX), e->body,
			    e->len, e->gone);
		return;
	}
	if (e->name[0] == '\0' || !doc_name_ok(e->name))
		return;
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, e->name);
	if (e->gone) {
		if (unlink(path) == -1 && errno != ENOENT)
			log_msg(LOG_ERR, "cluster: %s: %s", path,
			    strerror(errno));
	} else if (store_write(e->name, e->body, e->len) == -1)
		log_msg(LOG_ERR, "cluster: %s could not be written", path);
	cl.gen++;
	changed(e->name);
}

/* The applied write at seq of term? */
static bool
applied_as(uint64_t seq, uint64_t term)
{

	return (cl.ring[seq % CL_RING].seq == seq &&
	    cl.ring[seq % CL_RING].term == term);
}

static void
pending_end(struct pending *p, bool ok, const char *why)
{
	struct acl_write_rsp	 rsp;
	struct acl_doc		 d;

	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = ok;
	rsp.error = why;
	if (ok) {
		memset(&d, 0, sizeof(d));
		d.name = p->name;
		d.has_term = d.has_seq = true;
		d.term = p->term;
		d.seq = p->seq;
		rsp.has_term = true;
		rsp.term = p->term;
		rsp.doc.n = 1;
		rsp.doc.v = &d;
	}
	(void)acl_write_reply(p->req, &rsp);
	(void)cbl_req_complete(p->req, 0);
	p->req = NULL;
}

static void
send_out(int to, const struct craft_msg *m);

/*
 * After craft has changed: kept first, then said, then applied.  A reply
 * of the type want to node from is the caller's, into reply.
 */
static void
pump(int want, const char *from, struct craft_msg *reply)
{
	const struct craft_entry *e;
	size_t			 i;
	int			 to, k;
	bool			 got;

	persist();
	got = false;
	for (i = 0; i < cl.c.nout; i++) {
		if (reply != NULL && !got && (int)cl.c.out[i].type == want &&
		    strcmp(cl.c.out[i].to, from) == 0) {
			*reply = cl.c.out[i];
			got = true;
			continue;
		}
		if ((to = node_of(cl.c.out[i].to)) >= 0 && to != cl.self)
			send_out(to, &cl.c.out[i]);
	}
	craft_out_clear(&cl.c);
	while ((e = craft_next_apply(&cl.c)) != NULL)
		apply_one(e);
	/* The leader's answers to the followers' writes. */
	for (k = 0; k < CL_PENDING; k++) {
		if (cl.pend[k].req == NULL || cl.pend[k].seq > cl.c.applied)
			continue;
		if (applied_as(cl.pend[k].seq, cl.pend[k].term))
			pending_end(&cl.pend[k], true, NULL);
		else
			pending_end(&cl.pend[k], false, "a new leader took "
			    "its place before it was written: write it again");
	}
	if (cl.c.nlog > CL_LOG_MAX) {
		craft_compact(&cl.c, CL_LOG_KEEP);
		persist();
	}
	pthread_cond_broadcast(&cl.cv);
}

/* ---- To the others ---------------------------------------------------- */

static void
msg_free(struct craft_msg *m)
{
	size_t	i;

	for (i = 0; i < m->nentries; i++) {
		free(m->entries[i].name);
		free(m->entries[i].body);
	}
	free(m->entries);
	m->entries = NULL;
	m->nentries = 0;
}

/* Queued to the node's thread, its entries copied (they are the log's,
 * and the log changes): CL_BATCH_BYTES of them at most. */
static void
send_out(int to, const struct craft_msg *m)
{
	struct peer		*p = &cl.peers[to];
	struct craft_msg	 c;
	size_t			 i, bytes;
	int			 k;

	c = *m;
	c.entries = NULL;
	c.nentries = 0;
	if (m->nentries > 0) {
		if ((c.entries = calloc(m->nentries, sizeof(*c.entries))) ==
		    NULL)
			return;
		for (i = 0, bytes = 0; i < m->nentries && (i == 0 || bytes +
		    m->entries[i].len <= CL_BATCH_BYTES); i++) {
			c.entries[i] = m->entries[i];
			c.entries[i].name = strdup(m->entries[i].name);
			c.entries[i].body = NULL;
			if (m->entries[i].len > 0 && (c.entries[i].body =
			    malloc(m->entries[i].len)) != NULL)
				memcpy(c.entries[i].body, m->entries[i].body,
				    m->entries[i].len);
			c.nentries = i + 1;
			bytes += m->entries[i].len;
		}
	}
	/* An append makes the one before it moot. */
	if (c.type == CRAFT_APPEND)
		for (k = 0; k < p->nq; k++)
			if (p->q[k].type == CRAFT_APPEND) {
				msg_free(&p->q[k]);
				p->q[k] = c;
				pthread_cond_signal(&p->cv);
				return;
			}
	if (p->nq == CL_QUEUE) {
		msg_free(&p->q[0]);
		memmove(&p->q[0], &p->q[1], (CL_QUEUE - 1) * sizeof(p->q[0]));
		p->nq--;
	}
	p->q[p->nq++] = c;
	pthread_cond_signal(&p->cv);
}

/* A failure to reach a node, logged when it is not the last one said. */
static void
peer_fail(struct peer *p, const char *what, int error)
{
	char	why[256];

	snprintf(why, sizeof(why), "%s: %s", what, error != 0 ?
	    strerror(error) : "refused");
	if (strcmp(why, p->why) != 0)
		log_msg(LOG_NOTICE, "cluster: %s: %s", cl.nodes[p->idx].name,
		    why);
	strlcpy(p->why, why, sizeof(p->why));
}

static void
peer_close(struct peer *p)
{

	if (p->conn == NULL)
		return;
	acl_client_fini(&p->cl);
	cbl_conn_free(p->conn);
	cbl_tls_free(p->tls);
	p->conn = NULL;
	p->tls = NULL;
}

/* A connection to node i, as a console of its cluster. */
static int
dial(int i, cbl_conn **connp, cbl_tls **tlsp, struct acl_client *c)
{
	const struct node	*n = &cl.nodes[i];
	cbl_conn		*conn;
	cbl_tls			*tls;

	*connp = NULL;
	*tlsp = NULL;
	tls = NULL;
	if (cbl_conn_new(cl.ctx, n->uri, 0, &conn) != 0)
		return (-1);
	if (strncmp(n->uri, "unix:", 5) != 0) {
		if (cbl_tls_new(&tls) != 0 || cbl_tls_set_cert(tls, cl.cert,
		    cl.key) != 0 || cbl_tls_set_ca(tls, cfg.tls_ca, NULL) !=
		    0 || cbl_tls_set_peer_name(tls, n->host) != 0) {
			cbl_conn_free(conn);
			cbl_tls_free(tls);
			return (-1);
		}
		(void)cbl_conn_set_tls(conn, tls);
	}
	if (cbl_conn_connect(conn) != 0 || acl_client_init(c, conn) != 0) {
		cbl_conn_free(conn);
		cbl_tls_free(tls);
		return (-1);
	}
	*connp = conn;
	*tlsp = tls;
	return (0);
}

static void
docs_of(const struct craft_msg *m, struct acl_doc *d)
{
	size_t	i;

	for (i = 0; i < m->nentries; i++) {
		memset(&d[i], 0, sizeof(d[i]));
		d[i].name = m->entries[i].name;
		d[i].has_term = d[i].has_seq = true;
		d[i].term = m->entries[i].term;
		d[i].seq = m->entries[i].seq;
		d[i].body.p = m->entries[i].body;
		d[i].body.len = m->entries[i].len;
		d[i].gone = m->entries[i].gone;
	}
}

/* The documents, as they are applied, read under the lock. */
struct snapdoc {
	char	 name[256];
	char	*body;
	size_t	 len;
};

static void
snap_read_dir(const char *sub, struct snapdoc **v, size_t *n, size_t *cap)
{
	DIR		*d;
	struct dirent	*e;
	char		 path[MAXPATHLEN], name[256];
	struct snapdoc	*nv;
	FILE		*fp;
	long		 len;

	snprintf(path, sizeof(path), "%s%s%s", cfg.datadir, sub[0] != '\0' ?
	    "/" : "", sub);
	if ((d = opendir(path)) == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		snprintf(name, sizeof(name), "%s%s%s", sub, sub[0] != '\0' ?
		    "/" : "", e->d_name);
		if (e->d_type != DT_REG || !replicated(name))
			continue;
		if (*n == *cap) {
			*cap = *cap == 0 ? 64 : *cap * 2;
			if ((nv = realloc(*v, *cap * sizeof(**v))) == NULL)
				break;
			*v = nv;
		}
		snprintf(path, sizeof(path), "%s/%s", cfg.datadir, name);
		if ((fp = fopen(path, "r")) == NULL)
			continue;
		if (fseek(fp, 0, SEEK_END) != 0 || (len = ftell(fp)) < 0 ||
		    len > ACL_MAX_DOC || fseek(fp, 0, SEEK_SET) != 0) {
			fclose(fp);
			continue;
		}
		strlcpy((*v)[*n].name, name, sizeof((*v)[*n].name));
		(*v)[*n].len = (size_t)len;
		if (((*v)[*n].body = malloc((size_t)len + 1)) == NULL ||
		    fread((*v)[*n].body, 1, (size_t)len, fp) != (size_t)len) {
			free((*v)[*n].body);
			fclose(fp);
			continue;
		}
		fclose(fp);
		(*n)++;
	}
	closedir(d);
}

static uint64_t
applied_term(void)
{
	const struct craft_entry *e;

	if (cl.c.applied == cl.c.base_seq)
		return (cl.c.base_term);
	return ((e = craft_entry_at(&cl.c, cl.c.applied)) != NULL ? e->term :
	    0);
}

/* Every document to node p, as they are applied now, in parts. */
static int
send_snapshot(struct peer *p, uint64_t *seqp)
{
	struct acl_snapshot_req	 rq;
	struct acl_snapshot_rsp	*rsp;
	struct snapdoc		*v = NULL;
	struct acl_doc		*d;
	size_t			 n = 0, cap = 0, i, j, bytes;
	uint64_t		 term, last_term, last_seq;
	int			 rc = 0, err;

	pthread_mutex_lock(&cl.mu);
	snap_read_dir("", &v, &n, &cap);
	snap_read_dir("runs", &v, &n, &cap);
	snap_read_dir(SESSIONS_DIR, &v, &n, &cap);
	term = cl.c.term;
	last_seq = cl.c.applied;
	last_term = applied_term();
	pthread_mutex_unlock(&cl.mu);
	if ((d = calloc(n + 1, sizeof(*d))) == NULL) {
		rc = -1;
		goto out;
	}
	i = 0;
	do {
		memset(&rq, 0, sizeof(rq));
		rq.node = cl.nodes[cl.self].name;
		rq.has_term = rq.has_last_term = rq.has_last_seq = true;
		rq.term = term;
		rq.last_term = last_term;
		rq.last_seq = last_seq;
		rq.first = i == 0;
		for (j = 0, bytes = 0; i + j < n && (j == 0 || bytes +
		    v[i + j].len <= CL_SNAP_PART); j++) {
			memset(&d[j], 0, sizeof(d[j]));
			d[j].name = v[i + j].name;
			d[j].body.p = v[i + j].body;
			d[j].body.len = v[i + j].len;
			bytes += v[i + j].len;
		}
		rq.doc.n = j;
		rq.doc.v = d;
		i += j;
		rq.last = i >= n;
		rsp = NULL;
		if ((err = acl_snapshot(&p->cl, &rq, &rsp)) != 0)
			peer_fail(p, "documents", err);
		if (err != 0 || rsp == NULL || !rsp->ok) {
			if (rsp != NULL && rsp->error != NULL)
				log_msg(LOG_NOTICE, "cluster: %s refused the "
				    "documents: %s", cl.nodes[p->idx].name,
				    rsp->error);
			acl_snapshot_rsp_free(rsp);
			rc = -1;
			break;
		}
		acl_snapshot_rsp_free(rsp);
	} while (i < n);
	*seqp = last_seq;
out:
	for (i = 0; i < n; i++)
		free(v[i].body);
	free(v);
	free(d);
	return (rc);
}

static void *
peer_run(void *arg)
{
	struct peer		*p = arg;
	struct craft_msg	 m, r;
	struct acl_doc		*d;
	uint64_t		 seq;
	int			 rc, err;

	for (;;) {
		pthread_mutex_lock(&cl.mu);
		while (p->nq == 0)
			pthread_cond_wait(&p->cv, &cl.mu);
		m = p->q[0];
		memmove(&p->q[0], &p->q[1], (size_t)(p->nq - 1) *
		    sizeof(p->q[0]));
		p->nq--;
		pthread_mutex_unlock(&cl.mu);
		if (p->conn == NULL && dial(p->idx, &p->conn, &p->tls,
		    &p->cl) != 0) {
			peer_fail(p, "cannot connect", 0);
			msg_free(&m);
			usleep(300000);
			continue;
		}
		memset(&r, 0, sizeof(r));
		strlcpy(r.from, cl.nodes[p->idx].name, sizeof(r.from));
		strlcpy(r.to, cl.nodes[cl.self].name, sizeof(r.to));
		rc = -1;
		if (m.type == CRAFT_VOTE) {
			struct acl_vote_req	 rq;
			struct acl_vote_rsp	*rsp = NULL;

			memset(&rq, 0, sizeof(rq));
			rq.node = cl.nodes[cl.self].name;
			rq.has_term = rq.has_last_term = rq.has_last_seq = true;
			rq.term = m.term;
			rq.last_term = m.last_term;
			rq.last_seq = m.last_seq;
			if ((err = acl_vote(&p->cl, &rq, &rsp)) != 0)
				peer_fail(p, "vote", err);
			if (err == 0 && rsp != NULL) {
				r.type = CRAFT_VOTE_REPLY;
				r.term = rsp->term;
				r.granted = rsp->granted;
				rc = 0;
			}
			acl_vote_rsp_free(rsp);
		} else if (m.type == CRAFT_APPEND) {
			struct acl_append_req	 rq;
			struct acl_append_rsp	*rsp = NULL;

			if ((d = calloc(m.nentries + 1, sizeof(*d))) != NULL) {
				docs_of(&m, d);
				memset(&rq, 0, sizeof(rq));
				rq.node = cl.nodes[cl.self].name;
				rq.has_term = rq.has_prev_term =
				    rq.has_prev_seq = rq.has_commit_seq = true;
				rq.term = m.term;
				rq.prev_term = m.prev_term;
				rq.prev_seq = m.prev_seq;
				rq.commit_seq = m.commit;
				if (cl.nodes[cl.self].origin[0] != '\0')
					rq.origin = cl.nodes[cl.self].origin;
				rq.doc.n = m.nentries;
				rq.doc.v = d;
				if ((err = acl_append(&p->cl, &rq, &rsp)) != 0)
					peer_fail(p, "append", err);
				if (err == 0 && rsp != NULL) {
					r.type = CRAFT_APPEND_REPLY;
					r.term = rsp->term;
					r.ok = rsp->ok;
					r.last_term = rsp->last_term;
					r.last_seq = rsp->last_seq;
					rc = 0;
				}
				acl_append_rsp_free(rsp);
				free(d);
			}
		} else if (m.type == CRAFT_SNAPSHOT_NEEDED) {
			if (send_snapshot(p, &seq) == 0) {
				pthread_mutex_lock(&cl.mu);
				craft_snapshot_done(&cl.c, cl.nodes[p->idx].name,
				    seq);
				pump(-1, NULL, NULL);
				pthread_mutex_unlock(&cl.mu);
				msg_free(&m);
				continue;
			}
		}
		msg_free(&m);
		if (rc != 0) {
			peer_close(p);
			continue;
		}
		pthread_mutex_lock(&cl.mu);
		craft_recv(&cl.c, &r);
		pump(-1, NULL, NULL);
		pthread_mutex_unlock(&cl.mu);
	}
	return (NULL);
}

/* ---- From the others ---------------------------------------------------- */

/* Is the peer node n: a console of this CA, under the node's host? */
static bool
peer_ok(cbl_req *req, const char *node, int *ip)
{
	const cbl_peer	*p = cbl_req_peer(req);
	const char	*san;
	char		 dns[300], ip6[300];
	size_t		 i, ns;
	bool		 role, host;
	int		 n;

	if ((n = node_of(node)) == -1 || n == cl.self)
		return (false);
	*ip = n;
	if (cbl_peer_transport(p) == CBL_TR_UNIX)
		return (true);	/* the socket's mode guards it */
	snprintf(dns, sizeof(dns), "DNS:%s", cl.nodes[n].host);
	snprintf(ip6, sizeof(ip6), "IP:%s", cl.nodes[n].host);
	role = host = false;
	ns = cbl_peer_san_count(p);
	for (i = 0; i < ns; i++) {
		if ((san = cbl_peer_san(p, i)) == NULL)
			continue;
		if (strcmp(san, ROLE_CONSOLE) == 0)
			role = true;
		else if (strcasecmp(san, dns) == 0 || strcmp(san, ip6) == 0)
			host = true;
	}
	return (role && host);
}

int
acl_vote_doit(cbl_req *req, const struct acl_vote_req *rq, void *arg __unused)
{
	struct acl_vote_rsp	 rsp;
	struct craft_msg	 m, r;
	int			 n;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	memset(&m, 0, sizeof(m));
	m.type = CRAFT_VOTE;
	strlcpy(m.from, rq->node, sizeof(m.from));
	strlcpy(m.to, cl.nodes[cl.self].name, sizeof(m.to));
	m.term = rq->term;
	m.last_term = rq->last_term;
	m.last_seq = rq->last_seq;
	memset(&r, 0, sizeof(r));
	pthread_mutex_lock(&cl.mu);
	craft_recv(&cl.c, &m);
	pump(CRAFT_VOTE_REPLY, rq->node, &r);
	pthread_mutex_unlock(&cl.mu);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_term = rsp.has_granted = true;
	rsp.term = r.term;
	rsp.granted = r.granted;
	return (acl_vote_reply(req, &rsp));
}

int
acl_append_doit(cbl_req *req, const struct acl_append_req *rq,
    void *arg __unused)
{
	struct acl_append_rsp	 rsp;
	struct craft_msg	 m, r;
	struct craft_entry	*e;
	size_t			 i;
	int			 n, rc;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	if ((e = calloc(rq->doc.n + 1, sizeof(*e))) == NULL)
		return (ENOMEM);
	for (i = 0; i < rq->doc.n; i++) {
		if (!rq->doc.v[i].has_term || !rq->doc.v[i].has_seq) {
			free(e);
			return (EINVAL);
		}
		e[i].term = rq->doc.v[i].term;
		e[i].seq = rq->doc.v[i].seq;
		e[i].name = (char *)(uintptr_t)rq->doc.v[i].name;
		e[i].body = (uint8_t *)(uintptr_t)rq->doc.v[i].body.p;
		e[i].len = rq->doc.v[i].body.len;
		e[i].gone = rq->doc.v[i].gone;
	}
	memset(&m, 0, sizeof(m));
	m.type = CRAFT_APPEND;
	strlcpy(m.from, rq->node, sizeof(m.from));
	strlcpy(m.to, cl.nodes[cl.self].name, sizeof(m.to));
	m.term = rq->term;
	m.prev_term = rq->prev_term;
	m.prev_seq = rq->prev_seq;
	m.commit = rq->commit_seq;
	m.entries = e;
	m.nentries = rq->doc.n;
	memset(&r, 0, sizeof(r));
	pthread_mutex_lock(&cl.mu);
	craft_recv(&cl.c, &m);
	pump(CRAFT_APPEND_REPLY, rq->node, &r);
	pthread_mutex_unlock(&cl.mu);
	free(e);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_term = rsp.has_ok = rsp.has_last_term = rsp.has_last_seq =
	    true;
	rsp.term = r.term;
	rsp.ok = r.ok;
	rsp.last_term = r.last_term;
	rsp.last_seq = r.last_seq;
	rc = acl_append_reply(req, &rsp);
	return (rc);
}

static int
mkdirs_for(const char *path)
{
	char	buf[MAXPATHLEN], *p;

	strlcpy(buf, path, sizeof(buf));
	for (p = buf + 1; (p = strchr(p, '/')) != NULL; p++) {
		*p = '\0';
		if (mkdir(buf, 0700) == -1 && errno != EEXIST)
			return (-1);
		*p = '/';
	}
	return (0);
}

static int
snap_reply(cbl_req *req, bool ok, const char *why)
{
	struct acl_snapshot_rsp	rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.has_term = rsp.has_ok = true;
	pthread_mutex_lock(&cl.mu);
	rsp.term = cl.c.term;
	pthread_mutex_unlock(&cl.mu);
	rsp.ok = ok;
	rsp.error = why;
	return (acl_snapshot_reply(req, &rsp));
}

/* The documents the leader has, in parts; the last makes them these. */
int
acl_snapshot_doit(cbl_req *req, const struct acl_snapshot_req *rq,
    void *arg __unused)
{
	char		 stage[MAXPATHLEN], path[MAXPATHLEN], name[256];
	DIR		*d;
	struct dirent	*e;
	size_t		 i;
	int		 n, k;
	const char	*subs[] = { "", "runs", SESSIONS_DIR };

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	snprintf(stage, sizeof(stage), "%s/snap", cl.dir);
	if (rq->first) {
		/* Whatever was staged before is not this one. */
		for (k = (int)nitems(subs) - 1; k >= 0; k--) {
			snprintf(path, sizeof(path), "%s%s%s", stage,
			    subs[k][0] != '\0' ? "/" : "", subs[k]);
			if ((d = opendir(path)) == NULL)
				continue;
			while ((e = readdir(d)) != NULL)
				if (e->d_type == DT_REG) {
					snprintf(name, sizeof(name), "%s/%s",
					    path, e->d_name);
					unlink(name);
				}
			closedir(d);
			rmdir(path);
		}
		if (mkdir(stage, 0700) == -1 && errno != EEXIST)
			return (snap_reply(req, false, strerror(errno)));
		cl.staging = true;
	}
	if (!cl.staging)
		return (snap_reply(req, false, "no first part"));
	for (i = 0; i < rq->doc.n; i++) {
		if (!replicated(rq->doc.v[i].name))
			return (snap_reply(req, false, "not a document"));
		snprintf(path, sizeof(path), "%s/%s", stage,
		    rq->doc.v[i].name);
		if (mkdirs_for(path) == -1 || write_file(path,
		    rq->doc.v[i].body.p, rq->doc.v[i].body.len, 0600) == -1)
			return (snap_reply(req, false, "cannot stage it"));
	}
	if (!rq->last)
		return (snap_reply(req, true, NULL));
	cl.staging = false;
	pthread_mutex_lock(&cl.mu);
	if (rq->term < cl.c.term) {
		pthread_mutex_unlock(&cl.mu);
		return (snap_reply(req, false, "an old leader's"));
	}
	/* What is here and not there goes; what is there is put here. */
	for (k = 0; k < (int)nitems(subs); k++) {
		snprintf(path, sizeof(path), "%s%s%s", cfg.datadir,
		    subs[k][0] != '\0' ? "/" : "", subs[k]);
		if ((d = opendir(path)) == NULL)
			continue;
		while ((e = readdir(d)) != NULL) {
			snprintf(name, sizeof(name), "%s%s%s", subs[k],
			    subs[k][0] != '\0' ? "/" : "", e->d_name);
			if (e->d_type != DT_REG || !replicated(name))
				continue;
			snprintf(path, sizeof(path), "%s/%s", stage, name);
			if (access(path, F_OK) == -1) {
				snprintf(path, sizeof(path), "%s/%s",
				    cfg.datadir, name);
				unlink(path);
			}
		}
		closedir(d);
	}
	for (k = 0; k < (int)nitems(subs); k++) {
		snprintf(path, sizeof(path), "%s%s%s", stage, subs[k][0] !=
		    '\0' ? "/" : "", subs[k]);
		if ((d = opendir(path)) == NULL)
			continue;
		while ((e = readdir(d)) != NULL) {
			char	to[MAXPATHLEN];

			snprintf(name, sizeof(name), "%s%s%s", subs[k],
			    subs[k][0] != '\0' ? "/" : "", e->d_name);
			if (e->d_type != DT_REG || !replicated(name))
				continue;
			snprintf(path, sizeof(path), "%s/%s", stage, name);
			snprintf(to, sizeof(to), "%s/%s", cfg.datadir, name);
			if (mkdirs_for(to) == -1 || rename(path, to) == -1)
				log_msg(LOG_ERR, "cluster: %s: %s", to,
				    strerror(errno));
		}
		closedir(d);
	}
	craft_install_snapshot(&cl.c, rq->term, rq->last_term, rq->last_seq,
	    rq->node);
	cl.gen++;
	changed(NULL);
	pump(-1, NULL, NULL);
	pthread_mutex_unlock(&cl.mu);
	log_msg(LOG_NOTICE, "cluster: the documents of %s as of %ju taken",
	    rq->node, (uintmax_t)rq->last_seq);
	return (snap_reply(req, true, NULL));
}

/* A follower's write, at the leader: answered once it is written. */
int
acl_write_doit(cbl_req *req, const struct acl_write_req *rq,
    void *arg __unused)
{
	struct acl_write_rsp	 rsp;
	const struct acl_doc	*d;
	uint64_t		 term, seq;
	int			 n, k;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	if (rq->doc.n != 1 || !replicated(rq->doc.v[0].name)) {
		rsp.error = "one document of the data directory";
		return (acl_write_reply(req, &rsp));
	}
	d = &rq->doc.v[0];
	pthread_mutex_lock(&cl.mu);
	for (k = 0; k < CL_PENDING && cl.pend[k].req != NULL; k++)
		;
	if (k == CL_PENDING || craft_propose(&cl.c, d->name, d->body.p,
	    d->body.len, d->gone, &term, &seq) != 0) {
		pthread_mutex_unlock(&cl.mu);
		rsp.error = k == CL_PENDING ? "too many writes at once" :
		    "not the leader";
		return (acl_write_reply(req, &rsp));
	}
	if (cbl_req_defer(req) != 0) {
		pump(-1, NULL, NULL);
		pthread_mutex_unlock(&cl.mu);
		return (EIO);
	}
	cl.pend[k].req = req;
	cl.pend[k].term = term;
	cl.pend[k].seq = seq;
	cl.pend[k].since = now_ms();
	strlcpy(cl.pend[k].name, d->name, sizeof(cl.pend[k].name));
	pump(-1, NULL, NULL);
	pthread_mutex_unlock(&cl.mu);
	return (0);
}

/* The lock written to the log (the lock held, so the others know it,
 * or let go): the write's place in *seqp, which the holder waits for. */
static void
lock_write(const char *name, const char *holder, uint64_t until, bool gone,
    uint64_t *seqp)
{
	char		lname[256 + sizeof(LOCK_PREFIX)], body[160];
	uint64_t	term, seq;

	snprintf(lname, sizeof(lname), "%s%s", LOCK_PREFIX, name);
	snprintf(body, sizeof(body), "%s\n%ju", holder, (uintmax_t)until);
	if (craft_propose(&cl.c, lname, (const uint8_t *)body, strlen(body),
	    gone, &term, &seq) == 0) {
		if (seqp != NULL)
			*seqp = seq;
		pump(-1, NULL, NULL);
	}
}

/*
 * The leader's lock name taken by holder for ttl ms, or held already by
 * it: true; the newest committed write into commitp.  With the lock.
 */
static bool
lock_try(const char *name, const char *holder, uint64_t ttl,
    uint64_t *commitp, const char **why)
{
	uint64_t	now;
	int		i, free_i;

	*why = NULL;
	if (cl.c.role != CRAFT_LEADER) {
		*why = "not the leader";
		return (false);
	}
	/* On its lease alone: a leader cut off grants nothing, so that
	 * the one elected instead and it never grant the same lock. */
	if (!craft_quorum_heard(&cl.c, CRAFT_LEASE_MS)) {
		*why = "the leader has not heard from a majority";
		return (false);
	}
	now = now_ms();
	*commitp = cl.c.commit;
	free_i = -1;
	for (i = 0; i < CL_LOCKS; i++) {
		if (cl.locks[i].name[0] == '\0' || cl.locks[i].until <= now) {
			if (free_i == -1)
				free_i = i;
			continue;
		}
		if (strcmp(cl.locks[i].name, name) == 0) {
			if (strcmp(cl.locks[i].holder, holder) != 0) {
				*why = "held";
				return (false);
			}
			cl.locks[i].until = now + ttl;
			lock_write(name, holder, now + ttl, false, commitp);
			return (true);
		}
	}
	if (free_i == -1) {
		*why = "too many locks held";
		return (false);
	}
	strlcpy(cl.locks[free_i].name, name, sizeof(cl.locks[free_i].name));
	strlcpy(cl.locks[free_i].holder, holder,
	    sizeof(cl.locks[free_i].holder));
	cl.locks[free_i].until = now + ttl;
	lock_write(name, holder, now + ttl, false, commitp);
	return (true);
}

static void
lock_drop(const char *name, const char *holder)
{
	int	i;

	for (i = 0; i < CL_LOCKS; i++)
		if (strcmp(cl.locks[i].name, name) == 0 &&
		    strcmp(cl.locks[i].holder, holder) == 0) {
			cl.locks[i].name[0] = '\0';
			if (cl.c.role == CRAFT_LEADER)
				lock_write(name, holder, cl.locks[i].until, true,
				    NULL);
		}
}

int
acl_lock_doit(cbl_req *req, const struct acl_lock_req *rq, void *arg __unused)
{
	struct acl_lock_rsp	 rsp;
	const char		*why;
	uint64_t		 ttl, commit;
	int			 n;
	bool			 ok;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	ttl = rq->has_ttl_ms && rq->ttl_ms > 0 && rq->ttl_ms <= 60000 ?
	    rq->ttl_ms : 10000;
	pthread_mutex_lock(&cl.mu);
	ok = lock_try(rq->lock, rq->holder, ttl, &commit, &why);
	pthread_mutex_unlock(&cl.mu);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = ok;
	rsp.error = why;
	rsp.has_commit_seq = ok;
	rsp.commit_seq = commit;
	return (acl_lock_reply(req, &rsp));
}

int
acl_unlock_doit(cbl_req *req, const struct acl_unlock_req *rq,
    void *arg __unused)
{
	struct acl_unlock_rsp	rsp;
	int			n;

	if (!peer_ok(req, rq->node, &n))
		return (EACCES);
	pthread_mutex_lock(&cl.mu);
	lock_drop(rq->lock, rq->holder);
	pthread_mutex_unlock(&cl.mu);
	memset(&rsp, 0, sizeof(rsp));
	rsp.has_ok = true;
	rsp.ok = true;
	return (acl_unlock_reply(req, &rsp));
}

/* ---- The clock ---------------------------------------------------------- */

static void
tick(cbl_timer *t __unused, void *arg __unused)
{
	uint64_t	now;
	int		k;

	now = now_ms();
	pthread_mutex_lock(&cl.mu);
	craft_tick(&cl.c, now);
	pump(-1, NULL, NULL);
	for (k = 0; k < CL_PENDING; k++)
		if (cl.pend[k].req != NULL && (now - cl.pend[k].since >
		    CL_DEFER_MS || cbl_req_cancelled(cl.pend[k].req)))
			pending_end(&cl.pend[k], false, "not committed in time: "
			    "the cluster has no majority here");
	pthread_mutex_unlock(&cl.mu);
}

static void *
loop_run(void *arg __unused)
{

	(void)cbl_loop_run(cl.loop);
	return (NULL);
}

/* ---- This node's writes ------------------------------------------------- */

/* Wait, with the lock held, until applied reaches seq or the deadline. */
static bool
wait_applied(uint64_t seq, uint64_t deadline) __no_lock_analysis
{
	struct timespec	ts;
	uint64_t	now;

	while (cl.c.applied < seq) {
		if ((now = now_ms()) >= deadline)
			return (false);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += (long)((deadline - now) % 1000) * 1000000 + 0;
		ts.tv_sec += (time_t)((deadline - now) / 1000) + ts.tv_nsec /
		    1000000000;
		ts.tv_nsec %= 1000000000;
		(void)pthread_cond_timedwait(&cl.cv, &cl.mu, &ts);
	}
	return (true);
}

/* The connection of this node's own asks to the leader; with wmu. */
static bool
leader_client(int leader, char *err, size_t errlen)
{

	if (cl.wconn != NULL && cl.wnode != leader) {
		acl_client_fini(&cl.wcl);
		cbl_conn_free(cl.wconn);
		cbl_tls_free(cl.wtls);
		cl.wconn = NULL;
		cl.wtls = NULL;
	}
	if (cl.wconn == NULL) {
		if (dial(leader, &cl.wconn, &cl.wtls, &cl.wcl) != 0) {
			snprintf(err, errlen, "the leader, %s, does not answer",
			    cl.nodes[leader].name);
			return (false);
		}
		cl.wnode = leader;
	}
	return (true);
}

static void
leader_drop(void)
{

	if (cl.wconn == NULL)
		return;
	acl_client_fini(&cl.wcl);
	cbl_conn_free(cl.wconn);
	cbl_tls_free(cl.wtls);
	cl.wconn = NULL;
	cl.wtls = NULL;
}

/* A follower's write, sent to the leader; its sequence, or 0. */
static uint64_t
write_to(int leader, const char *name, const void *body, size_t len,
    bool gone, char *err, size_t errlen)
{
	struct acl_write_req	 rq;
	struct acl_write_rsp	*rsp = NULL;
	struct acl_doc		 d;
	uint64_t		 seq = 0;

	pthread_mutex_lock(&cl.wmu);
	if (!leader_client(leader, err, errlen)) {
		pthread_mutex_unlock(&cl.wmu);
		return (0);
	}
	memset(&d, 0, sizeof(d));
	d.name = name;
	d.body.p = body;
	d.body.len = len;
	d.gone = gone;
	memset(&rq, 0, sizeof(rq));
	rq.node = cl.nodes[cl.self].name;
	rq.doc.n = 1;
	rq.doc.v = &d;
	if (acl_write(&cl.wcl, &rq, &rsp) != 0 || rsp == NULL) {
		leader_drop();
		snprintf(err, errlen, "the leader, %s, did not answer",
		    cl.nodes[leader].name);
	} else if (!rsp->ok || rsp->doc.n != 1 || !rsp->doc.v[0].has_seq)
		snprintf(err, errlen, "%s", rsp->error != NULL ? rsp->error :
		    "the leader did not take it");
	else
		seq = rsp->doc.v[0].seq;
	acl_write_rsp_free(rsp);
	pthread_mutex_unlock(&cl.wmu);
	return (seq);
}

/*
 * A document written through the cluster: 0 once a majority holds it and
 * it is written here too, -1 if it could not be within CL_WAIT_MS.
 */
int
cluster_save(const char *name, const void *body, size_t len, bool gone)
{
	char		 err[256];
	uint64_t	 deadline, term, seq;
	int		 leader;

	if (!replicated(name))
		return (store_write(name, body, len));
	/*
	 * While the worker starts, no majority can be waited for (the
	 * loop is not running yet): what is written then is the
	 * defaults each node makes alike, in memory; the next change
	 * writes them.
	 */
	/* Not started: nothing would be written, which must not pass for
	 * written. */
	if (!cl.started)
		return (-1);
	deadline = now_ms() + CL_WAIT_MS;
	err[0] = '\0';
	pthread_mutex_lock(&cl.mu);
	for (;;) {
		if (cl.c.role == CRAFT_LEADER) {
			if (craft_propose(&cl.c, name, body, len, gone, &term,
			    &seq) != 0) {
				snprintf(err, sizeof(err), "cannot propose it");
				break;
			}
			pump(-1, NULL, NULL);
			if (!wait_applied(seq, deadline)) {
				snprintf(err, sizeof(err), "not committed in "
				    "time: the cluster has no majority here");
				break;
			}
			if (!applied_as(seq, term)) {
				snprintf(err, sizeof(err), "a new leader took "
				    "its place before it was written");
				break;
			}
			pthread_mutex_unlock(&cl.mu);
			return (0);
		}
		if ((leader = node_of(cl.c.leader)) >= 0 && leader !=
		    cl.self) {
			pthread_mutex_unlock(&cl.mu);
			seq = write_to(leader, name, body, len, gone, err,
			    sizeof(err));
			pthread_mutex_lock(&cl.mu);
			if (seq != 0) {
				/* Committed: here once the leader says so. */
				(void)wait_applied(seq, deadline);
				pthread_mutex_unlock(&cl.mu);
				return (0);
			}
		}
		if (now_ms() >= deadline || !wait_applied(cl.c.applied + 1,
		    MIN(deadline, now_ms() + 200))) {
			if (now_ms() >= deadline) {
				if (err[0] == '\0')
					snprintf(err, sizeof(err), "no leader: "
					    "the cluster has no majority here");
				break;
			}
		}
	}
	pthread_mutex_unlock(&cl.mu);
	log_msg(LOG_ERR, "cluster: %s not written: %s", name, err);
	return (-1);
}

/* ---- Locks of the cluster ------------------------------------------------ */

#define	CL_LOCK_WAIT_MS	10000

static void
holder_of(char *buf, size_t len)
{

	snprintf(buf, len, "%s/%lx", cl.nodes[cl.self].name, (unsigned long)
	    (uintptr_t)pthread_self());
}

/*
 * What is read, changed and written again by one node of the cluster at
 * a time (labels, templates, prefix lists): the leader's lock name,
 * besides the caller's flock(2) of its own node; and, taken, every write
 * the leader had committed written here first, so that what is read is
 * the newest.  False when no leader gave it within CL_LOCK_WAIT_MS: the
 * write that follows then fails for want of a majority anyway.
 */
bool
cluster_lock(const char *name)
{
	struct acl_lock_req	 rq;
	struct acl_lock_rsp	*rsp;
	char			 holder[128], err[256];
	const char		*why;
	uint64_t		 deadline, commit;
	int			 leader;
	bool			 ok;

	if (!cl.on || !cl.started)
		return (true);
	holder_of(holder, sizeof(holder));
	deadline = now_ms() + CL_LOCK_WAIT_MS;
	while (now_ms() < deadline) {
		pthread_mutex_lock(&cl.mu);
		if (cl.c.role == CRAFT_LEADER) {
			ok = lock_try(name, holder, CL_LOCK_TTL_MS, &commit,
			    &why);
			if (ok)
				(void)wait_applied(commit, deadline);
			pthread_mutex_unlock(&cl.mu);
			if (ok)
				return (true);
			usleep(50000);
			continue;
		}
		leader = node_of(cl.c.leader);
		pthread_mutex_unlock(&cl.mu);
		if (leader < 0 || leader == cl.self) {
			usleep(100000);
			continue;
		}
		pthread_mutex_lock(&cl.wmu);
		ok = false;
		commit = 0;
		if (leader_client(leader, err, sizeof(err))) {
			memset(&rq, 0, sizeof(rq));
			rq.node = cl.nodes[cl.self].name;
			rq.lock = name;
			rq.holder = holder;
			rq.has_ttl_ms = true;
			rq.ttl_ms = CL_LOCK_TTL_MS;
			rsp = NULL;
			if (acl_lock(&cl.wcl, &rq, &rsp) != 0 || rsp == NULL)
				leader_drop();
			else if (rsp->ok) {
				ok = true;
				commit = rsp->commit_seq;
			}
			acl_lock_rsp_free(rsp);
		}
		pthread_mutex_unlock(&cl.wmu);
		if (ok) {
			pthread_mutex_lock(&cl.mu);
			(void)wait_applied(commit, deadline);
			pthread_mutex_unlock(&cl.mu);
			return (true);
		}
		usleep(50000);
	}
	log_msg(LOG_ERR, "cluster: the lock %s not had in time", name);
	return (false);
}

void
cluster_unlock(const char *name)
{
	struct acl_unlock_req	 rq;
	struct acl_unlock_rsp	*rsp;
	char			 holder[128], err[256];
	int			 leader;

	if (!cl.on || !cl.started)
		return;
	holder_of(holder, sizeof(holder));
	pthread_mutex_lock(&cl.mu);
	if (cl.c.role == CRAFT_LEADER) {
		lock_drop(name, holder);
		pthread_mutex_unlock(&cl.mu);
		return;
	}
	leader = node_of(cl.c.leader);
	pthread_mutex_unlock(&cl.mu);
	if (leader < 0 || leader == cl.self)
		return;		/* it runs out by itself */
	pthread_mutex_lock(&cl.wmu);
	if (leader_client(leader, err, sizeof(err))) {
		memset(&rq, 0, sizeof(rq));
		rq.node = cl.nodes[cl.self].name;
		rq.lock = name;
		rq.holder = holder;
		rsp = NULL;
		if (acl_unlock(&cl.wcl, &rq, &rsp) != 0)
			leader_drop();
		acl_unlock_rsp_free(rsp);
	}
	pthread_mutex_unlock(&cl.wmu);
}

/* ---- Start ---------------------------------------------------------------- */

int
cluster_init(void)
{
	const char	*peers[CRAFT_NODES_MAX];
	char		 err[256];
	cbl_tls		*tls;
	cbl_timer	*t;
	pthread_t	 tid;
	int		 i, np, error;
	bool		 unix_;

	if (!cl.on)
		return (0);
	snprintf(cl.dir, sizeof(cl.dir), "%s/%s", cfg.datadir, CL_DIR);
	if (mkdir(cl.dir, 0700) == -1 && errno != EEXIST) {
		log_msg(LOG_ERR, "%s: %s", cl.dir, strerror(errno));
		return (-1);
	}
	unix_ = strncmp(cl.listen, "unix:", 5) == 0;
	snprintf(cl.cert, sizeof(cl.cert), "%s/node.pem", cl.dir);
	snprintf(cl.key, sizeof(cl.key), "%s/node.key", cl.dir);
	if (!unix_ && pki_node_cert(cl.nodes[cl.self].host, cl.cert, cl.key,
	    err, sizeof(err)) == -1) {
		log_msg(LOG_ERR, "cluster: %s", err);
		return (-1);
	}
	np = 0;
	for (i = 0; i < cl.nn; i++)
		if (i != cl.self)
			peers[np++] = cl.nodes[i].name;
	craft_init(&cl.c, cl.nodes[cl.self].name, peers, np, now_ms(),
	    (uint32_t)arc4random());
	restore();
	if ((error = cbl_ctx_new(&cl.ctx)) != 0 ||
	    (error = cbl_loop_new(cl.ctx, &cl.loop)) != 0) {
		log_msg(LOG_ERR, "cluster: cblink: %s", strerror(error));
		return (-1);
	}
	(void)cbl_ctx_set_limit(cl.ctx, CBL_LIM_MAX_FRAME, CL_FRAME);
	(void)cbl_ctx_set_limit(cl.ctx, CBL_LIM_MAX_ATTRS, ACL_MAX_DOCS * 8 +
	    64);
	(void)cbl_ctx_set_limit(cl.ctx, CBL_LIM_REQUEST_MS, 5000);
	if ((error = acl_register(cl.ctx, NULL, NULL)) != 0) {
		log_msg(LOG_ERR, "cluster: its family: %s", strerror(error));
		return (-1);
	}
	if ((error = cbl_listener_new(cl.ctx, cl.listen, unix_ ?
	    CBL_LF_UNIX_TRUSTED : 0, &cl.ls)) != 0) {
		log_msg(LOG_ERR, "cluster: %s: %s", cl.listen,
		    strerror(error));
		return (-1);
	}
	if (unix_)
		error = cbl_listener_set_unix_perm(cl.ls, 0600, (uid_t)-1,
		    (gid_t)-1);
	else if (cbl_tls_new(&tls) != 0 || cbl_tls_set_cert(tls, cl.cert,
	    cl.key) != 0 || cbl_tls_set_ca(tls, cfg.tls_ca, NULL) != 0)
		error = EINVAL;
	else
		error = cbl_listener_set_tls(cl.ls, tls);
	if (error != 0 || (error = cbl_listener_start(cl.ls, cl.loop)) != 0) {
		log_msg(LOG_ERR, "cluster: %s: %s", cl.listen,
		    cbl_listener_errstr(cl.ls));
		return (-1);
	}
	if (cbl_loop_timer(cl.loop, CL_TICK_MS, CBL_TF_REPEAT, tick, NULL,
	    &t) != 0) {
		log_msg(LOG_ERR, "cluster: its clock");
		return (-1);
	}
	for (i = 0; i < cl.nn; i++) {
		if (i == cl.self)
			continue;
		cl.peers[i].idx = i;
		pthread_cond_init(&cl.peers[i].cv, NULL);
		if (pthread_create(&cl.peers[i].thread, NULL, peer_run,
		    &cl.peers[i]) != 0) {
			log_msg(LOG_ERR, "cluster: pthread_create");
			return (-1);
		}
		(void)pthread_detach(cl.peers[i].thread);
	}
	if (pthread_create(&tid, NULL, loop_run, NULL) != 0)
		return (-1);
	(void)pthread_detach(tid);
	log_msg(LOG_NOTICE, "cluster: node %s of %d, on %s",
	    cl.nodes[cl.self].name, cl.nn, cl.listen);
	return (0);
}

/*
 * One of the nodes' web origins: a browser signed in on a.console.example
 * is one of b.console.example's too (the relying party ID is a name they
 * share, console.example).
 */
bool
cluster_origin(const char *o)
{
	int	i;

	for (i = 0; cl.on && o != NULL && i < cl.nn; i++)
		if (cl.nodes[i].origin[0] != '\0' && strcmp(o,
		    cl.nodes[i].origin) == 0)
			return (true);
	return (false);
}

/* The worker has started: writes go to the cluster from now on. */
void
cluster_started(void)
{

	cl.started = true;
}

/* The cluster as this node knows it, for GET /api/cluster. */
void
cluster_status(ucl_object_t *o)
{
	ucl_object_t	*arr, *n;
	int		 i;

	ucl_object_insert_key(o, ucl_object_frombool(cl.on), "on", 0, false);
	if (!cl.on)
		return;
	pthread_mutex_lock(&cl.mu);
	ucl_object_insert_key(o, ucl_object_fromstring(cl.nodes[cl.self].name),
	    "self", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(cl.c.role ==
	    CRAFT_LEADER ? "leader" : cl.c.role == CRAFT_CANDIDATE ?
	    "candidate" : "follower"), "role", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(cl.c.leader), "leader",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)cl.c.term),
	    "term", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)cl.c.commit),
	    "commit", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint((int64_t)cl.c.applied),
	    "applied", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < cl.nn; i++) {
		n = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(n, ucl_object_fromstring(
		    cl.nodes[i].name), "name", 0, false);
		ucl_object_insert_key(n, ucl_object_fromstring(
		    cl.nodes[i].origin), "origin", 0, false);
		if (i != cl.self && cl.c.role == CRAFT_LEADER) {
			int	k;

			for (k = 0; k < cl.c.npeers; k++)
				if (strcmp(cl.c.peers[k].name,
				    cl.nodes[i].name) == 0)
					ucl_object_insert_key(n,
					    ucl_object_fromint((int64_t)
					    cl.c.peers[k].match), "match", 0,
					    false);
		}
		ucl_array_append(arr, n);
	}
	ucl_object_insert_key(o, arr, "nodes", 0, false);
	pthread_mutex_unlock(&cl.mu);
}

/* GET /api/cluster: the nodes, who leads, how far each has come. */
int
api_cluster(struct http_request *req)
{
	ucl_object_t	*o;

	if (!guard(req, false))
		return (WEB_OK);
	o = ucl_object_typed_new(UCL_OBJECT);
	cluster_status(o);
	return (reply_json(req, 200, o));
}
