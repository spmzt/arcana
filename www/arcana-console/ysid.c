/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A schema's SIDs as a peer numbers them (PLAN-SDN-YANG 4.2, 4.3): the
 * items of its .sid files, RFC 9595's ietf-sid-file structure as GET-SID
 * sends it in YANG-CBOR or as the files are in JSON, sorted by SID and
 * by identifier.  Each is resolved to what the console's tables have of
 * the same identifier, a data node by its schema-node path walked from
 * its module, an identity, an annotation or a module by module and
 * name: the SID the console's tables give it may differ, and a node only
 * one side has is the other's to pass over or refuse.  A data item's
 * base is the SID its key is a delta from (RFC 9254 section 3.2): its
 * parent's, the rpc's or the action's for what is in an input or an
 * output.  With them, the modules the peer's YANG library (RFC 8525)
 * says, and its content-id.
 */

#include <sys/param.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ysid.h"
#include "yxlate.h"

/* ietf-sid-file's SIDs (cblink's share/yang, RFC 9595 Appendix B). */
#define	S_FILE		1301
#define	S_ITEM		1309
#define	S_ITEM_ID	1310
#define	S_ITEM_NS	1311
#define	S_ITEM_SID	1312
#define	S_ITEM_STATUS	1313
#define	S_MODULE	1314
#define	S_REVISION	1315
#define	ST_OBSOLETE	2

#define	PATH_MAX_LEN	1024

struct ysids {
	const struct cbl_yschema *types;
	cbl_yarena		*a;
	struct ysid_item	*item;		/* by SID once done */
	size_t			 nitem;
	size_t			 citem;
	const struct ysid_item	**byid;		/* by ns, id, module */
	const struct ysid_item	**bywhat;	/* resolved, by what */
	size_t			 nwhat;
	struct ysid_mod		*mod;
	size_t			 nmod;
	size_t			 cmod;
	const char		*content_id;
	bool			 done;
};

static int
fail(char *why, size_t len, const char *fmt, ...)
{
	va_list	ap;

	if (why != NULL && len > 0) {
		va_start(ap, fmt);
		(void)vsnprintf(why, len, fmt, ap);
		va_end(ap);
	}
	return (EINVAL);
}

static const char *
sdup(struct ysids *s, const char *p, size_t len)
{
	char	*d;

	if ((d = cbl_yarena_alloc(s->a, len + 1)) == NULL)
		return (NULL);
	memcpy(d, p, len);
	d[len] = '\0';
	return (d);
}

struct ysids *
ysids_new(const struct cbl_yschema *types)
{
	struct ysids	*s;

	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (NULL);
	if ((s->a = cbl_yarena_new()) == NULL) {
		free(s);
		return (NULL);
	}
	s->types = types;
	return (s);
}

void
ysids_free(struct ysids *s)
{

	if (s == NULL)
		return;
	free(s->item);
	free(s->byid);
	free(s->bywhat);
	free(s->mod);
	cbl_yarena_free(s->a);
	free(s);
}

/* An item of module mod, the strings copied. */
static int
add(struct ysids *s, const char *mod, int ns, const char *id, size_t idlen,
    uint64_t sid, bool obsolete)
{
	struct ysid_item	*it, *v;
	size_t			 c;

	if (s->done || ns < YSID_NS_MODULE || ns > YSID_NS_ANNOTATION)
		return (EINVAL);
	if (s->nitem == s->citem) {
		c = s->citem > 0 ? s->citem * 2 : 1024;
		if ((v = reallocarray(s->item, c, sizeof(*v))) == NULL)
			return (ENOMEM);
		s->item = v;
		s->citem = c;
	}
	it = &s->item[s->nitem];
	memset(it, 0, sizeof(*it));
	it->sid = sid;
	it->ns = (uint8_t)ns;
	it->obsolete = obsolete;
	if ((it->id = sdup(s, id, idlen)) == NULL || (it->module = sdup(s,
	    mod, strlen(mod))) == NULL)
		return (ENOMEM);
	s->nitem++;
	return (0);
}

/* A text string's value at r, NUL-terminated in s's arena. */
static int
rd_str(struct ysids *s, struct yxrd *r, const char **out)
{
	const char	*p;
	size_t		 len;

	if (yxrd_text(r, &p, &len) != 0)
		return (EINVAL);
	if ((*out = sdup(s, p, len)) == NULL)
		return (ENOMEM);
	return (0);
}

/* An unsigned integer's at r. */
static int
rd_uint(struct yxrd *r, uint64_t *v)
{
	int	major;

	if (yxrd_head(r, &major, v) != 0 || major != 0)
		return (EINVAL);
	return (0);
}

/* A map's head at r: its size. */
static int
rd_map(struct yxrd *r, uint64_t *n)
{
	int	major;

	if (yxrd_head(r, &major, n) != 0 || major != 5)
		return (EINVAL);
	return (0);
}

/* A key at r, a delta from base: its SID. */
static int
rd_key(struct yxrd *r, uint64_t base, uint64_t *sid)
{
	uint64_t	v;
	int		major;

	if (yxrd_head(r, &major, &v) != 0 || (major != 0 && major != 1))
		return (EINVAL);
	*sid = major == 0 ? base + v : base - 1 - v;
	return (0);
}

int
ysids_file_cbor(struct ysids *s, const void *cbor, size_t len, char *why,
    size_t whylen)
{
	struct yxrd	 r = { cbor, (const uint8_t *)cbor + len }, items;
	const char	*mod = NULL, *id;
	uint64_t	 n, ni, k, ns, v, isid;
	int		 major, error;
	bool		 have_items = false, obs;

	if (rd_map(&r, &n) != 0)
		return (fail(why, whylen, "a .sid file not a map"));
	/* The module's name may come after its items: they are read after. */
	for (uint64_t i = 0; i < n; i++) {
		if (rd_key(&r, S_FILE, &k) != 0)
			return (fail(why, whylen, "a .sid file's key"));
		if (k == S_MODULE) {
			if ((error = rd_str(s, &r, &mod)) != 0)
				return (error == ENOMEM ? error : fail(why,
				    whylen, "module-name not a string"));
			continue;
		}
		if (k == S_ITEM) {
			items = r;
			have_items = true;
		}
		if (yxrd_skip(&r) != 0)
			return (fail(why, whylen, "a .sid file's value"));
	}
	if (mod == NULL)
		return (fail(why, whylen, "a .sid file without module-name"));
	if (!have_items)
		return (0);
	if (yxrd_head(&items, &major, &ni) != 0 || major != 4)
		return (fail(why, whylen, "%s: item not an array", mod));
	for (uint64_t i = 0; i < ni; i++) {
		if (rd_map(&items, &n) != 0)
			return (fail(why, whylen, "%s: an item not a map", mod));
		id = NULL;
		ns = YSID_NS_DATA + 1;
		isid = 0;
		obs = false;
		for (uint64_t j = 0; j < n; j++) {
			if (rd_key(&items, S_ITEM, &k) != 0)
				return (fail(why, whylen, "%s: an item's key",
				    mod));
			switch (k) {
			case S_ITEM_ID:
				if ((error = rd_str(s, &items, &id)) != 0)
					return (error == ENOMEM ? error :
					    fail(why, whylen, "%s: an "
					    "identifier", mod));
				break;
			case S_ITEM_NS:
				if (rd_uint(&items, &ns) != 0)
					return (fail(why, whylen, "%s: a "
					    "namespace", mod));
				break;
			case S_ITEM_SID:
				if (rd_uint(&items, &isid) != 0)
					return (fail(why, whylen, "%s: a sid",
					    mod));
				break;
			case S_ITEM_STATUS:
				if (rd_uint(&items, &v) != 0)
					return (fail(why, whylen, "%s: a status",
					    mod));
				obs = v == ST_OBSOLETE;
				break;
			default:
				if (yxrd_skip(&items) != 0)
					return (fail(why, whylen, "%s: an item",
					    mod));
			}
		}
		if (id == NULL || ns > YSID_NS_ANNOTATION || isid == 0)
			return (fail(why, whylen, "%s: an item without its "
			    "identifier, namespace or sid", mod));
		if ((error = add(s, mod, (int)ns, id, strlen(id), isid, obs)) !=
		    0)
			return (error);
	}
	return (0);
}

int
ysids_file_json(struct ysids *s, const ucl_object_t *file, char *why,
    size_t whylen)
{
	static const char *const nss[] = { "module", "identity", "feature",
	    "data", "annotation" };
	const ucl_object_t	*f, *items, *e, *v;
	ucl_object_iter_t	 it = NULL;
	const char		*mod, *id, *ns, *st, *sidtext;
	char			*end;
	uint64_t		 sid;
	size_t			 k;
	int			 error;

	if ((f = ucl_object_lookup(file, "ietf-sid-file:sid-file")) == NULL)
		f = file;
	if ((mod = ucl_object_tostring(ucl_object_lookup(f, "module-name"))) ==
	    NULL)
		return (fail(why, whylen, "a .sid file without module-name"));
	if ((items = ucl_object_lookup(f, "item")) == NULL)
		return (0);
	while ((e = ucl_object_iterate(items, &it, true)) != NULL) {
		id = ucl_object_tostring(ucl_object_lookup(e, "identifier"));
		ns = ucl_object_tostring(ucl_object_lookup(e, "namespace"));
		v = ucl_object_lookup(e, "sid");
		st = ucl_object_tostring(ucl_object_lookup(e, "status"));
		if (id == NULL || ns == NULL || v == NULL)
			return (fail(why, whylen, "%s: an item without its "
			    "identifier, namespace or sid", mod));
		/* A uint64 is a string in JSON (RFC 7951 section 6.1). */
		if (ucl_object_type(v) == UCL_INT)
			sid = (uint64_t)ucl_object_toint(v);
		else {
			if ((sidtext = ucl_object_tostring(v)) == NULL)
				return (fail(why, whylen, "%s: a sid", mod));
			errno = 0;
			sid = strtoull(sidtext, &end, 10);
			if (errno != 0 || *end != '\0' || end == sidtext)
				return (fail(why, whylen, "%s: sid %s", mod,
				    sidtext));
		}
		for (k = 0; k < nitems(nss) && strcmp(nss[k], ns) != 0; k++)
			;
		if (k == nitems(nss))
			return (fail(why, whylen, "%s: namespace %s", mod, ns));
		if ((error = add(s, mod, (int)k, id, strlen(id), sid, st !=
		    NULL && strcmp(st, "obsolete") == 0)) != 0)
			return (error);
	}
	return (0);
}

bool
ysids_node_path(const struct cbl_ynode *n, char *buf, size_t len)
{
	const struct cbl_ynode	*chain[64];
	const struct cbl_ymodule *prev = NULL;
	size_t			 nc = 0, o = 0;
	int			 w;

	for (; n != NULL; n = n->parent) {
		if (nc == nitems(chain))
			return (false);
		chain[nc++] = n;
	}
	if (len == 0)
		return (false);
	buf[0] = '\0';
	while (nc-- > 0) {
		n = chain[nc];
		if (n->module != prev)
			w = snprintf(buf + o, len - o, "/%s:%s",
			    n->module->name, n->name);
		else
			w = snprintf(buf + o, len - o, "/%s", n->name);
		if (w < 0 || (size_t)w >= len - o)
			return (false);
		o += (size_t)w;
		prev = n->module;
	}
	return (true);
}

int
ysids_tables(struct ysids *s)
{
	const struct cbl_yschema *t = s->types;
	char			 path[PATH_MAX_LEN];
	int			 error;

	for (uint32_t i = 0; i < t->nmod; i++)
		if ((error = add(s, t->mod[i]->name, YSID_NS_MODULE,
		    t->mod[i]->name, strlen(t->mod[i]->name), t->mod[i]->sid,
		    false)) != 0)
			return (error);
	for (uint32_t i = 0; i < t->nnode; i++) {
		const struct cbl_ynode *n = t->node[i];

		if (!ysids_node_path(n, path, sizeof(path)))
			continue;
		if ((error = add(s, n->module->name, YSID_NS_DATA, path,
		    strlen(path), n->sid, (n->flags & CBL_YNF_OBSOLETE) !=
		    0)) != 0)
			return (error);
	}
	for (uint32_t i = 0; i < t->nident; i++) {
		const struct cbl_yident *id = &t->ident[i];

		if (id->module != NULL && (error = add(s, id->module->name,
		    YSID_NS_IDENTITY, id->name, strlen(id->name), id->sid,
		    false)) != 0)
			return (error);
	}
	for (uint32_t i = 0; i < t->nannot; i++) {
		const struct cbl_yannot *an = t->annot[i];

		if ((error = add(s, an->module->name, YSID_NS_ANNOTATION,
		    an->name, strlen(an->name), an->sid, false)) != 0)
			return (error);
	}
	return (0);
}

int
ysids_module(struct ysids *s, const char *name, const char *revision,
    bool implemented)
{
	struct ysid_mod	*v;
	size_t		 c;

	if (s->done)
		return (EINVAL);
	if (s->nmod == s->cmod) {
		c = s->cmod > 0 ? s->cmod * 2 : 64;
		if ((v = reallocarray(s->mod, c, sizeof(*v))) == NULL)
			return (ENOMEM);
		s->mod = v;
		s->cmod = c;
	}
	v = &s->mod[s->nmod];
	v->implemented = implemented;
	if (revision == NULL)
		revision = "";
	if ((v->name = sdup(s, name, strlen(name))) == NULL ||
	    (v->revision = sdup(s, revision, strlen(revision))) == NULL)
		return (ENOMEM);
	s->nmod++;
	return (0);
}

int
ysids_set_content_id(struct ysids *s, const char *id)
{

	if (s->done)
		return (EINVAL);
	if ((s->content_id = sdup(s, id, strlen(id))) == NULL)
		return (ENOMEM);
	return (0);
}

static int
by_sid(const void *a, const void *b)
{
	const struct ysid_item *x = a, *y = b;

	return (x->sid < y->sid ? -1 : x->sid > y->sid);
}

static int
by_id(const void *a, const void *b)
{
	const struct ysid_item *x = *(const struct ysid_item *const *)a,
	    *y = *(const struct ysid_item *const *)b;
	int c;

	if (x->ns != y->ns)
		return (x->ns < y->ns ? -1 : 1);
	if ((c = strcmp(x->id, y->id)) != 0)
		return (c);
	/* Data paths say their modules; the others' are the files'. */
	return (x->ns == YSID_NS_DATA ? 0 : strcmp(x->module, y->module));
}

static int
by_what(const void *a, const void *b)
{
	const struct ysid_item *x = *(const struct ysid_item *const *)a,
	    *y = *(const struct ysid_item *const *)b;

	return ((uintptr_t)x->what < (uintptr_t)y->what ? -1 :
	    (uintptr_t)x->what > (uintptr_t)y->what);
}

static const struct cbl_ymodule *
module_of(const struct cbl_yschema *t, const char *name, size_t len)
{

	for (uint32_t i = 0; i < t->nmod; i++)
		if (strlen(t->mod[i]->name) == len && strncmp(t->mod[i]->name,
		    name, len) == 0)
			return (t->mod[i]);
	return (NULL);
}

/* A data path's last name and its module, into it; its parent's length. */
static void
split_path(struct ysids *s, struct ysid_item *it, size_t *plen)
{
	const char	*p, *last, *colon, *mod = it->module;
	size_t		 mlen = strlen(it->module);

	last = it->id;
	for (p = it->id; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		last = p + 1;
		colon = strchr(last, ':');
		if (colon != NULL && (strchr(last, '/') == NULL ||
		    colon < strchr(last, '/'))) {
			mod = last;
			mlen = (size_t)(colon - last);
		}
	}
	*plen = last > it->id ? (size_t)(last - it->id - 1) : 0;
	colon = strchr(last, ':');
	it->name = colon != NULL ? colon + 1 : last;
	it->nmod = sdup(s, mod, mlen);
}

/* The console's node of a schema-node path, walked from its module. */
static const struct cbl_ynode *
walk(const struct cbl_yschema *t, const char *path)
{
	const struct cbl_ymodule *m = NULL, *cm;
	const struct cbl_ynode	*n = NULL, *c;
	const char		*p = path, *e, *colon, *name;
	size_t			 nlen;

	while (*p == '/') {
		p++;
		e = strchrnul(p, '/');
		colon = memchr(p, ':', (size_t)(e - p));
		cm = m;
		if (colon != NULL && (cm = module_of(t, p, (size_t)(colon -
		    p))) == NULL)
			return (NULL);
		if (cm == NULL)
			return (NULL);
		name = colon != NULL ? colon + 1 : p;
		nlen = (size_t)(e - name);
		c = NULL;
		if (n == NULL) {
			for (uint32_t k = 0; c == NULL && k < cm->ntop; k++)
				if (strlen(cm->top[k]->name) == nlen &&
				    strncmp(cm->top[k]->name, name, nlen) == 0)
					c = cm->top[k];
		} else
			for (uint32_t k = 0; c == NULL && k < n->nchild; k++)
				if (n->child[k]->module == cm &&
				    strlen(n->child[k]->name) == nlen &&
				    strncmp(n->child[k]->name, name, nlen) == 0)
					c = n->child[k];
		if (c == NULL)
			return (NULL);
		n = c;
		m = cm;
		p = e;
	}
	return (*p == '\0' ? n : NULL);
}

/* What the console's tables have of item it, or NULL. */
static const void *
resolve(const struct cbl_yschema *t, const struct ysid_item *it)
{
	const struct cbl_ynode	*n;
	const struct cbl_yident	*id;
	const struct cbl_yannot	*an;
	char			 path[PATH_MAX_LEN];

	switch (it->ns) {
	case YSID_NS_MODULE:
		return (module_of(t, it->id, strlen(it->id)));
	case YSID_NS_DATA:
		/* The console's SID first: they are the same, mostly. */
		if ((n = cbl_yschema_node(t, it->sid)) != NULL &&
		    ysids_node_path(n, path, sizeof(path)) && strcmp(path,
		    it->id) == 0)
			return (n);
		return (walk(t, it->id));
	case YSID_NS_IDENTITY:
		if ((id = cbl_yschema_ident(t, it->sid)) != NULL &&
		    id->module != NULL && strcmp(id->name, it->id) == 0 &&
		    strcmp(id->module->name, it->module) == 0)
			return (id);
		for (uint32_t i = 0; i < t->nident; i++)
			if (t->ident[i].module != NULL && strcmp(t->ident[i].name,
			    it->id) == 0 && strcmp(t->ident[i].module->name,
			    it->module) == 0)
				return (&t->ident[i]);
		return (NULL);
	case YSID_NS_ANNOTATION:
		if ((an = cbl_yschema_annot(t, it->sid)) != NULL &&
		    strcmp(an->name, it->id) == 0 && strcmp(an->module->name,
		    it->module) == 0)
			return (an);
		for (uint32_t i = 0; i < t->nannot; i++)
			if (strcmp(t->annot[i]->name, it->id) == 0 &&
			    strcmp(t->annot[i]->module->name, it->module) == 0)
				return (t->annot[i]);
		return (NULL);
	default:
		return (NULL);
	}
}

int
ysids_done(struct ysids *s, char *why, size_t whylen)
{
	struct ysid_item	*it, key;
	const struct ysid_item	*p, *kp;
	size_t			 i, o, plen;

	if (s->done)
		return (0);
	/* By SID; a SID twice, the same item twice (a file given twice). */
	qsort(s->item, s->nitem, sizeof(*s->item), by_sid);
	for (i = o = 0; i < s->nitem; i++) {
		if (o > 0 && s->item[o - 1].sid == s->item[i].sid) {
			if (s->item[o - 1].ns == s->item[i].ns &&
			    strcmp(s->item[o - 1].id, s->item[i].id) == 0)
				continue;
			return (fail(why, whylen, "SID %" PRIu64 " is %s's and "
			    "%s's", s->item[i].sid, s->item[o - 1].id,
			    s->item[i].id));
		}
		s->item[o++] = s->item[i];
	}
	s->nitem = o;
	if ((s->byid = calloc(s->nitem + 1, sizeof(*s->byid))) == NULL ||
	    (s->bywhat = calloc(s->nitem + 1, sizeof(*s->bywhat))) == NULL)
		return (ENOMEM);
	for (i = 0; i < s->nitem; i++) {
		it = &s->item[i];
		it->name = it->id;
		it->nmod = it->module;
		if (it->ns == YSID_NS_DATA) {
			if (it->id[0] != '/')
				return (fail(why, whylen, "%s: not a path",
				    it->id));
			split_path(s, it, &plen);
		}
		if (it->name == NULL || it->nmod == NULL)
			return (ENOMEM);
		s->byid[i] = it;
		if ((it->what = resolve(s->types, it)) != NULL)
			s->bywhat[s->nwhat++] = it;
	}
	qsort(s->byid, s->nitem, sizeof(*s->byid), by_id);
	qsort(s->bywhat, s->nwhat, sizeof(*s->bywhat), by_what);
	/* Parents before their children, by path: each one's base. */
	for (i = 0; i < s->nitem; i++) {
		it = (struct ysid_item *)(uintptr_t)s->byid[i];
		if (it->ns != YSID_NS_DATA)
			continue;
		plen = (size_t)(strrchr(it->id, '/') - it->id);
		if (it->what != NULL) {
			const struct cbl_ynode *n = it->what;

			it->io = n->kind == CBL_YN_INPUT ||
			    n->kind == CBL_YN_OUTPUT;
		}
		if (plen == 0) {
			it->top = true;
			continue;
		}
		key.ns = YSID_NS_DATA;
		key.id = sdup(s, it->id, plen);
		key.module = it->module;
		kp = &key;
		if (key.id == NULL)
			return (ENOMEM);
		p = NULL;
		{
			const struct ysid_item **f = bsearch(&kp, s->byid,
			    s->nitem, sizeof(*s->byid), by_id);

			if (f != NULL)
				p = *f;
		}
		if (p == NULL)
			return (fail(why, whylen, "%s: no item for its parent",
			    it->id));
		if (it->what == NULL && p->what != NULL &&
		    (strcmp(it->name, "input") == 0 || strcmp(it->name,
		    "output") == 0)) {
			const struct cbl_ynode *pn = p->what;

			it->io = pn->kind == CBL_YN_RPC ||
			    pn->kind == CBL_YN_ACTION;
		}
		it->base = p->io ? p->base : p->sid;
	}
	s->done = true;
	return (0);
}

const struct ysid_item *
ysids_sid(const struct ysids *s, uint64_t sid)
{
	struct ysid_item key;

	if (s == NULL || !s->done)
		return (NULL);
	key.sid = sid;
	return (bsearch(&key, s->item, s->nitem, sizeof(*s->item), by_sid));
}

const struct ysid_item *
ysids_data(const struct ysids *s, const char *path)
{
	struct ysid_item	 key;
	const struct ysid_item	*kp = &key, **f;

	if (s == NULL || !s->done)
		return (NULL);
	key.ns = YSID_NS_DATA;
	key.id = path;
	key.module = "";
	f = bsearch(&kp, s->byid, s->nitem, sizeof(*s->byid), by_id);
	return (f != NULL ? *f : NULL);
}

const struct ysid_item *
ysids_named(const struct ysids *s, int ns, const char *module,
    const char *name)
{
	struct ysid_item	 key;
	const struct ysid_item	*kp = &key, **f;

	if (s == NULL || !s->done || ns == YSID_NS_DATA)
		return (NULL);
	key.ns = (uint8_t)ns;
	key.id = name;
	key.module = module;
	f = bsearch(&kp, s->byid, s->nitem, sizeof(*s->byid), by_id);
	return (f != NULL ? *f : NULL);
}

const struct ysid_item *
ysids_of(const struct ysids *s, const void *what)
{
	struct ysid_item	 key;
	const struct ysid_item	*kp = &key, **f;

	if (s == NULL || !s->done || what == NULL)
		return (NULL);
	key.what = what;
	f = bsearch(&kp, s->bywhat, s->nwhat, sizeof(*s->bywhat), by_what);
	return (f != NULL ? *f : NULL);
}

const struct ysid_mod *
ysids_mod(const struct ysids *s, const char *name)
{

	for (size_t i = 0; s != NULL && i < s->nmod; i++)
		if (strcmp(s->mod[i].name, name) == 0)
			return (&s->mod[i]);
	return (NULL);
}

size_t
ysids_nmod(const struct ysids *s)
{

	return (s != NULL ? s->nmod : 0);
}

const struct ysid_mod *
ysids_mod_at(const struct ysids *s, size_t i)
{

	return (s != NULL && i < s->nmod ? &s->mod[i] : NULL);
}

const char *
ysids_content_id(const struct ysids *s)
{

	return (s != NULL ? s->content_id : NULL);
}

size_t
ysids_count(const struct ysids *s)
{

	return (s != NULL ? s->nitem : 0);
}

const struct cbl_yschema *
ysids_types(const struct ysids *s)
{

	return (s != NULL ? s->types : NULL);
}
