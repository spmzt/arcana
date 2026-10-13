/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's storage: its ZFS pools with their devices, the datasets and
 * the snapshots; its disks with their partitions; what is mounted and
 * what fstab says to mount.  What is changed is a job for the host,
 * which checks every word of it; what cannot be taken back asks first,
 * and what destroys asks for the name to be typed.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

enum { SK_POOLS, SK_DATASETS, SK_SNAPSHOTS, SK_DISKS, SK_MOUNTS, SK_HEALTH,
    SK_N };
enum {
	SM_NONE, SM_SNAPSHOT, SM_DATASET, SM_PROPS, SM_CLONE, SM_PART_ADD,
	SM_PART_LABEL, SM_PART_RESIZE, SM_SCHEME, SM_FSTAB, SM_POOL_NEW,
	SM_POOL_ADD, SM_POOL_IMPORT, SM_VDEV_REPLACE, SM_VDEV_ATTACH,
	SM_ASK, SM_KEY,
};
/* What the box that asks for one word is asked for. */
enum { A_JAIL, A_UNJAIL, A_REPLICATE, A_NEWFS, A_SWAPON };

static const char *const kind_arg[SK_N] = { "pools", "datasets", "snapshots",
    "disks", "mounts", "health" };
static const char *const kind_title[SK_N] = { "Pools", "Datasets",
    "Snapshots", "Disks", "Mounts", "Health" };

static struct {
	char		 sid[9];
	int		 kind;
	ucl_object_t	*data[SK_N];
	bool		 loading[SK_N];
	bool		 cut[SK_N];	/* more than a reply carried */
	char		 error[SK_N][300];
	double		 fetched[SK_N];
	char		 of[256];	/* snapshots: of this dataset, or "" */
	int		 modal;
	int		 ask;		/* A_*: what SM_ASK asks for */
	char		 target[256];	/* what the box is about */
	char		 part[8];	/* a partition's index */
	char		 dev[256];	/* a pool's device */
	ucl_object_t	*importable;	/* pools that could be imported */
	bool		 importing;
	char		*fstab;		/* its text, as last read */
	char		 fstab_sha[65];
	char		*draft;		/* typed, kept over a refusal */
	bool		 saving;
	char		**sel;		/* the snapshots picked, to destroy */
	int		 nsel;
} sg;

#define	SEL_MAX		2000

static int
sel_find(const char *name)
{
	int	i;

	for (i = 0; i < sg.nsel; i++)
		if (strcmp(sg.sel[i], name) == 0)
			return (i);
	return (-1);
}

static void
sel_set(const char *name, bool on)
{
	int	i;

	i = sel_find(name);
	if (on && i == -1 && sg.nsel < SEL_MAX) {
		if ((sg.sel = reallocarray(sg.sel, (size_t)sg.nsel + 1,
		    sizeof(*sg.sel))) == NULL)
			abort();
		if ((sg.sel[sg.nsel++] = strdup(name)) == NULL)
			abort();
	} else if (!on && i != -1) {
		free(sg.sel[i]);
		sg.sel[i] = sg.sel[--sg.nsel];
	}
}

static void
sel_clear(void)
{

	while (sg.nsel > 0)
		free(sg.sel[--sg.nsel]);
}

/* Is the snapshot in the list now?  A picked one that went is let go. */
static bool
snap_there(const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(sg.data[SK_SNAPSHOTS],
	    "snapshots"), &it, true)) != NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (true);
	return (false);
}

static const struct tcol snap_cols[] = {
	{ "Snapshot", "name", false }, { "Used", "used", true },
	{ "Referenced", "refer", true }, { "Taken", "creation", true },
};

/*
 * Is it the newest snapshot of its dataset?  The host lists them the
 * newest first: the first of its dataset is.
 */
static bool
snap_newest(const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	const char		*n;
	size_t			 ds;

	ds = strcspn(name, "@");
	it = NULL;
	while ((o = ucl_object_iterate(jget(sg.data[SK_SNAPSHOTS],
	    "snapshots"), &it, true)) != NULL) {
		if ((n = jstr(o, "name")) == NULL || strncmp(n, name, ds) != 0 ||
		    n[ds] != '@')
			continue;
		return (strcmp(n, name) == 0);
	}
	return (false);
}

static void
size(char *buf, size_t len, int64_t n)
{
	static const char *const units[] = { "B", "KiB", "MiB", "GiB", "TiB",
	    "PiB" };
	double	v;
	int	u;

	v = (double)n;
	for (u = 0; v >= 1024 && u < 5; u++)
		v /= 1024;
	snprintf(buf, len, u == 0 ? "%.0f %s" : v < 10 ? "%.2f %s" :
	    v < 100 ? "%.1f %s" : "%.0f %s", v, units[u]);
}

struct sctx {
	char	sid[9];
	int	kind;
	char	of[256];
};

static void
storage_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct sctx	*c = arg;
	int		 k;

	k = c->kind;
	if (strcmp(c->sid, sg.sid) != 0 || (k == SK_SNAPSHOTS && strcmp(c->of,
	    sg.of) != 0)) {
		free(c);
		return;
	}
	free(c);
	sg.loading[k] = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(sg.error[k], sizeof(sg.error[k]), "%s", status ==
		    200 && jstr(o, "error") != NULL ? jstr(o, "error") :
		    err != NULL ? err : "no answer");
		return;
	}
	sg.error[k][0] = '\0';
	if (sg.data[k] != NULL)
		ucl_object_unref(sg.data[k]);
	sg.data[k] = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
	    "data"));
	sg.cut[k] = jbool(o, "truncated");
	sg.fetched[k] = arc_now();
}

/* Read the kind shown of the host's storage. */
void
refresh_storage(struct server *s, bool again)
{
	struct sctx	*c;
	char		 url[400];
	int		 k;

	if (!app.online)
		return;
	if (strcmp(sg.sid, s->id) != 0) {
		for (k = 0; k < SK_N; k++) {
			if (sg.data[k] != NULL)
				ucl_object_unref(sg.data[k]);
			sg.data[k] = NULL;
			sg.error[k][0] = '\0';
			sg.loading[k] = false;
		}
		sg.of[0] = '\0';
		free(sg.fstab);
		sg.fstab = NULL;
		snprintf(sg.sid, sizeof(sg.sid), "%s", s->id);
	}
	k = sg.kind;
	if (sg.loading[k] || (!again && (sg.data[k] != NULL ||
	    sg.error[k][0] != '\0')))
		return;
	sg.loading[k] = true;
	if ((c = calloc(1, sizeof(*c))) == NULL)
		abort();
	snprintf(c->sid, sizeof(c->sid), "%s", s->id);
	c->kind = k;
	snprintf(c->of, sizeof(c->of), "%s", sg.of);
	snprintf(url, sizeof(url), "/api/servers/%s/storage/%s%s%s", s->id,
	    kind_arg[k], k == SK_SNAPSHOTS && sg.of[0] != '\0' ? "?filter=" :
	    "", k == SK_SNAPSHOTS ? sg.of : "");
	api("GET", url, NULL, storage_cb, c);
}

/* A job of storage: kind, verb, flags as JSON members, then the words. */
static void
sjob(struct server *s, const char *kind, const char *verb, const char *flags,
    const char *target, int n, ...)
{
	struct html	 b;
	va_list		 ap;
	const char	*a;
	char		*q, title[300];
	int		 i;

	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\"kind\":\"%s\",\"verb\":\"%s\"%s,\"args\":[", kind, verb,
	    flags);
	snprintf(title, sizeof(title), "%s %s", strcmp(kind, "mount") == 0 ?
	    "" : kind, verb);
	va_start(ap, n);
	for (i = 0; i < n; i++) {
		a = va_arg(ap, const char *);
		q = json_quote(a);
		h_fmt(&b, "%s", i > 0 ? "," : "");
		h_raw(&b, q);
		free(q);
		if (strlen(title) + strlen(a) + 2 < sizeof(title)) {
			strcat(title, " ");
			strcat(title, a);
		}
	}
	va_end(ap);
	h_raw(&b, "]}");
	job_send_host(s, b.s, title[0] == ' ' ? title + 1 : title,
	    JOB_STORAGE, target);
}

/* The same, with the words in an array. */
static void
sjobv(struct server *s, const char *kind, const char *verb, const char *flags,
    const char *target, int n, const char **v)
{
	struct html	 b;
	char		*q, title[300];
	int		 i;

	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\"kind\":\"%s\",\"verb\":\"%s\"%s,\"args\":[", kind, verb,
	    flags);
	snprintf(title, sizeof(title), "%s %s", kind, verb);
	for (i = 0; i < n; i++) {
		q = json_quote(v[i]);
		h_fmt(&b, "%s", i > 0 ? "," : "");
		h_raw(&b, q);
		free(q);
		if (strlen(title) + strlen(v[i]) + 2 < sizeof(title)) {
			strcat(title, " ");
			strcat(title, v[i]);
		}
	}
	h_raw(&b, "]}");
	job_send_host(s, b.s, title, JOB_STORAGE, target);
}

/* Words separated by blanks or line ends, into v; how many, or -1. */
static int
words(char *text, const char **v, int max)
{
	char	*w;
	int	 n;

	n = 0;
	while ((w = strsep(&text, " \t\r\n,")) != NULL) {
		if (*w == '\0')
			continue;
		if (n == max || *w == '-')
			return (-1);
		v[n++] = w;
	}
	return (n);
}

static bool
name_ok(const char *s, const char *more)
{

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > 255)
		return (false);
	for (; *s != '\0'; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') || strchr(more, *s) != NULL))
			return (false);
	return (true);
}

static void
bar(struct html *h, int64_t used, int64_t total)
{
	double	pct;

	pct = total > 0 ? 100.0 * (double)used / (double)total : 0;
	h_fmt(h, "<span class=\"usage%s\"><i style=\"width:%.1f%%\"></i>"
	    "</span>", pct >= 90 ? " full" : pct >= 80 ? " high" : "", pct);
}

static void
view_pools(struct html *h)
{
	const ucl_object_t	*p, *v, *nx;
	ucl_object_iter_t	 it, vit;
	const char		*name, *health, *st;
	char			 a[32], b[32], both[400];
	int			 n, i, cnt;

	n = 0;
	it = NULL;
	while ((p = ucl_object_iterate(jget(sg.data[SK_POOLS], "pools"), &it,
	    true)) != NULL) {
		name = jstr(p, "name") != NULL ? jstr(p, "name") : "";
		if (app.filter[0] != '\0' && strstr(name, app.filter) == NULL)
			continue;
		n++;
		health = jstr(p, "health") != NULL ? jstr(p, "health") : "?";
		h_fmt(h, "<section class=\"pane pool %s\"", strcmp(health,
		    "ONLINE") == 0 ? "up" : "down");
		h_attr(h, "data-pool", name);
		h_raw(h, "><h4><span>");
		h_txt(h, name);
		h_fmt(h, " <small class=\"state %s\">", strcmp(health,
		    "ONLINE") == 0 ? "up" : "down");
		h_txt(h, health);
		h_raw(h, "</small></span><span class=\"pane-actions\">");
		{
			static const char *const vs[] = { "scrub", "scrub-stop",
			    "trim", "clear" };
			static const char *const ts[] = { "Scrub", "Stop scrub",
			    "Trim", "Clear errors" };

			for (i = 0; i < 4; i++) {
				h_fmt(h, "<button class=\"ghost small\" "
				    "data-act=\"st-zpool\" data-arg=\"%s\"",
				    vs[i]);
				h_attr(h, "data-value", name);
				h_fmt(h, ">%s</button>", ts[i]);
			}
		}
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "st-pool-add\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">+ devices</button><button class=\"ghost small\" "
		    "data-act=\"st-pool-export\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">Export</button><button class=\"icon\" data-act=\""
		    "st-pool-destroy\" title=\"Destroy the pool\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">×</button>");
		h_raw(h, "</span></h4><div class=\"poolbar\">");
		bar(h, jint(p, "alloc", 0), jint(p, "size", 0));
		size(a, sizeof(a), jint(p, "alloc", 0));
		size(b, sizeof(b), jint(p, "size", 0));
		h_fmt(h, "<span>%s of %s", a, b);
		size(a, sizeof(a), jint(p, "free", 0));
		h_fmt(h, " · %s free · %lld%% fragmented · dedup ", a,
		    (long long)jint(p, "frag", 0));
		h_txt(h, jstr(p, "dedup"));
		h_raw(h, "</span></div>");
		if (jstr(p, "scan") != NULL) {
			h_raw(h, "<p class=\"mono dim\">");
			h_txt(h, jstr(p, "scan"));
			h_raw(h, "</p>");
		}
		if (jstr(p, "status") != NULL) {
			h_raw(h, "<div class=\"notice bad\">");
			h_txt(h, jstr(p, "status"));
			if (jstr(p, "action") != NULL) {
				h_raw(h, " ");
				h_txt(h, jstr(p, "action"));
			}
			h_raw(h, "</div>");
		}
		h_raw(h, "<table class=\"net vdevs\"><thead><tr><th>Device</th>"
		    "<th>State</th><th>Read</th><th>Write</th><th>Checksum"
		    "</th><th></th></tr></thead><tbody>");
		cnt = (int)ucl_array_size(jget(p, "vdevs"));
		vit = NULL;
		i = 0;
		while ((v = ucl_object_iterate(jget(p, "vdevs"), &vit,
		    true)) != NULL) {
			st = jstr(v, "state") != NULL ? jstr(v, "state") : "";
			h_fmt(h, "<tr class=\"%s\"><td style=\"padding-left:"
			    "%.1frem\"><b>", strcmp(st, "ONLINE") == 0 ? "" :
			    "bad", 0.6 + 1.1 * (double)jint(v, "depth", 0));
			h_txt(h, jstr(v, "name"));
			h_raw(h, "</b>");
			if (jstr(v, "note") != NULL) {
				h_raw(h, " <small class=\"dim\">");
				h_txt(h, jstr(v, "note"));
				h_raw(h, "</small>");
			}
			h_raw(h, "</td><td>");
			h_txt(h, st);
			h_raw(h, "</td><td>");
			h_txt(h, jstr(v, "read"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(v, "write"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(v, "cksum"));
			h_raw(h, "</td><td class=\"acts\">");
			/* A device itself: nothing nested under it. */
			nx = i + 1 < cnt ? ucl_array_find_index(jget(p,
			    "vdevs"), (unsigned int)i + 1) : NULL;
			if (jint(v, "depth", 0) > 0 && (nx == NULL || jint(nx,
			    "depth", 0) <= jint(v, "depth", 0)) && jstr(v,
			    "name") != NULL) {
				h_fmt(h, "<button class=\"ghost small\" "
				    "data-act=\"st-vdev\" data-arg=\"%s\"",
				    strcmp(st, "OFFLINE") == 0 ? "online" :
				    "offline");
				/* The pool and the device, a space between. */
				snprintf(both, sizeof(both), "%s %s", name,
				    jstr(v, "name"));
				h_attr(h, "data-value", both);
				h_fmt(h, ">%s</button>", strcmp(st,
				    "OFFLINE") == 0 ? "Online" : "Offline");
				{
					static const char *const as[] = {
					    "replace", "attach", "detach" };
					static const char *const ts[] = {
					    "Replace", "Mirror", "Detach" };
					int k;

					for (k = 0; k < 3; k++) {
						h_fmt(h, "<button class=\"ghost "
						    "small\" data-act=\"st-vdev\" "
						    "data-arg=\"%s\"", as[k]);
						h_attr(h, "data-value", both);
						h_fmt(h, ">%s</button>", ts[k]);
					}
				}
			}
			h_raw(h, "</td></tr>");
			i++;
		}
		h_raw(h, "</tbody></table></section>");
	}
	if (n == 0)
		h_raw(h, "<div class=\"empty small\"><p>No ZFS pool.</p></div>");
}

static void
view_datasets(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Dataset", "name", false }, { "Used", "used", true },
		{ "Available", "avail", true }, { "Referenced", "refer", true },
		{ "Ratio", "ratio", false }, { "Mounted on", "mountpoint",
		false },
	};
	const ucl_object_t	**rows, *d;
	const char		*name, *p;
	char			 buf[32];
	int			 depth, n, r;
	bool			 vol, tree, enc, locked, jailed;

	h_raw(h, "<table class=\"net datasets\">");
	tbl_head(h, "datasets", cols, 6, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("datasets", jget(sg.data[SK_DATASETS], "datasets"),
	    cols, 6, app.filter);
	/* As a tree while in the host's order; by whole names once sorted. */
	tree = !tbl_sorted("datasets");
	n = 0;
	for (r = 0; (d = rows[r]) != NULL; r++) {
		name = jstr(d, "name") != NULL ? jstr(d, "name") : "";
		n++;
		depth = 0;
		for (p = name; *p != '\0'; p++)
			if (*p == '/')
				depth++;
		vol = jstr(d, "type") != NULL && strcmp(jstr(d, "type"),
		    "volume") == 0;
		h_raw(h, "<tr");
		h_attr(h, "data-ds", name);
		h_fmt(h, "><td style=\"padding-left:%.1frem\"><b>", 0.6 + (tree ?
		    0.9 * depth : 0));
		h_txt(h, tree && depth > 0 ? strrchr(name, '/') + 1 : name);
		h_raw(h, "</b>");
		if (vol) {
			size(buf, sizeof(buf), jint(d, "volsize", 0));
			h_fmt(h, " <span class=\"chip\">volume %s</span>", buf);
		}
		if (jstr(d, "origin") != NULL) {
			h_raw(h, " <small class=\"dim\">clone of ");
			h_txt(h, jstr(d, "origin"));
			h_raw(h, "</small>");
		}
		if (jstr(d, "readonly") != NULL && strcmp(jstr(d, "readonly"),
		    "on") == 0)
			h_raw(h, " <span class=\"chip\">read-only</span>");
		enc = jstr(d, "encryption") != NULL && strcmp(jstr(d,
		    "encryption"), "off") != 0 && strcmp(jstr(d, "encryption"),
		    "-") != 0;
		locked = enc && jstr(d, "keystatus") != NULL && strcmp(jstr(d,
		    "keystatus"), "unavailable") == 0;
		jailed = jstr(d, "jailed") != NULL && strcmp(jstr(d, "jailed"),
		    "on") == 0;
		if (enc) {
			h_fmt(h, " <span class=\"chip%s\"", locked ? " warn" :
			    "");
			h_attr(h, "title", jstr(d, "keylocation"));
			h_fmt(h, ">encrypted · key %s</span>", locked ?
			    "not loaded" : "loaded");
		}
		if (jailed)
			h_raw(h, " <span class=\"chip\" title=\"A jail it was "
			    "given to manages it as its own\">jailed</span>");
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(d, "used", 0));
		h_txt(h, buf);
		if (jint(d, "quota", 0) > 0) {
			h_raw(h, " ");
			bar(h, jint(d, "used", 0), jint(d, "quota", 0));
		}
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(d, "avail", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(d, "refer", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(d, "ratio"));
		h_raw(h, "×</td><td class=\"mono\">");
		if (!vol) {
			h_txt(h, jstr(d, "mountpoint"));
			if (jstr(d, "mounted") != NULL && strcmp(jstr(d,
			    "mounted"), "yes") != 0)
				h_raw(h, " <small class=\"dim\">not mounted"
				    "</small>");
		}
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\""
		    " data-act=\"st-snapshot\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">Snapshot</button><button class=\"ghost small\" "
		    "data-act=\"st-snaps-of\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">Snapshots</button><button class=\"ghost small\" "
		    "data-act=\"st-props\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">Set</button>");
		if (!vol) {
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "st-zfs-mount\" data-arg=\"%s\"", jstr(d,
			    "mounted") != NULL && strcmp(jstr(d, "mounted"),
			    "yes") == 0 ? "unmount" : "mount");
			h_attr(h, "data-value", name);
			h_fmt(h, ">%s</button>", jstr(d, "mounted") != NULL &&
			    strcmp(jstr(d, "mounted"), "yes") == 0 ?
			    "Unmount" : "Mount");
		}
		/* A key asked for at a prompt: typed here, and changed. */
		if (enc && jstr(d, "keylocation") != NULL && strcmp(jstr(d,
		    "keylocation"), "prompt") == 0) {
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "st-typekey\" data-arg=\"%s\"", locked ? "load" :
			    "change");
			h_attr(h, "data-value", name);
			h_fmt(h, " title=\"%s\">%s</button>", locked ? "Its key "
			    "is asked for at a prompt: type it" : "A new key, "
			    "asked for at a prompt as this one is", locked ?
			    "Type the key" : "Change key");
		}
		if (enc && !(locked && jstr(d, "keylocation") != NULL &&
		    strcmp(jstr(d, "keylocation"), "prompt") == 0)) {
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "st-key\" data-arg=\"%s\"", locked ? "load-key" :
			    "unload-key");
			h_attr(h, "data-value", name);
			h_fmt(h, " title=\"%s\">%s</button>", locked ? "Read "
			    "its key from where its keylocation says" :
			    "Forget its key: it is unmounted first, and "
			    "cannot be read until the key is loaded again",
			    locked ? "Load key" : "Unload key");
		}
		if (depth > 0) {
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "st-ask\" data-arg=\"%s\"", jailed ? "unjail" :
			    "jail");
			h_attr(h, "data-value", name);
			h_fmt(h, " title=\"%s\">%s</button>", jailed ? "Take "
			    "it back from the jail it was given to" : "Give "
			    "it to a running jail, to manage as its own",
			    jailed ? "Unjail" : "Jail");
		}
		if (depth > 0) {
			h_raw(h, "<button class=\"icon\" data-act=\""
			    "st-destroy\" title=\"Destroy it\"");
			h_attr(h, "data-arg", name);
			h_raw(h, ">×</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (n == 0)
		h_raw(h, "<div class=\"empty small\"><p>No dataset.</p></div>");
}

static void
view_snapshots(struct html *h)
{
	const struct tcol	*cols = snap_cols;
	const ucl_object_t	**rows, *o;
	const char		*name;
	char			 buf[32], when[32];
	int			 n, r, all, newest;

	if (sg.of[0] != '\0') {
		h_raw(h, "<div class=\"notice info\">Snapshots of <b>");
		h_txt(h, sg.of);
		h_raw(h, "</b> and those under it. <button class=\"ghost small\""
		    " data-act=\"st-snaps-of\" data-arg=\"\">All</button> "
		    "<button class=\"ghost small\" data-act=\"st-snapshot\"");
		h_attr(h, "data-arg", sg.of);
		h_raw(h, ">Snapshot now</button></div>");
	}
	/* What was picked and is gone since is no longer picked. */
	for (r = sg.nsel - 1; r >= 0; r--)
		if (!snap_there(sg.sel[r]))
			sel_set(sg.sel[r], false);
	rows = tbl_rows("snapshots", jget(sg.data[SK_SNAPSHOTS], "snapshots"),
	    cols, 4, app.filter);
	for (n = 0, all = 0; rows[n] != NULL; n++)
		if (jstr(rows[n], "name") != NULL && sel_find(jstr(rows[n],
		    "name")) != -1)
			all++;
	h_fmt(h, "<div class=\"selbar%s\"><label class=\"toggle\" title=\""
	    "Pick every snapshot shown, as the filter leaves them\"><input "
	    "type=\"checkbox\" data-act=\"st-sel-all\"%s%s><span>%s</span>"
	    "</label>", sg.nsel > 0 ? " on" : "", n > 0 && all == n ?
	    " checked" : "", n == 0 ? " disabled" : "", app.filter[0] !=
	    '\0' ? "All shown" : "All");
	for (r = 0, newest = 0; r < sg.nsel; r++)
		if (snap_newest(sg.sel[r]))
			newest++;
	if (sg.nsel > 0) {
		h_fmt(h, "<b>%d</b> picked<button class=\"small danger\" "
		    "data-act=\"st-destroy-sel\">Destroy %d</button>",
		    sg.nsel, sg.nsel);
		/* Only the newest of a dataset is made again. */
		if (newest > 0)
			h_fmt(h, "<button class=\"small\" data-act=\""
			    "st-resnap-sel\" title=\"Each picked that is the "
			    "newest of its dataset, taken again now under its "
			    "name\">Resnapshot %d</button>", newest);
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "st-sel-none\">Clear</button>");
	} else
		h_raw(h, "<span class=\"dim\">Pick snapshots to destroy or "
		    "take them again at once; the filter narrows what All "
		    "picks: a dataset's name, or a date.</span>");
	if (n > 0)
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "st-sel-newest\" title=\"Pick the newest snapshot of "
		    "each dataset shown\">Pick the newest</button>");
	h_raw(h, "</div>");
	h_raw(h, "<table class=\"net snapshots\">");
	tbl_head(h, "snapshots", cols, 4, 1);
	h_raw(h, "<tbody>");
	n = 0;
	for (r = 0; (o = rows[r]) != NULL; r++) {
		name = jstr(o, "name") != NULL ? jstr(o, "name") : "";
		n++;
		h_fmt(h, "<tr%s", sel_find(name) != -1 ? " class=\"picked\"" :
		    "");
		h_attr(h, "data-snap", name);
		h_raw(h, "><td class=\"mono\"><input type=\"checkbox\" "
		    "class=\"pick\" data-act=\"st-sel\"");
		h_attr(h, "data-arg", name);
		h_raw(h, sel_find(name) != -1 ? " checked>" : ">");
		h_txt(h, name);
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(o, "used", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(o, "refer", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td class=\"dim\">");
		fmt_age(when, sizeof(when), (double)jint(o, "creation", 0) *
		    1000.0);
		h_txt(h, when);
		h_raw(h, "</td><td class=\"acts\">");
		/* The newest of its dataset: made again, now. */
		if (snap_newest(name)) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "st-resnap\" title=\"Destroy it and take it again, "
			    "now, under the same name\"");
			h_attr(h, "data-arg", name);
			h_raw(h, ">Resnapshot</button>");
		}
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "st-rollback\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">Roll back</button><button class=\"ghost small\" "
		    "data-act=\"st-clone\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">Clone</button><button class=\"ghost small\" "
		    "data-act=\"st-ask\" data-arg=\"replicate\" title=\"Send "
		    "it into a new dataset of this host, another pool's "
		    "say: zfs send into zfs receive\"");
		h_attr(h, "data-value", name);
		h_raw(h, ">Replicate</button><button class=\"icon\" data-act=\""
		    "st-destroy\" title=\"Destroy it\"");
		h_attr(h, "data-arg", name);
		h_raw(h, ">×</button></td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (n == 0)
		h_raw(h, "<div class=\"empty small\"><p>No snapshot.</p></div>");
	if (sg.cut[SK_SNAPSHOTS])
		h_raw(h, "<p class=\"dim\">There are more: these are the "
		    "newest. Pick a dataset's <b>Snapshots</b> for its own."
		    "</p>");
}

static void
view_disks(struct html *h)
{
	static const struct tcol pcols[] = {
		{ "#", "index", true }, { "Partition", "name", false },
		{ "Type", "type", false }, { "Label", "label", false },
		{ "Size", "size", true }, { "Mounted on", "mounted", false },
	};
	const ucl_object_t	**rows, *d, *p;
	ucl_object_iter_t	 it, pit;
	const char		*name, *type;
	char			 buf[32], both[120];
	int64_t			 total, sect, first, last, pos, start, end;
	int			 n, np, r;

	n = 0;
	it = NULL;
	while ((d = ucl_object_iterate(jget(sg.data[SK_DISKS], "disks"), &it,
	    true)) != NULL) {
		name = jstr(d, "name") != NULL ? jstr(d, "name") : "";
		if (app.filter[0] != '\0' && strstr(name, app.filter) == NULL)
			continue;
		n++;
		total = jint(d, "size", 0);
		sect = jint(d, "sectorsize", 512);
		np = (int)ucl_array_size(jget(d, "parts"));
		h_raw(h, "<section class=\"pane disk\"");
		h_attr(h, "data-disk", name);
		h_raw(h, "><h4><span>");
		h_txt(h, name);
		size(buf, sizeof(buf), total);
		h_fmt(h, " <small>%s", buf);
		if (jstr(d, "descr") != NULL) {
			h_raw(h, " · ");
			h_txt(h, jstr(d, "descr"));
		}
		if (jstr(d, "rotation") != NULL)
			h_fmt(h, " · %s", strcmp(jstr(d, "rotation"), "0") ==
			    0 ? "solid state" : "rotating");
		h_raw(h, "</small></span><span class=\"pane-actions\">");
		if (jstr(d, "scheme") == NULL) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "st-scheme\"");
			h_attr(h, "data-arg", name);
			h_raw(h, ">Create a partition table</button>");
		} else {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "st-part-add\"");
			h_attr(h, "data-arg", name);
			h_raw(h, ">+ partition</button>");
			if (np == 0) {
				h_raw(h, "<button class=\"ghost small\" "
				    "data-act=\"st-scheme-destroy\"");
				h_attr(h, "data-arg", name);
				h_raw(h, ">Destroy the table</button>");
			}
		}
		h_raw(h, "</span></h4>");
		if (jstr(d, "cam") != NULL || jstr(d, "ident") != NULL) {
			h_raw(h, "<p class=\"mono dim\">");
			h_txt(h, jstr(d, "cam"));
			if (jstr(d, "ident") != NULL && jstr(d, "ident")[0] !=
			    '\0') {
				h_raw(h, " serial ");
				h_txt(h, jstr(d, "ident"));
			}
			h_raw(h, "</p>");
		}
		if (jstr(d, "scheme") == NULL) {
			h_raw(h, "<p class=\"dim\">No partition table: used "
			    "whole, or not at all.</p></section>");
			continue;
		}
		/* The table drawn: partitions, and the room between them. */
		first = jint(d, "first", 0);
		last = jint(d, "last", 0);
		h_raw(h, "<div class=\"partbar\">");
		pos = first;
		pit = NULL;
		while (last > first && (p = ucl_object_iterate(jget(d,
		    "parts"), &pit, true)) != NULL) {
			start = jint(p, "start", 0);
			end = jint(p, "end", 0);
			if (start > pos + 2048)
				h_fmt(h, "<i class=\"free\" style=\"flex:%lld\""
				    " title=\"free\"></i>", (long long)(start -
				    pos));
			type = jstr(p, "type") != NULL ? jstr(p, "type") : "";
			h_fmt(h, "<i class=\"p %s\" style=\"flex:%lld\"",
			    strstr(type, "zfs") != NULL ? "zfs" : strstr(type,
			    "swap") != NULL ? "swap" : strstr(type, "efi") !=
			    NULL || strstr(type, "boot") != NULL ? "boot" :
			    "other", (long long)(end - start + 1));
			h_attr(h, "title", jstr(p, "name"));
			h_raw(h, "></i>");
			pos = end + 1;
		}
		if (last > pos + 2048)
			h_fmt(h, "<i class=\"free\" style=\"flex:%lld\" title="
			    "\"free\"></i>", (long long)(last - pos));
		h_raw(h, "</div><table class=\"net parts\">");
		tbl_head(h, "parts", pcols, 6, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows("parts", jget(d, "parts"), pcols, 6, NULL);
		for (r = 0; (p = rows[r]) != NULL; r++) {
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(p,
			    "index", 0));
			h_fmt(h, "<tr><td class=\"dim\">%s</td><td><b>", buf);
			h_txt(h, jstr(p, "name"));
			h_raw(h, "</b></td><td>");
			h_txt(h, jstr(p, "type"));
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(p, "label"));
			h_raw(h, "</td><td>");
			size(buf, sizeof(buf), jint(p, "size", 0));
			h_txt(h, buf);
			h_raw(h, "</td><td class=\"mono\">");
			h_txt(h, jstr(p, "mounted"));
			h_raw(h, "</td><td class=\"acts\">");
			snprintf(buf, sizeof(buf), "%lld", (long long)jint(p,
			    "index", 0));
			{
				static const char *const as[] = {
				    "st-part-label", "st-part-resize" };
				static const char *const ts[] = { "Label",
				    "Resize" };
				int k;

				for (k = 0; k < 2; k++) {
					h_fmt(h, "<button class=\"ghost small\""
					    " data-act=\"%s\"", as[k]);
					h_attr(h, "data-arg", name);
					h_attr(h, "data-value", buf);
					h_fmt(h, ">%s</button>", ts[k]);
				}
				/* UFS on it: made, or grown to its size. */
				if (jstr(p, "type") != NULL && strcmp(jstr(p,
				    "type"), "freebsd-ufs") == 0 && jstr(p,
				    "name") != NULL) {
					h_raw(h, "<button class=\"ghost small\" "
					    "data-act=\"st-ask\" data-arg=\""
					    "newfs\" title=\"Make a UFS file "
					    "system on it: newfs\"");
					h_attr(h, "data-value", jstr(p, "name"));
					h_raw(h, ">newfs</button><button class="
					    "\"ghost small\" data-act=\""
					    "st-growfs\" title=\"Grow its file "
					    "system to the partition's size: "
					    "growfs\"");
					h_attr(h, "data-arg", jstr(p, "name"));
					h_raw(h, ">growfs</button>");
				}
			}
			h_raw(h, "<button class=\"icon\" data-act=\""
			    "st-part-delete\" title=\"Delete the partition\"");
			h_attr(h, "data-arg", name);
			/* Its index and its name, a space between. */
			snprintf(both, sizeof(both), "%s %s", buf, jstr(p,
			    "name") != NULL ? jstr(p, "name") : "");
			h_attr(h, "data-value", both);
			h_raw(h, ">×</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table><p class=\"dim\">");
		h_txt(h, jstr(d, "scheme"));
		size(buf, sizeof(buf), (last - pos > 0 ? last - pos : 0) *
		    sect);
		h_fmt(h, " · %d partition%s · %s free at the end</p></section>",
		    np, np == 1 ? "" : "s", buf);
	}
	if (n == 0)
		h_raw(h, "<div class=\"empty small\"><p>No disk.</p></div>");
}

/* The swap the host has, and a device more for it. */
static void
view_swap(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Device", "device", false }, { "Size", "size", true },
		{ "Used", "used", true },
	};
	const ucl_object_t	**rows, *o;
	char			  buf[32];
	int			  r;

	h_raw(h, "<h4 class=\"family\">Swap <button class=\"ghost small\" "
	    "data-act=\"st-ask\" data-arg=\"swapon\" data-value=\"\" title="
	    "\"Swap on a device too: swapon\">+ swap</button></h4><table "
	    "class=\"net swap\">");
	tbl_head(h, "swap", cols, 3, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("swap", jget(sg.data[SK_MOUNTS], "swap"), cols, 3,
	    app.filter);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td class=\"mono\"><b>");
		h_txt(h, jstr(o, "device"));
		h_raw(h, "</b></td><td>");
		size(buf, sizeof(buf), jint(o, "size", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(o, "used", 0));
		h_txt(h, buf);
		h_raw(h, " ");
		bar(h, jint(o, "used", 0), jint(o, "size", 0));
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"st-swapoff\"");
		h_attr(h, "data-arg", jstr(o, "device"));
		h_raw(h, ">Swap off</button></td></tr>");
	}
	if (r == 0)
		h_raw(h, "<tr><td colspan=\"4\" class=\"dim\">The host swaps "
		    "on nothing.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table><p class=\"dim\">What is swapped on now. "
	    "For the next start it is a line of fstab, which <b>fstab</b> "
	    "above edits.</p>");
}

/* How each disk says it is. */
static void
view_health(struct html *h)
{
	static const struct tcol cols[] = {
		{ "Disk", "name", false }, { "It says", "ok", false },
		{ "Temperature", "temperature", true },
		{ "Powered on", "power_on_hours", true },
		{ "Worn", "used_pct", true }, { "Errors", NULL, false },
		{ "Asked with", "by", false },
	};
	static const struct {
		const char	*key, *title;
	} errs[] = {
		{ "media_errors", "media errors" },
		{ "reallocated", "reallocated sectors" },
		{ "pending", "sectors pending" },
		{ "uncorrectable", "uncorrectable" },
		{ "crc_errors", "CRC errors" },
		{ "unsafe_shutdowns", "unsafe shutdowns" },
	};
	const ucl_object_t	**rows, *o;
	size_t			  i;
	int			  r, n;

	h_raw(h, "<table class=\"net health\">");
	tbl_head(h, "health", cols, 7, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("health", jget(sg.data[SK_HEALTH], "disks"), cols, 7,
	    app.filter);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</b></td><td>");
		if (jget(o, "ok") != NULL)
			h_fmt(h, "<span class=\"chip %s\">%s</span>", jbool(o,
			    "ok") ? "ok" : "bad", jbool(o, "ok") ? "well" :
			    "failing");
		else {
			h_raw(h, "<small class=\"dim\">");
			h_txt(h, jstr(o, "note"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		if (jget(o, "temperature") != NULL)
			h_fmt(h, "%lld °C", (long long)jint(o, "temperature",
			    0));
		h_raw(h, "</td><td>");
		if (jget(o, "power_on_hours") != NULL)
			h_fmt(h, "%.1f years <small class=\"dim\">%lld h, %lld "
			    "starts</small>", (double)jint(o, "power_on_hours",
			    0) / 8766, (long long)jint(o, "power_on_hours", 0),
			    (long long)jint(o, "power_cycles", 0));
		h_raw(h, "</td><td>");
		if (jget(o, "used_pct") != NULL)
			h_fmt(h, "%lld%% <small class=\"dim\">spare %lld%%"
			    "</small>", (long long)jint(o, "used_pct", 0),
			    (long long)jint(o, "spare_pct", 0));
		else if (jget(o, "life_left") != NULL)
			h_fmt(h, "%lld%% left", (long long)jint(o, "life_left",
			    0));
		else if (jget(o, "wear_level") != NULL)
			h_fmt(h, "wear level %lld", (long long)jint(o,
			    "wear_level", 0));
		h_raw(h, "</td><td>");
		n = 0;
		for (i = 0; i < sizeof(errs) / sizeof(errs[0]); i++)
			if (jint(o, errs[i].key, 0) > 0) {
				h_fmt(h, "<span class=\"chip%s\">%lld %s</span> ",
				    i < 4 ? " warn" : "", (long long)jint(o,
				    errs[i].key, 0), errs[i].title);
				n++;
			}
		if (n == 0 && jget(o, "ok") != NULL)
			h_raw(h, "<small class=\"dim\">none</small>");
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(o, "by"));
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table><p class=\"dim\">An NVMe disk is asked "
	    "with <code>nvmecontrol logpage -p 2</code>; any other with "
	    "<code>smartctl</code> of smartmontools, when the host has it. "
	    "The agent has to be root to ask.</p>");
}

static void
view_mounts(struct html *h)
{
	static const struct tcol mcols[] = {
		{ "Mounted on", "on", false }, { "From", "from", false },
		{ "Type", "type", false }, { "Used", "used", true },
		{ "Options", "options", false },
	};
	static const struct tcol fcols[] = {
		{ "Mount point", "file", false }, { "Device", "spec", false },
		{ "Type", "vfstype", false }, { "Options", "mntops", false },
		{ "Dump", "freq", true }, { "Pass", "passno", true },
	};
	const ucl_object_t	**rows, *m;
	const char		*on;
	char			 a[32], b[32];
	int			 r;

	h_raw(h, "<table class=\"net mounts\">");
	tbl_head(h, "mounts", mcols, 5, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("mounts", jget(sg.data[SK_MOUNTS], "mounts"), mcols, 5,
	    app.filter);
	for (r = 0; (m = rows[r]) != NULL; r++) {
		on = jstr(m, "on") != NULL ? jstr(m, "on") : "";
		h_raw(h, "<tr><td class=\"mono\"><b>");
		h_txt(h, on);
		h_raw(h, "</b></td><td class=\"mono\">");
		h_txt(h, jstr(m, "from"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(m, "type"));
		h_raw(h, "</td><td>");
		if (jint(m, "size", 0) > 0) {
			bar(h, jint(m, "used", 0), jint(m, "size", 0));
			size(a, sizeof(a), jint(m, "used", 0));
			size(b, sizeof(b), jint(m, "size", 0));
			h_fmt(h, " %s of %s", a, b);
		}
		h_raw(h, "</td><td class=\"dim\">");
		h_txt(h, jstr(m, "options"));
		h_raw(h, "</td><td class=\"acts\">");
		if (strcmp(on, "/") != 0) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "st-umount\"");
			h_attr(h, "data-arg", on);
			h_raw(h, ">Unmount</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table><h4 class=\"family\">fstab <button class=\""
	    "ghost small\" data-act=\"st-fstab\">Edit</button></h4><table "
	    "class=\"net fstab\">");
	tbl_head(h, "fstab", fcols, 6, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("fstab", jget(sg.data[SK_MOUNTS], "fstab"), fcols, 6,
	    app.filter);
	for (r = 0; (m = rows[r]) != NULL; r++) {
		on = jstr(m, "file") != NULL ? jstr(m, "file") : "";
		h_raw(h, "<tr");
		h_attr(h, "data-fs", on);
		h_raw(h, "><td class=\"mono\"><b>");
		h_txt(h, on);
		h_raw(h, "</b></td><td class=\"mono\">");
		h_txt(h, jstr(m, "spec"));
		h_raw(h, "</td><td>");
		h_txt(h, jstr(m, "vfstype"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(m, "mntops"));
		h_fmt(h, "</td><td>%lld</td><td>%lld</td><td class=\"acts\">",
		    (long long)jint(m, "freq", 0), (long long)jint(m, "passno",
		    0));
		if (on[0] == '/' && !jbool(m, "mounted")) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "st-mount\"");
			h_attr(h, "data-arg", on);
			h_raw(h, ">Mount</button>");
		} else if (jbool(m, "mounted"))
			h_raw(h, "<span class=\"chip\">mounted</span>");
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	view_swap(h);
}

/*
 * Snapshots sent to another host, or from one: what the console says
 * of them (/api/transfers), read again every two seconds while one of
 * this host's runs, and when the tab is opened.
 */
static ucl_object_t	*xfers;
static double		 xfers_at;
static bool		 xfers_loading;

static void
xfers_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	xfers_loading = false;
	if (status != 200)
		return;
	if (xfers != NULL)
		ucl_object_unref(xfers);
	xfers = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
}

static void
xfers_load(void)
{

	if (xfers_loading)
		return;
	xfers_loading = true;
	xfers_at = arc_now();
	api("GET", "/api/transfers", NULL, xfers_cb, NULL);
}

static const char *
server_name(const char *sid)
{
	int	k;

	for (k = 0; sid != NULL && k < app.nservers; k++)
		if (strcmp(app.servers[k].id, sid) == 0)
			return (app.servers[k].name);
	return (sid != NULL ? sid : "?");
}

/* Is one of this host's running? */
static bool
xfers_running(const char *sid)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(xfers, "transfers"), &it, true)) !=
	    NULL)
		if (jstr(o, "state") != NULL && strcmp(jstr(o, "state"),
		    "running") == 0 && (strcmp(jstr(o, "from") != NULL ?
		    jstr(o, "from") : "", sid) == 0 || strcmp(jstr(o, "to") !=
		    NULL ? jstr(o, "to") : "", sid) == 0))
			return (true);
	return (false);
}

void
storage_tick(double now)
{
	struct server	*s;

	if (app.node != NODE_HOST || app.tab != TAB_STORAGE || (s =
	    cur_server()) == NULL)
		return;
	if (xfers == NULL ? now - xfers_at > 10000 : xfers_running(s->id) &&
	    now - xfers_at > 2000)
		xfers_load();
}

static void
view_transfers(struct html *h, struct server *s)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	const char		*st;
	char			 size[24];
	int			 n;

	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(xfers, "transfers"), &it, true)) !=
	    NULL) {
		bool	out;

		out = jstr(o, "from") != NULL && strcmp(jstr(o, "from"),
		    s->id) == 0;
		if (!out && (jstr(o, "to") == NULL || strcmp(jstr(o, "to"),
		    s->id) != 0))
			continue;
		if (n++ == 0)
			h_raw(h, "<section class=\"pane xfers\"><h4><span>"
			    "Sent between hosts</span></h4><ul class=\"xfers\">");
		st = jstr(o, "state") != NULL ? jstr(o, "state") : "?";
		fmt_size(size, sizeof(size), jnum(o, "bytes", 0));
		h_fmt(h, "<li class=\"%s\"><b>", st);
		h_txt(h, jstr(o, "snapshot"));
		h_raw(h, "</b>");
		if (jstr(o, "since") != NULL) {
			h_raw(h, " <small>since ");
			h_txt(h, strchr(jstr(o, "since"), '@') != NULL ?
			    strchr(jstr(o, "since"), '@') : jstr(o, "since"));
			h_raw(h, "</small>");
		}
		h_raw(h, out ? " → " : " ← ");
		h_txt(h, server_name(out ? jstr(o, "to") : jstr(o, "from")));
		if (out) {
			h_raw(h, " <code>");
			h_txt(h, jstr(o, "dataset"));
			h_raw(h, "</code>");
		}
		h_raw(h, "<span class=\"dim\">");
		h_txt(h, st);
		h_raw(h, " · ");
		h_txt(h, size);
		h_raw(h, "</span>");
		if (jstr(o, "error") != NULL) {
			h_raw(h, "<small class=\"bad\">");
			h_txt(h, jstr(o, "error"));
			h_raw(h, "</small>");
		}
		if (strcmp(st, "running") == 0) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "st-xfer-stop\"");
			h_attr(h, "data-arg", jstr(o, "id"));
			h_raw(h, ">Stop</button>");
		}
		h_raw(h, "</li>");
	}
	if (n > 0)
		h_raw(h, "</ul></section>");
}

static void
xfer_started_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200)
		toast(true, "Not sent: %s", jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err : "no answer");
	else
		toast(false, "Sending: it is listed under Storage");
	xfers_load();
}

static void
xfers_stopped_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{

	(void)arg;
	if (status != 200)
		toast(true, "Not stopped: %s", jstr(o, "error.message") !=
		    NULL ? jstr(o, "error.message") : err != NULL ? err :
		    "no answer");
	xfers_load();
}

/* A snapshot to another host: the console carries it. */
static void
transfer_start(struct server *s, const char *to, const char *snap,
    const char *since, const char *dataset, bool recursive)
{
	char	*qf, *qt, *qs, *qi, *qd, *body;

	qf = json_quote(s->id);
	qt = json_quote(to);
	qs = json_quote(snap);
	qi = json_quote(since != NULL ? since : "");
	qd = json_quote(dataset);
	if (asprintf(&body, "{\"from\":%s,\"to\":%s,\"snapshot\":%s,"
	    "\"since\":%s,\"dataset\":%s,\"recursive\":%s}", qf, qt, qs, qi,
	    qd, recursive ? "true" : "false") == -1)
		abort();
	free(qf);
	free(qt);
	free(qs);
	free(qi);
	free(qd);
	api("POST", "/api/transfers", body, xfer_started_cb, NULL);
	free(body);
	app.modal = MODAL_NONE;
}

void
view_storage(struct html *h, struct server *s)
{
	char	age[32];
	int	k;
	bool	mine;

	k = sg.kind;
	mine = sg.data[k] != NULL && strcmp(sg.sid, s->id) == 0;
	h_raw(h, "<div class=\"toolbar\"><nav class=\"sub\">");
	for (k = 0; k < SK_N; k++)
		h_fmt(h, "<button class=\"ghost small%s\" data-act=\"st-kind\" "
		    "data-arg=\"%s\">%s</button>", sg.kind == k ? " on" : "",
		    kind_arg[k], kind_title[k]);
	h_raw(h, "</nav>");
	k = sg.kind;
	if (k == SK_DATASETS)
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "st-dataset\">+ dataset</button>");
	if (k == SK_POOLS)
		h_raw(h, "<button class=\"ghost small\" data-act=\""
		    "st-pool-new\">+ pool</button><button class=\"ghost "
		    "small\" data-act=\"st-pool-import\" title=\"Pools on "
		    "this host's devices that are not imported\">Import"
		    "</button>");
	if (k == SK_DISKS)
		h_raw(h, "<button class=\"ghost small\" data-act=\"st-rescan\""
		    " title=\"camcontrol rescan all: look for disks that "
		    "came or went\">Rescan</button>");
	h_raw(h, "<input class=\"filter\" id=\"filter\" data-input=\"filter\" "
	    "placeholder=\"Filter\" autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, ">");
	if (mine) {
		fmt_age(age, sizeof(age), sg.fetched[k]);
		h_raw(h, "<span class=\"tally\">");
		h_txt(h, age);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div>");
	view_transfers(h, s);
	if (sg.error[k][0] != '\0' && strcmp(sg.sid, s->id) == 0) {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sg.error[k]);
		h_raw(h, "</div>");
	}
	if (!mine) {
		h_raw(h, sg.loading[k] ? "<div class=\"empty\"><div class=\""
		    "loader\"></div></div>" : "<div class=\"empty\"><h2>No "
		    "data</h2><p>The host has not answered yet.</p></div>");
		return;
	}
	switch (k) {
	case SK_POOLS:
		view_pools(h);
		break;
	case SK_DATASETS:
		view_datasets(h);
		break;
	case SK_SNAPSHOTS:
		view_snapshots(h);
		break;
	case SK_DISKS:
		view_disks(h);
		break;
	case SK_HEALTH:
		view_health(h);
		break;
	default:
		view_mounts(h);
		break;
	}
}

static void
fstab_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	save;

	save = arg != NULL;
	sg.saving = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    status == 200 && jstr(o, "error") != NULL ? jstr(o,
		    "error") : err != NULL ? err : "no answer");
		return;
	}
	if (jstr(o, "text") != NULL) {
		free(sg.fstab);
		sg.fstab = strdup(jstr(o, "text"));
		snprintf(sg.fstab_sha, sizeof(sg.fstab_sha), "%s", jstr(o,
		    "sha256") != NULL ? jstr(o, "sha256") : "");
	}
	if (save) {
		free(sg.draft);
		sg.draft = NULL;
		app.modal = MODAL_NONE;
		toast(false, "fstab is in place; the one before is kept "
		    "beside it");
		if (cur_server() != NULL)
			refresh_storage(cur_server(), true);
	}
}

static void
import_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	sg.importing = false;
	if (sg.importable != NULL)
		ucl_object_unref(sg.importable);
	sg.importable = NULL;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "%s",
		    status == 200 && jstr(o, "error") != NULL ? jstr(o,
		    "error") : err != NULL ? err : "no answer");
		return;
	}
	sg.importable = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
	    "data"));
}

/* The boxes of storage: true when the one open is one of them. */
bool
storage_modal(struct html *h)
{
	static const char *const types[] = { "freebsd-zfs", "freebsd-ufs",
	    "freebsd-swap", "efi", "freebsd-boot", "freebsd", "linux-data",
	    "ms-basic-data" };
	char	 name[80];
	time_t	 t;
	size_t	 i;

	if (app.modal != MODAL_STORAGE)
		return (false);
	switch (sg.modal) {
	case SM_ASK:
		h_raw(h, "<form data-form=\"st-ask\"><h2>");
		h_txt(h, sg.ask == A_JAIL ? "Give to a jail: " : sg.ask ==
		    A_UNJAIL ? "Take back from its jail: " : sg.ask ==
		    A_REPLICATE ? "Replicate " : sg.ask == A_NEWFS ?
		    "New file system on " : "Swap on a device");
		h_txt(h, sg.target);
		h_fmt(h, "</h2><label>%s<input name=\"name\" spellcheck=\""
		    "false\" autocomplete=\"off\" autofocus placeholder=\"%s\">"
		    "<small>%s</small></label>", sg.ask == A_JAIL || sg.ask ==
		    A_UNJAIL ? "The jail" : sg.ask == A_REPLICATE ? "Into the "
		    "new dataset" : sg.ask == A_NEWFS ? "Its label" :
		    "The device", sg.ask == A_JAIL || sg.ask == A_UNJAIL ?
		    "web" : sg.ask == A_REPLICATE ? "backup/path/name" :
		    sg.ask == A_NEWFS ? "nothing, or data" : "/dev/ada0p3",
		    sg.ask == A_JAIL ? "A running jail: the dataset is its "
		    "own from then on (zfs jail), when its jailed property "
		    "is on and the jail is allowed to mount zfs." : sg.ask ==
		    A_UNJAIL ? "The jail it was given to (zfs unjail)." :
		    sg.ask == A_REPLICATE ? "A dataset that is not there "
		    "yet, on this host: the snapshot is sent into it, and "
		    "it is not mounted." : sg.ask == A_NEWFS ? "newfs -U: "
		    "whatever is on the partition is gone. The host refuses "
		    "while it is mounted, swapped on or a pool's." :
		    "swapon: until the next start, unless fstab has it.");
		if (sg.ask == A_REPLICATE && app.nservers > 1) {
			int	k;

			/* Another host: the console carries it there. */
			h_raw(h, "<label>To<select name=\"to\"><option value=\"\">"
			    "this host</option>");
			for (k = 0; k < app.nservers; k++) {
				if (cur_server() != NULL && strcmp(
				    app.servers[k].id, cur_server()->id) == 0)
					continue;
				h_raw(h, "<option");
				h_attr(h, "value", app.servers[k].id);
				h_raw(h, ">");
				h_txt(h, app.servers[k].name);
				h_raw(h, "</option>");
			}
			h_raw(h, "</select><small>Another host: zfs send here, "
			    "zfs receive there, the console carrying it at the "
			    "pace the slower takes.</small></label>");
		}
		if (sg.ask == A_REPLICATE)
			h_raw(h, "<label>Only what changed since<input name=\""
			    "from\" spellcheck=\"false\" autocomplete=\"off\" "
			    "placeholder=\"nothing: all of it; or "
			    "pool/name@earlier\"><small>A snapshot both "
			    "have, for one that was replicated before."
			    "</small></label><label class=\"toggle\"><input "
			    "type=\"checkbox\" name=\"recursive\"><span>With "
			    "the datasets under it, their snapshots and "
			    "properties</span></label>");
		if (sg.ask == A_NEWFS)
			h_raw(h, "<label>File system<select name=\"fs\"><option "
			    "value=\"ufs\">UFS, with soft updates (newfs -U)"
			    "</option><option value=\"msdos\">FAT, for other "
			    "systems too (newfs_msdos: FAT32, or FAT16 when it "
			    "is small)</option></select>"
			    "</label><label class=\"toggle\"><input type=\""
			    "checkbox\" name=\"force\"><span>Though it has a "
			    "file system on it already</span></label>");
		return (true);
	case SM_KEY:
		h_raw(h, "<form data-form=\"st-typekey\"><h2>");
		h_raw(h, strcmp(sg.part, "load") == 0 ? "The key of " :
		    "A new key for ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><p>Sent to the host once, given to <code>zfs");
		h_raw(h, strcmp(sg.part, "load") == 0 ? " load-key" :
		    " change-key");
		h_raw(h, "</code> in a file only root reads while zfs reads it, "
		    "and kept nowhere: not by the console, not in a job. A "
		    "passphrase is 8 characters at least; a hex key, 64 hex "
		    "digits.</p>");
		if (strcmp(sg.part, "load") == 0)
			h_raw(h, "<label>Key<input type=\"password\" name=\"key\" "
			    "autocomplete=\"off\" autofocus></label>");
		else
			h_raw(h, "<label>New key<input type=\"password\" name=\""
			    "new_key\" autocomplete=\"new-password\" autofocus>"
			    "</label><label>New key, again<input type=\""
			    "password\" name=\"again\" autocomplete=\""
			    "new-password\"></label><p class=\"dim\">It is asked "
			    "for at a prompt after, as now.</p>");
		return (true);
	case SM_SNAPSHOT:
		t = time(NULL);
		strftime(name, sizeof(name), "%Y-%m-%d-%H%M", gmtime(&t));
		h_raw(h, "<form data-form=\"st-snapshot\"><h2>Snapshot ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><label>Its name<input name=\"name\" spellcheck="
		    "\"false\" autocomplete=\"off\" autofocus");
		h_attr(h, "value", name);
		h_raw(h, "><small>Letters, digits and _ . : -</small></label>"
		    "<label class=\"toggle\"><input type=\"checkbox\" name=\""
		    "recursive\"><span>Of every dataset under it too, at the "
		    "same moment</span></label>");
		return (true);
	case SM_DATASET:
		h_raw(h, "<form data-form=\"st-dataset\"><h2>Create a dataset"
		    "</h2><label>Name<input name=\"name\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"pool/path/name\" "
		    "autofocus></label><label>Size, for a volume<input name=\""
		    "volsize\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"empty for a file system; 10G for a volume\">"
		    "</label><label>Properties<textarea name=\"props\" class=\""
		    "code\" rows=\"4\" spellcheck=\"false\" placeholder=\""
		    "compression=zstd&#10;quota=20G&#10;mountpoint=/srv/data\">"
		    "</textarea><small>One <code>name=value</code> a line."
		    "</small></label>");
		return (true);
	case SM_PROPS:
		h_raw(h, "<form data-form=\"st-props\"><h2>Set properties of ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><label>Properties<textarea name=\"props\" "
		    "class=\"code\" rows=\"5\" spellcheck=\"false\" autofocus "
		    "placeholder=\"quota=20G&#10;compression=zstd&#10;"
		    "atime=off\"></textarea><small>One <code>name=value</code> "
		    "a line, of those zfs has or your own (<code>module:name"
		    "</code>).</small></label><label>Back to what it inherits"
		    "<input name=\"inherit\" spellcheck=\"false\" autocomplete="
		    "\"off\" placeholder=\"a property's name, or nothing\">"
		    "</label>");
		return (true);
	case SM_CLONE:
		h_raw(h, "<form data-form=\"st-clone\"><h2>Clone ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><label>The new dataset<input name=\"name\" "
		    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
		    "pool/path/name\" autofocus><small>A dataset made of the "
		    "snapshot; the snapshot cannot be destroyed while it "
		    "exists.</small></label>");
		return (true);
	case SM_PART_ADD:
		h_raw(h, "<form data-form=\"st-part-add\"><h2>Add a partition "
		    "to ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><label>Type<select name=\"type\">");
		for (i = 0; i < sizeof(types) / sizeof(types[0]); i++)
			h_fmt(h, "<option>%s</option>", types[i]);
		h_raw(h, "</select></label><div class=\"two\"><label>Size"
		    "<input name=\"size\" spellcheck=\"false\" autocomplete=\""
		    "off\" placeholder=\"all that is free; or 20G\"></label>"
		    "<label>Label<input name=\"label\" spellcheck=\"false\" "
		    "autocomplete=\"off\"></label></div><p class=\"dim\">In "
		    "the first free room large enough, aligned to 1 MiB.</p>");
		return (true);
	case SM_PART_LABEL:
		h_raw(h, "<form data-form=\"st-part-label\"><h2>Label of "
		    "partition ");
		h_txt(h, sg.part);
		h_raw(h, " of ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><label>Label<input name=\"label\" spellcheck=\""
		    "false\" autocomplete=\"off\" autofocus><small>Letters, "
		    "digits and _ . -</small></label>");
		return (true);
	case SM_PART_RESIZE:
		h_raw(h, "<form data-form=\"st-part-resize\"><h2>Resize "
		    "partition ");
		h_txt(h, sg.part);
		h_raw(h, " of ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><label>New size<input name=\"size\" spellcheck="
		    "\"false\" autocomplete=\"off\" placeholder=\"all the room "
		    "after it; or 40G\" autofocus><small>The partition, not "
		    "what is in it: a file system is grown after, and made "
		    "smaller before.</small></label>");
		return (true);
	case SM_SCHEME:
		h_raw(h, "<form data-form=\"st-scheme\"><h2>Partition table "
		    "for ");
		h_txt(h, sg.target);
		h_raw(h, "</h2><label>Scheme<select name=\"scheme\"><option>"
		    "gpt</option><option>mbr</option><option>bsd</option>"
		    "</select></label><p class=\"dim\">gpart refuses a disk "
		    "that has one already.</p>");
		return (true);
	case SM_POOL_NEW:
	case SM_POOL_ADD:
		if (sg.modal == SM_POOL_NEW)
			h_raw(h, "<form data-form=\"st-pool-new\"><h2>Create a "
			    "pool</h2><label>Name<input name=\"name\" "
			    "spellcheck=\"false\" autocomplete=\"off\" "
			    "autofocus></label>");
		else {
			h_raw(h, "<form data-form=\"st-pool-add\"><h2>Add "
			    "devices to ");
			h_txt(h, sg.target);
			h_raw(h, "</h2>");
		}
		h_raw(h, "<label>The devices are<select name=\"layout\">"
		    "<option value=\"\">each by itself (a stripe)</option>"
		    "<option value=\"mirror\">a mirror of each other</option>"
		    "<option value=\"raidz1\">raidz1: one may fail</option>"
		    "<option value=\"raidz2\">raidz2: two may fail</option>"
		    "<option value=\"raidz3\">raidz3: three may fail</option>");
		if (sg.modal == SM_POOL_ADD)
			h_raw(h, "<option value=\"log\">a log device</option>"
			    "<option value=\"cache\">a cache device</option>"
			    "<option value=\"spare\">spares</option><option "
			    "value=\"special\">a special device</option>");
		h_raw(h, "</select></label><label>Devices<textarea name=\""
		    "devices\" class=\"code\" rows=\"3\" spellcheck=\"false\" "
		    "placeholder=\"ada1p1 ada2p1, or gpt/disk1 gpt/disk2\">"
		    "</textarea><small>Partitions or whole disks, as the "
		    "<b>Disks</b> view names them, or their labels. What is "
		    "on them is lost.</small></label>");
		if (sg.modal == SM_POOL_NEW)
			h_raw(h, "<div class=\"two\"><label>Mounted on<input "
			    "name=\"mountpoint\" spellcheck=\"false\" "
			    "autocomplete=\"off\" placeholder=\"/ and its name"
			    "\"></label><label>Sector size, as a power of two"
			    "<input name=\"ashift\" inputmode=\"numeric\" "
			    "autocomplete=\"off\" placeholder=\"as the disks "
			    "say; 12 for 4 KiB\"></label></div>");
		h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
		    "name=\"force\"><span>Though zpool finds something on "
		    "them already, or they differ (-f)</span></label>");
		if (sg.modal == SM_POOL_ADD)
			h_raw(h, "<p class=\"dim\">Devices added to a pool as "
			    "data cannot always be taken out again.</p>");
		return (true);
	case SM_POOL_IMPORT:
		h_raw(h, "<form data-form=\"st-pool-import\"><h2>Import a pool"
		    "</h2>");
		if (sg.importing)
			h_raw(h, "<div class=\"empty small\"><div class=\""
			    "loader\"></div></div>");
		else if (ucl_array_size(jget(sg.importable, "importable")) ==
		    0)
			h_raw(h, "<p class=\"dim\">zpool finds no pool on this "
			    "host's devices that is not imported.</p>");
		else {
			const ucl_object_t	*o;
			ucl_object_iter_t	 it;

			h_raw(h, "<ul class=\"blocks\">");
			it = NULL;
			while ((o = ucl_object_iterate(jget(sg.importable,
			    "importable"), &it, true)) != NULL) {
				h_raw(h, "<li data-act=\"st-import\"");
				h_attr(h, "data-arg", jstr(o, "name"));
				h_raw(h, "><b>");
				h_txt(h, jstr(o, "name"));
				h_raw(h, "</b><span class=\"dim\">");
				h_txt(h, jstr(o, "state"));
				h_raw(h, " · ");
				h_txt(h, jstr(o, "id"));
				h_raw(h, "</span></li>");
			}
			h_raw(h, "</ul><p class=\"dim\">Pick one to import "
			    "it.</p>");
		}
		return (true);
	case SM_VDEV_REPLACE:
	case SM_VDEV_ATTACH:
		h_fmt(h, "<form data-form=\"%s\"><h2>%s ", sg.modal ==
		    SM_VDEV_REPLACE ? "st-vdev-replace" : "st-vdev-attach",
		    sg.modal == SM_VDEV_REPLACE ? "Replace" : "Mirror");
		h_txt(h, sg.dev);
		h_raw(h, " of ");
		h_txt(h, sg.target);
		h_fmt(h, "</h2><label>%s<input name=\"device\" spellcheck=\""
		    "false\" autocomplete=\"off\" placeholder=\"ada3p1, or "
		    "gpt/disk3\" autofocus><small>%s</small></label>",
		    sg.modal == SM_VDEV_REPLACE ? "With the device" :
		    "The device to mirror it", sg.modal == SM_VDEV_REPLACE ?
		    "Empty when the new disk took the old one's place and "
		    "name. The pool copies what was there onto it." :
		    "It becomes a copy of this one; what is on it is lost.");
		return (true);
	case SM_FSTAB:
		h_raw(h, "<form data-form=\"st-fstab\" class=\"wide\"><h2>fstab"
		    "</h2><label>What is mounted when the host starts"
		    "<textarea name=\"text\" class=\"code\" spellcheck=\""
		    "false\" rows=\"16\">");
		h_txt(h, sg.draft != NULL ? sg.draft : sg.fstab != NULL ?
		    sg.fstab : "");
		h_raw(h, "</textarea><small>The host checks that every line is "
		    "an entry before it takes the file, and keeps the one "
		    "before beside it. A wrong line here can keep the host "
		    "from starting.</small></label>");
		return (true);
	default:
		return (false);
	}
}

void
storage_modal_buttons(struct html *h)
{

	if (sg.modal == SM_POOL_IMPORT)
		return;
	h_fmt(h, "<button class=\"primary\"%s>%s</button>", sg.saving ?
	    " disabled" : "", sg.modal == SM_ASK ? (sg.ask == A_JAIL ? "Give" :
	    sg.ask == A_UNJAIL ? "Take back" : sg.ask == A_REPLICATE ?
	    "Replicate" : sg.ask == A_NEWFS ? "Make it" : "Swap on") :
	    sg.modal == SM_SNAPSHOT ? "Snapshot" : sg.modal == SM_KEY ?
	    (strcmp(sg.part, "load") == 0 ? "Load" : "Change") :
	    sg.modal == SM_VDEV_REPLACE ? "Replace" : sg.modal ==
	    SM_VDEV_ATTACH ? "Mirror" : sg.modal == SM_POOL_ADD ? "Add" :
	    sg.modal == SM_POOL_NEW ? "Create" :
	    sg.modal == SM_DATASET || sg.modal == SM_SCHEME ? "Create" :
	    sg.modal == SM_CLONE ? "Clone" : sg.modal == SM_PART_ADD ? "Add" :
	    sg.modal == SM_PART_RESIZE ? "Resize" : sg.modal == SM_FSTAB ?
	    "Save" : "Set");
}

/* name=value lines into words; false when one is not that. */
static int
prop_words(char *text, const char **v, int max)
{
	char	*line;
	int	 n;

	n = 0;
	while ((line = strsep(&text, "\n")) != NULL) {
		while (*line == ' ' || *line == '\t')
			line++;
		line[strcspn(line, "\r")] = '\0';
		if (*line == '\0')
			continue;
		if (strchr(line, '=') == NULL || line[0] == '=' || line[0] ==
		    '-' || n == max)
			return (-1);
		v[n++] = line;
	}
	return (n);
}

static void
typekey_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct server	*s;

	(void)arg;
	sg.saving = false;
	if (status == 200 && jbool(o, "ok")) {
		toast(false, "%s", strcmp(sg.part, "load") == 0 ? "The key is "
		    "loaded" : "The key is changed");
		app.modal = MODAL_NONE;
		if ((s = cur_server()) != NULL)
			refresh_storage(s, true);
		return;
	}
	snprintf(app.modal_error, sizeof(app.modal_error), "%s", jstr(o,
	    "error") != NULL ? jstr(o, "error") : jstr(o, "error.message") !=
	    NULL ? jstr(o, "error.message") : err != NULL ? err : "failed");
}

/* The key typed, straight to the host: not a job, which is kept. */
static bool
typekey_form(struct server *s, const ucl_object_t *f)
{
	const char	*k, *n, *a;
	char		*qd, *qk, *body, url[96];

	k = jstr(f, "key") != NULL ? jstr(f, "key") : "";
	n = jstr(f, "new_key") != NULL ? jstr(f, "new_key") : "";
	a = jstr(f, "again") != NULL ? jstr(f, "again") : "";
	if (strcmp(sg.part, "load") == 0 ? k[0] == '\0' : n[0] == '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "The key");
		return (true);
	}
	if (strcmp(sg.part, "load") != 0 && strcmp(n, a) != 0) {
		snprintf(app.modal_error, sizeof(app.modal_error), "The new key "
		    "is not the same twice");
		return (true);
	}
	qd = json_quote(sg.target);
	qk = json_quote(strcmp(sg.part, "load") == 0 ? k : n);
	if (asprintf(&body, "{\"dataset\":%s,\"%s\":%s}", qd, strcmp(sg.part,
	    "load") == 0 ? "key" : "new_key", qk) == -1)
		abort();
	explicit_bzero(qk, strlen(qk));
	free(qd);
	free(qk);
	snprintf(url, sizeof(url), "/api/servers/%s/zfs/key", s->id);
	sg.saving = true;
	app.modal_error[0] = '\0';
	api("POST", url, body, typekey_cb, NULL);
	explicit_bzero(body, strlen(body));
	free(body);
	return (true);
}

bool
storage_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	struct html	 b;
	const char	*name, *v[16], *sz, *label;
	char		*text, *q, full[320], title[320];
	int		 n, i;

	if (strncmp(form, "st-", 3) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
	if (strcmp(form, "st-ask") == 0) {
		const char *from = jstr(f, "from") != NULL ? jstr(f, "from") :
		    "";

		if (sg.ask == A_JAIL || sg.ask == A_UNJAIL) {
			if (!name_ok(name, "_.-")) {
				snprintf(app.modal_error,
				    sizeof(app.modal_error), "Name the jail");
				return (true);
			}
			sjob(s, "zfs", sg.ask == A_JAIL ? "jail" : "unjail",
			    "", sg.target, 2, sg.target, name);
		} else if (sg.ask == A_REPLICATE) {
			if (!name_ok(name, "_.:/-") || strchr(name, '/') ==
			    NULL || (from[0] != '\0' && (!name_ok(from,
			    "_.:/@-") || strchr(from, '@') == NULL))) {
				snprintf(app.modal_error,
				    sizeof(app.modal_error), "Into pool/name; "
				    "since nothing, or a snapshot");
				return (true);
			}
			if (jstr(f, "to") != NULL && jstr(f, "to")[0] != '\0') {
				transfer_start(s, jstr(f, "to"), sg.target, from,
				    name, jbool(f, "recursive"));
				return (true);
			}
			if (from[0] != '\0')
				sjob(s, "zfs", "replicate", jbool(f,
				    "recursive") ? ",\"recursive\":true" : "",
				    name, 3, sg.target, name, from);
			else
				sjob(s, "zfs", "replicate", jbool(f,
				    "recursive") ? ",\"recursive\":true" : "",
				    name, 2, sg.target, name);
		} else if (sg.ask == A_NEWFS) {
			if (name[0] != '\0' && !name_ok(name, "_.-")) {
				snprintf(app.modal_error,
				    sizeof(app.modal_error), "A label is "
				    "letters, digits and _ . -");
				return (true);
			}
			if (jstr(f, "fs") != NULL && strcmp(jstr(f, "fs"),
			    "msdos") == 0 && strlen(name) > 11) {
				snprintf(app.modal_error,
				    sizeof(app.modal_error), "A FAT label is "
				    "11 characters at most");
				return (true);
			}
			sjob(s, "gpart", jstr(f, "fs") != NULL && strcmp(jstr(f,
			    "fs"), "msdos") == 0 ? "newfs-msdos" : "newfs",
			    jbool(f, "force") ? ",\"force\":true" : "",
			    sg.target, 2, sg.target, name);
		} else {
			if (strncmp(name, "/dev/", 5) != 0 || !name_ok(name +
			    5, "_./-")) {
				snprintf(app.modal_error,
				    sizeof(app.modal_error), "A device: "
				    "/dev/ada0p3");
				return (true);
			}
			sjob(s, "mount", "swapon", "", name, 1, name);
		}
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "st-typekey") == 0)
		return (typekey_form(s, f));
	if (strcmp(form, "st-snapshot") == 0) {
		if (!name_ok(name, "_.:-")) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "A snapshot's name is letters, digits and _ . : -");
			return (true);
		}
		snprintf(full, sizeof(full), "%s@%s", sg.target, name);
		sjob(s, "zfs", "snapshot", jbool(f, "recursive") ?
		    ",\"recursive\":true" : "", sg.target, 1, full);
	} else if (strcmp(form, "st-dataset") == 0 || strcmp(form,
	    "st-props") == 0) {
		bool	create = form[3] == 'd';

		if (create && (!name_ok(name, "_.:/-") || strchr(name, '/') ==
		    NULL)) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "A dataset is pool/name: letters, digits and "
			    "_ . : / -");
			return (true);
		}
		text = strdup(jstr(f, "props") != NULL ? jstr(f, "props") : "");
		n = prop_words(text, v, 14);
		sz = jstr(f, "volsize") != NULL ? jstr(f, "volsize") : "";
		label = jstr(f, "inherit") != NULL ? jstr(f, "inherit") : "";
		if (n < 0 || (!create && n == 0 && label[0] == '\0')) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "%s", n < 0 ? "A property is name=value, one a "
			    "line" : "Nothing to set");
			free(text);
			return (true);
		}
		if (create || n > 0) {
			memset(&b, 0, sizeof(b));
			h_fmt(&b, "{\"kind\":\"zfs\",\"verb\":\"%s\",\"args\":[",
			    create ? "create" : "set");
			q = json_quote(create ? name : sg.target);
			h_raw(&b, q);
			free(q);
			if (create && sz[0] != '\0') {
				snprintf(full, sizeof(full), "volsize=%s", sz);
				q = json_quote(full);
				h_raw(&b, ",");
				h_raw(&b, q);
				free(q);
			}
			for (i = 0; i < n; i++) {
				q = json_quote(v[i]);
				h_raw(&b, ",");
				h_raw(&b, q);
				free(q);
			}
			h_raw(&b, "]}");
			snprintf(title, sizeof(title), "zfs %s %s", create ?
			    "create" : "set", create ? name : sg.target);
			job_send_host(s, b.s, title, JOB_STORAGE, create ?
			    name : sg.target);
		}
		if (!create && label[0] != '\0')
			sjob(s, "zfs", "inherit", "", sg.target, 2, sg.target,
			    label);
		free(text);
	} else if (strcmp(form, "st-clone") == 0) {
		if (!name_ok(name, "_.:/-") || strchr(name, '/') == NULL) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "A dataset is pool/name");
			return (true);
		}
		sjob(s, "zfs", "clone", "", name, 2, sg.target, name);
	} else if (strcmp(form, "st-part-add") == 0) {
		sjob(s, "gpart", "add", "", sg.target, 4, sg.target, jstr(f,
		    "type") != NULL ? jstr(f, "type") : "", jstr(f, "size") !=
		    NULL ? jstr(f, "size") : "", jstr(f, "label") != NULL ?
		    jstr(f, "label") : "");
	} else if (strcmp(form, "st-part-label") == 0) {
		label = jstr(f, "label") != NULL ? jstr(f, "label") : "";
		if (!name_ok(label, "_.-")) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "A label is letters, digits and _ . -");
			return (true);
		}
		sjob(s, "gpart", "modify", "", sg.target, 3, sg.target,
		    sg.part, label);
	} else if (strcmp(form, "st-part-resize") == 0) {
		sz = jstr(f, "size") != NULL ? jstr(f, "size") : "";
		if (sz[0] != '\0')
			sjob(s, "gpart", "resize", "", sg.target, 3, sg.target,
			    sg.part, sz);
		else
			sjob(s, "gpart", "resize", "", sg.target, 2, sg.target,
			    sg.part);
	} else if (strcmp(form, "st-scheme") == 0) {
		sjob(s, "gpart", "create", "", sg.target, 2, sg.target,
		    jstr(f, "scheme") != NULL ? jstr(f, "scheme") : "gpt");
	} else if (strcmp(form, "st-pool-new") == 0 || strcmp(form,
	    "st-pool-add") == 0) {
		const char	*pv[24], *lay, *mp, *as;
		char		 mpw[300], asw[32];
		bool		 create = form[8] == 'n';

		lay = jstr(f, "layout") != NULL ? jstr(f, "layout") : "";
		text = strdup(jstr(f, "devices") != NULL ? jstr(f, "devices") :
		    "");
		n = 0;
		pv[n++] = create ? name : sg.target;
		if (lay[0] != '\0')
			pv[n++] = lay;
		i = words(text, pv + n, 18);
		if ((create && !name_ok(name, "_.:-")) || i <= 0) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "%s", i <= 0 ? "Name the devices, with blanks "
			    "between them" : "A pool's name is letters, "
			    "digits and _ . : -");
			free(text);
			return (true);
		}
		n += i;
		mp = jstr(f, "mountpoint") != NULL ? jstr(f, "mountpoint") : "";
		as = jstr(f, "ashift") != NULL ? jstr(f, "ashift") : "";
		if (create && mp[0] != '\0') {
			snprintf(mpw, sizeof(mpw), "mountpoint=%s", mp);
			pv[n++] = mpw;
		}
		if (create && as[0] != '\0') {
			snprintf(asw, sizeof(asw), "ashift=%s", as);
			pv[n++] = asw;
		}
		sjobv(s, "zpool", create ? "create" : "add", jbool(f, "force") ?
		    ",\"force\":true" : "", pv[0], n, pv);
		free(text);
	} else if (strcmp(form, "st-vdev-replace") == 0 || strcmp(form,
	    "st-vdev-attach") == 0) {
		label = jstr(f, "device") != NULL ? jstr(f, "device") : "";
		if (form[8] == 'a' && label[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Name the device to mirror it");
			return (true);
		}
		if (label[0] != '\0')
			sjob(s, "zpool", form[8] == 'a' ? "attach" : "replace",
			    "", sg.target, 3, sg.target, sg.dev, label);
		else
			sjob(s, "zpool", "replace", "", sg.target, 2, sg.target,
			    sg.dev);
	} else if (strcmp(form, "st-pool-import") == 0) {
		return (true);
	} else if (strcmp(form, "st-fstab") == 0) {
		char	url[96], *qt, *body;

		if (sg.saving)
			return (true);
		free(sg.draft);
		sg.draft = strdup(jstr(f, "text") != NULL ? jstr(f, "text") :
		    "");
		snprintf(url, sizeof(url), "/api/servers/%s/fstab", s->id);
		qt = json_quote(sg.draft);
		if (asprintf(&body, "{\"text\":%s,\"sha256\":\"%s\"}", qt,
		    sg.fstab_sha) == -1)
			abort();
		free(qt);
		sg.saving = true;
		app.modal_error[0] = '\0';
		api("POST", url, body, fstab_cb, &sg);
		free(body);
		return (true);
	} else
		return (false);
	app.modal = MODAL_NONE;
	return (true);
}

static void
box(int which, const char *target, const char *part)
{

	sg.modal = which;
	snprintf(sg.target, sizeof(sg.target), "%s", target);
	snprintf(sg.part, sizeof(sg.part), "%s", part);
	app.modal = MODAL_STORAGE;
	app.modal_error[0] = '\0';
}

bool
storage_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	const char	*dev;
	char		 body[500], url[96], first[256];
	int		 k;

	/* Where a value is two words, the second is a device's name. */
	snprintf(first, sizeof(first), "%.*s", (int)strcspn(value, " "), value);
	dev = strchr(value, ' ') != NULL ? strchr(value, ' ') + 1 : "";

	if (strncmp(act, "st-", 3) != 0 && strncmp(act, "do-st-", 6) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "st-kind") == 0) {
		for (k = 0; k < SK_N; k++)
			if (strcmp(arg, kind_arg[k]) == 0)
				sg.kind = k;
		refresh_storage(s, true);
	} else if (strcmp(act, "st-snaps-of") == 0) {
		snprintf(sg.of, sizeof(sg.of), "%s", arg);
		sg.kind = SK_SNAPSHOTS;
		if (sg.data[SK_SNAPSHOTS] != NULL)
			ucl_object_unref(sg.data[SK_SNAPSHOTS]);
		sg.data[SK_SNAPSHOTS] = NULL;
		sg.loading[SK_SNAPSHOTS] = false;
		refresh_storage(s, true);
	} else if (strcmp(act, "st-ask") == 0) {
		sg.ask = strcmp(arg, "jail") == 0 ? A_JAIL : strcmp(arg,
		    "unjail") == 0 ? A_UNJAIL : strcmp(arg, "replicate") == 0 ?
		    A_REPLICATE : strcmp(arg, "newfs") == 0 ? A_NEWFS :
		    A_SWAPON;
		box(SM_ASK, value, "");
	} else if (strcmp(act, "st-typekey") == 0) {
		box(SM_KEY, value, strcmp(arg, "load") == 0 ? "load" :
		    "change");
	} else if (strcmp(act, "st-key") == 0 && (strcmp(arg, "load-key") ==
	    0 || strcmp(arg, "unload-key") == 0)) {
		/* Its key is read where keylocation says, never typed here. */
		sjob(s, "zfs", arg, "", value, 1, value);
	} else if (strcmp(act, "st-growfs") == 0) {
		sjob(s, "gpart", "growfs", "", arg, 1, arg);
	} else if (strcmp(act, "st-swapoff") == 0) {
		snprintf(body, sizeof(body), "swapoff %s, on %s: what is "
		    "swapped out there has to fit the memory and the swap "
		    "that is left, or the host refuses.", arg, s->name);
		confirm("Swap off", body, "Swap off", true, "",
		    "do-st-swapoff", arg, "");
	} else if (strcmp(act, "do-st-swapoff") == 0) {
		sjob(s, "mount", "swapoff", "", arg, 1, arg);
	} else if (strcmp(act, "st-snapshot") == 0) {
		box(SM_SNAPSHOT, arg, "");
	} else if (strcmp(act, "st-dataset") == 0) {
		box(SM_DATASET, "", "");
	} else if (strcmp(act, "st-props") == 0) {
		box(SM_PROPS, arg, "");
	} else if (strcmp(act, "st-clone") == 0) {
		box(SM_CLONE, arg, "");
	} else if (strcmp(act, "st-part-add") == 0) {
		box(SM_PART_ADD, arg, "");
	} else if (strcmp(act, "st-part-label") == 0) {
		box(SM_PART_LABEL, arg, value);
	} else if (strcmp(act, "st-part-resize") == 0) {
		box(SM_PART_RESIZE, arg, value);
	} else if (strcmp(act, "st-scheme") == 0) {
		box(SM_SCHEME, arg, "");
	} else if (strcmp(act, "st-fstab") == 0) {
		free(sg.draft);
		sg.draft = NULL;
		box(SM_FSTAB, "", "");
		snprintf(url, sizeof(url), "/api/servers/%s/fstab", s->id);
		api("GET", url, NULL, fstab_cb, NULL);
	} else if (strcmp(act, "st-zpool") == 0) {
		/* arg: the verb; value: the pool. */
		if (strcmp(arg, "scrub") == 0 || strcmp(arg, "scrub-stop") ==
		    0 || strcmp(arg, "trim") == 0 || strcmp(arg, "clear") == 0)
			sjob(s, "zpool", arg, "", value, 1, value);
	} else if (strcmp(act, "st-pool-new") == 0) {
		box(SM_POOL_NEW, "", "");
	} else if (strcmp(act, "st-pool-add") == 0) {
		box(SM_POOL_ADD, arg, "");
	} else if (strcmp(act, "st-pool-import") == 0) {
		box(SM_POOL_IMPORT, "", "");
		sg.importing = true;
		snprintf(url, sizeof(url), "/api/servers/%s/storage/importable",
		    s->id);
		api("GET", url, NULL, import_cb, NULL);
	} else if (strcmp(act, "st-import") == 0) {
		sjob(s, "zpool", "import", "", arg, 1, arg);
		app.modal = MODAL_NONE;
	} else if (strcmp(act, "st-pool-export") == 0) {
		snprintf(body, sizeof(body), "zpool export %s, on %s: its "
		    "datasets are unmounted and the pool is no longer this "
		    "host's until it is imported again, here or elsewhere. "
		    "The host refuses for the pool it runs from, and zpool "
		    "while something uses it.", arg, s->name);
		confirm("Export the pool", body, "Export", true, "",
		    "do-st-pool-export", arg, "");
	} else if (strcmp(act, "do-st-pool-export") == 0) {
		sjob(s, "zpool", "export", "", arg, 1, arg);
	} else if (strcmp(act, "st-pool-destroy") == 0) {
		snprintf(body, sizeof(body), "zpool destroy %s, on %s: the "
		    "pool, every dataset and every snapshot in it, are gone "
		    "for good. The host refuses for the pool it runs from.",
		    arg, s->name);
		confirm("Destroy the pool", body, "Destroy", true, arg,
		    "do-st-pool-destroy", arg, "");
	} else if (strcmp(act, "do-st-pool-destroy") == 0) {
		sjob(s, "zpool", "destroy", "", arg, 1, arg);
	} else if (strcmp(act, "st-vdev") == 0 && (strcmp(arg, "replace") ==
	    0 || strcmp(arg, "attach") == 0)) {
		box(arg[0] == 'r' ? SM_VDEV_REPLACE : SM_VDEV_ATTACH, first,
		    "");
		snprintf(sg.dev, sizeof(sg.dev), "%s", dev);
	} else if (strcmp(act, "st-vdev") == 0 && strcmp(arg, "detach") == 0) {
		snprintf(body, sizeof(body), "zpool detach %s %s, on %s: the "
		    "device leaves its mirror, which goes on with one copy "
		    "less. zpool refuses for a device that is no part of a "
		    "mirror.", first, dev, s->name);
		confirm("Detach the device", body, "Detach", true, "",
		    "do-st-detach", first, dev);
	} else if (strcmp(act, "do-st-detach") == 0) {
		sjob(s, "zpool", "detach", "", arg, 2, arg, value);
	} else if (strcmp(act, "st-vdev") == 0) {
		if (strcmp(arg, "online") == 0)
			sjob(s, "zpool", "online", "", first, 2, first, dev);
		else {
			snprintf(body, sizeof(body), "zpool offline %s %s, on "
			    "%s: the pool goes on without the device, with "
			    "less to lose before data is lost, until it is "
			    "brought online again. zpool refuses when the "
			    "pool cannot do without it.", first, dev, s->name);
			confirm("Take the device offline", body, "Offline",
			    true, "", "do-st-offline", first, dev);
		}
	} else if (strcmp(act, "do-st-offline") == 0) {
		sjob(s, "zpool", "offline", "", arg, 2, arg, value);
	} else if (strcmp(act, "st-zfs-mount") == 0) {
		sjob(s, "zfs", strcmp(arg, "mount") == 0 ? "mount" : "unmount",
		    "", value, 1, value);
	} else if (strcmp(act, "st-xfer-stop") == 0) {
		confirm("Stop sending", "zfs send stops on the one host, and "
		    "zfs receive on the other ends without what was not sent: "
		    "nothing of it is kept there.", "Stop", true, "",
		    "do-st-xfer-stop", arg, "");
	} else if (strcmp(act, "do-st-xfer-stop") == 0) {
		char	url[64];

		snprintf(url, sizeof(url), "/api/transfers/%u", (unsigned int)
		    strtoul(arg, NULL, 10));
		api("DELETE", url, NULL, xfers_stopped_cb, NULL);
	} else if (strcmp(act, "st-rollback") == 0) {
		snprintf(body, sizeof(body), "zfs rollback %s, on %s: the "
		    "dataset becomes what it was when the snapshot was "
		    "taken, and everything written since is gone. zfs "
		    "refuses when there are snapshots after this one.", arg,
		    s->name);
		confirm("Roll back to the snapshot", body, "Roll back", true,
		    strchr(arg, '@') != NULL ? strchr(arg, '@') + 1 : arg,
		    "do-st-rollback", arg, "");
	} else if (strcmp(act, "do-st-rollback") == 0) {
		sjob(s, "zfs", "rollback", "", arg, 1, arg);
	} else if (strcmp(act, "st-resnap") == 0) {
		snprintf(body, sizeof(body), "zfs resnapshot %s, on %s: the "
		    "snapshot is taken again, now, under the same name, and "
		    "what it held of before is let go. The new one is taken "
		    "first; the old one stays when zfs will not destroy it.",
		    arg, s->name);
		confirm("Take the snapshot again", body, "Resnapshot", false,
		    "", "do-st-resnap", arg, "");
	} else if (strcmp(act, "do-st-resnap") == 0) {
		sjob(s, "zfs", "resnapshot", "", arg, 1, arg);
	} else if (strcmp(act, "st-destroy") == 0) {
		snprintf(body, sizeof(body), "zfs destroy %s, on %s. %s zfs "
		    "refuses while it has snapshots, clones or datasets "
		    "under it, or is in use.", arg, s->name, strchr(arg,
		    '@') != NULL ? "The snapshot is gone for good." : "The "
		    "dataset and everything in it is gone for good.");
		/* A snapshot is asked about; a dataset's name is typed. */
		confirm(strchr(arg, '@') != NULL ? "Destroy the snapshot" :
		    "Destroy the dataset", body, "Destroy", true, strchr(arg,
		    '@') != NULL ? "" : strrchr(arg, '/') != NULL ?
		    strrchr(arg, '/') + 1 : arg, "do-st-destroy", arg, "");
	} else if (strcmp(act, "st-sel") == 0) {
		sel_set(arg, sel_find(arg) == -1);
	} else if (strcmp(act, "st-sel-none") == 0) {
		sel_clear();
	} else if (strcmp(act, "st-sel-all") == 0) {
		const ucl_object_t	**rows, *o;
		int	r, all;
		bool	on;

		/* All shown picked: none of them; else all of them. */
		rows = tbl_rows("snapshots", jget(sg.data[SK_SNAPSHOTS],
		    "snapshots"), snap_cols, 4, app.filter);
		for (r = all = 0; (o = rows[r]) != NULL; r++)
			if (jstr(o, "name") != NULL && sel_find(jstr(o,
			    "name")) != -1)
				all++;
		/* r is how many are shown now. */
		on = all != r;
		for (r = 0; (o = rows[r]) != NULL; r++)
			if (jstr(o, "name") != NULL)
				sel_set(jstr(o, "name"), on);
		free(rows);
	} else if (strcmp(act, "st-destroy-sel") == 0 && sg.nsel > 0) {
		uint64_t	bytes;
		const ucl_object_t *o;
		ucl_object_iter_t it;
		char		 sz[32];

		bytes = 0;
		it = NULL;
		while ((o = ucl_object_iterate(jget(sg.data[SK_SNAPSHOTS],
		    "snapshots"), &it, true)) != NULL)
			if (jstr(o, "name") != NULL && sel_find(jstr(o,
			    "name")) != -1)
				bytes += (uint64_t)jint(o, "used", 0);
		size(sz, sizeof(sz), (int64_t)bytes);
		snprintf(body, sizeof(body), "zfs destroy of %d snapshot%s on "
		    "%s, each a job of its own in one batch: %s%s%s. What "
		    "each holds alone, about %s, is freed; a snapshot a "
		    "clone was made of is refused, and the others are "
		    "destroyed all the same.", sg.nsel, sg.nsel == 1 ? "" :
		    "s", s->name, sg.sel[0], sg.nsel > 1 ? " and " : "",
		    sg.nsel > 2 ? "the others" : sg.nsel == 2 ? sg.sel[1] :
		    "", sz);
		confirm("Destroy the snapshots", body, "Destroy", true, "",
		    "do-st-destroy-sel", "", "");
	} else if (strcmp(act, "st-sel-newest") == 0) {
		const ucl_object_t	**rows;
		int			  r;

		/* As the table shows them: the filter narrows them. */
		rows = tbl_rows("snapshots", jget(sg.data[SK_SNAPSHOTS],
		    "snapshots"), snap_cols, 4, app.filter);
		for (r = 0; rows[r] != NULL; r++)
			if (jstr(rows[r], "name") != NULL && snap_newest(jstr(
			    rows[r], "name")) && sel_find(jstr(rows[r],
			    "name")) == -1)
				sel_set(jstr(rows[r], "name"), true);
		free(rows);
	} else if (strcmp(act, "st-resnap-sel") == 0 && sg.nsel > 0) {
		int	i, k;

		for (i = k = 0; i < sg.nsel; i++)
			if (snap_newest(sg.sel[i]))
				k++;
		snprintf(body, sizeof(body), "zfs resnapshot of %d snapshot%s "
		    "on %s, each a job of its own in one batch: each is "
		    "taken again, now, under the same name, the new one "
		    "first. %s One zfs will not destroy (held, cloned) stays "
		    "as it was, and the others are taken again all the "
		    "same.", k, k == 1 ? "" : "s", s->name, k < sg.nsel ?
		    "Those picked that are not the newest of their dataset "
		    "are left as they are." : "");
		confirm("Take the snapshots again", body, "Resnapshot", false,
		    "", "do-st-resnap-sel", "", "");
	} else if (strcmp(act, "do-st-resnap-sel") == 0 && sg.nsel > 0) {
		struct queued	*q;
		char		*qn;
		int		 i, k;

		if ((q = calloc((size_t)sg.nsel, sizeof(*q))) == NULL)
			abort();
		for (i = k = 0; i < sg.nsel; i++) {
			if (!snap_newest(sg.sel[i]))
				continue;
			qn = json_quote(sg.sel[i]);
			if (asprintf(&q[k].json, "{\"kind\":\"zfs\",\"verb\":"
			    "\"resnapshot\",\"args\":[%s]}", qn) == -1)
				abort();
			free(qn);
			snprintf(q[k].title, sizeof(q[k].title),
			    "zfs resnapshot %s", sg.sel[i]);
			snprintf(q[k].target, sizeof(q[k].target), "%s",
			    sg.sel[i]);
			k++;
		}
		if (k > 0)
			job_send_many(s, q, k, JOB_STORAGE);
		free(q);
		sel_clear();
	} else if (strcmp(act, "do-st-destroy-sel") == 0 && sg.nsel > 0) {
		struct queued	*q;
		char		*qn;
		int		 i;

		if ((q = calloc((size_t)sg.nsel, sizeof(*q))) == NULL)
			abort();
		for (i = 0; i < sg.nsel; i++) {
			qn = json_quote(sg.sel[i]);
			if (asprintf(&q[i].json, "{\"kind\":\"zfs\",\"verb\":"
			    "\"destroy\",\"args\":[%s]}", qn) == -1)
				abort();
			free(qn);
			snprintf(q[i].title, sizeof(q[i].title), "zfs destroy %s",
			    sg.sel[i]);
			snprintf(q[i].target, sizeof(q[i].target), "%s",
			    sg.sel[i]);
		}
		job_send_many(s, q, sg.nsel, JOB_STORAGE);
		free(q);
		sel_clear();
	} else if (strcmp(act, "do-st-destroy") == 0) {
		sjob(s, "zfs", "destroy", "", arg, 1, arg);
	} else if (strcmp(act, "st-mount") == 0) {
		sjob(s, "mount", "mount", "", arg, 1, arg);
	} else if (strcmp(act, "st-umount") == 0) {
		snprintf(body, sizeof(body), "umount %s, on %s. What uses it "
		    "keeps it mounted: the host says so then.", arg, s->name);
		confirm("Unmount", body, "Unmount", true, "", "do-st-umount",
		    arg, "");
	} else if (strcmp(act, "do-st-umount") == 0) {
		sjob(s, "mount", "unmount", "", arg, 1, arg);
	} else if (strcmp(act, "st-part-delete") == 0) {
		snprintf(body, sizeof(body), "gpart delete -i %s %s, on %s: "
		    "the partition %s is taken out of the table, and what "
		    "was in it is no longer reached.", first, arg, s->name,
		    dev);
		confirm("Delete the partition", body, "Delete", true, dev,
		    "do-st-part-delete", arg, first);
	} else if (strcmp(act, "do-st-part-delete") == 0) {
		sjob(s, "gpart", "delete", "", arg, 2, arg, value);
	} else if (strcmp(act, "st-scheme-destroy") == 0) {
		snprintf(body, sizeof(body), "gpart destroy %s, on %s: the "
		    "empty partition table is removed.", arg, s->name);
		confirm("Destroy the partition table", body, "Destroy", true,
		    arg, "do-st-scheme-destroy", arg, "");
	} else if (strcmp(act, "do-st-scheme-destroy") == 0) {
		sjob(s, "gpart", "destroy", "", arg, 1, arg);
	} else if (strcmp(act, "st-rescan") == 0) {
		sjob(s, "cam", "rescan", "", "cam", 0);
	}
	return (true);
}

/* ---- A jail's own datasets, on its page ------------------------------ */

static struct {
	char		 sid[9];
	char		 jail[256];
	ucl_object_t	*data;
	bool		 loading;
	char		 error[300];
} jd;

static void
jail_ds_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	jd.loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(jd.error, sizeof(jd.error), "%s", jstr(o, "error") !=
		    NULL ? jstr(o, "error") : err != NULL ? err : "no answer");
		return;
	}
	jd.error[0] = '\0';
	if (jd.data != NULL)
		ucl_object_unref(jd.data);
	jd.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

/* What the jail's own zfs sees: the datasets given to it. */
void
refresh_jail_datasets(struct server *s, const char *jail)
{
	char	url[400];

	if (!app.online || jd.loading)
		return;
	if (strcmp(jd.sid, s->id) != 0 || strcmp(jd.jail, jail) != 0) {
		if (jd.data != NULL)
			ucl_object_unref(jd.data);
		jd.data = NULL;
		jd.error[0] = '\0';
	}
	snprintf(jd.sid, sizeof(jd.sid), "%s", s->id);
	snprintf(jd.jail, sizeof(jd.jail), "%s", jail);
	jd.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/storage/datasets?jail=%s",
	    s->id, jail);
	api("GET", url, NULL, jail_ds_cb, NULL);
}

void
view_jail_datasets(struct html *h, struct server *s, const ucl_object_t *j)
{
	static const struct tcol cols[] = {
		{ "Dataset", "name", false }, { "Used", "used", true },
		{ "Available", "avail", true }, { "Mounted at", "mountpoint",
		false }, { "", NULL, false },
	};
	const ucl_object_t	**rows, *d;
	char			 buf[32];
	int			 n;

	/* Only one that runs has a zfs of its own to ask. */
	if (jstr(j, "state") == NULL || strcmp(jstr(j, "state"), "running") !=
	    0 || strcmp(jd.sid, s->id) != 0 || strcmp(jd.jail, app.jail) != 0)
		return;
	if (jd.error[0] != '\0' || (jd.data != NULL && ucl_array_size(jget(
	    jd.data, "datasets")) == 0))
		return;
	h_raw(h, "<h4>Datasets <span class=\"dim\">as the jail's own zfs "
	    "sees them: those given to it (zfs jail)</span></h4>");
	if (jd.data == NULL) {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	h_raw(h, "<table class=\"net jail-ds\">");
	tbl_head(h, "jail-ds", cols, 5, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("jail-ds", jget(jd.data, "datasets"), cols, 5, NULL);
	for (n = 0; (d = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(d, "name"));
		h_raw(h, "</b>");
		if (jstr(d, "jailed") != NULL && strcmp(jstr(d, "jailed"), "on") ==
		    0)
			h_raw(h, " <span class=\"chip\" title=\"Given to it: it "
			    "manages it as its own\">its own</span>");
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(d, "used", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(d, "avail", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(d, "mountpoint") != NULL ? jstr(d, "mountpoint") :
		    "");
		if (jstr(d, "mounted") != NULL && strcmp(jstr(d, "mounted"),
		    "yes") != 0)
			h_raw(h, " <small class=\"dim\">not mounted</small>");
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"st-snapshot\"");
		h_attr(h, "data-arg", jstr(d, "name"));
		h_raw(h, ">Snapshot</button></td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}
