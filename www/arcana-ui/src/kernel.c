/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's kernel: the files linked into it and the modules each holds,
 * to be unloaded, and others loaded; what rc.conf loads at boot; and
 * what the kernel's memory went to.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char		 sid[9];
	ucl_object_t	*data;
	bool		 loading;
	char		 error[300];
	double		 fetched;
	bool		 zones;		/* the memory shown: zones, or types */
} kn;

static void
size(char *buf, size_t len, int64_t n)
{
	static const char *const units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	double	v;
	int	u;

	v = (double)n;
	for (u = 0; v >= 1024 && u < 4; u++)
		v /= 1024;
	snprintf(buf, len, u == 0 ? "%.0f %s" : v < 10 ? "%.2f %s" :
	    v < 100 ? "%.1f %s" : "%.0f %s", v, units[u]);
}

static void
kernel_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid;

	sid = arg;
	if (strcmp(sid, kn.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	kn.loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(kn.error, sizeof(kn.error), "%s", status == 200 &&
		    jstr(o, "error") != NULL ? jstr(o, "error") : err != NULL ?
		    err : "no answer");
		return;
	}
	kn.error[0] = '\0';
	if (kn.data != NULL)
		ucl_object_unref(kn.data);
	kn.data = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
	kn.fetched = arc_now();
}

/* Read the host's kernel; again asks though it is here already. */
void
refresh_kernel(struct server *s, bool again)
{
	char	url[96];

	if (!app.online || kn.loading)
		return;
	if (strcmp(kn.sid, s->id) != 0) {
		if (kn.data != NULL)
			ucl_object_unref(kn.data);
		kn.data = NULL;
		kn.error[0] = '\0';
	} else if (!again && (kn.data != NULL || kn.error[0] != '\0'))
		return;
	snprintf(kn.sid, sizeof(kn.sid), "%s", s->id);
	kn.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/kernel", s->id);
	api("GET", url, NULL, kernel_cb, strdup(s->id));
}

static bool
in_list(const ucl_object_t *list, const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	const char		*v;
	size_t			 n;

	/* kld_list names a module with or without its .ko. */
	n = strlen(name);
	if (n > 3 && strcmp(name + n - 3, ".ko") == 0)
		n -= 3;
	it = NULL;
	while ((o = ucl_object_iterate(list, &it, true)) != NULL) {
		v = ucl_object_tostring_forced(o);
		if (strncmp(v, name, n) == 0 && (v[n] == '\0' || strcmp(v + n,
		    ".ko") == 0))
			return (true);
	}
	return (false);
}

static void
tile(struct html *h, const char *label, int64_t bytes, const char *note)
{
	char	buf[32];

	size(buf, sizeof(buf), bytes);
	h_raw(h, "<div><b>");
	h_txt(h, buf);
	h_raw(h, "</b><span>");
	h_txt(h, label);
	if (note != NULL) {
		h_raw(h, " · ");
		h_txt(h, note);
	}
	h_raw(h, "</span></div>");
}

void
view_kernel(struct html *h, struct server *s)
{
	static const struct tcol fcols[] = {
		{ "Id", "id", true }, { "File", "name", false },
		{ "Size", "size", true }, { "References", "refs", true },
		{ "Modules in it", NULL, false }, { "At boot", NULL, false },
	};
	static const struct tcol mcols[] = {
		{ "Type", "name", false }, { "Memory", "bytes", true },
		{ "", NULL, false }, { "In use", "count", true },
		{ "Requests", "requests", true },
	};
	static const struct tcol zcols[] = {
		{ "Zone", "name", false }, { "Memory", "bytes", true },
		{ "", NULL, false }, { "In use", "count", true },
		{ "Free", "free", true }, { "Item size", "size", true },
		{ "Requests", "requests", true },
	};
	const ucl_object_t	**rows, *o, *m, *mem;
	ucl_object_iter_t	 it, mit;
	const char		*name;
	char			 buf[32], age[32], base[80];
	int64_t			 used, top;
	bool			 mine, first;
	int			 n, shown, r;

	mine = kn.data != NULL && strcmp(kn.sid, s->id) == 0;
	h_raw(h, "<div class=\"toolbar\"><form data-form=\"kmod-load\" class=\""
	    "kmod-load\"><input name=\"name\" list=\"kmods\" spellcheck=\""
	    "false\" autocomplete=\"off\" placeholder=\"a module to load: "
	    "sctp, if_wg, pf…\"><datalist id=\"kmods\">");
	it = NULL;
	while (mine && (o = ucl_object_iterate(jget(kn.data, "available"), &it,
	    true)) != NULL) {
		h_raw(h, "<option");
		h_attr(h, "value", ucl_object_tostring_forced(o));
		h_raw(h, ">");
	}
	h_raw(h, "</datalist><label class=\"toggle\" title=\"Also in rc.conf's "
	    "kld_list: loaded when the host starts\"><input type=\"checkbox\" "
	    "name=\"persist\"><span>at boot too</span></label><button class=\""
	    "ghost small\">Load</button></form><input class=\"filter\" id=\""
	    "filter\" data-input=\"filter\" placeholder=\"Filter rows\" "
	    "autocomplete=\"off\" spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, ">");
	if (mine) {
		fmt_age(age, sizeof(age), kn.fetched);
		h_raw(h, "<span class=\"tally\">");
		h_txt(h, age);
		h_raw(h, "</span>");
	}
	h_raw(h, "</div>");
	if (kn.error[0] != '\0' && strcmp(kn.sid, s->id) == 0) {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, kn.error);
		h_raw(h, "</div>");
	}
	if (!mine) {
		h_raw(h, kn.loading ? "<div class=\"empty\"><div class=\"loader"
		    "\"></div></div>" : "<div class=\"empty\"><h2>No data</h2>"
		    "<p>The host has not answered yet.</p></div>");
		return;
	}
	mem = jget(kn.data, "memory");
	used = jint(mem, "kmem_map_size", 0);
	h_raw(h, "<div class=\"facts kmem\">");
	snprintf(buf, sizeof(buf), "%d files", (int)ucl_array_size(jget(
	    kn.data, "files")));
	tile(h, "the kernel and its modules", jint(mem, "files", 0), buf);
	size(buf, sizeof(buf), jint(mem, "kmem_size", 0));
	snprintf(base, sizeof(base), "of %s", buf);
	tile(h, "kernel memory in use", used, base);
	tile(h, "in malloc(9) types", jint(mem, "malloc_total", 0), NULL);
	tile(h, "kernel memory free", jint(mem, "kmem_map_free", 0), NULL);
	h_raw(h, "</div>");

	/* Whatever rc.conf loads at boot and is not in now. */
	first = true;
	it = NULL;
	while ((o = ucl_object_iterate(jget(kn.data, "kept"), &it, true)) !=
	    NULL) {
		name = ucl_object_tostring_forced(o);
		mit = NULL;
		while ((m = ucl_object_iterate(jget(kn.data, "files"), &mit,
		    true)) != NULL) {
			snprintf(base, sizeof(base), "%s", jstr(m, "name") !=
			    NULL ? jstr(m, "name") : "");
			if (strlen(base) > 3 && strcmp(base + strlen(base) - 3,
			    ".ko") == 0)
				base[strlen(base) - 3] = '\0';
			if (strcmp(base, name) == 0 || (jstr(m, "name") !=
			    NULL && strcmp(jstr(m, "name"), name) == 0))
				break;
		}
		if (m != NULL)
			continue;
		h_raw(h, first ? "<div class=\"notice info\">Loaded at boot by "
		    "<code>kld_list</code>, and not in the kernel now: " : ", ");
		h_raw(h, "<b>");
		h_txt(h, name);
		h_raw(h, "</b>");
		first = false;
	}
	if (!first)
		h_raw(h, ".</div>");

	h_raw(h, "<table class=\"net kmods\">");
	tbl_head(h, "kmods", fcols, 6, 1);
	h_raw(h, "<tbody>");
	/* The filter is its own here: a file's name, or a module's in it. */
	rows = tbl_rows("kmods", jget(kn.data, "files"), fcols, 6, NULL);
	shown = 0;
	for (r = 0; (o = rows[r]) != NULL; r++) {
		name = jstr(o, "name") != NULL ? jstr(o, "name") : "";
		if (app.filter[0] != '\0' && strstr(name, app.filter) == NULL) {
			/* Or one of the modules it holds. */
			mit = NULL;
			while ((m = ucl_object_iterate(jget(o, "modules"),
			    &mit, true)) != NULL)
				if (strstr(ucl_object_tostring_forced(m),
				    app.filter) != NULL)
					break;
			if (m == NULL)
				continue;
		}
		shown++;
		h_raw(h, "<tr");
		h_attr(h, "data-kld", name);
		h_fmt(h, "><td class=\"dim\">%lld</td><td><b>", (long long)jint(
		    o, "id", 0));
		h_txt(h, name);
		h_raw(h, "</b><small class=\"dim\">");
		h_txt(h, jstr(o, "path"));
		h_raw(h, "</small></td><td>");
		size(buf, sizeof(buf), jint(o, "size", 0));
		h_txt(h, buf);
		h_fmt(h, "</td><td>%lld</td><td class=\"mods\"", (long long)
		    jint(o, "refs", 0));
		n = (int)ucl_array_size(jget(o, "modules"));
		if (n > 6) {
			/* The kernel itself holds hundreds: counted. */
			h_fmt(h, "><details><summary>%d modules</summary>", n);
		} else
			h_raw(h, ">");
		mit = NULL;
		first = true;
		while ((m = ucl_object_iterate(jget(o, "modules"), &mit,
		    true)) != NULL) {
			h_raw(h, first ? "" : ", ");
			h_txt(h, ucl_object_tostring_forced(m));
			first = false;
		}
		h_raw(h, n > 6 ? "</details></td><td>" : "</td><td>");
		if (in_list(jget(kn.data, "kept"), name))
			h_raw(h, "<span class=\"chip\">kld_list</span>");
		h_raw(h, "</td><td class=\"acts\">");
		if (jint(o, "id", 0) != 1 && strcmp(name, "kernel") != 0) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "kmod-unload\"");
			h_attr(h, "data-arg", name);
			h_attr(h, "data-value", in_list(jget(kn.data, "kept"),
			    name) ? "kept" : "");
			h_fmt(h, "%s>Unload</button>", jint(o, "refs", 0) > 1 ?
			    " title=\"Something else in the kernel holds it: "
			    "the kernel refuses while that is so\"" : "");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
	if (shown == 0)
		h_raw(h, "<p class=\"dim\">No file of that name, and none "
		    "holding a module of it.</p>");

	/* Its memory: by what asked for it. */
	h_fmt(h, "<h4 class=\"family\">Kernel memory <nav class=\"sub\"><button "
	    "class=\"ghost small%s\" data-act=\"kmem\" data-arg=\"malloc\">"
	    "malloc types</button><button class=\"ghost small%s\" data-act=\""
	    "kmem\" data-arg=\"zones\">zones</button></nav></h4>", kn.zones ?
	    "" : " on", kn.zones ? " on" : "");
	h_raw(h, "<table class=\"net kmem\">");
	if (kn.zones)
		tbl_head(h, "kzones", zcols, 7, 0);
	else
		tbl_head(h, "kmalloc", mcols, 5, 0);
	h_raw(h, "<tbody>");
	/* The bars are to the largest of all, whatever the order. */
	top = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(mem, kn.zones ? "zones" :
	    "malloc"), &it, true)) != NULL)
		if (jint(o, "bytes", 0) > top)
			top = jint(o, "bytes", 0);
	rows = tbl_rows(kn.zones ? "kzones" : "kmalloc", jget(mem, kn.zones ?
	    "zones" : "malloc"), kn.zones ? zcols : mcols, kn.zones ? 7 : 5,
	    app.filter);
	for (r = 0; (o = rows[r]) != NULL; r++) {
		name = jstr(o, "name") != NULL ? jstr(o, "name") : "";
		h_raw(h, "<tr><td>");
		h_txt(h, name);
		h_raw(h, "</td><td>");
		size(buf, sizeof(buf), jint(o, "bytes", 0));
		h_txt(h, buf);
		h_fmt(h, "</td><td class=\"bar\"><i style=\"width:%.1f%%\"></i>"
		    "</td><td>%lld</td>", top > 0 ? 100.0 * (double)jint(o,
		    "bytes", 0) / (double)top : 0.0, (long long)jint(o, "count",
		    0));
		if (kn.zones) {
			size(buf, sizeof(buf), jint(o, "size", 0));
			h_fmt(h, "<td>%lld</td><td>%s</td>", (long long)jint(o,
			    "free", 0), buf);
		}
		h_fmt(h, "<td class=\"dim\">%lld</td></tr>", (long long)jint(o,
		    "requests", 0));
	}
	free(rows);
	h_raw(h, "</tbody></table><p class=\"dim\">The largest, as <code>"
	    "vmstat -m</code> and <code>vmstat -z</code> count them. A "
	    "module's own memory is under the types and zones it made, "
	    "not under its file. A zone's memory is its items, in use and "
	    "free, times their size; zones are built on one another, so "
	    "they do not add up.</p>");
}

static void
kmod_job(struct server *s, const char *verb, const char *name, bool persist)
{
	char	*q, *json, title[160];

	q = json_quote(name);
	if (asprintf(&json, "{\"kind\":\"kmod\",\"verb\":\"%s\",\"args\":[%s],"
	    "\"persist\":%s}", verb, q, persist ? "true" : "false") == -1)
		abort();
	free(q);
	snprintf(title, sizeof(title), "kld%s %s", verb, name);
	job_send_host(s, json, title, JOB_KERNEL, name);
}

static bool
name_ok(const char *s)
{

	if (s[0] == '\0' || s[0] == '-' || s[0] == '.' || strlen(s) > 64)
		return (false);
	return (s[strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
	    "YZ0123456789_.-")] == '\0');
}

bool
kernel_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*name;

	if (strcmp(form, "kmod-load") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	name = jstr(f, "name") != NULL ? jstr(f, "name") : "";
	if (!name_ok(name)) {
		toast(true, "Name a module as kldload finds it, without a "
		    "path: sctp, if_wg");
		return (true);
	}
	kmod_job(s, "load", name, jbool(f, "persist"));
	return (true);
}

bool
kernel_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[400];

	if (strcmp(act, "kmem") != 0 && strcmp(act, "kmod-unload") != 0 &&
	    strcmp(act, "do-kmod-unload") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "kmem") == 0) {
		kn.zones = strcmp(arg, "zones") == 0;
	} else if (strcmp(act, "kmod-unload") == 0 && name_ok(arg)) {
		snprintf(body, sizeof(body), "kldunload %s, on %s%s. What the "
		    "module did stops with it: an interface it drives is "
		    "gone, a firewall it is lets everything through or "
		    "nothing. The kernel refuses while something still uses "
		    "it.", arg, s->name, value[0] != '\0' ? ", and it is taken "
		    "out of rc.conf's kld_list" : "");
		confirm("Unload the module", body, "Unload", true, arg,
		    "do-kmod-unload", arg, value);
	} else if (strcmp(act, "do-kmod-unload") == 0 && name_ok(arg)) {
		kmod_job(s, "unload", arg, value[0] != '\0');
	}
	return (true);
}
