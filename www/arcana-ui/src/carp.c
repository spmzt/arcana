/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * CARP: an address that hosts on one network share with carp(4), held
 * by the one that is MASTER of its virtual host (vhid), by CARP's own
 * protocol or by VRRPv3.  Read from the interfaces, each vhid a row:
 * its state, its timing, its addresses; one told to step back or to
 * take over, changed, an address added under a vhid or taken off.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char	ifname[32];	/* the vhid changed, or "" a new one */
	int	vhid;
	int	version;
	/* The interfaces offered, as they were when the box opened: the
	 * network shown may be read again meanwhile. */
	char	ifs[64][32];
	int	nifs;
} cp;

/* A carp job in the network shown; key is never kept by the page. */
static void
carp_job(struct server *s, const char *verb, const char *ifname,
    const char *address, const char *words, const char *key, bool keep)
{
	struct html	 b;
	char		*q, title[200];
	const char	*p, *e;
	bool		 first;

	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\"kind\":\"carp\",\"verb\":\"%s\",\"interface\":", verb);
	q = json_quote(ifname);
	h_raw(&b, q);
	free(q);
	if (address != NULL) {
		q = json_quote(address);
		h_raw(&b, ",\"address\":");
		h_raw(&b, q);
		free(q);
	}
	h_raw(&b, ",\"args\":[");
	first = true;
	for (p = words; *p != '\0'; p = e) {
		p += strspn(p, " ");
		if (*p == '\0')
			break;
		e = p + strcspn(p, " ");
		{
			char	one[64];

			snprintf(one, sizeof(one), "%.*s", (int)(e - p), p);
			q = json_quote(one);
			h_fmt(&b, "%s%s", first ? "" : ",", q);
			free(q);
		}
		first = false;
	}
	h_raw(&b, "]");
	if (key != NULL && key[0] != '\0') {
		q = json_quote(key);
		h_raw(&b, ",\"preshared_key\":");
		h_raw(&b, q);
		free(q);
	}
	h_fmt(&b, ",\"persist\":%s}", keep ? "true" : "false");
	snprintf(title, sizeof(title), "%s: carp %s %s%s%s", ifname, verb,
	    words, address != NULL ? " " : "", address != NULL ? address : "");
	job_send(s, b.s, title, JOB_IFACE, ifname);	/* it keeps b.s */
}

/* The vhids of every interface, a row each, with their addresses. */
void
view_carp(struct html *h, struct server *s, const ucl_object_t *data)
{
	static const struct tcol cols[] = {
		{ "Interface", "if", false }, { "VHID", "vhid", true },
		{ "State", "state", false }, { "Protocol", "proto", false },
		{ "Timing", NULL, false }, { "Addresses", "addrs", false },
		{ "", NULL, false },
	};
	const ucl_object_t	*i, *c, *a, **rows, *r;
	ucl_object_iter_t	 it, ct, at;
	ucl_object_t		*arr, *o;
	struct html		 ad;
	char			 buf[96];
	int			 n;

	(void)s;
	h_raw(h, "<p class=\"dim\">An address the hosts on one network share "
	    "with <code>carp(4)</code>: the host that is MASTER of its virtual "
	    "host (vhid) answers for it, the others wait as BACKUP and take "
	    "over when its advertisements stop. The one with the smallest "
	    "skew (CARP) or the highest priority (VRRPv3) is MASTER; with "
	    "<code>net.inet.carp.preempt</code> it takes it back when it "
	    "returns. Every host of a vhid has the same key.</p>");
	if (!jbool(data, "carp")) {
		h_raw(h, "<div class=\"notice info\">carp(4) is not loaded on "
		    "this host. <button class=\"ghost small\" data-act=\""
		    "carp-load\" title=\"kldload carp, and carp in rc.conf's "
		    "kld_list\">Load carp</button></div>");
		return;
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((i = ucl_object_iterate(jget(data, "interfaces"), &it, true)) !=
	    NULL) {
		ct = NULL;
		while ((c = ucl_object_iterate(jget(i, "carp"), &ct, true)) !=
		    NULL) {
			o = ucl_object_copy(c);
			ucl_object_insert_key(o, ucl_object_fromstring(jstr(i,
			    "name")), "if", 0, false);
			ucl_object_insert_key(o, ucl_object_fromstring(jint(c,
			    "version", 2) == 3 ? "VRRPv3" : "CARP"), "proto", 0,
			    false);
			memset(&ad, 0, sizeof(ad));
			at = NULL;
			while ((a = ucl_object_iterate(jget(i, "addresses"), &at,
			    true)) != NULL)
				if (jint(a, "vhid", 0) == jint(c, "vhid", -1))
					h_fmt(&ad, "%s%s/%lld", ad.s != NULL ? " " :
					    "", jstr(a, "address"), (long long)jint(a,
					    "prefixlen", 0));
			ucl_object_insert_key(o, ucl_object_fromstring(ad.s !=
			    NULL ? ad.s : ""), "addrs", 0, false);
			free(ad.s);
			ucl_array_append(arr, o);
		}
	}
	h_raw(h, "<table class=\"net carp\">");
	tbl_head(h, "carp", cols, 7, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("carp", arr, cols, 7, app.filter);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(r, "if"));
		h_fmt(h, "</b></td><td>%lld</td><td><span class=\"chip %s\">",
		    (long long)jint(r, "vhid", 0), strcmp(jstr(r, "state"),
		    "MASTER") == 0 ? "ok" : strcmp(jstr(r, "state"), "BACKUP") ==
		    0 ? "" : "warn");
		h_txt(h, jstr(r, "state"));
		h_raw(h, "</span></td><td>");
		h_txt(h, jstr(r, "proto"));
		h_raw(h, "</td><td class=\"dim\">");
		if (jint(r, "version", 2) == 3)
			snprintf(buf, sizeof(buf), "priority %lld, every %lld cs",
			    (long long)jint(r, "prio", 0), (long long)jint(r,
			    "interval", 0));
		else
			snprintf(buf, sizeof(buf), "every %lld s, skew %lld",
			    (long long)jint(r, "advbase", 0), (long long)jint(r,
			    "advskew", 0));
		h_txt(h, buf);
		h_raw(h, "</td><td><ul class=\"chips\">");
		{
			const char	*p, *e;

			for (p = jstr(r, "addrs"); p != NULL && *p != '\0';
			    p = *e != '\0' ? e + 1 : e) {
				char	one[80];

				e = p + strcspn(p, " ");
				snprintf(one, sizeof(one), "%.*s", (int)(e - p), p);
				h_raw(h, "<li class=\"chip\"><span>");
				h_txt(h, one);
				h_raw(h, "</span><button class=\"icon\" data-act=\""
				    "carp-remove\" title=\"Taken off; the vhid goes "
				    "with its last\"");
				h_attr(h, "data-arg", jstr(r, "if"));
				snprintf(one, sizeof(one), "%.*s %lld", (int)strcspn(p,
				    "/"), p, (long long)jint(r, "vhid", 0));
				h_attr(h, "data-value", one);
				h_raw(h, ">×</button></li>");
			}
		}
		h_raw(h, "</ul></td><td class=\"acts\">");
		snprintf(buf, sizeof(buf), "%lld %lld", (long long)jint(r, "vhid",
		    0), (long long)jint(r, "version", 2));
		if (strcmp(jstr(r, "state"), "MASTER") == 0)
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "carp-backup\" title=\"Step back: another host of "
			    "the vhid takes over\"");
		else
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "carp-master\" title=\"Take over now\"");
		h_attr(h, "data-arg", jstr(r, "if"));
		h_attr(h, "data-value", buf);
		h_fmt(h, ">%s</button><button class=\"icon\" data-act=\""
		    "carp-edit\" title=\"Its timing and key\"", strcmp(jstr(r,
		    "state"), "MASTER") == 0 ? "Backup" : "Master");
		h_attr(h, "data-arg", jstr(r, "if"));
		h_attr(h, "data-value", buf);
		h_raw(h, ">&#9998;</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"7\" class=\"dim\">No vhid here: "
		    "<b>+ CARP address</b> makes one.</td></tr>");
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");
}

/* The interfaces to offer, from the interfaces read for this view. */
static void
carp_ifs(void)
{
	const ucl_object_t	*i;
	ucl_object_iter_t	 it;

	if (app.net.data_kind != NET_CARP)
		return;
	it = NULL;
	while (cp.nifs < 64 && (i = ucl_object_iterate(jget(app.net.data,
	    "data.interfaces"), &it, true)) != NULL)
		if (jstr(i, "name") != NULL && strncmp(jstr(i, "name"), "lo",
		    2) != 0)
			snprintf(cp.ifs[cp.nifs++], sizeof(cp.ifs[0]), "%s",
			    jstr(i, "name"));
}

bool
carp_modal(struct html *h)
{
	bool			 isnew;
	int			 k;

	if (app.modal != MODAL_CARP)
		return (false);
	isnew = cp.ifname[0] == '\0';
	if (isnew && cp.nifs == 0)
		carp_ifs();
	h_raw(h, "<form data-form=\"carp\"><h2>");
	if (isnew)
		h_raw(h, "An address shared with carp(4)");
	else
		h_fmt(h, "vhid %d of ", cp.vhid);
	h_txt(h, isnew ? "" : cp.ifname);
	h_raw(h, "</h2><p>");
	h_raw(h, isnew ? "Every host that shares it gets the same address, "
	    "vhid and key, each on its interface on that network. The vhid "
	    "is set through carp's netlink family, so its key is never on a "
	    "command line; the address is added under it with <code>"
	    "ifconfig … vhid</code>." : "What is left empty stays as it is.");
	h_raw(h, "</p>");
	if (isnew) {
		h_raw(h, "<label>Interface<select name=\"ifname\">");
		for (k = 0; k < cp.nifs; k++) {
			h_raw(h, "<option");
			h_attr(h, "value", cp.ifs[k]);
			h_raw(h, ">");
			h_txt(h, cp.ifs[k]);
			h_raw(h, "</option>");
		}
		h_raw(h, "</select></label><label>Address<input name=\"address\" "
		    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
		    "192.0.2.1/24\" autofocus></label><label>VHID<input name=\""
		    "vhid\" inputmode=\"numeric\" placeholder=\"1 to 255\">"
		    "</label><label>Protocol<select name=\"version\"><option "
		    "value=\"2\">CARP</option><option value=\"3\">VRRPv3</option>"
		    "</select></label>");
	}
	if (isnew || cp.version != 3)
		h_raw(h, "<label>Advertised every<input name=\"advbase\" "
		    "inputmode=\"numeric\" placeholder=\"1\"><small>seconds, 1 to "
		    "255 (CARP)</small></label><label>Skew<input name=\""
		    "advskew\" inputmode=\"numeric\" placeholder=\"0\"><small>"
		    "0 to 254, added in 1/256 s: the smallest is MASTER (CARP)"
		    "</small></label>");
	if (isnew || cp.version == 3)
		h_raw(h, "<label>Priority<input name=\"prio\" inputmode=\""
		    "numeric\" placeholder=\"100\"><small>1 to 255: the highest "
		    "is MASTER (VRRPv3)</small></label><label>Interval<input "
		    "name=\"interval\" inputmode=\"numeric\" placeholder=\"100\">"
		    "<small>centiseconds (VRRPv3)</small></label>");
	if (isnew || cp.version != 3)
		h_raw(h, "<label>Key<input name=\"key\" type=\"password\" "
		    "autocomplete=\"new-password\"><small>the same on every host "
		    "of the vhid, 19 characters at most; it is sent once and the "
		    "page keeps it nowhere</small></label>");
	h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" name=\""
	    "persist\" checked> Keep it for a boot <small>an "
	    "<code>ifconfig_&lt;if&gt;_alias</code> line with the vhid's "
	    "words, its key too, and carp in <code>kld_list</code></small>"
	    "</label>");
	return (true);
}

/* "word=value " for each field given, as the host takes them. */
static void
words_of(const ucl_object_t *f, char *out, size_t len, bool isnew)
{
	static const char *const keys[] = { "advbase", "advskew", "prio",
	    "interval" };
	size_t	i, o;
	const char *v;

	o = 0;
	out[0] = '\0';
	if (isnew && jstr(f, "version") != NULL && strcmp(jstr(f, "version"),
	    "3") == 0)
		o += (size_t)snprintf(out + o, len - o, " version=3");
	for (i = 0; i < sizeof(keys) / sizeof(keys[0]) && o < len; i++)
		if ((v = jstr(f, keys[i])) != NULL && v[0] != '\0')
			o += (size_t)snprintf(out + o, len - o, " %s=%s", keys[i],
			    v);
}

bool
carp_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*ifn, *addr, *v;
	char		 words[200], all[240];
	int		 vhid;

	if (strcmp(form, "carp") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (cp.ifname[0] == '\0') {
		ifn = jstr(f, "ifname") != NULL ? jstr(f, "ifname") : "";
		addr = jstr(f, "address") != NULL ? jstr(f, "address") : "";
		vhid = (v = jstr(f, "vhid")) != NULL ? atoi(v) : 0;
		if (ifn[0] == '\0' || addr[0] == '\0' || strchr(addr, ' ') !=
		    NULL || vhid < 1 || vhid > 255) {
			snprintf(app.modal_error, sizeof(app.modal_error), "An "
			    "interface, an address such as 192.0.2.1/24, and a "
			    "vhid of 1 to 255");
			return (true);
		}
	} else {
		ifn = cp.ifname;
		addr = NULL;
		vhid = cp.vhid;
	}
	if ((v = jstr(f, "key")) != NULL && strlen(v) > 19) {
		snprintf(app.modal_error, sizeof(app.modal_error), "A key of 19 "
		    "characters at most");
		return (true);
	}
	words_of(f, words, sizeof(words), cp.ifname[0] == '\0');
	snprintf(all, sizeof(all), "vhid=%d%s", vhid, words);
	carp_job(s, addr != NULL ? "add" : "set", ifn, addr, all, jstr(f,
	    "key"), jbool(f, "persist"));
	app.modal = MODAL_NONE;
	return (true);
}

bool
carp_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 words[64], addr[80], body[400];
	int		 vhid, ver;

	if (strncmp(act, "carp-", 5) != 0 && strcmp(act, "do-carp-remove") !=
	    0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	app.modal_error[0] = '\0';
	vhid = ver = 0;
	if (value != NULL)
		(void)sscanf(value, "%d %d", &vhid, &ver);
	if (strcmp(act, "carp-add") == 0) {
		cp.ifname[0] = '\0';
		cp.nifs = 0;
		carp_ifs();
		app.modal = MODAL_CARP;
	} else if (strcmp(act, "carp-edit") == 0) {
		snprintf(cp.ifname, sizeof(cp.ifname), "%s", arg);
		cp.vhid = vhid;
		cp.version = ver;
		app.modal = MODAL_CARP;
	} else if (strcmp(act, "carp-master") == 0 || strcmp(act,
	    "carp-backup") == 0) {
		snprintf(words, sizeof(words), "vhid=%d state=%s", vhid, act[5] ==
		    'm' ? "master" : "backup");
		carp_job(s, "set", arg, NULL, words, NULL, false);
	} else if (strcmp(act, "carp-remove") == 0) {
		(void)sscanf(value, "%79s %d", addr, &vhid);
		snprintf(body, sizeof(body), "%s taken off %s of %s, and out of "
		    "rc.conf where it is kept there; vhid %d goes with its last "
		    "address.", addr, arg, s->name, vhid);
		confirm("Take the address off", body, "Take off", true, "",
		    "do-carp-remove", arg, value);
	} else if (strcmp(act, "do-carp-remove") == 0) {
		(void)sscanf(value, "%79s %d", addr, &vhid);
		snprintf(words, sizeof(words), "vhid=%d", vhid);
		carp_job(s, "remove", arg, addr, words, NULL, true);
	} else if (strcmp(act, "carp-load") == 0) {
		char	*j;

		if ((j = strdup("{\"kind\":\"kmod\",\"verb\":\"load\",\"args\":"
		    "[\"carp\"],\"persist\":true}")) == NULL)
			abort();
		job_send_host(s, j, "kldload carp", JOB_KERNEL, "carp");
	}
	return (true);
}
