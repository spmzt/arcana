/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * In a host's network tab: its IPsec, strongSwan through swanctl(8),
 * IKEv2 only.  The host has a key of its own, made there; the page
 * knows its public half, which is what a peer is given.  A connection
 * is between two addresses, in tunnel mode or in transport mode, and
 * with a reqid it serves the ipsec(4) interface made with that reqid.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static void
ipsec_job(struct server *s, const char *title, const char *fmt, ...)
{
	va_list	 ap;
	char	*json;

	va_start(ap, fmt);
	if (vasprintf(&json, fmt, ap) == -1)
		abort();
	va_end(ap);
	job_send(s, json, title, JOB_IFACE, "vpn");
}

/* The SA of a connection, by its name, or NULL. */
static const ucl_object_t *
sa_of(const ucl_object_t *data, const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while (name != NULL && (o = ucl_object_iterate(jget(data, "sas"), &it,
	    true)) != NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (o);
	return (NULL);
}

static void
list(struct html *h, const ucl_object_t *a)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	bool			 first;

	first = true;
	it = NULL;
	while ((v = ucl_object_iterate(a, &it, true)) != NULL) {
		if (!first)
			h_raw(h, ", ");
		h_txt(h, ucl_object_tostring_forced(v));
		first = false;
	}
	if (first)
		h_raw(h, "<span class=\"dim\">—</span>");
}

static void
bytes(char *buf, size_t len, int64_t n)
{
	static const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	double	v;
	int	u;

	v = (double)n;
	for (u = 0; v >= 1024 && u < 4; u++)
		v /= 1024;
	snprintf(buf, len, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
}

void
view_ipsec(struct html *h, struct server *s, const ucl_object_t *data)
{
	static const struct tcol	ccols[] = {
		{ "Connection", "name", false }, { "Between", NULL, false },
		{ "Child", NULL, false }, { "State", NULL, false },
		{ "In / out", NULL, false },
	};
	const ucl_object_t		**rows, *c, *k, *sa, *sk;
	ucl_object_iter_t		  it;
	const char			 *state;
	char				  in[24], out[24];
	int				  r;
	bool				  running;

	(void)s;
	running = jbool(data, "running");
	h_raw(h, "<section class=\"pane ipsec\"><h4><span>strongSwan <small>"
	    "IKEv2 only</small></span><span class=\"pane-actions\">");
	if (!running)
		h_raw(h, "<button class=\"ghost small\" data-act=\"ipsec-start\" "
		    "title=\"service strongswan onestart\">Start</button>");
	h_fmt(h, "<button class=\"ghost small\" data-act=\"ipsec-init\" "
	    "title=\"%s\">%s</button><button class=\"ghost small\" data-act=\""
	    "ipsec-conn-add\">+ connection</button></span></h4>",
	    jstr(data, "public-key") != NULL ? "Keep it started at boot; the "
	    "key it has stays" : "The host makes its key and keeps it",
	    jstr(data, "public-key") != NULL ? "At boot" : "Make its key");
	if (!running)
		h_raw(h, "<p class=\"notice warn\">strongSwan is not running "
		    "here: <b>Start</b> starts it, and what is in "
		    "<code>swanctl/conf.d</code> is read then.</p>");
	if (jstr(data, "public-key") != NULL) {
		h_raw(h, "<p>Its public key, for its peers <code class=\"key "
		    "pub\">");
		h_txt(h, jstr(data, "public-key"));
		h_raw(h, "</code></p>");
	} else
		h_raw(h, "<p class=\"dim\">It has no key yet: <b>Make its "
		    "key</b> has the host make one, ECDSA P-256, which stays "
		    "on the host; its peers are given the public half.</p>");
	h_raw(h, "</section>");

	if (ucl_array_size(jget(data, "connections")) == 0) {
		h_raw(h, "<div class=\"empty\"><p>No connections. <b>+ "
		    "connection</b> joins this host to another by their two "
		    "keys: in tunnel mode, or in transport mode under a gre, "
		    "gif or WireGuard tunnel between the same addresses.</p>"
		    "</div>");
		return;
	}
	h_raw(h, "<table class=\"net ipsec\">");
	tbl_head(h, "ipsec", ccols, 5, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("ipsec", jget(data, "connections"), ccols, 5,
	    app.filter);
	for (r = 0; (c = rows[r]) != NULL; r++) {
		sa = sa_of(data, jstr(c, "name"));
		sk = sa != NULL ? ucl_array_find_index(jget(sa, "children"), 0) :
		    NULL;
		state = sk != NULL ? jstr(sk, "state") : sa != NULL ? jstr(sa,
		    "state") : NULL;
		h_fmt(h, "<tr class=\"%s\"><td><i class=\"led\"></i><b>",
		    state != NULL && strcmp(state, "INSTALLED") == 0 ? "up" :
		    "down");
		h_txt(h, jstr(c, "name"));
		h_raw(h, "</b>");
		if (jstr(c, "version") == NULL || strcmp(jstr(c, "version"),
		    "IKEv2") != 0) {
			h_raw(h, "<small class=\"warn\">");
			h_txt(h, jstr(c, "version") != NULL ? jstr(c,
			    "version") : "?");
			h_raw(h, ": not IKEv2</small>");
		} else if (!jbool(c, "arcana"))
			h_raw(h, "<small>not arcana's</small>");
		h_raw(h, "</td><td>");
		list(h, jget(c, "local_addrs"));
		h_raw(h, " ⇄ ");
		list(h, jget(c, "remote_addrs"));
		h_raw(h, "<small>");
		h_txt(h, jstr(c, "local-id"));
		h_raw(h, " ⇄ ");
		h_txt(h, jstr(c, "remote-id"));
		h_raw(h, "</small></td><td>");
		it = NULL;
		while ((k = ucl_object_iterate(jget(c, "children"), &it,
		    true)) != NULL) {
			h_txt(h, jstr(k, "mode") != NULL ? jstr(k, "mode") :
			    "?");
			h_raw(h, "<small>");
			list(h, jget(k, "local-ts"));
			h_raw(h, " ⇄ ");
			list(h, jget(k, "remote-ts"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		if (sa == NULL)
			h_raw(h, "<span class=\"dim\">no SA</span>");
		else {
			h_txt(h, jstr(sa, "state"));
			if (sk != NULL) {
				h_raw(h, "<small>");
				h_txt(h, jstr(sk, "state"));
				if (jint(sk, "reqid", 0) > 0)
					h_fmt(h, " · reqid %lld", (long long)jint(sk,
					    "reqid", 0));
				h_raw(h, " · ");
				h_txt(h, jstr(sa, "encr-alg"));
				h_raw(h, "</small>");
			}
		}
		h_raw(h, "</td><td>");
		if (sk != NULL) {
			bytes(in, sizeof(in), jint(sk, "bytes-in", 0));
			bytes(out, sizeof(out), jint(sk, "bytes-out", 0));
			h_txt(h, in);
			h_raw(h, " / ");
			h_txt(h, out);
		}
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"ipsec-up\"");
		h_attr(h, "data-arg", jstr(c, "name"));
		h_raw(h, ">Up</button><button class=\"ghost small\" data-act=\""
		    "ipsec-down\"");
		h_attr(h, "data-arg", jstr(c, "name"));
		h_raw(h, ">Down</button>");
		if (jbool(c, "arcana")) {
			h_raw(h, "<button class=\"icon\" data-act=\""
			    "ipsec-unconn\" title=\"Take the connection away\"");
			h_attr(h, "data-arg", jstr(c, "name"));
			h_raw(h, ">×</button>");
		}
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

bool
ipsec_modal(struct html *h)
{

	if (app.modal != MODAL_IPSEC_CONN)
		return (false);
	h_raw(h, "<form data-form=\"ipsec-conn\"><h2>An IPsec connection</h2>"
	    "<p>IKEv2, the two hosts known by their keys. Written as "
	    "<code>conf.d/arcana-</code><i>name</i><code>.conf</code>, which "
	    "strongSwan reads again; one of that name is replaced. The peer "
	    "is given this host's key the same way.</p>"
	    "<label>Name<input name=\"conn\" spellcheck=\"false\" "
	    "autocomplete=\"off\" maxlength=\"32\" placeholder=\"to-edge-b\" "
	    "autofocus></label>"
	    "<div class=\"two\"><label>This host's address<input name=\""
	    "local\" spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
	    "192.0.2.1 or 2001:db8::1\"></label><label>The peer's address"
	    "<input name=\"remote\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"192.0.2.2 or 2001:db8::2\"></label></div>"
	    "<label>Mode<select name=\"mode\"><option value=\"tunnel\">tunnel: "
	    "packets inside new ones</option><option value=\"transport\">"
	    "transport: what is sent between the two addresses, as it is"
	    "</option></select></label>"
	    "<label>The peer's public key<textarea name=\"pubkey\" rows=\"3\" "
	    "spellcheck=\"false\" placeholder=\"base64, as the peer's IPsec "
	    "tab shows it\"></textarea></label>"
	    "<div class=\"two\"><label>This side's traffic<input name=\""
	    "local_ts\" spellcheck=\"false\" autocomplete=\"off\" placeholder="
	    "\"its address; 192.0.2.1[gre]\"></label><label>The peer's "
	    "traffic<input name=\"remote_ts\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"its address; 192.0.2.2[gre]\">"
	    "</label></div>"
	    "<div class=\"two\"><label>reqid<input name=\"reqid\" inputmode="
	    "\"numeric\" placeholder=\"none\"><small>Of the ipsec interface it "
	    "serves, made with that reqid: tunnel mode, its traffic the "
	    "interface's.</small></label><label>Started<select name=\"start\">"
	    "<option value=\"trap\">with the first packet</option><option "
	    "value=\"start\">at once, and kept up</option><option value=\""
	    "none\">only when asked</option></select></label></div>"
	    "<div class=\"two\"><label>This side's identity<input name=\""
	    "local_id\" spellcheck=\"false\" autocomplete=\"off\" placeholder="
	    "\"its address\"></label><label>The peer's identity<input name=\""
	    "remote_id\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"its address\"></label></div>");
	return (true);
}

/* A field, as JSON after its key, or nothing when it is empty. */
static char *
opt(const ucl_object_t *f, const char *field, const char *key)
{
	char	*q, *out;

	if (jstr(f, field) == NULL || jstr(f, field)[0] == '\0')
		return (strdup(""));
	q = json_quote(jstr(f, field));
	if (asprintf(&out, ",\"%s\":%s", key, q) == -1)
		abort();
	free(q);
	return (out);
}

bool
ipsec_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v, *k;
	char		 title[160], key[1100], reqid[32], *qn, *ql, *qr, *qm,
			*qk, *lts, *rts, *lid, *rid, *qs;
	size_t		 n;

	if (strcmp(form, "ipsec-conn") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (jstr(f, "conn") == NULL || jstr(f, "conn")[0] == '\0' ||
	    jstr(f, "local") == NULL || jstr(f, "local")[0] == '\0' ||
	    jstr(f, "remote") == NULL || jstr(f, "remote")[0] == '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "A "
		    "connection has a name and both addresses");
		return (true);
	}
	/* The key as pasted, PEM or not: its base64 alone. */
	n = 0;
	k = jstr(f, "pubkey") != NULL ? jstr(f, "pubkey") : "";
	if ((v = strstr(k, "-----BEGIN PUBLIC KEY-----")) != NULL)
		k = v + strlen("-----BEGIN PUBLIC KEY-----");
	for (; *k != '\0' && *k != '-' && n < sizeof(key) - 1; k++)
		if (*k != ' ' && *k != '\n' && *k != '\r' && *k != '\t')
			key[n++] = *k;
	key[n] = '\0';
	if (n < 40) {
		snprintf(app.modal_error, sizeof(app.modal_error), "The peer's "
		    "public key, as its IPsec tab shows it");
		return (true);
	}
	reqid[0] = '\0';
	if ((v = jstr(f, "reqid")) != NULL && v[0] != '\0') {
		if (strlen(v) > 5 || v[strspn(v, "0123456789")] != '\0' ||
		    atoi(v) < 1 || atoi(v) > 16383) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "reqid is a number from 1 to 16383");
			return (true);
		}
		if (strcmp(jstr(f, "mode") != NULL ? jstr(f, "mode") : "",
		    "tunnel") != 0) {
			snprintf(app.modal_error, sizeof(app.modal_error), "An "
			    "ipsec interface's connection is in tunnel mode");
			return (true);
		}
		snprintf(reqid, sizeof(reqid), ",\"reqid\":%d", atoi(v));
	}
	qn = json_quote(jstr(f, "conn"));
	ql = json_quote(jstr(f, "local"));
	qr = json_quote(jstr(f, "remote"));
	qm = json_quote(jstr(f, "mode") != NULL ? jstr(f, "mode") : "tunnel");
	qk = json_quote(key);
	qs = json_quote(jstr(f, "start") != NULL ? jstr(f, "start") : "trap");
	lts = opt(f, "local_ts", "local_ts");
	rts = opt(f, "remote_ts", "remote_ts");
	lid = opt(f, "local_id", "local_id");
	rid = opt(f, "remote_id", "remote_id");
	snprintf(title, sizeof(title), "ipsec conn %s (%s)", jstr(f, "conn"),
	    jstr(f, "mode") != NULL ? jstr(f, "mode") : "tunnel");
	ipsec_job(s, title, "{\"kind\":\"ipsec\",\"verb\":\"conn\",\"conn\":%s,"
	    "\"tunnel_local\":%s,\"tunnel_remote\":%s,\"ipsec_mode\":%s,"
	    "\"pubkey\":%s,\"start_action\":%s%s%s%s%s%s}", qn, ql, qr, qm, qk,
	    qs, reqid, lts, rts, lid, rid);
	free(qn);
	free(ql);
	free(qr);
	free(qm);
	free(qk);
	free(qs);
	free(lts);
	free(rts);
	free(lid);
	free(rid);
	app.modal = MODAL_NONE;
	return (true);
}

bool
ipsec_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[400], title[160], *qa;

	(void)value;
	if (strncmp(act, "ipsec-", 6) != 0 && strncmp(act, "do-ipsec-", 9) !=
	    0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "ipsec-conn-add") == 0) {
		app.modal = MODAL_IPSEC_CONN;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "ipsec-init") == 0) {
		ipsec_job(s, "ipsec init", "{\"kind\":\"ipsec\",\"verb\":"
		    "\"init\",\"persist\":true}");
	} else if (strcmp(act, "ipsec-start") == 0) {
		ipsec_job(s, "ipsec start", "{\"kind\":\"ipsec\",\"verb\":"
		    "\"start\"}");
	} else if (strcmp(act, "ipsec-up") == 0 || strcmp(act, "ipsec-down") ==
	    0) {
		qa = json_quote(arg);
		snprintf(title, sizeof(title), "ipsec %s %s", act + 6, arg);
		ipsec_job(s, title, "{\"kind\":\"ipsec\",\"verb\":\"%s\","
		    "\"conn\":%s}", act + 6, qa);
		free(qa);
	} else if (strcmp(act, "ipsec-unconn") == 0) {
		snprintf(body, sizeof(body), "The connection %s goes, on %s: its "
		    "security associations end, and its file and its peer's "
		    "key are taken out of swanctl's directory. What went "
		    "through it stops, or goes in the clear.", arg, s->name);
		confirm("Take the connection away", body, "Take away", true,
		    "", "do-ipsec-unconn", arg, "");
	} else if (strcmp(act, "do-ipsec-unconn") == 0) {
		qa = json_quote(arg);
		snprintf(title, sizeof(title), "ipsec unconn %s", arg);
		ipsec_job(s, title, "{\"kind\":\"ipsec\",\"verb\":\"unconn\","
		    "\"conn\":%s}", qa);
		free(qa);
	}
	return (true);
}
