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
#include <time.h>

#include "app.h"

static bool	ipsec_child_modal(struct html *);

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
	    "ipsec-conn-add\">+ connection</button><button class=\"ghost "
	    "small\" data-act=\"ipsec-sa-add\" title=\"Security associations "
	    "keyed by hand or by a key agreement of the two hosts' own, for an "
	    "ipsec(4) interface: setkey(8), no IKE\">+ manual SAs</button>"
	    "</span></h4>",
	    jstr(data, "public-key") != NULL ? "Keep it started at boot; the "
	    "key it has stays" : "The host makes its key and keeps it",
	    jstr(data, "public-key") != NULL ? "At boot" : "Make its key");
	/* A jail cannot load ipsec.ko: its host must have it. */
	if (jget(data, "kernel") != NULL && !jbool(data, "kernel"))
		h_raw(h, "<p class=\"notice bad\">The kernel has no IPsec: "
		    "load it on the host, <code>kldload ipsec</code> (and "
		    "<code>ipsec_load=\"YES\"</code> in its <code>loader.conf"
		    "</code>); a jail cannot.</p>");
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

	/* The certificates in swanctl's x509 and x509ca: a peer known by
	 * one of them needs no key pasted. */
	if (jget(data, "certificates") != NULL && ucl_array_size(jget(data,
	    "certificates")) > 0) {
		static const struct tcol	kcols[] = {
			{ "File", "file", false }, { "Where", "where", false },
			{ "Subject", "subject", false },
			{ "Names", NULL, false }, { "Until", "not_after", true },
		};
		const ucl_object_t	**krows, *x;
		char			  when[32];
		int			  kr;

		h_raw(h, "<h4 class=\"family\">Certificates <small class=\"dim"
		    "\">in swanctl's x509 and x509ca: a peer's, or a CA that "
		    "signed it, is picked for a connection instead of its key"
		    "</small></h4><table class=\"net ipsec-certs\">");
		tbl_head(h, "ipsec-certs", kcols, 5, 0);
		h_raw(h, "<tbody>");
		krows = tbl_rows("ipsec-certs", jget(data, "certificates"),
		    kcols, 5, app.filter);
		for (kr = 0; (x = krows[kr]) != NULL; kr++) {
			h_raw(h, "<tr><td class=\"mono\">");
			h_txt(h, jstr(x, "file"));
			h_raw(h, "</td><td>");
			h_txt(h, jstr(x, "where"));
			if (jbool(x, "ca"))
				h_raw(h, " <span class=\"chip\">CA</span>");
			h_raw(h, "</td><td>");
			if (jstr(x, "error") != NULL) {
				h_raw(h, "<span class=\"bad\">");
				h_txt(h, jstr(x, "error"));
				h_raw(h, "</span>");
			} else {
				h_txt(h, jstr(x, "subject"));
				if (!jbool(x, "self_signed")) {
					h_raw(h, "<small class=\"dim\">by ");
					h_txt(h, jstr(x, "issuer"));
					h_raw(h, "</small>");
				}
			}
			h_raw(h, "</td><td>");
			list(h, jget(x, "names"));
			h_raw(h, "</td><td>");
			if (jget(x, "not_after") != NULL) {
				/* The day it ends, and how far off: a month
				 * away is amber, past is red. */
				time_t		t = (time_t)jint(x, "not_after", 0);
				double		left = (double)t - arc_now() / 1000;
				struct tm	tm;

				localtime_r(&t, &tm);
				strftime(when, sizeof(when), "%Y-%m-%d", &tm);
				h_fmt(h, "<span class=\"%s\" title=\"%s\">", left <
				    0 ? "bad" : left < 30 * 86400 ? "warn" : "",
				    left < 0 ? "ended" : "valid");
				h_txt(h, when);
				h_raw(h, "</span>");
				if (left < 0)
					h_raw(h, " <small class=\"dim\">ended</small>");
				else if (left < 86400)
					h_raw(h, " <small class=\"dim\">today</small>");
				else if (left < 30 * 86400)
					h_fmt(h, " <small class=\"dim\">in %.0f days"
					    "</small>", left / 86400);
			}
			h_raw(h, "</td></tr>");
		}
		free(krows);
		h_raw(h, "</tbody></table>");
	}

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
		h_raw(h, "</small>");
		if (jstr(jget(c, "model"), "remote_cert") != NULL) {
			h_raw(h, "<small class=\"dim\">peer by certificate ");
			h_txt(h, jstr(jget(c, "model"), "remote_cert"));
			h_raw(h, "</small>");
		} else if (jstr(jget(c, "model"), "remote_ca") != NULL) {
			h_raw(h, "<small class=\"dim\">peer by CA ");
			h_txt(h, jstr(jget(c, "model"), "remote_ca"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		it = NULL;
		while ((k = ucl_object_iterate(jget(c, "children"), &it,
		    true)) != NULL) {
			h_raw(h, "<div class=\"child\"><b>");
			h_txt(h, jstr(k, "name") != NULL ? jstr(k, "name") : "");
			h_raw(h, "</b> ");
			h_txt(h, jstr(k, "mode") != NULL ? jstr(k, "mode") :
			    "?");
			h_raw(h, "<small>");
			list(h, jget(k, "local-ts"));
			h_raw(h, " ⇄ ");
			list(h, jget(k, "remote-ts"));
			h_raw(h, "</small>");
			if (jbool(c, "arcana") && jstr(k, "name") != NULL) {
				h_raw(h, "<button class=\"icon\" data-act=\""
				    "ipsec-unchild\" title=\"Take the child "
				    "away\"");
				h_attr(h, "data-arg", jstr(c, "name"));
				h_attr(h, "data-value", jstr(k, "name"));
				h_raw(h, ">×</button>");
			}
			h_raw(h, "</div>");
		}
		if (jbool(c, "arcana")) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "ipsec-child-add\"");
			h_attr(h, "data-arg", jstr(c, "name"));
			h_raw(h, ">+ child</button>");
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

/* How many certificates the host has, CAs or the others. */
static int
ipsec_certs(bool ca)
{
	const ucl_object_t	*x;
	ucl_object_iter_t	 it;
	int			 n;

	n = 0;
	it = NULL;
	while ((x = ucl_object_iterate(jget(jget(app.net.data, "data"),
	    "certificates"), &it, true)) != NULL)
		if (jstr(x, "error") == NULL && jbool(x, "ca") == ca)
			n++;
	return (n);
}

/* A certificate picked: those in x509, or the CAs in x509ca. */
static void
cert_pick(struct html *h, const char *name, const char *label, bool ca)
{
	const ucl_object_t	*x;
	ucl_object_iter_t	 it;

	h_raw(h, "<label>");
	h_txt(h, label);
	h_raw(h, "<select");
	h_attr(h, "name", name);
	h_raw(h, ">");
	if (strcmp(name, "local_cert") == 0)
		h_raw(h, "<option value=\"\">the key arcana made</option>");
	it = NULL;
	while ((x = ucl_object_iterate(jget(jget(app.net.data, "data"),
	    "certificates"), &it, true)) != NULL) {
		if (jstr(x, "error") != NULL || jbool(x, "ca") != ca)
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", jstr(x, "file"));
		h_raw(h, ">");
		h_txt(h, jstr(x, "file"));
		h_raw(h, ": ");
		h_txt(h, jstr(x, "subject"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

/* Manually keyed SAs of an ipsec(4) interface: a verb, its words. */
static bool
ipsec_sa_modal(struct html *h)
{

	if (app.modal != MODAL_IPSEC_SA)
		return (false);
	h_raw(h, "<form data-form=\"ipsec-sa\"><h2>Manually keyed security "
	    "associations</h2><p>For an ipsec(4) interface made with a reqid, "
	    "without IKE: the SAs set by setkey(8) from keys given here "
	    "(<b>set</b>), or derived on both hosts from a key pair each "
	    "host makes (<b>key</b>) and the other's public half (<b>derive"
	    "</b>), the public halves shown by the host's SD-WAN read; a "
	    "rotation derives from the next pair (<b>key next</b>, <b>derive "
	    "&hellip; next</b>) and <b>commit</b> makes it the pair; <b>clear"
	    "</b> takes the SAs out.  In safe mode the host puts back what "
	    "was in when the console does not confirm the job: derived SAs "
	    "come back from their words, ones set by hand cannot, so a safe "
	    "job over those is refused.</p>"
	    "<div class=\"two\"><label>Verb<select name=\"verb\">"
	    "<option value=\"key\">key: a pair of this interface's</option>"
	    "<option value=\"derive\">derive: the SAs from the pair and "
	    "the peer's public half</option>"
	    "<option value=\"set\">set: the SAs from keys given</option>"
	    "<option value=\"commit\">commit: the next pair the pair</option>"
	    "<option value=\"clear\">clear: the SAs out</option></select>"
	    "</label><label>Interface<input name=\"interface\" spellcheck=\""
	    "false\" autocomplete=\"off\" placeholder=\"ipsec0\" autofocus>"
	    "</label></div>"
	    "<div class=\"two\"><label>reqid<input name=\"reqid\" inputmode="
	    "\"numeric\" placeholder=\"100\"><small>The interface's; not "
	    "for key.</small></label><label>This host's outer address<input "
	    "name=\"local\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"192.0.2.1\"></label></div>"
	    "<label>The peer's outer address<input name=\"remote\" "
	    "spellcheck=\"false\" autocomplete=\"off\" placeholder=\""
	    "192.0.2.2\"></label>"
	    "<label>Words<input name=\"words\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"peer &lt;base64&gt; enc "
	    "aes-gcm-16 epoch 1 lifetime 3600\"><small>As arcanactl takes "
	    "them: for derive, <code>peer</code>, <code>enc</code> (aes-cbc "
	    "with <code>auth</code>, or aes-gcm-16), <code>epoch</code>, "
	    "<code>install</code> both, in or out, <code>encap</code>, "
	    "<code>esn</code>, <code>lifetime</code>, <code>next</code>; for "
	    "set, <code>spi-in</code>, <code>spi-out</code>, <code>key-in"
	    "</code>, <code>key-out</code>, <code>akey-in</code>, <code>"
	    "akey-out</code> in hex; for key, <code>next</code> at most."
	    "</small></label>"
	    "<label class=\"toggle\"><input type=\"checkbox\" name=\"safe\" "
	    "checked><span>Safe mode <em>undone by the host unless the "
	    "console confirms it</em></span></label>");
	return (true);
}

bool
ipsec_modal(struct html *h)
{

	if (ipsec_child_modal(h) || ipsec_sa_modal(h))
		return (true);
	if (app.modal != MODAL_IPSEC_CONN)
		return (false);
	h_raw(h, "<form data-form=\"ipsec-conn\"><h2>An IPsec connection</h2>"
	    "<p>IKEv2, the two hosts known by their keys, or by certificates in swanctl&#39;s x509 and x509ca. Written as "
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
	    "</option></select></label>");
	/* The peer known by its key, pasted, or by a certificate here. */
	h_raw(h, "<label>The peer is known by<select name=\"auth\" "
	    "data-input=\"ipsec-auth\"><option value=\"pubkey\">its public "
	    "key, pasted</option>");
	if (ipsec_certs(false) > 0)
		h_raw(h, "<option value=\"cert\">its certificate, in x509"
		    "</option>");
	if (ipsec_certs(true) > 0)
		h_raw(h, "<option value=\"ca\">a CA in x509ca that signed its "
		    "certificate</option>");
	h_raw(h, "</select></label>");
	if (strcmp(app.ipsec_auth, "cert") == 0)
		cert_pick(h, "remote_cert", "The peer's certificate", false);
	else if (strcmp(app.ipsec_auth, "ca") == 0)
		cert_pick(h, "remote_ca", "The CA", true);
	else
		h_raw(h, "<label>The peer's public key<textarea name=\"pubkey\" "
		    "rows=\"3\" spellcheck=\"false\" placeholder=\"base64, as "
		    "the peer's IPsec tab shows it\"></textarea></label>");
	if (ipsec_certs(false) > 0)
		cert_pick(h, "local_cert", "This host's certificate, if not "
		    "the key arcana made it", false);
	h_raw(h,
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
	    "placeholder=\"its address; with a CA, the certificate's name\">"
	    "</label></div>");
	return (true);
}

/* A child of a connection: its own mode and traffic. */
static bool
ipsec_child_modal(struct html *h)
{

	if (app.modal != MODAL_IPSEC_CHILD)
		return (false);
	h_raw(h, "<form data-form=\"ipsec-child\"><h2>A child of ");
	h_txt(h, app.confirm.arg);
	h_raw(h, "</h2><p>One more thing the connection carries, in its own "
	    "mode between its own traffic selectors; strongSwan reads it "
	    "again at once.</p><input type=\"hidden\" name=\"conn\"");
	h_attr(h, "value", app.confirm.arg);
	h_raw(h, "><label>Name<input name=\"child\" spellcheck=\"false\" "
	    "autocomplete=\"off\" maxlength=\"32\" placeholder=\"lan\" "
	    "autofocus></label>"
	    "<label>Mode<select name=\"mode\"><option value=\"tunnel\">tunnel"
	    "</option><option value=\"transport\">transport</option></select>"
	    "</label>"
	    "<div class=\"two\"><label>This side's traffic<input name=\""
	    "local_ts\" spellcheck=\"false\" autocomplete=\"off\" placeholder="
	    "\"10.1.0.0/24\"></label><label>The peer's traffic<input name=\""
	    "remote_ts\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"10.2.0.0/24\"></label></div>");
	h_raw(h, "<div class=\"two\">");
	pfxlist_select(h, "This side's, from a list", "lts_pfx", "A prefix list "
	    "of the console's, added to the traffic selectors.", true);
	pfxlist_select(h, "The peer's, from a list", "rts_pfx", NULL, true);
	h_raw(h, "</div>"
	    "<div class=\"two\"><label>reqid<input name=\"reqid\" inputmode="
	    "\"numeric\" placeholder=\"none\"></label><label>Started<select "
	    "name=\"start\"><option value=\"trap\">with the first packet"
	    "</option><option value=\"start\">at once, and kept up</option>"
	    "<option value=\"none\">only when asked</option></select></label>"
	    "</div>");
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

/* As opt(), the prefixes of a console list (field list) after the
 * text, by commas, as strongSwan takes traffic selectors. */
static char *
opt_list(const ucl_object_t *f, const char *field, const char *list,
    const char *key)
{
	char	*all, *q, *out;

	all = with_list(jstr(f, field), jstr(f, list));
	if (all[0] == '\0') {
		free(all);
		return (strdup(""));
	}
	q = json_quote(all);
	free(all);
	if (asprintf(&out, ",\"%s\":%s", key, q) == -1)
		abort();
	free(q);
	return (out);
}

bool
ipsec_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v, *k, *auth;
	char		 title[160], key[1100], reqid[32], *qn, *ql, *qr, *qm,
			*qk, *lts, *rts, *lid, *rid, *qs, *way, *lcert;
	size_t		 n;

	if (strcmp(form, "ipsec-sa") == 0) {
		const char	*verb, *p, *e;
		char		*words, *qw, *qi, *q;
		size_t		 len;
		bool		 iskey;

		if ((s = cur_server()) == NULL)
			return (true);
		verb = jstr(f, "verb") != NULL ? jstr(f, "verb") : "derive";
		iskey = strcmp(verb, "key") == 0;
		v = jstr(f, "interface");
		if (v == NULL || strncmp(v, "ipsec", 5) != 0 || v[5] == '\0' ||
		    v[5 + strspn(v + 5, "0123456789")] != '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "The "
			    "interface is an ipsec(4) one, ipsec0");
			return (true);
		}
		qi = json_quote(v);
		reqid[0] = '\0';
		ql = qr = NULL;
		if (!iskey) {
			v = jstr(f, "reqid");
			if (v == NULL || v[0] == '\0' || strlen(v) > 5 || v[strspn(v,
			    "0123456789")] != '\0' || atoi(v) < 1 || atoi(v) > 16383
			    || jstr(f, "local") == NULL || jstr(f, "local")[0] ==
			    '\0' || jstr(f, "remote") == NULL || jstr(f, "remote")[0]
			    == '\0') {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "But for key, the reqid (1 to 16383) and the two "
				    "outer addresses are needed");
				free(qi);
				return (true);
			}
			snprintf(reqid, sizeof(reqid), ",\"reqid\":%d", atoi(v));
			ql = json_quote(jstr(f, "local"));
			qr = json_quote(jstr(f, "remote"));
		}
		/* The words, each a string of the args list. */
		words = strdup("");
		len = 0;
		for (p = jstr(f, "words") != NULL ? jstr(f, "words") : ""; *p !=
		    '\0'; p = e) {
			p += strspn(p, " \t\n,");
			e = p + strcspn(p, " \t\n,");
			if (e == p)
				break;
			{
				char	*word = strndup(p, (size_t)(e - p));

				q = json_quote(word);
				free(word);
			}
			if (asprintf(&qw, "%s%s%s", words, len > 0 ? "," : "", q) ==
			    -1)
				abort();
			free(q);
			free(words);
			words = qw;
			len++;
		}
		snprintf(title, sizeof(title), "ipsec sa %s %s", verb, jstr(f,
		    "interface"));
		if (iskey)
			ipsec_job(s, title, "{\"kind\":\"ipsec-sa\",\"verb\":\"key\","
			    "\"interface\":%s,\"args\":[%s],\"safe\":%s}", qi, words,
			    jbool(f, "safe") ? "true" : "false");
		else
			ipsec_job(s, title, "{\"kind\":\"ipsec-sa\",\"verb\":\"%s\","
			    "\"interface\":%s%s,\"tunnel_local\":%s,\"tunnel_remote\":%s,"
			    "\"args\":[%s],\"safe\":%s}", verb, qi, reqid, ql, qr,
			    words, jbool(f, "safe") ? "true" : "false");
		free(qi);
		free(ql);
		free(qr);
		free(words);
		app.modal = MODAL_NONE;
		return (true);
	}
	if (strcmp(form, "ipsec-child") == 0) {
		char	*qc, *qd;

		if ((s = cur_server()) == NULL)
			return (true);
		if (jstr(f, "child") == NULL || jstr(f, "child")[0] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "child has a name");
			return (true);
		}
		reqid[0] = '\0';
		if ((v = jstr(f, "reqid")) != NULL && v[0] != '\0') {
			if (strlen(v) > 5 || v[strspn(v, "0123456789")] != '\0'
			    || atoi(v) < 1 || atoi(v) > 16383) {
				snprintf(app.modal_error, sizeof(app.modal_error),
				    "A reqid is a number from 1 to 16383");
				return (true);
			}
			snprintf(reqid, sizeof(reqid), ",\"reqid\":%d", atoi(v));
		}
		qc = json_quote(jstr(f, "conn"));
		qd = json_quote(jstr(f, "child"));
		qm = json_quote(jstr(f, "mode") != NULL ? jstr(f, "mode") :
		    "tunnel");
		qs = json_quote(jstr(f, "start") != NULL ? jstr(f, "start") :
		    "trap");
		lts = opt_list(f, "local_ts", "lts_pfx", "local_ts");
		rts = opt_list(f, "remote_ts", "rts_pfx", "remote_ts");
		snprintf(title, sizeof(title), "ipsec child %s %s", jstr(f,
		    "conn"), jstr(f, "child"));
		ipsec_job(s, title, "{\"kind\":\"ipsec\",\"verb\":\"child\","
		    "\"conn\":%s,\"child\":%s,\"ipsec_mode\":%s,\"start_action\":"
		    "%s%s%s%s}", qc, qd, qm, qs, reqid, lts, rts);
		free(qc);
		free(qd);
		free(qm);
		free(qs);
		free(lts);
		free(rts);
		app.modal = MODAL_NONE;
		return (true);
	}
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
	/* The key as pasted, PEM or not: its base64 alone; or a
	 * certificate, or a CA with the peer's identity. */
	n = 0;
	key[0] = '\0';
	auth = jstr(f, "auth") != NULL ? jstr(f, "auth") : "pubkey";
	if (strcmp(auth, "pubkey") == 0) {
		k = jstr(f, "pubkey") != NULL ? jstr(f, "pubkey") : "";
		if ((v = strstr(k, "-----BEGIN PUBLIC KEY-----")) != NULL)
			k = v + strlen("-----BEGIN PUBLIC KEY-----");
		for (; *k != '\0' && *k != '-' && n < sizeof(key) - 1; k++)
			if (*k != ' ' && *k != '\n' && *k != '\r' && *k != '\t')
				key[n++] = *k;
		key[n] = '\0';
		if (n < 40) {
			snprintf(app.modal_error, sizeof(app.modal_error), "The "
			    "peer's public key, as its IPsec tab shows it");
			return (true);
		}
	} else if (strcmp(auth, "ca") == 0 && (jstr(f, "remote_id") == NULL ||
	    jstr(f, "remote_id")[0] == '\0')) {
		snprintf(app.modal_error, sizeof(app.modal_error), "With a CA, "
		    "the peer's identity says which certificate is the peer's");
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
	way = strcmp(auth, "cert") == 0 ? opt(f, "remote_cert", "remote_cert") :
	    strcmp(auth, "ca") == 0 ? opt(f, "remote_ca", "remote_ca") :
	    strdup("");
	lcert = opt(f, "local_cert", "local_cert");
	qs = json_quote(jstr(f, "start") != NULL ? jstr(f, "start") : "trap");
	lts = opt(f, "local_ts", "local_ts");
	rts = opt(f, "remote_ts", "remote_ts");
	lid = opt(f, "local_id", "local_id");
	rid = opt(f, "remote_id", "remote_id");
	snprintf(title, sizeof(title), "ipsec conn %s (%s)", jstr(f, "conn"),
	    jstr(f, "mode") != NULL ? jstr(f, "mode") : "tunnel");
	if (key[0] != '\0')
		ipsec_job(s, title, "{\"kind\":\"ipsec\",\"verb\":\"conn\","
		    "\"conn\":%s,\"tunnel_local\":%s,\"tunnel_remote\":%s,"
		    "\"ipsec_mode\":%s,\"pubkey\":%s,\"start_action\":%s%s%s%s%s%s%s}",
		    qn, ql, qr, qm, qk, qs, reqid, lts, rts, lid, rid, lcert);
	else
		ipsec_job(s, title, "{\"kind\":\"ipsec\",\"verb\":\"conn\","
		    "\"conn\":%s,\"tunnel_local\":%s,\"tunnel_remote\":%s,"
		    "\"ipsec_mode\":%s,\"start_action\":%s%s%s%s%s%s%s%s}", qn,
		    ql, qr, qm, qs, reqid, lts, rts, lid, rid, way, lcert);
	free(way);
	free(lcert);
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

	if (strncmp(act, "ipsec-", 6) != 0 && strncmp(act, "do-ipsec-", 9) !=
	    0 && strcmp(act, "input:ipsec-auth") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "input:ipsec-auth") == 0) {
		snprintf(app.ipsec_auth, sizeof(app.ipsec_auth), "%s", value);
	} else if (strcmp(act, "ipsec-child-add") == 0) {
		app.modal = MODAL_IPSEC_CHILD;
		app.modal_error[0] = '\0';
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
	} else if (strcmp(act, "ipsec-unchild") == 0) {
		char	*qc, *qd;

		qc = json_quote(arg);
		qd = json_quote(value);
		snprintf(title, sizeof(title), "ipsec unchild %s %s", arg, value);
		ipsec_job(s, title, "{\"kind\":\"ipsec\",\"verb\":\"unchild\","
		    "\"conn\":%s,\"child\":%s}", qc, qd);
		free(qc);
		free(qd);
	} else if (strcmp(act, "ipsec-sa-add") == 0) {
		app.modal = MODAL_IPSEC_SA;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "ipsec-conn-add") == 0) {
		app.modal = MODAL_IPSEC_CONN;
		app.modal_error[0] = '\0';
		snprintf(app.ipsec_auth, sizeof(app.ipsec_auth), "pubkey");
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
