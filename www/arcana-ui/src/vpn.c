/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * In a host's network tab: its WireGuard interfaces with their peers,
 * and its BIRD routing daemon with its protocols.  Of a WireGuard
 * interface the page knows the public key only: the private one is
 * made on the host and never leaves it.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static void
vpn_job(struct server *s, const char *title, const char *fmt, ...)
{
	va_list	 ap;
	char	*json;

	va_start(ap, fmt);
	if (vasprintf(&json, fmt, ap) == -1)
		abort();
	va_end(ap);
	job_send(s, json, title, JOB_IFACE, "vpn");
}

/* A time gone by, in the two units that say it best. */
void
vpn_age(char *buf, size_t len, int64_t s)
{

	if (s < 60)
		snprintf(buf, len, "%llds", (long long)s);
	else if (s < 3600)
		snprintf(buf, len, "%lldm %llds", (long long)(s / 60),
		    (long long)(s % 60));
	else if (s < 86400)
		snprintf(buf, len, "%lldh %lldm", (long long)(s / 3600),
		    (long long)(s % 3600 / 60));
	else
		snprintf(buf, len, "%lldd %lldh", (long long)(s / 86400),
		    (long long)(s % 86400 / 3600));
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
view_wireguard(struct html *h, struct server *s, const ucl_object_t *data)
{
	const ucl_object_t	*o, *p, *ip;
	ucl_object_iter_t	 it, pit, iit;
	char			 buf[64], rx[24], tx[24];
	int64_t			 now, hs;
	int			 n;

	(void)s;
	now = jint(data, "now", 0);
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(data, "interfaces"), &it, true)) !=
	    NULL) {
		if (jstr(o, "name") == NULL)
			continue;
		n++;
		h_raw(h, "<section class=\"pane wg\"><h4><span>");
		h_txt(h, jstr(o, "name"));
		if (jint(o, "listen-port", 0) > 0)
			h_fmt(h, " <small>port %lld</small>", (long long)jint(o,
			    "listen-port", 0));
		h_raw(h, "</span><span class=\"pane-actions\"><button class=\""
		    "ghost small\" data-act=\"wg-init\"");
		h_attr(h, "data-arg", jstr(o, "name"));
		h_fmt(h, ">%s</button><button class=\"ghost small\" data-act=\""
		    "wg-peer-add\"", jbool(o, "private-key") ? "Port" :
		    "Make its key");
		h_attr(h, "data-arg", jstr(o, "name"));
		h_raw(h, ">+ peer</button></span></h4>");
		if (jstr(o, "public-key") != NULL) {
			h_raw(h, "<p>Public key <code class=\"key\">");
			h_txt(h, jstr(o, "public-key"));
			h_raw(h, "</code></p>");
		} else
			h_raw(h, "<p class=\"dim\">It has no key yet: <b>Make "
			    "its key</b> has the host make one, which stays on "
			    "the host.</p>");
		if (ucl_array_size(jget(o, "peers")) == 0) {
			h_raw(h, "<p class=\"dim\">No peers.</p></section>");
			continue;
		}
		h_raw(h, "<table class=\"net\"><thead><tr><th>Peer</th><th>"
		    "Endpoint</th><th>Allowed</th><th>Handshake</th><th>In / "
		    "out</th><th></th></tr></thead><tbody>");
		pit = NULL;
		while ((p = ucl_object_iterate(jget(o, "peers"), &pit, true)) !=
		    NULL) {
			hs = jint(p, "latest-handshake", 0);
			h_fmt(h, "<tr class=\"%s\"><td><code class=\"key\"",
			    hs != 0 && now - hs < 180 ? "up" : "down");
			h_attr(h, "title", jstr(p, "public-key"));
			h_raw(h, ">");
			snprintf(buf, sizeof(buf), "%.12s…", jstr(p,
			    "public-key") != NULL ? jstr(p, "public-key") : "");
			h_txt(h, buf);
			h_raw(h, "</code>");
			if (jbool(p, "preshared-key"))
				h_raw(h, "<small>with a preshared key</small>");
			h_raw(h, "</td><td>");
			h_txt(h, jstr(p, "endpoint") != NULL ? jstr(p,
			    "endpoint") : "—");
			if (jint(p, "keepalive", 0) > 0)
				h_fmt(h, "<small>keepalive %lld s</small>",
				    (long long)jint(p, "keepalive", 0));
			h_raw(h, "</td><td>");
			iit = NULL;
			while ((ip = ucl_object_iterate(jget(p, "allowed-ips"),
			    &iit, true)) != NULL) {
				h_raw(h, "<span class=\"chip\"><span>");
				h_txt(h, ucl_object_tostring_forced(ip));
				h_raw(h, "</span></span> ");
			}
			h_raw(h, "</td><td>");
			if (hs == 0)
				h_raw(h, "<span class=\"dim\">never</span>");
			else {
				vpn_age(buf, sizeof(buf), now - hs);
				h_txt(h, buf);
				h_raw(h, " ago");
			}
			bytes(rx, sizeof(rx), jint(p, "rx", 0));
			bytes(tx, sizeof(tx), jint(p, "tx", 0));
			h_raw(h, "</td><td>");
			h_txt(h, rx);
			h_raw(h, " / ");
			h_txt(h, tx);
			h_raw(h, "</td><td><button class=\"icon\" data-act=\""
			    "wg-unpeer\" title=\"Remove this peer\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_attr(h, "data-value", jstr(p, "public-key"));
			h_raw(h, ">×</button></td></tr>");
		}
		h_raw(h, "</tbody></table></section>");
	}
	if (n == 0)
		h_raw(h, "<div class=\"empty\"><p>No WireGuard interfaces on "
		    "this host. Create one in <b>Interfaces</b> with "
		    "<b>+ interface</b>, named <code>wg</code>, or draw a "
		    "tunnel between two hosts in <b>Network</b>.</p></div>");
}

static const char keep_wg[] = "<label class=\"toggle\"><input type=\""
    "checkbox\" name=\"persist\" checked><span>Keep the interface for a "
    "boot: written for <code>wg-quick</code>, with its key, for root "
    "alone to read</span></label>";

bool
vpn_modal(struct html *h)
{

	switch (app.modal) {
	case MODAL_WG_INIT:
		h_raw(h, "<form data-form=\"wg-init\"><h2>Set up ");
		h_txt(h, app.confirm.arg);
		h_raw(h, "</h2><p>When the interface has no private key, the "
		    "host makes one and keeps it: the console is told the "
		    "public key only. A key it has is left as it is.</p>"
		    "<label>Port it listens on<input name=\"port\" inputmode="
		    "\"numeric\" placeholder=\"51820\" autofocus><small>Empty "
		    "leaves the port as it is.</small></label>");
		h_raw(h, keep_wg);
		return (true);
	case MODAL_WG_PEER:
		h_raw(h, "<form data-form=\"wg-peer\"><h2>A peer of ");
		h_txt(h, app.confirm.arg);
		h_raw(h, "</h2><p>With <code>wg set</code>. A peer that is "
		    "there already is changed.</p><label>Its public key<input "
		    "name=\"peer\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"44 characters of base64\" autofocus></label>"
		    "<label>Endpoint<input name=\"endpoint\" spellcheck=\""
		    "false\" autocomplete=\"off\" placeholder=\"192.0.2.9:"
		    "51820 or [2001:db8::9]:51820\"><small>Where it is "
		    "reached; empty for a peer that comes to this host."
		    "</small></label><label>Allowed addresses<input name=\""
		    "allowed\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"10.9.0.2/32, fd00::2/128\"><small>What it "
		    "may send from, and what is routed to it.</small></label>"
		    "<label>Keepalive, seconds<input name=\"keepalive\" "
		    "inputmode=\"numeric\" placeholder=\"none; 25 behind NAT\">"
		    "</label>");
		h_raw(h, keep_wg);
		return (true);
	default:
		return (false);
	}
}

static bool
digits(const char *s)
{

	return (s != NULL && s[0] != '\0' && strlen(s) < 6 && s[strspn(s,
	    "0123456789")] == '\0');
}

bool
vpn_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v;
	char		 title[160], allowed[512], *qi, *qp, *qe, *qa, extra[64];
	size_t		 n;

	if (strcmp(form, "wg-init") != 0 && strcmp(form, "wg-peer") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	qi = json_quote(app.confirm.arg);
	if (strcmp(form, "wg-init") == 0) {
		v = jstr(f, "port");
		extra[0] = '\0';
		if (v != NULL && v[0] != '\0') {
			if (!digits(v)) {
				snprintf(app.modal_error,
				    sizeof(app.modal_error), "A port is a "
				    "number");
				free(qi);
				return (true);
			}
			snprintf(extra, sizeof(extra), ",\"listen_port\":%s", v);
		}
		snprintf(title, sizeof(title), "%s: wireguard init",
		    app.confirm.arg);
		vpn_job(s, title, "{\"kind\":\"wireguard\",\"interface\":%s,"
		    "\"verb\":\"init\"%s,\"persist\":%s}", qi, extra, jbool(f,
		    "persist") ? "true" : "false");
		free(qi);
		app.modal = MODAL_NONE;
		return (true);
	}
	v = jstr(f, "peer") != NULL ? jstr(f, "peer") : "";
	if (strlen(v) != 44) {
		snprintf(app.modal_error, sizeof(app.modal_error), "A public "
		    "key is 44 characters of base64");
		free(qi);
		return (true);
	}
	/* "a, b" as typed becomes "a,b" as wg(8) takes it. */
	n = 0;
	for (v = jstr(f, "allowed") != NULL ? jstr(f, "allowed") : "";
	    *v != '\0' && n < sizeof(allowed) - 1; v++)
		if (*v != ' ')
			allowed[n++] = *v;
	allowed[n] = '\0';
	extra[0] = '\0';
	if (digits(jstr(f, "keepalive")))
		snprintf(extra, sizeof(extra), ",\"keepalive\":%s", jstr(f,
		    "keepalive"));
	qp = json_quote(jstr(f, "peer"));
	qe = json_quote(jstr(f, "endpoint") != NULL ? jstr(f, "endpoint") : "");
	qa = json_quote(allowed);
	snprintf(title, sizeof(title), "%s: wireguard peer", app.confirm.arg);
	vpn_job(s, title, "{\"kind\":\"wireguard\",\"interface\":%s,\"verb\":"
	    "\"peer\",\"peer\":%s%s%s,\"allowed_ips\":%s%s,\"persist\":%s}", qi,
	    qp, jstr(f, "endpoint") != NULL && jstr(f, "endpoint")[0] != '\0' ?
	    ",\"endpoint\":" : "", jstr(f, "endpoint") != NULL && jstr(f,
	    "endpoint")[0] != '\0' ? qe : "", qa, extra, jbool(f, "persist") ?
	    "true" : "false");
	free(qi);
	free(qp);
	free(qe);
	free(qa);
	app.modal = MODAL_NONE;
	return (true);
}

bool
vpn_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[400], title[160], *qa, *qv;

	if (strncmp(act, "wg-", 3) != 0 && strncmp(act, "do-wg-", 6) != 0 &&
	    strncmp(act, "bird-", 5) != 0 && strncmp(act, "do-bird-", 8) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "wg-init") == 0 || strcmp(act, "wg-peer-add") == 0) {
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
		app.modal = act[3] == 'i' ? MODAL_WG_INIT : MODAL_WG_PEER;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "wg-unpeer") == 0) {
		snprintf(body, sizeof(body), "wg set %s peer %.12s… remove, on "
		    "%s. What goes to that peer through the tunnel stops. If "
		    "the interface is kept for a boot, the peer is forgotten "
		    "there too.", arg, value, s->name);
		confirm("Remove the peer", body, "Remove", true, "",
		    "do-wg-unpeer", arg, value);
	} else if (strcmp(act, "do-wg-unpeer") == 0) {
		qa = json_quote(arg);
		qv = json_quote(value);
		snprintf(title, sizeof(title), "%s: wireguard unpeer", arg);
		vpn_job(s, title, "{\"kind\":\"wireguard\",\"interface\":%s,"
		    "\"verb\":\"unpeer\",\"peer\":%s}", qa, qv);
		free(qa);
		free(qv);
	} else if (strcmp(act, "bird-verb") == 0) {
		/* What interrupts routing is asked about first. */
		if (strcmp(arg, "reload") == 0 || strcmp(arg, "enable") == 0) {
			vpn_action("do-bird-verb", arg, value);
			return (true);
		}
		snprintf(body, sizeof(body), "birdc %s %s, on %s. %s", arg,
		    value, s->name, strcmp(arg, "configure") == 0 ? "BIRD "
		    "reads its configuration again; protocols whose "
		    "configuration changed restart." : "Its sessions drop, and "
		    "the routes learned through it go until it is back.");
		snprintf(title, sizeof(title), "BIRD: %s %s", arg, value);
		confirm(title, body, arg, strcmp(arg, "configure") != 0, "",
		    "do-bird-verb", arg, value);
	} else if (strcmp(act, "do-bird-verb") == 0) {
		qa = json_quote(arg);
		qv = json_quote(value);
		snprintf(title, sizeof(title), "bird %s%s%s", arg, value[0] !=
		    '\0' ? " " : "", value);
		vpn_job(s, title, "{\"kind\":\"bird\",\"verb\":%s,\"args\":[%s]}",
		    qa, value[0] != '\0' ? qv : "");
		free(qa);
		free(qv);
	}
	return (true);
}
