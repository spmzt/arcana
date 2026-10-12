/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * In a host's network tab: its WireGuard interfaces with their peers,
 * and its BIRD routing daemon with its protocols.  Of a WireGuard
 * interface the page knows the public key only: the private one is
 * made on the host and never leaves it.  A client made here (+ client)
 * has its key pair made by the console and kept nowhere: the page puts
 * the private half in the client's configuration, shown once with its
 * QR code, and gives the host the public half as a peer.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

/* A client being made, and its configuration while it is shown. */
static struct {
	char	server[16], iface[32], name[64], address[128], dns[128];
	char	endpoint[200], allowed[256], keepalive[8], srvpub[64];
	char	conf[1536];
	bool	persist;
} wgc;

/* The client's configuration, once shown, forgotten. */
static void
wgc_forget(void)
{

	explicit_bzero(&wgc, sizeof(wgc));
}

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
	static const struct tcol	pcols[] = {
		{ "Peer", "public-key", false }, { "Endpoint", "endpoint",
		false }, { "Allowed", NULL, false }, { "Handshake",
		"latest-handshake", true }, { "In / out", "rx", true },
	};
	const ucl_object_t		**rows;
	char				  tid[64];
	int				  r;
	const ucl_object_t	*o, *p, *ip;
	ucl_object_iter_t	 it, iit;
	char			 buf[64], rx[24], tx[24];
	int64_t			 now, hs;
	int			 n;

	(void)s;
	if (app.modal != MODAL_WG_CONF && wgc.conf[0] != '\0')
		wgc_forget();
	now = jint(data, "now", 0);
	/* A wg interface made here, by the same job as the network's
	 * interface form, then its key and port. */
	h_raw(h, "<p class=\"pane-actions\"><button class=\"ghost small\" data-act"
	    "=\"wg-if-create\" title=\"A wg interface made with ifconfig "
	    "create; its key and port after\">+ interface</button></p>");
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
		h_raw(h, ">+ peer</button>");
		if (jstr(o, "public-key") != NULL) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "wg-client-add\" title=\"A client of this interface: "
			    "its key pair made for it, its configuration and a QR "
			    "code for the WireGuard app\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_raw(h, ">+ client</button>");
		}
		h_raw(h, "</span></h4>");
		if (jstr(o, "public-key") != NULL) {
			h_raw(h, "<p>Public key <code class=\"key\">");
			h_txt(h, jstr(o, "public-key"));
			h_raw(h, "</code> <button class=\"ghost small copy\" "
			    "title=\"Copy this interface's public key, for its "
			    "peers\"");
			h_attr(h, "data-copy", jstr(o, "public-key"));
			h_raw(h, ">Copy</button></p>");
		} else
			h_raw(h, "<p class=\"dim\">It has no key yet: <b>Make "
			    "its key</b> has the host make one, which stays on "
			    "the host.</p>");
		if (ucl_array_size(jget(o, "peers")) == 0) {
			h_raw(h, "<p class=\"dim\">No peers.</p></section>");
			continue;
		}
		h_raw(h, "<table class=\"net wgpeers\">");
		snprintf(tid, sizeof(tid), "wg-%.40s", jstr(o, "name") != NULL ?
		    jstr(o, "name") : "");
		tbl_head(h, tid, pcols, 5, 1);
		h_raw(h, "<tbody>");
		rows = tbl_rows(tid, jget(o, "peers"), pcols, 5, app.filter);
		for (r = 0; (p = rows[r]) != NULL; r++) {
			hs = jint(p, "latest-handshake", 0);
			/* The whole key, to be read and copied: a peer is
			 * known by it, and it is no secret. */
			h_fmt(h, "<tr class=\"%s\"><td><code class=\"key\">",
			    hs != 0 && now - hs < 180 ? "up" : "down");
			h_txt(h, jstr(p, "public-key"));
			h_raw(h, "</code> <button class=\"ghost small copy\" "
			    "title=\"Copy the peer's public key\"");
			h_attr(h, "data-copy", jstr(p, "public-key"));
			h_raw(h, ">Copy</button>");
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
			    "wg-peer-edit\" title=\"Change its endpoint, "
			    "allowed addresses or keepalive\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_attr(h, "data-value", jstr(p, "public-key"));
			h_raw(h, ">✎</button><button class=\"icon\" data-act=\""
			    "wg-unpeer\" title=\"Remove this peer\"");
			h_attr(h, "data-arg", jstr(o, "name"));
			h_attr(h, "data-value", jstr(p, "public-key"));
			h_raw(h, ">×</button></td></tr>");
		}
		free(rows);
		h_raw(h, "</tbody></table></section>");
	}
	if (n == 0)
		h_raw(h, "<div class=\"empty\"><p>No WireGuard interfaces on "
		    "this host. Create one in <b>Interfaces</b> with "
		    "<b>+ interface</b>, named <code>wg</code>, or draw a "
		    "tunnel between two hosts in <b>Network</b>.</p></div>");
}

/* The peer being changed, its form filled with what it has now. */
static struct {
	bool	on;
	char	key[64], endpoint[128], allowed[512], keepalive[8];
} wge;

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
		h_raw(h, "<form data-form=\"wg-peer\"><h2>");
		h_raw(h, wge.on ? "A peer of " : "A new peer of ");
		h_txt(h, app.confirm.arg);
		h_raw(h, "</h2><p>With <code>wg set</code>: what is given here "
		    "is what the peer has after; its key is what names it."
		    "</p><label>Its public key<input name=\"peer\" "
		    "spellcheck=\"false\" autocomplete=\"off\" placeholder="
		    "\"44 characters of base64\"");
		if (wge.on) {
			h_attr(h, "value", wge.key);
			h_raw(h, " readonly");
		} else
			h_raw(h, " autofocus");
		h_raw(h, "></label><label>Endpoint<input name=\"endpoint\" "
		    "spellcheck=\"false\" autocomplete=\"off\" placeholder="
		    "\"192.0.2.9:51820 or [2001:db8::9]:51820\"");
		if (wge.on)
			h_attr(h, "value", wge.endpoint);
		h_raw(h, "><small>Where it is reached; empty for a peer that "
		    "comes to this host, or to leave it as it is."
		    "</small></label><label>Allowed addresses<input name=\""
		    "allowed\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"10.9.0.2/32, fd00::2/128\"");
		if (wge.on)
			h_attr(h, "value", wge.allowed);
		h_raw(h, "><small>What it may send from, and what is routed to "
		    "it: the whole list.</small></label><label>Keepalive, "
		    "seconds<input name=\"keepalive\" inputmode=\"numeric\" "
		    "placeholder=\"none; 25 behind NAT\"");
		if (wge.on)
			h_attr(h, "value", wge.keepalive);
		h_raw(h, "><small>0 turns it off.</small></label>");
		h_raw(h, keep_wg);
		return (true);
	case MODAL_WG_CLIENT:
		h_raw(h, "<form data-form=\"wg-client\"><h2>A new client of ");
		h_txt(h, wgc.iface);
		h_raw(h, "</h2><p>The console makes its key pair and keeps "
		    "neither half: the private one goes into the client's "
		    "configuration, shown once with a QR code for the WireGuard "
		    "app; the host gets the public one as a peer.</p>"
		    "<label>Name<input name=\"name\" autocomplete=\"off\" "
		    "placeholder=\"laptop\" autofocus");
		h_attr(h, "value", wgc.name);
		h_raw(h, "><small>For the file's name; the peer is known by "
		    "its key.</small></label><label>Its address in the tunnel"
		    "<input name=\"address\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"10.9.0.2/32\"");
		h_attr(h, "value", wgc.address);
		h_raw(h, "><small>One address a family, the host's peer allowed "
		    "these alone; the next free one after the peers' is "
		    "offered.</small></label><label>Endpoint<input name=\""
		    "endpoint\" spellcheck=\"false\" autocomplete=\"off\" "
		    "placeholder=\"vpn.example.org:51820\"");
		h_attr(h, "value", wgc.endpoint);
		h_raw(h, "><small>Where the client reaches this host: its name "
		    "or public address, and the interface's port.</small>"
		    "</label><label>What it sends through the tunnel<input "
		    "name=\"allowed\" spellcheck=\"false\" autocomplete=\"off"
		    "\"");
		h_attr(h, "value", wgc.allowed);
		h_raw(h, "><small>0.0.0.0/0, ::/0 for everything; the "
		    "tunnel's network alone for a split tunnel.</small></label>"
		    "<label>DNS<input name=\"dns\" spellcheck=\"false\" "
		    "autocomplete=\"off\" placeholder=\"none, or 10.9.0.1\"");
		h_attr(h, "value", wgc.dns);
		h_raw(h, "></label><label>Keepalive, seconds<input name=\""
		    "keepalive\" inputmode=\"numeric\"");
		h_attr(h, "value", wgc.keepalive);
		h_raw(h, "><small>25 keeps a client behind NAT reachable; empty "
		    "for none.</small></label>");
		h_raw(h, keep_wg);
		return (true);
	case MODAL_WG_CONF:
		h_raw(h, "<form data-form=\"wg-conf\"><h2>");
		h_txt(h, wgc.name[0] != '\0' ? wgc.name : "The client");
		h_raw(h, "</h2><p>Its configuration, with its private key: "
		    "shown now and not again. Scan the code with the WireGuard "
		    "app, or copy or download the file for "
		    "<code>wg-quick</code>.</p>");
		qr_svg(h, wgc.conf, "For the WireGuard app: Add a tunnel, Scan "
		    "from QR code.");
		h_raw(h, "<pre class=\"wg-conf\">");
		h_txt(h, wgc.conf);
		h_raw(h, "</pre><p class=\"pane-actions\"><button type=\""
		    "button\" class=\"ghost small copy\"");
		h_attr(h, "data-copy", wgc.conf);
		h_raw(h, ">Copy</button><a class=\"ghost small\" download=\"");
		h_txt(h, wgc.name[0] != '\0' ? wgc.name : "client");
		h_raw(h, ".conf\" href=\"data:text/plain;charset=utf-8,");
		{
			static const char	 hex[] = "0123456789ABCDEF";
			const char		*c;
			char			 e[4];

			for (c = wgc.conf; *c != '\0'; c++) {
				if ((*c >= 'A' && *c <= 'Z') || (*c >= 'a' &&
				    *c <= 'z') || (*c >= '0' && *c <= '9') ||
				    strchr("-_.~", *c) != NULL) {
					e[0] = *c;
					e[1] = '\0';
				} else {
					e[0] = '%';
					e[1] = hex[(unsigned char)*c >> 4];
					e[2] = hex[(unsigned char)*c & 15];
					e[3] = '\0';
				}
				h_raw(h, e);
			}
		}
		h_raw(h, "\">Download</a></p>");
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

/* A list as typed, "a, b", as wg(8) and wg-quick take it: "a,b" and
 * "a, b". */
static void
squeeze(const char *in, char *out, size_t len)
{
	size_t	n;

	for (n = 0; in != NULL && *in != '\0' && n + 1 < len; in++)
		if (*in != ' ')
			out[n++] = *in;
	out[n] = '\0';
}

/*
 * The key pair the console made: the host's peer added with the
 * public half, and the client's configuration made with the private
 * half and shown.
 */
static void
client_keys_cb(int status, const ucl_object_t *o, const char *err,
    void *arg)
{
	struct server	*s;
	char		 title[160], addr[128], *qi, *qp, *qa;
	const char	*priv, *pub;
	int		 n;

	(void)arg;
	if (status != 200 || (priv = jstr(o, "private_key")) == NULL ||
	    (pub = jstr(o, "public_key")) == NULL) {
		toast(true, "No key pair: %s", err != NULL ? err : "the console "
		    "did not make one");
		return;
	}
	for (n = 0; n < app.nservers; n++)
		if (strcmp(app.servers[n].id, wgc.server) == 0)
			break;
	if (n == app.nservers)
		return;
	s = &app.servers[n];
	squeeze(wgc.address, addr, sizeof(addr));
	qi = json_quote(wgc.iface);
	qp = json_quote(pub);
	qa = json_quote(addr);
	snprintf(title, sizeof(title), "%s: wireguard client %s", wgc.iface,
	    wgc.name);
	vpn_job(s, title, "{\"kind\":\"wireguard\",\"interface\":%s,\"verb\":"
	    "\"peer\",\"peer\":%s,\"allowed_ips\":%s,\"persist\":%s}", qi, qp,
	    qa, wgc.persist ? "true" : "false");
	free(qi);
	free(qp);
	free(qa);
	/* What the client keeps: wg-quick's file, which the app reads. */
	n = snprintf(wgc.conf, sizeof(wgc.conf), "[Interface]\nPrivateKey = "
	    "%s\nAddress = %s\n", priv, wgc.address);
	if (wgc.dns[0] != '\0' && n > 0 && (size_t)n < sizeof(wgc.conf))
		n += snprintf(wgc.conf + n, sizeof(wgc.conf) - (size_t)n, "DNS = "
		    "%s\n", wgc.dns);
	if (n > 0 && (size_t)n < sizeof(wgc.conf))
		n += snprintf(wgc.conf + n, sizeof(wgc.conf) - (size_t)n,
		    "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n",
		    wgc.srvpub, wgc.endpoint, wgc.allowed);
	if (wgc.keepalive[0] != '\0' && strcmp(wgc.keepalive, "0") != 0 &&
	    n > 0 && (size_t)n < sizeof(wgc.conf))
		(void)snprintf(wgc.conf + n, sizeof(wgc.conf) - (size_t)n,
		    "PersistentKeepalive = %s\n", wgc.keepalive);
	app.modal = MODAL_WG_CONF;
	app.modal_error[0] = '\0';
	render();
}

/* The client's form: checked, then its key pair asked of the console. */
static bool
client_form(const ucl_object_t *f)
{
	const char	*v;

#define	TAKE(k, field) \
	snprintf(wgc.field, sizeof(wgc.field), "%s", jstr(f, k) != NULL ? \
	    jstr(f, k) : "")
	TAKE("name", name);
	TAKE("address", address);
	TAKE("endpoint", endpoint);
	TAKE("allowed", allowed);
	TAKE("dns", dns);
	TAKE("keepalive", keepalive);
#undef TAKE
	wgc.persist = jbool(f, "persist");
	for (v = wgc.name; *v != '\0'; v++)
		if (!((*v >= 'a' && *v <= 'z') || (*v >= 'A' && *v <= 'Z') ||
		    (*v >= '0' && *v <= '9') || *v == '-' || *v == '_' || *v ==
		    '.')) {
			snprintf(app.modal_error, sizeof(app.modal_error), "A "
			    "name is letters, digits, -, _ and .");
			return (true);
		}
	if (wgc.address[0] == '\0' || strchr(wgc.address, '/') == NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "Its address "
		    "with its prefix length: 10.9.0.2/32");
		return (true);
	}
	if (wgc.endpoint[0] == '\0' || strchr(wgc.endpoint, ':') == NULL) {
		snprintf(app.modal_error, sizeof(app.modal_error), "The endpoint "
		    "is a name or address and a port: vpn.example.org:51820");
		return (true);
	}
	if (wgc.allowed[0] == '\0') {
		snprintf(app.modal_error, sizeof(app.modal_error), "What it "
		    "sends through the tunnel: 0.0.0.0/0, ::/0 for everything");
		return (true);
	}
	if (wgc.keepalive[0] != '\0' && !digits(wgc.keepalive)) {
		snprintf(app.modal_error, sizeof(app.modal_error), "Keepalive is "
		    "seconds");
		return (true);
	}
	app.modal_error[0] = '\0';
	api("POST", "/api/wg/keypair", "{}", client_keys_cb, NULL);
	return (true);
}

/*
 * The form's first values: the next address after the peers' (one
 * past the highest IPv4 /32 of them), the host's name or address with
 * the interface's port, everything through the tunnel, a keepalive.
 */
static bool
client_open(struct server *s, const char *ifname)
{
	const ucl_object_t	*o, *p, *ip;
	ucl_object_iter_t	 it, pit, iit;
	const char		*u, *e;
	unsigned int		 a[4], best, v;
	char			 host[160];
	bool			 found;

	wgc_forget();
	snprintf(wgc.server, sizeof(wgc.server), "%s", s->id);
	snprintf(wgc.iface, sizeof(wgc.iface), "%s", ifname);
	found = false;
	best = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(app.net.data, "data.interfaces"),
	    &it, true)) != NULL) {
		if (jstr(o, "name") == NULL || strcmp(jstr(o, "name"), ifname) !=
		    0)
			continue;
		found = true;
		snprintf(wgc.srvpub, sizeof(wgc.srvpub), "%s", jstr(o,
		    "public-key") != NULL ? jstr(o, "public-key") : "");
		/* The host: from the agent's address, or the console's. */
		u = s->uri;
		if (strncmp(u, "tcp://", 6) == 0) {
			u += 6;
			if (*u == '[' && (e = strchr(u, ']')) != NULL)
				snprintf(host, sizeof(host), "%.*s", (int)(e - u +
				    1), u);
			else if ((e = strrchr(u, ':')) != NULL)
				snprintf(host, sizeof(host), "%.*s", (int)(e - u),
				    u);
			else
				snprintf(host, sizeof(host), "%s", u);
		} else {
			u = arc_origin();
			u = strstr(u, "://") != NULL ? strstr(u, "://") + 3 : u;
			snprintf(host, sizeof(host), "%s", u);
			if (host[0] != '[' && (e = strchr(host, ':')) != NULL)
				host[e - host] = '\0';
			else if (host[0] == '[' && (e = strchr(host, ']')) !=
			    NULL)
				host[e - host + 1] = '\0';
		}
		snprintf(wgc.endpoint, sizeof(wgc.endpoint), "%s:%lld", host,
		    (long long)(jint(o, "listen-port", 0) > 0 ? jint(o,
		    "listen-port", 0) : 51820));
		pit = NULL;
		while ((p = ucl_object_iterate(jget(o, "peers"), &pit, true)) !=
		    NULL) {
			iit = NULL;
			while ((ip = ucl_object_iterate(jget(p, "allowed-ips"),
			    &iit, true)) != NULL)
				if (sscanf(ucl_object_tostring_forced(ip),
				    "%u.%u.%u.%u/32", &a[0], &a[1], &a[2], &a[3])
				    == 4 && a[0] < 256 && a[1] < 256 && a[2] <
				    256 && a[3] < 256 && (v = a[0] << 24 | a[1] <<
				    16 | a[2] << 8 | a[3]) > best)
					best = v;
		}
	}
	if (!found || wgc.srvpub[0] == '\0') {
		toast(true, "%s has no key yet: Make its key first", ifname);
		return (false);
	}
	if (best != 0 && (best & 0xff) < 254)
		snprintf(wgc.address, sizeof(wgc.address), "%u.%u.%u.%u/32",
		    best >> 24, (best >> 16) & 0xff, (best >> 8) & 0xff, (best &
		    0xff) + 1);
	snprintf(wgc.allowed, sizeof(wgc.allowed), "0.0.0.0/0, ::/0");
	snprintf(wgc.keepalive, sizeof(wgc.keepalive), "25");
	return (true);
}

bool
vpn_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*v;
	char		 title[160], allowed[512], *qi, *qp, *qe, *qa, extra[64];
	size_t		 n;

	if (strcmp(form, "wg-conf") == 0) {
		app.modal = MODAL_NONE;
		wgc_forget();
		return (true);
	}
	if (strcmp(form, "wg-client") == 0)
		return (client_form(f));
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
	if (strcmp(act, "wg-if-create") == 0) {
		if ((s = cur_server()) != NULL)
			topo_if_create_open(s->id, "wg");
		return (true);
	}
	if (strcmp(act, "wg-client-add") == 0) {
		if (client_open(s, arg)) {
			app.modal = MODAL_WG_CLIENT;
			app.modal_error[0] = '\0';
		}
		return (true);
	}
	if (strcmp(act, "wg-init") == 0 || strcmp(act, "wg-peer-add") == 0) {
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
		app.modal = act[3] == 'i' ? MODAL_WG_INIT : MODAL_WG_PEER;
		app.modal_error[0] = '\0';
		wge.on = false;
	} else if (strcmp(act, "wg-peer-edit") == 0) {
		/* The form, filled with what the peer has now. */
		const ucl_object_t	*o, *p, *ip;
		ucl_object_iter_t	 it, pit, iit;
		size_t			 n;

		memset(&wge, 0, sizeof(wge));
		it = NULL;
		while ((o = ucl_object_iterate(jget(app.net.data,
		    "data.interfaces"), &it, true)) != NULL) {
			if (jstr(o, "name") == NULL || strcmp(jstr(o, "name"),
			    arg) != 0)
				continue;
			pit = NULL;
			while ((p = ucl_object_iterate(jget(o, "peers"), &pit,
			    true)) != NULL) {
				if (jstr(p, "public-key") == NULL || strcmp(jstr(p,
				    "public-key"), value) != 0)
					continue;
				wge.on = true;
				snprintf(wge.key, sizeof(wge.key), "%s", value);
				snprintf(wge.endpoint, sizeof(wge.endpoint), "%s",
				    jstr(p, "endpoint") != NULL ? jstr(p,
				    "endpoint") : "");
				if (jint(p, "keepalive", 0) > 0)
					snprintf(wge.keepalive,
					    sizeof(wge.keepalive), "%lld",
					    (long long)jint(p, "keepalive", 0));
				n = 0;
				iit = NULL;
				while ((ip = ucl_object_iterate(jget(p,
				    "allowed-ips"), &iit, true)) != NULL &&
				    n + 2 < sizeof(wge.allowed))
					n += (size_t)snprintf(wge.allowed + n,
					    sizeof(wge.allowed) - n, "%s%s", n > 0 ?
					    ", " : "", ucl_object_tostring_forced(
					    ip));
			}
		}
		if (!wge.on)
			return (true);
		snprintf(app.confirm.arg, sizeof(app.confirm.arg), "%s", arg);
		app.modal = MODAL_WG_PEER;
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
