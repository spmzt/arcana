/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Span: traffic mirrored, and taken.  A bridge's span port has a copy
 * of every frame the bridge carries, for a sniffer or an IDS on the
 * other end; an ipfw rule with log (logdst bpf) has a bpf(4) tap of its
 * own, ipfw and its number, with what it matches.  Either, or any
 * interface, is taken from for a few packets or seconds with tcpdump on
 * the host: the packets as lines, and a pcap to save.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char		 sid[9];
	char		 jail[256];
	ucl_object_t	*fw;		/* the firewall's rules */
	ucl_object_t	*src;		/* {"sources": [...]} */
	ucl_object_t	*cap;		/* the last capture */
	bool		 cap_busy;
	char		 error[300];
	char		 source[16];	/* the next capture's, chosen */
} sp;

static void
fw_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	if (status != 200 || jget(o, "data") == NULL)
		return;
	if (sp.fw != NULL)
		ucl_object_unref(sp.fw);
	sp.fw = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

static void
src_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	if (status != 200 || jget(o, "data") == NULL)
		return;
	if (sp.src != NULL)
		ucl_object_unref(sp.src);
	sp.src = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

static void
cap_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	sp.cap_busy = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "data") == NULL) {
		snprintf(sp.error, sizeof(sp.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : jstr(o,
		    "error") != NULL ? jstr(o, "error") : err != NULL ? err :
		    "no answer");
		return;
	}
	sp.error[0] = '\0';
	if (sp.cap != NULL)
		ucl_object_unref(sp.cap);
	sp.cap = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o, "data"));
}

static void
capture_send(struct server *s, const char *body)
{
	char	url[400];

	snprintf(url, sizeof(url), "/api/servers/%s/capture%s%s", s->id,
	    sp.jail[0] != '\0' ? "?jail=" : "", sp.jail);
	api("POST", url, body, body[1] == '}' ? src_cb : cap_cb, NULL);
}

/* The rules and the sources, read with the bridges. */
void
span_refresh(struct server *s)
{
	char	url[400];

	if (strcmp(sp.sid, s->id) != 0 || strcmp(sp.jail, net_scope()) != 0) {
		if (sp.fw != NULL)
			ucl_object_unref(sp.fw);
		if (sp.src != NULL)
			ucl_object_unref(sp.src);
		if (sp.cap != NULL)
			ucl_object_unref(sp.cap);
		sp.fw = sp.src = sp.cap = NULL;
		sp.error[0] = '\0';
		sp.source[0] = '\0';
	}
	snprintf(sp.sid, sizeof(sp.sid), "%s", s->id);
	snprintf(sp.jail, sizeof(sp.jail), "%s", net_scope());
	snprintf(url, sizeof(url), "/api/servers/%s/net/ipfw?family=all%s%s",
	    s->id, sp.jail[0] != '\0' ? "&jail=" : "", sp.jail);
	api("GET", url, NULL, fw_cb, NULL);
	capture_send(s, "{}");
}

/* Is the rule's text one with a tap of its own? */
static bool
tapped(const char *text)
{
	const char	*l;

	if (text == NULL || (l = strstr(text, " log")) == NULL || (l[4] !=
	    ' ' && l[4] != '\0'))
		return (false);
	/* logdst names where: the tap is one of them, or there is none
	 * named and net.inet.ip.fw.verbose is 0. */
	if ((l = strstr(text, "logdst ")) != NULL)
		return (strstr(l, "bpf") != NULL);
	return (sp.fw == NULL || !jbool(sp.fw, "verbose"));
}

void
view_span(struct html *h, struct server *s)
{
	static const struct tcol pc[] = {
		{ "Bridge", "bridge", false }, { "Span port", "port", false },
		{ "", NULL, false },
	};
	static const struct tcol rc[] = {
		{ "Rule", "num", true }, { "Tap", "tap", false },
		{ "Words", "text", false }, { "Packets", "pkts", true },
		{ "", NULL, false },
	};
	const ucl_object_t	*b, *m, *f, *o, **rows;
	ucl_object_iter_t	 it, mit, fit;
	ucl_object_t		*arr, *row;
	char			 tap[24];
	int			 n;

	(void)s;
	h_raw(h, "<p class=\"dim\">Traffic mirrored, and taken. A bridge's "
	    "<b>span port</b> has a copy of every frame the bridge carries, for "
	    "a sniffer or an IDS on its other end. An ipfw rule with <code>log "
	    "logdst bpf</code> has a bpf(4) tap of its own, <code>ipfw</code> "
	    "and its number, with what it matches. Either, or any interface, "
	    "is taken from below, with tcpdump(1) on the host.</p>");
	/* Span ports, of each bridge. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((b = ucl_object_iterate(jget(app.net.data, "data.bridges"), &it,
	    true)) != NULL) {
		mit = NULL;
		while ((m = ucl_object_iterate(jget(b, "members"), &mit,
		    true)) != NULL) {
			fit = NULL;
			while ((f = ucl_object_iterate(jget(m, "flags"), &fit,
			    true)) != NULL)
				if (strcasecmp(ucl_object_tostring_forced(f),
				    "span") == 0)
					break;
			if (f == NULL)
				continue;
			row = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(row, ucl_object_fromstring(jstr(b,
			    "name")), "bridge", 0, false);
			ucl_object_insert_key(row, ucl_object_fromstring(jstr(m,
			    "name")), "port", 0, false);
			ucl_array_append(arr, row);
		}
	}
	h_raw(h, "<h4 class=\"family\">Span ports</h4><form data-form=\""
	    "span-port\" class=\"fw-obj\"><label>bridge<select name=\"bridge\">");
	it = NULL;
	while ((b = ucl_object_iterate(jget(app.net.data, "data.bridges"), &it,
	    true)) != NULL) {
		h_raw(h, "<option>");
		h_txt(h, jstr(b, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label><label>copies out of<input name=\"port\" "
	    "spellcheck=\"false\" autocomplete=\"off\" size=\"10\" "
	    "placeholder=\"em2\"></label><label class=\"toggle\"><input "
	    "type=\"checkbox\" name=\"persist\" checked><span>keep</span>"
	    "</label><button class=\"small\">Mirror</button></form>");
	h_raw(h, "<table class=\"net span-ports\">");
	tbl_head(h, "span-ports", pc, 3, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("span-ports", arr, pc, 3, NULL);
	for (n = 0; (o = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td>");
		h_txt(h, jstr(o, "bridge"));
		h_raw(h, "</td><td><b>");
		h_txt(h, jstr(o, "port"));
		h_raw(h, "</b></td><td class=\"acts\"><button class=\"ghost "
		    "small\" data-act=\"span-take\" title=\"Take what it copies "
		    "out\"");
		h_attr(h, "data-arg", jstr(o, "port"));
		h_raw(h, ">Capture</button><button class=\"icon\" data-act=\""
		    "span-unport\" title=\"No more a span port\"");
		h_attr(h, "data-arg", jstr(o, "bridge"));
		h_attr(h, "data-value", jstr(o, "port"));
		h_raw(h, ">×</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"3\" class=\"dim\">None.</td></tr>");
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");

	/* Rules with a tap. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while (sp.fw != NULL && (o = ucl_object_iterate(jget(sp.fw, "rules"),
	    &it, true)) != NULL) {
		if (!tapped(jstr(o, "text")))
			continue;
		row = ucl_object_copy(o);
		snprintf(tap, sizeof(tap), "ipfw%lld", (long long)jint(o, "num",
		    0));
		ucl_object_insert_key(row, ucl_object_fromstring(tap), "tap", 0,
		    false);
		ucl_array_append(arr, row);
	}
	h_raw(h, "<h4 class=\"family\">Mirror rules</h4><form data-form=\""
	    "span-rule\" class=\"fw-obj\"><label>rule<input name=\"num\" "
	    "inputmode=\"numeric\" size=\"5\" placeholder=\"150\"></label>"
	    "<label>protocol<select name=\"proto\"><option>ip</option><option>"
	    "tcp</option><option>udp</option><option>icmp</option></select>"
	    "</label><label>from<input name=\"from\" spellcheck=\"false\" "
	    "size=\"12\" placeholder=\"any\"></label><label>to<input name=\"to\" "
	    "spellcheck=\"false\" size=\"12\" placeholder=\"any\"></label>"
	    "<label>port<input name=\"port\" inputmode=\"numeric\" size=\"5\" "
	    "placeholder=\"any\"></label><label>via<input name=\"via\" "
	    "spellcheck=\"false\" size=\"7\" placeholder=\"any\"></label>"
	    "<label class=\"toggle\"><input type=\"checkbox\" name=\"persist\" "
	    "checked><span>keep</span></label><button class=\"small\" title=\""
	    "ipfw add N count log logdst bpf …: counted and mirrored, and "
	    "passed on to the rules after it\">Mirror</button></form>");
	h_raw(h, "<table class=\"net span-rules\">");
	tbl_head(h, "span-rules", rc, 5, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("span-rules", arr, rc, 5, NULL);
	for (n = 0; (o = rows[n]) != NULL; n++) {
		h_fmt(h, "<tr><td><b>%05lld</b></td><td class=\"mono\">", (long
		    long)jint(o, "num", 0));
		h_txt(h, jstr(o, "tap"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(o, "text"));
		h_fmt(h, "</td><td>%lld</td><td class=\"acts\"><button class=\""
		    "ghost small\" data-act=\"span-take\"", (long long)jint(o,
		    "pkts", 0));
		h_attr(h, "data-arg", jstr(o, "tap"));
		h_raw(h, ">Capture</button></td></tr>");
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"5\" class=\"dim\">None: a rule with "
		    "log has a tap when net.inet.ip.fw.verbose is 0, or its "
		    "logdst names bpf.</td></tr>");
	free(rows);
	ucl_object_unref(arr);
	h_raw(h, "</tbody></table>");

	/* Capture. */
	h_raw(h, "<h4 class=\"family\">Capture</h4><form data-form=\""
	    "span-capture\" class=\"fw-obj\"><label>from<input name=\"source\" "
	    "list=\"span-sources\" spellcheck=\"false\" autocomplete=\"off\" "
	    "size=\"10\" placeholder=\"em0, ipfw150\"");
	h_attr(h, "value", sp.source);
	h_raw(h, "><datalist id=\"span-sources\">");
	it = NULL;
	while (sp.src != NULL && (o = ucl_object_iterate(jget(sp.src,
	    "sources"), &it, true)) != NULL) {
		h_raw(h, "<option");
		h_attr(h, "value", ucl_object_tostring_forced(o));
		h_raw(h, ">");
	}
	h_raw(h, "</datalist></label><label>filter<input name=\"filter\" "
	    "spellcheck=\"false\" autocomplete=\"off\" size=\"22\" "
	    "placeholder=\"tcp port 443, pcap-filter(7)\"></label><label>"
	    "packets<input name=\"packets\" inputmode=\"numeric\" size=\"4\" "
	    "placeholder=\"50\"></label><label>seconds<input name=\"seconds\" "
	    "inputmode=\"numeric\" size=\"3\" placeholder=\"10\"></label>");
	h_fmt(h, "<button class=\"small primary\"%s>%s</button></form>",
	    sp.cap_busy ? " disabled" : "", sp.cap_busy ? "Taking…" :
	    "Capture");
	if (sp.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, sp.error);
		h_raw(h, "</div>");
	}
	if (sp.cap != NULL) {
		h_fmt(h, "<p class=\"dim span-sum\"><b>%lld</b> packets from <b>",
		    (long long)jint(sp.cap, "packets", 0));
		h_txt(h, jstr(sp.cap, "source"));
		h_raw(h, "</b>");
		if (jstr(sp.cap, "filter") != NULL && jstr(sp.cap,
		    "filter")[0] != '\0') {
			h_raw(h, ", <code>");
			h_txt(h, jstr(sp.cap, "filter"));
			h_raw(h, "</code>");
		}
		h_fmt(h, "%s. ", jbool(sp.cap, "timed_out") ? "; its time was up "
		    "first" : "");
		if (jstr(sp.cap, "pcap") != NULL)
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "span-save\">Save the pcap</button> <small>%lld "
			    "bytes, for Wireshark or tcpdump -r</small>",
			    (long long)jint(sp.cap, "bytes", 0));
		h_raw(h, "</p><pre class=\"mono span-lines\">");
		it = NULL;
		while ((o = ucl_object_iterate(jget(sp.cap, "lines"), &it,
		    true)) != NULL) {
			h_txt(h, ucl_object_tostring_forced(o));
			h_raw(h, "\n");
		}
		h_raw(h, "</pre>");
	}
}

/* An address field: an address, a network, any, me. */
static bool
addr_ok(const char *a)
{

	return (a[0] == '\0' || strcmp(a, "any") == 0 || strcmp(a, "me") ==
	    0 || (strlen(a) < 64 && a[strspn(a, "0123456789abcdefABCDEF.:/")] ==
	    '\0'));
}

static bool
name_ok(const char *s)
{

	return (s[0] != '\0' && strlen(s) < 16 && s[strspn(s,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")]
	    == '\0');
}

bool
span_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*b, *p, *num, *proto, *from, *to, *port, *via, *flt;
	char		*q, *q2, *json, words[400], title[200], *w, *e;
	struct html	 j;
	int		 pk, sec;

	if (strncmp(form, "span-", 5) != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(form, "span-port") == 0) {
		b = jstr(f, "bridge") != NULL ? jstr(f, "bridge") : "";
		p = jstr(f, "port") != NULL ? jstr(f, "port") : "";
		if (!name_ok(b) || !name_ok(p)) {
			toast(true, "A bridge, and the interface it copies out of");
			return (true);
		}
		q = json_quote(b);
		q2 = json_quote(p);
		if (asprintf(&json, "{\"kind\":\"bridge\",\"interface\":%s,"
		    "\"verb\":\"flag\",\"args\":[%s,\"span\"],\"persist\":%s}", q,
		    q2, jbool(f, "persist") ? "true" : "false") == -1)
			abort();
		free(q);
		free(q2);
		snprintf(title, sizeof(title), "%s span %s", b, p);
		job_send(s, json, title, JOB_IFACE, b);
	} else if (strcmp(form, "span-rule") == 0) {
		num = jstr(f, "num") != NULL ? jstr(f, "num") : "";
		proto = jstr(f, "proto") != NULL ? jstr(f, "proto") : "ip";
		from = jstr(f, "from") != NULL ? jstr(f, "from") : "";
		to = jstr(f, "to") != NULL ? jstr(f, "to") : "";
		port = jstr(f, "port") != NULL ? jstr(f, "port") : "";
		via = jstr(f, "via") != NULL ? jstr(f, "via") : "";
		if (num[0] == '\0' || num[strspn(num, "0123456789")] != '\0' ||
		    atoi(num) < 1 || atoi(num) > 65534 || !addr_ok(from) ||
		    !addr_ok(to) || port[strspn(port, "0123456789")] != '\0' ||
		    (via[0] != '\0' && !name_ok(via)) || (strcmp(proto, "ip") !=
		    0 && strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") !=
		    0 && strcmp(proto, "icmp") != 0) || (port[0] != '\0' &&
		    strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0)) {
			toast(true, "A rule number 1 to 65534, addresses or any; a "
			    "port is of tcp or udp");
			return (true);
		}
		snprintf(words, sizeof(words), "count log logdst bpf %s from %s "
		    "to %s%s%s%s%s", proto, from[0] != '\0' ? from : "any",
		    to[0] != '\0' ? to : "any", port[0] != '\0' ? " dst-port " :
		    "", port, via[0] != '\0' ? " via " : "", via);
		memset(&j, 0, sizeof(j));
		h_fmt(&j, "{\"kind\":\"ipfw\",\"verb\":\"add\",\"args\":[\"%d\"",
		    atoi(num));
		for (w = words; *w != '\0'; w = e) {
			e = w + strcspn(w, " ");
			q = strndup(w, (size_t)(e - w));
			q2 = json_quote(q);
			h_fmt(&j, ",%s", q2);
			free(q);
			free(q2);
			if (*e == ' ')
				e++;
		}
		h_fmt(&j, "],\"live\":true,\"persist\":%s}", jbool(f, "persist") ?
		    "true" : "false");
		snprintf(title, sizeof(title), "ipfw add %d %.140s", atoi(num),
		    words);
		job_send(s, j.s, title, JOB_IFACE, "span");
	} else if (strcmp(form, "span-capture") == 0) {
		p = jstr(f, "source") != NULL ? jstr(f, "source") : "";
		flt = jstr(f, "filter") != NULL ? jstr(f, "filter") : "";
		if (!name_ok(p) || strlen(flt) > 128) {
			toast(true, "From an interface or a tap; a filter of 128 "
			    "characters at most");
			return (true);
		}
		pk = jstr(f, "packets") != NULL && atoi(jstr(f, "packets")) > 0 ?
		    atoi(jstr(f, "packets")) : 50;
		sec = jstr(f, "seconds") != NULL && atoi(jstr(f, "seconds")) >
		    0 ? atoi(jstr(f, "seconds")) : 10;
		snprintf(sp.source, sizeof(sp.source), "%s", p);
		q = json_quote(p);
		q2 = json_quote(flt);
		if (asprintf(&json, "{\"source\":%s,\"filter\":%s,\"packets\":%d,"
		    "\"seconds\":%d}", q, q2, pk > 500 ? 500 : pk, sec > 60 ? 60 :
		    sec) == -1)
			abort();
		free(q);
		free(q2);
		sp.cap_busy = true;
		sp.error[0] = '\0';
		capture_send(s, json);
		free(json);
	}
	return (true);
}

bool
span_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 body[300], *q, *q2, *json, name[64];

	if (strncmp(act, "span-", 5) != 0 && strcmp(act, "do-span-unport") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	if (strcmp(act, "span-take") == 0)
		snprintf(sp.source, sizeof(sp.source), "%s", arg);
	else if (strcmp(act, "span-save") == 0 && sp.cap != NULL &&
	    jstr(sp.cap, "pcap") != NULL) {
		snprintf(name, sizeof(name), "%s-%s.pcap", s->name, jstr(sp.cap,
		    "source"));
		arc_save_b64(name, "application/vnd.tcpdump.pcap", jstr(sp.cap,
		    "pcap"));
	} else if (strcmp(act, "span-unport") == 0) {
		snprintf(body, sizeof(body), "%s no more a span port of %s: it "
		    "copies out nothing from then on.", value, arg);
		confirm("No more a span port", body, "Stop", true, "",
		    "do-span-unport", arg, value);
	} else if (strcmp(act, "do-span-unport") == 0) {
		q = json_quote(arg);
		q2 = json_quote(value);
		if (asprintf(&json, "{\"kind\":\"bridge\",\"interface\":%s,"
		    "\"verb\":\"flag\",\"args\":[%s,\"-span\"],\"persist\":true}",
		    q, q2) == -1)
			abort();
		free(q);
		free(q2);
		snprintf(body, sizeof(body), "%s -span %s", arg, value);
		job_send(s, json, body, JOB_IFACE, arg);
	}
	return (true);
}
