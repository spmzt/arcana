/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * BIRD's BGP, OSPF and BFD protocols as forms: a protocol's text read
 * into fields, the fields checked and written back as text.  A text is
 * read only when every word of it is one the form shows, comments
 * included among what it does not: what the form cannot show it could
 * not write back, and such a protocol is changed as text instead.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "app.h"

#define	BF_IFS		6	/* interfaces, or neighbours, of a form */
#define	BF_TOKS		768
#define	BF_TOKLEN	136

struct bfif {
	char	name[64];		/* an interface's pattern */
	char	cost[12], type[16], hello[12], dead[12];
	bool	bfd, stub;
	char	rx[12], tx[12], mult[8];	/* BFD's, in ms */
};

struct bfnbr {
	char	addr[64];
	char	dev[32];
	char	local[64];		/* the address it is sent from */
	bool	multihop;
};

struct bfconf {
	char		kind[8];	/* bgp, ospf or bfd */
	char		name[64];
	/* BGP */
	char		desc[128];
	char		las[12], nbr[80], nas[12], src[64], pass[128];
	char		multihop[8];	/* "" none, "0" BIRD's default */
	bool		bfd, passive;
	bool		ch[2];		/* ipv4, ipv6 */
	char		imp[2][72], exp[2][72];	/* all, none, filter X */
	bool		nhself[2];
	/* OSPF */
	char		ver[4];		/* v2 or v3 */
	int		chan;		/* 0 ipv4, 1 ipv6 */
	char		area[40];
	/* OSPF's and BFD's interfaces; BFD's neighbours */
	struct bfif	ifs[BF_IFS];
	int		nifs;
	struct bfnbr	nbrs[BF_IFS];
	int		nnbrs;
};

static bool	ospf_chan;	/* the OSPF text read had its channel */
static bool	md5;		/* the BGP text read said authentication md5 */

struct toks {
	char	t[BF_TOKS][BF_TOKLEN];
	int	n;
	int	i;			/* the one read next */
};

/* The text in words, strings and { } ; ,: false for a comment. */
static bool
tokenize(const char *p, struct toks *k)
{
	size_t	n;

	k->n = k->i = 0;
	for (;;) {
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '\0')
			return (true);
		if (*p == '#' || (p[0] == '/' && p[1] == '*') || k->n ==
		    BF_TOKS)
			return (false);
		n = 0;
		if (*p == '"') {
			do
				k->t[k->n][n++] = *p++;
			while (*p != '\0' && *p != '"' && *p != '\n' &&
			    *p != '\\' && n + 2 < BF_TOKLEN);
			if (*p != '"')
				return (false);
			k->t[k->n][n++] = *p++;
		} else if (strchr("{};,", *p) != NULL)
			k->t[k->n][n++] = *p++;
		else
			while (*p != '\0' && !isspace((unsigned char)*p) &&
			    strchr("{};,\"#", *p) == NULL) {
				if (n + 1 == BF_TOKLEN)
					return (false);
				k->t[k->n][n++] = *p++;
			}
		k->t[k->n++][n] = '\0';
	}
}

static const char *
peek(struct toks *k)
{

	return (k->i < k->n ? k->t[k->i] : "");
}

static bool
eat(struct toks *k, const char *w)
{

	if (strcmp(peek(k), w) != 0)
		return (false);
	k->i++;
	return (true);
}

/* A word into buf; false at the end, or at punctuation. */
static bool
take(struct toks *k, char *buf, size_t len)
{
	const char	*w;

	w = peek(k);
	if (w[0] == '\0' || strchr("{};,\"", w[0]) != NULL || strlen(w) >=
	    len)
		return (false);
	snprintf(buf, len, "%s", w);
	k->i++;
	return (true);
}

/* A string's text, without its quotes. */
static bool
take_str(struct toks *k, char *buf, size_t len)
{
	const char	*w;
	size_t		 n;

	w = peek(k);
	n = strlen(w);
	if (w[0] != '"' || n < 2 || n - 2 >= len)
		return (false);
	snprintf(buf, len, "%.*s", (int)(n - 2), w + 1);
	k->i++;
	return (true);
}

/* on, yes, off, no, or nothing (on); then the ';'. */
static bool
take_bool(struct toks *k, bool *v)
{

	*v = true;
	if (eat(k, "off") || eat(k, "no"))
		*v = false;
	else if (!eat(k, "on"))
		(void)eat(k, "yes");
	return (eat(k, ";"));
}

/* import or export: all, none, or filter NAME. */
static bool
take_filter(struct toks *k, char *buf, size_t len)
{
	char	name[64];

	if (eat(k, "all"))
		snprintf(buf, len, "all");
	else if (eat(k, "none"))
		snprintf(buf, len, "none");
	else if (eat(k, "filter") && take(k, name, sizeof(name)))
		snprintf(buf, len, "filter %s", name);
	else
		return (false);
	return (eat(k, ";"));
}

/* A block's end: '}', and the ';' that may follow it. */
static void
block_end(struct toks *k)
{

	(void)eat(k, ";");
}

static bool
parse_bgp(struct toks *k, struct bfconf *c)
{
	char	w[80];
	int	ch;

	md5 = false;

	while (!eat(k, "}")) {
		if (eat(k, "description")) {
			if (!take_str(k, c->desc, sizeof(c->desc)) ||
			    !eat(k, ";"))
				return (false);
		} else if (eat(k, "local")) {
			if (!eat(k, "as")) {
				if (!take(k, c->src, sizeof(c->src)) ||
				    !eat(k, "as"))
					return (false);
			}
			if (!take(k, c->las, sizeof(c->las)) || !eat(k, ";"))
				return (false);
		} else if (eat(k, "neighbor")) {
			if (!take(k, c->nbr, sizeof(c->nbr)) || !eat(k, "as") ||
			    !take(k, c->nas, sizeof(c->nas)) || !eat(k, ";"))
				return (false);
		} else if (eat(k, "source")) {
			if (!eat(k, "address") || !take(k, c->src,
			    sizeof(c->src)) || !eat(k, ";"))
				return (false);
		} else if (eat(k, "multihop")) {
			if (eat(k, ";"))
				snprintf(c->multihop, sizeof(c->multihop), "0");
			else if (!take(k, c->multihop, sizeof(c->multihop)) ||
			    !eat(k, ";"))
				return (false);
		} else if (eat(k, "authentication")) {
			/* What a password is written with; none, or another
			 * kind, the form does not show. */
			if (!eat(k, "md5") || !eat(k, ";"))
				return (false);
			md5 = true;
		} else if (eat(k, "password")) {
			if (!take_str(k, c->pass, sizeof(c->pass)) ||
			    !eat(k, ";"))
				return (false);
		} else if (eat(k, "bfd")) {
			if (!take_bool(k, &c->bfd))
				return (false);
		} else if (eat(k, "passive")) {
			if (!take_bool(k, &c->passive))
				return (false);
		} else if ((ch = eat(k, "ipv4") ? 0 : eat(k, "ipv6") ? 1 :
		    -1) != -1) {
			if (c->ch[ch] || !eat(k, "{"))
				return (false);
			c->ch[ch] = true;
			while (!eat(k, "}")) {
				if (eat(k, "import")) {
					if (!take_filter(k, c->imp[ch],
					    sizeof(c->imp[0])))
						return (false);
				} else if (eat(k, "export")) {
					if (!take_filter(k, c->exp[ch],
					    sizeof(c->exp[0])))
						return (false);
				} else if (eat(k, "next")) {
					if (!eat(k, "hop") || !eat(k, "self") ||
					    !eat(k, ";"))
						return (false);
					c->nhself[ch] = true;
				} else
					return (false);
			}
			block_end(k);
		} else {
			(void)take(k, w, sizeof(w));
			return (false);
		}
	}
	return (true);
}

static bool
parse_if_ospf(struct toks *k, struct bfif *f)
{

	while (!eat(k, "}")) {
		if (eat(k, "cost")) {
			if (!take(k, f->cost, sizeof(f->cost)) || !eat(k, ";"))
				return (false);
		} else if (eat(k, "type")) {
			if (!take(k, f->type, sizeof(f->type)) || !eat(k, ";"))
				return (false);
			/* As the form names them. */
			if (strcmp(f->type, "bcast") == 0)
				snprintf(f->type, sizeof(f->type), "broadcast");
			else if (strcmp(f->type, "pointopoint") == 0)
				snprintf(f->type, sizeof(f->type), "ptp");
			else if (strcmp(f->type, "broadcast") != 0 &&
			    strcmp(f->type, "ptp") != 0)
				return (false);
		} else if (eat(k, "hello")) {
			if (!take(k, f->hello, sizeof(f->hello)) || !eat(k,
			    ";"))
				return (false);
		} else if (eat(k, "dead")) {
			if (!take(k, f->dead, sizeof(f->dead)) || !eat(k, ";"))
				return (false);
		} else if (eat(k, "bfd")) {
			if (!take_bool(k, &f->bfd))
				return (false);
		} else if (eat(k, "stub")) {
			if (!take_bool(k, &f->stub))
				return (false);
		} else
			return (false);
	}
	block_end(k);
	return (true);
}

static bool
parse_ospf(struct toks *k, struct bfconf *c)
{
	struct bfif	*f;
	bool		 area, chan;

	area = chan = ospf_chan = false;
	while (!eat(k, "}")) {
		if (strcmp(peek(k), "ipv4") == 0 || strcmp(peek(k), "ipv6") ==
		    0) {
			if (chan)
				return (false);
			chan = ospf_chan = true;
			c->chan = eat(k, "ipv4") ? 0 : (eat(k, "ipv6"), 1);
			if (!eat(k, "{"))
				return (false);
			while (!eat(k, "}")) {
				if (eat(k, "import")) {
					if (!take_filter(k, c->imp[0],
					    sizeof(c->imp[0])))
						return (false);
				} else if (eat(k, "export")) {
					if (!take_filter(k, c->exp[0],
					    sizeof(c->exp[0])))
						return (false);
				} else
					return (false);
			}
			block_end(k);
		} else if (eat(k, "area")) {
			if (area || !take(k, c->area, sizeof(c->area)) ||
			    !eat(k, "{"))
				return (false);
			area = true;
			while (!eat(k, "}")) {
				if (!eat(k, "interface") || c->nifs == BF_IFS)
					return (false);
				f = &c->ifs[c->nifs++];
				if (!take_str(k, f->name, sizeof(f->name)))
					return (false);
				if (eat(k, ";"))
					continue;
				if (!eat(k, "{") || !parse_if_ospf(k, f))
					return (false);
			}
			block_end(k);
		} else
			return (false);
	}
	return (area);
}

/* A time as BFD has it, N ms or N s, into ms. */
static bool
take_ms(struct toks *k, char *buf, size_t len)
{
	char	n[12];

	if (!take(k, n, sizeof(n)) || n[strspn(n, "0123456789")] != '\0')
		return (false);
	if (eat(k, "ms"))
		snprintf(buf, len, "%s", n);
	else if (eat(k, "s"))
		snprintf(buf, len, "%lld", strtoll(n, NULL, 10) * 1000);
	else
		return (false);
	return (eat(k, ";"));
}

static bool
parse_bfd(struct toks *k, struct bfconf *c)
{
	struct bfif	*f;
	struct bfnbr	*b;

	while (!eat(k, "}")) {
		if (eat(k, "interface")) {
			if (c->nifs == BF_IFS)
				return (false);
			f = &c->ifs[c->nifs++];
			if (!take_str(k, f->name, sizeof(f->name)))
				return (false);
			if (eat(k, ";"))
				continue;
			if (!eat(k, "{"))
				return (false);
			while (!eat(k, "}")) {
				if (eat(k, "min")) {
					if (eat(k, "rx")) {
						if (!eat(k, "interval") ||
						    !take_ms(k, f->rx,
						    sizeof(f->rx)))
							return (false);
					} else if (!eat(k, "tx") || !eat(k,
					    "interval") || !take_ms(k, f->tx,
					    sizeof(f->tx)))
						return (false);
				} else if (eat(k, "interval")) {
					if (!take_ms(k, f->rx, sizeof(f->rx)))
						return (false);
					snprintf(f->tx, sizeof(f->tx), "%s",
					    f->rx);
				} else if (eat(k, "multiplier")) {
					if (!take(k, f->mult, sizeof(f->mult)) ||
					    !eat(k, ";"))
						return (false);
				} else
					return (false);
			}
			block_end(k);
		} else if (eat(k, "neighbor")) {
			if (c->nnbrs == BF_IFS)
				return (false);
			b = &c->nbrs[c->nnbrs++];
			if (!take(k, b->addr, sizeof(b->addr)))
				return (false);
			for (;;) {
				if (eat(k, ";"))
					break;
				if (eat(k, "dev")) {
					if (!take_str(k, b->dev, sizeof(b->dev)))
						return (false);
				} else if (eat(k, "local")) {
					if (!take(k, b->local, sizeof(b->local)))
						return (false);
				} else if (eat(k, "multihop")) {
					b->multihop = true;
					if (eat(k, "off") || eat(k, "no"))
						b->multihop = false;
					else if (!eat(k, "on"))
						(void)eat(k, "yes");
				} else
					return (false);
			}
		} else
			return (false);
	}
	return (true);
}

/* A new protocol of the kind, as the form starts it. */
struct bfconf *
bf_new(const char *kind)
{
	struct bfconf	*c;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		abort();
	snprintf(c->kind, sizeof(c->kind), "%s", kind);
	c->ch[0] = true;
	snprintf(c->imp[0], sizeof(c->imp[0]), "all");
	snprintf(c->exp[0], sizeof(c->exp[0]), "none");
	snprintf(c->imp[1], sizeof(c->imp[1]), "all");
	snprintf(c->exp[1], sizeof(c->exp[1]), "none");
	snprintf(c->ver, sizeof(c->ver), "v2");
	snprintf(c->area, sizeof(c->area), "0");
	return (c);
}

/* The protocol's text read into a form; NULL when it has more. */
struct bfconf *
bf_parse(const char *kind, const char *text)
{
	static struct toks	 k;
	struct bfconf		*c;
	bool			 ok;

	c = bf_new(kind);
	c->ch[0] = false;
	c->imp[0][0] = c->exp[0][0] = '\0';
	ok = tokenize(text, &k) && eat(&k, "protocol") && eat(&k, kind);
	if (ok && strcmp(kind, "ospf") == 0 && (strcmp(peek(&k), "v2") == 0 ||
	    strcmp(peek(&k), "v3") == 0))
		ok = take(&k, c->ver, sizeof(c->ver));
	ok = ok && take(&k, c->name, sizeof(c->name)) && eat(&k, "{");
	if (ok)
		ok = strcmp(kind, "bgp") == 0 ? parse_bgp(&k, c) : strcmp(kind,
		    "ospf") == 0 ? parse_ospf(&k, c) : strcmp(kind, "bfd") ==
		    0 ? parse_bfd(&k, c) : false;
	if (ok)
		block_end(&k);
	/*
	 * A BGP channel without its import or export has BIRD's default,
	 * which is not the same for every session (RFC 8212 for eBGP):
	 * the form would have to say one, so such a text is left as text.
	 * OSPF's defaults are import all and export none.
	 */
	if (ok && strcmp(kind, "bgp") == 0 && ((!c->ch[0] && !c->ch[1]) ||
	    (md5 && c->pass[0] == '\0')))
		ok = false;
	if (ok && strcmp(kind, "bgp") == 0)
		for (int ch = 0; ch < 2; ch++)
			if (c->ch[ch] && (c->imp[ch][0] == '\0' ||
			    c->exp[ch][0] == '\0'))
				ok = false;
	if (ok && strcmp(kind, "ospf") == 0) {
		if (strcmp(c->ver, "v3") == 0 && !ospf_chan)
			c->chan = 1;
		if (c->imp[0][0] == '\0')
			snprintf(c->imp[0], sizeof(c->imp[0]), "all");
		if (c->exp[0][0] == '\0')
			snprintf(c->exp[0], sizeof(c->exp[0]), "none");
	}
	if (!ok || k.i != k.n) {
		free(c);
		return (NULL);
	}
	return (c);
}

const char *
bf_name(const struct bfconf *c)
{

	return (c->name);
}

void
bf_free(struct bfconf *c)
{

	free(c);
}

/*
 * The form's fields.  filters: the names of the file's filters, NULL
 * last; edit: the name is the protocol's and is kept.
 */
static void
text_in(struct html *h, const char *label, const char *name, const char *v,
    const char *ph, const char *extra)
{

	h_fmt(h, "<label>%s<input name=\"%s\" spellcheck=\"false\" "
	    "autocomplete=\"off\"", label, name);
	h_attr(h, "value", v);
	if (ph != NULL)
		h_attr(h, "placeholder", ph);
	h_fmt(h, "%s></label>", extra != NULL ? extra : "");
}

static void
check_in(struct html *h, const char *label, const char *name, bool on)
{

	h_fmt(h, "<label class=\"check\"><input type=\"checkbox\" name=\"%s\""
	    "%s> %s</label>", name, on ? " checked" : "", label);
}

static void
filter_in(struct html *h, const char *label, const char *name,
    const char *v, const char *const *filters)
{
	char	opt[72];
	int	i;

	h_fmt(h, "<label>%s<select name=\"%s\">", label, name);
	h_fmt(h, "<option value=\"all\"%s>all</option><option value=\"none\""
	    "%s>none</option>", strcmp(v, "all") == 0 ? " selected" : "",
	    strcmp(v, "none") == 0 ? " selected" : "");
	for (i = 0; filters != NULL && filters[i] != NULL; i++) {
		snprintf(opt, sizeof(opt), "filter %s", filters[i]);
		h_raw(h, "<option");
		h_attr(h, "value", opt);
		h_fmt(h, "%s>filter ", strcmp(v, opt) == 0 ? " selected" : "");
		h_txt(h, filters[i]);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label>");
}

void
bf_fields(struct html *h, const struct bfconf *c, const char *const *filters,
    bool edit)
{
	static const char *const chn[] = { "IPv4", "IPv6" };
	char	 n[16];
	int	 i;

	text_in(h, "Name", "name", c->name, strcmp(c->kind, "bgp") == 0 ?
	    "upstream1" : strcmp(c->kind, "ospf") == 0 ? "ospf1" : "bfd1",
	    edit ? " readonly" : " autofocus");
	if (strcmp(c->kind, "bgp") == 0) {
		text_in(h, "Description", "desc", c->desc, "Transit, via "
		    "the exchange", NULL);
		h_raw(h, "<div class=\"two\">");
		text_in(h, "Neighbour address", "nbr", c->nbr, "192.0.2.1, or "
		    "fe80::1%em0", NULL);
		text_in(h, "Neighbour AS", "nas", c->nas, "65001",
		    " inputmode=\"numeric\"");
		h_raw(h, "</div><div class=\"two\">");
		text_in(h, "Local AS", "las", c->las, "65000",
		    " inputmode=\"numeric\"");
		text_in(h, "Source address", "src", c->src, "chosen by the "
		    "route", NULL);
		h_raw(h, "</div><div class=\"two\">");
		text_in(h, "Multihop (TTL)", "mh", c->multihop, "directly "
		    "connected", " inputmode=\"numeric\"");
		h_raw(h, "<label>Password (TCP-MD5)<input type=\"password\" "
		    "name=\"pass\" autocomplete=\"new-password\"");
		h_attr(h, "value", c->pass);
		h_raw(h, "><small>On FreeBSD the kernel signs the segments: "
		    "the key goes into an SA of setkey(8) as well, for "
		    "tcp(4)'s TCP_MD5SIG.</small></label></div><div class=\""
		    "checks\">");
		check_in(h, "BFD for this session", "bfd", c->bfd);
		check_in(h, "Passive: wait to be called", "passive",
		    c->passive);
		h_raw(h, "</div>");
		for (i = 0; i < 2; i++) {
			h_fmt(h, "<fieldset><legend>");
			snprintf(n, sizeof(n), "ch%d", i);
			check_in(h, chn[i], n, c->ch[i]);
			h_raw(h, "</legend><div class=\"two\">");
			snprintf(n, sizeof(n), "imp%d", i);
			filter_in(h, "Import", n, c->imp[i], filters);
			snprintf(n, sizeof(n), "exp%d", i);
			filter_in(h, "Export", n, c->exp[i], filters);
			h_raw(h, "</div>");
			snprintf(n, sizeof(n), "nh%d", i);
			check_in(h, "Next hop self", n, c->nhself[i]);
			h_raw(h, "</fieldset>");
		}
		return;
	}
	if (strcmp(c->kind, "ospf") == 0) {
		h_fmt(h, "<div class=\"two\"><label>Version<select name=\"ver\">"
		    "<option value=\"v2\"%s>OSPFv2 (IPv4)</option><option "
		    "value=\"v3\"%s>OSPFv3</option></select></label><label>"
		    "Addresses<select name=\"chan\"><option value=\"0\"%s>IPv4"
		    "</option><option value=\"1\"%s>IPv6</option></select>"
		    "</label></div>", strcmp(c->ver, "v2") == 0 ? " selected" :
		    "", strcmp(c->ver, "v3") == 0 ? " selected" : "",
		    c->chan == 0 ? " selected" : "", c->chan == 1 ?
		    " selected" : "");
		h_raw(h, "<div class=\"two\">");
		filter_in(h, "Import", "imp0", c->imp[0], filters);
		filter_in(h, "Export", "exp0", c->exp[0], filters);
		h_raw(h, "</div>");
		text_in(h, "Area", "area", c->area, "0, or 0.0.0.1", NULL);
		h_raw(h, "<table class=\"bf-rows\"><thead><tr><th>Interface"
		    "</th><th>Cost</th><th>Type</th><th>Hello (s)</th><th>"
		    "Dead (s)</th><th>BFD</th><th>Stub</th></tr></thead>"
		    "<tbody>");
		for (i = 0; i < BF_IFS; i++) {
			const struct bfif *f = &c->ifs[i];

			h_fmt(h, "<tr><td><input name=\"if%d\" spellcheck="
			    "\"false\" placeholder=\"%s\"", i, i == 0 ? "em0, "
			    "or gif*" : "");
			h_attr(h, "value", i < c->nifs ? f->name : "");
			h_fmt(h, "></td><td><input name=\"cost%d\" inputmode="
			    "\"numeric\" placeholder=\"10\"", i);
			h_attr(h, "value", i < c->nifs ? f->cost : "");
			h_fmt(h, "></td><td><select name=\"type%d\"><option "
			    "value=\"\">by the interface</option><option "
			    "value=\"broadcast\"%s>broadcast</option><option "
			    "value=\"ptp\"%s>point-to-point</option></select>"
			    "</td>", i, i < c->nifs && strcmp(f->type,
			    "broadcast") == 0 ? " selected" : "", i < c->nifs &&
			    strcmp(f->type, "ptp") == 0 ? " selected" : "");
			h_fmt(h, "<td><input name=\"hello%d\" inputmode="
			    "\"numeric\" placeholder=\"10\"", i);
			h_attr(h, "value", i < c->nifs ? f->hello : "");
			h_fmt(h, "></td><td><input name=\"dead%d\" inputmode="
			    "\"numeric\" placeholder=\"40\"", i);
			h_attr(h, "value", i < c->nifs ? f->dead : "");
			h_fmt(h, "></td><td><input type=\"checkbox\" name="
			    "\"bfd%d\"%s></td><td><input type=\"checkbox\" "
			    "name=\"stub%d\"%s></td></tr>", i, i < c->nifs &&
			    f->bfd ? " checked" : "", i, i < c->nifs &&
			    f->stub ? " checked" : "");
		}
		h_raw(h, "</tbody></table><small>An interface is a name or a "
		    "pattern; a row left empty is none. Stub: the network is "
		    "announced, but no neighbour is looked for on it.</small>");
		return;
	}
	h_raw(h, "<table class=\"bf-rows\"><thead><tr><th>Interface</th><th>"
	    "Min rx (ms)</th><th>Min tx (ms)</th><th>Multiplier</th></tr>"
	    "</thead><tbody>");
	for (i = 0; i < BF_IFS; i++) {
		const struct bfif *f = &c->ifs[i];

		h_fmt(h, "<tr><td><input name=\"if%d\" spellcheck=\"false\" "
		    "placeholder=\"%s\"", i, i == 0 ? "em0, or *" : "");
		h_attr(h, "value", i < c->nifs ? f->name : "");
		h_fmt(h, "></td><td><input name=\"rx%d\" inputmode=\"numeric\" "
		    "placeholder=\"10\"", i);
		h_attr(h, "value", i < c->nifs ? f->rx : "");
		h_fmt(h, "></td><td><input name=\"tx%d\" inputmode=\"numeric\" "
		    "placeholder=\"100\"", i);
		h_attr(h, "value", i < c->nifs ? f->tx : "");
		h_fmt(h, "></td><td><input name=\"mult%d\" inputmode=\"numeric\""
		    " placeholder=\"5\"", i);
		h_attr(h, "value", i < c->nifs ? f->mult : "");
		h_raw(h, "></td></tr>");
	}
	h_raw(h, "</tbody></table><small>The interfaces sessions are made "
	    "on, when a protocol asks for one (BGP or OSPF with BFD on). "
	    "Empty times are BIRD's own.</small><table class=\"bf-rows\">"
	    "<thead><tr><th>Neighbour of its own</th><th>Interface</th><th>"
	    "Local address</th><th>Multihop</th></tr></thead><tbody>");
	for (i = 0; i < BF_IFS; i++) {
		const struct bfnbr *b = &c->nbrs[i];

		h_fmt(h, "<tr><td><input name=\"nb%d\" spellcheck=\"false\" "
		    "placeholder=\"%s\"", i, i == 0 ? "192.0.2.1" : "");
		h_attr(h, "value", i < c->nnbrs ? b->addr : "");
		h_fmt(h, "></td><td><input name=\"dev%d\" spellcheck=\"false\"",
		    i);
		h_attr(h, "value", i < c->nnbrs ? b->dev : "");
		h_fmt(h, "></td><td><input name=\"local%d\" spellcheck=\"false\""
		    " placeholder=\"%s\"", i, i == 0 ? "for multihop" : "");
		h_attr(h, "value", i < c->nnbrs ? b->local : "");
		h_fmt(h, "></td><td><input type=\"checkbox\" name=\"mh%d\"%s>"
		    "</td></tr>", i, i < c->nnbrs && b->multihop ? " checked" :
		    "");
	}
	h_raw(h, "</tbody></table><small>A session BIRD keeps up by itself, "
	    "with no protocol asking for it.</small>");
}

/* An address; scoped (fe80::1%em0) where allowed. */
static bool
addr_ok(const char *s, bool scoped)
{
	unsigned char	raw[16];
	char		a[64];
	const char	*pc;

	pc = strchr(s, '%');
	if (pc != NULL && (!scoped || pc[1] == '\0' || strlen(pc + 1) > 15 ||
	    pc[1 + strspn(pc + 1, "abcdefghijklmnopqrstuvwxyz0123456789._")] !=
	    '\0'))
		return (false);
	snprintf(a, sizeof(a), "%.*s", (int)(pc != NULL ? pc - s :
	    (ptrdiff_t)strlen(s)), s);
	return (inet_pton(AF_INET, a, raw) == 1 || inet_pton(AF_INET6, a,
	    raw) == 1);
}

/* A number from lo to hi, or "" where empty is allowed. */
static bool
num_ok(const char *s, long long lo, long long hi, bool empty)
{
	long long	v;

	if (s[0] == '\0')
		return (empty);
	if (s[strspn(s, "0123456789")] != '\0' || strlen(s) > 10)
		return (false);
	v = strtoll(s, NULL, 10);
	return (v >= lo && v <= hi);
}

/* An AS: a number, or a constant of the file's (define MY_AS = ...). */
static bool
as_ok(const char *s)
{

	if (isalpha((unsigned char)s[0]) || s[0] == '_')
		return (strlen(s) < 64 && s[strspn(s, "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")] == '\0');
	return (num_ok(s, 1, 4294967295LL, false));
}

static bool
ifname_ok(const char *s)
{

	return (s[0] != '\0' && strlen(s) < 32 && s[strspn(s,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	    "._-*?")] == '\0');
}

static bool
words_ok(const char *s)
{

	return (strpbrk(s, "\"\\\n\r") == NULL);
}

static bool
filter_ok(const char *s, const char *const *filters)
{
	int	i;

	if (strcmp(s, "all") == 0 || strcmp(s, "none") == 0)
		return (true);
	if (strncmp(s, "filter ", 7) != 0)
		return (false);
	for (i = 0; filters != NULL && filters[i] != NULL; i++)
		if (strcmp(s + 7, filters[i]) == 0)
			return (true);
	return (false);
}

static const char *
field(const ucl_object_t *f, const char *key)
{

	return (jstr(f, key) != NULL ? jstr(f, key) : "");
}

static void
copy(char *dst, size_t len, const char *src)
{
	const char	*e;

	/* Blanks around what was typed are not part of it. */
	while (isspace((unsigned char)*src))
		src++;
	for (e = src + strlen(src); e > src && isspace((unsigned char)e[-1]);
	    e--)
		;
	snprintf(dst, len, "%.*s", (int)(e - src), src);
}

#define	FAIL(...) do {							\
	snprintf(err, len, __VA_ARGS__);				\
	free(c);							\
	return (NULL);							\
} while (0)

/* The form as filled, checked; NULL with err said when it is not. */
struct bfconf *
bf_read(const char *kind, const ucl_object_t *f, const char *const *filters,
    char *err, size_t len)
{
	struct bfconf	*c;
	char		 k[16];
	int		 i, ch;

	c = bf_new(kind);
	copy(c->name, sizeof(c->name), field(f, "name"));
	if (c->name[0] == '\0' || isdigit((unsigned char)c->name[0]) ||
	    c->name[strspn(c->name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	    "OPQRSTUVWXYZ0123456789_")] != '\0')
		FAIL("A name is letters, digits and _, not starting with a "
		    "digit.");
	if (strcmp(kind, "bgp") == 0) {
		copy(c->desc, sizeof(c->desc), field(f, "desc"));
		copy(c->nbr, sizeof(c->nbr), field(f, "nbr"));
		copy(c->nas, sizeof(c->nas), field(f, "nas"));
		copy(c->las, sizeof(c->las), field(f, "las"));
		copy(c->src, sizeof(c->src), field(f, "src"));
		copy(c->multihop, sizeof(c->multihop), field(f, "mh"));
		snprintf(c->pass, sizeof(c->pass), "%s", field(f, "pass"));
		c->bfd = jbool(f, "bfd");
		c->passive = jbool(f, "passive");
		if (!words_ok(c->desc) || !words_ok(c->pass))
			FAIL("The description and the password take no \" "
			    "or \\.");
		if (!addr_ok(c->nbr, true))
			FAIL("The neighbour's address is an IPv4 or IPv6 "
			    "address; a link-local one with its interface, "
			    "fe80::1%%em0.");
		if (!as_ok(c->nas) || !as_ok(c->las))
			FAIL("An AS is a number from 1 to 4294967295, or a "
			    "name the file defines.");
		if (c->src[0] != '\0' && !addr_ok(c->src, false))
			FAIL("The source address is an address of this "
			    "host's.");
		if (!num_ok(c->multihop, 0, 255, true))
			FAIL("Multihop is a TTL from 1 to 255, empty for a "
			    "neighbour directly connected.");
		if (c->multihop[0] != '\0' && (strchr(c->nbr, '%') != NULL ||
		    strncasecmp(c->nbr, "fe80:", 5) == 0))
			FAIL("A link-local neighbour is directly connected: "
			    "no multihop.");
		for (ch = 0; ch < 2; ch++) {
			snprintf(k, sizeof(k), "ch%d", ch);
			c->ch[ch] = jbool(f, k);
			snprintf(k, sizeof(k), "imp%d", ch);
			snprintf(c->imp[ch], sizeof(c->imp[0]), "%s", field(f,
			    k));
			snprintf(k, sizeof(k), "exp%d", ch);
			snprintf(c->exp[ch], sizeof(c->exp[0]), "%s", field(f,
			    k));
			snprintf(k, sizeof(k), "nh%d", ch);
			c->nhself[ch] = jbool(f, k);
			if (c->ch[ch] && (!filter_ok(c->imp[ch], filters) ||
			    !filter_ok(c->exp[ch], filters)))
				FAIL("Import and export are all, none, or a "
				    "filter of the file.");
		}
		if (!c->ch[0] && !c->ch[1])
			FAIL("A session carries IPv4 routes, IPv6 routes or "
			    "both.");
		return (c);
	}
	if (strcmp(kind, "ospf") == 0) {
		snprintf(c->ver, sizeof(c->ver), "%s", strcmp(field(f, "ver"),
		    "v3") == 0 ? "v3" : "v2");
		c->chan = strcmp(field(f, "chan"), "1") == 0 ? 1 : 0;
		if (strcmp(c->ver, "v2") == 0 && c->chan == 1)
			FAIL("OSPFv2 carries IPv4 only; IPv6 is OSPFv3's.");
		snprintf(c->imp[0], sizeof(c->imp[0]), "%s", field(f, "imp0"));
		snprintf(c->exp[0], sizeof(c->exp[0]), "%s", field(f, "exp0"));
		if (!filter_ok(c->imp[0], filters) || !filter_ok(c->exp[0],
		    filters))
			FAIL("Import and export are all, none, or a filter "
			    "of the file.");
		copy(c->area, sizeof(c->area), field(f, "area"));
		if (!num_ok(c->area, 0, 4294967295LL, false)) {
			unsigned char raw[4];

			if (inet_pton(AF_INET, c->area, raw) != 1)
				FAIL("An area is a number, or four numbers "
				    "with dots: 0, 0.0.0.1.");
		}
		for (i = 0; i < BF_IFS; i++) {
			struct bfif	*x = &c->ifs[c->nifs];

			snprintf(k, sizeof(k), "if%d", i);
			copy(x->name, sizeof(x->name), field(f, k));
			if (x->name[0] == '\0')
				continue;
			if (!ifname_ok(x->name))
				FAIL("An interface is a name, or a pattern with "
				    "* and ?.");
			snprintf(k, sizeof(k), "cost%d", i);
			copy(x->cost, sizeof(x->cost), field(f, k));
			snprintf(k, sizeof(k), "type%d", i);
			copy(x->type, sizeof(x->type), field(f, k));
			snprintf(k, sizeof(k), "hello%d", i);
			copy(x->hello, sizeof(x->hello), field(f, k));
			snprintf(k, sizeof(k), "dead%d", i);
			copy(x->dead, sizeof(x->dead), field(f, k));
			snprintf(k, sizeof(k), "bfd%d", i);
			x->bfd = jbool(f, k);
			snprintf(k, sizeof(k), "stub%d", i);
			x->stub = jbool(f, k);
			if (!num_ok(x->cost, 1, 65535, true) ||
			    !num_ok(x->hello, 1, 65535, true) ||
			    !num_ok(x->dead, 1, 65535, true))
				FAIL("A cost is from 1 to 65535, hello and dead "
				    "in seconds.");
			if (x->type[0] != '\0' && strcmp(x->type,
			    "broadcast") != 0 && strcmp(x->type, "ptp") != 0)
				FAIL("A type is broadcast or point-to-point.");
			c->nifs++;
		}
		if (c->nifs == 0)
			FAIL("OSPF runs on an interface at least.");
		return (c);
	}
	for (i = 0; i < BF_IFS; i++) {
		struct bfif	*x = &c->ifs[c->nifs];

		snprintf(k, sizeof(k), "if%d", i);
		copy(x->name, sizeof(x->name), field(f, k));
		if (x->name[0] == '\0')
			continue;
		if (!ifname_ok(x->name))
			FAIL("An interface is a name, or a pattern with * "
			    "and ?.");
		snprintf(k, sizeof(k), "rx%d", i);
		copy(x->rx, sizeof(x->rx), field(f, k));
		snprintf(k, sizeof(k), "tx%d", i);
		copy(x->tx, sizeof(x->tx), field(f, k));
		snprintf(k, sizeof(k), "mult%d", i);
		copy(x->mult, sizeof(x->mult), field(f, k));
		if (!num_ok(x->rx, 1, 60000, true) || !num_ok(x->tx, 1, 60000,
		    true) || !num_ok(x->mult, 1, 255, true))
			FAIL("Intervals are milliseconds up to 60000, the "
			    "multiplier from 1 to 255.");
		c->nifs++;
	}
	for (i = 0; i < BF_IFS; i++) {
		struct bfnbr	*b = &c->nbrs[c->nnbrs];

		snprintf(k, sizeof(k), "nb%d", i);
		copy(b->addr, sizeof(b->addr), field(f, k));
		if (b->addr[0] == '\0')
			continue;
		if (!addr_ok(b->addr, false))
			FAIL("A neighbour is an IPv4 or IPv6 address.");
		snprintf(k, sizeof(k), "dev%d", i);
		copy(b->dev, sizeof(b->dev), field(f, k));
		if (b->dev[0] != '\0' && !ifname_ok(b->dev))
			FAIL("An interface is a name.");
		snprintf(k, sizeof(k), "local%d", i);
		copy(b->local, sizeof(b->local), field(f, k));
		if (b->local[0] != '\0' && !addr_ok(b->local, false))
			FAIL("A local address is an address of this host's.");
		snprintf(k, sizeof(k), "mh%d", i);
		b->multihop = jbool(f, k);
		if (b->multihop && b->local[0] == '\0')
			FAIL("A neighbour over several hops is sent to from a "
			    "local address, to be given.");
		c->nnbrs++;
	}
	if (c->nifs == 0 && c->nnbrs == 0)
		FAIL("BFD needs an interface or a neighbour.");
	return (c);
}

/* The protocol as bird reads it; to be freed. */
char *
bf_text(const struct bfconf *c)
{
	static const char *const chn[] = { "ipv4", "ipv6" };
	struct html	 h;
	const struct bfif *x;
	int		 i;

	memset(&h, 0, sizeof(h));
	if (strcmp(c->kind, "bgp") == 0) {
		h_fmt(&h, "protocol bgp %s {\n", c->name);
		if (c->desc[0] != '\0')
			h_fmt(&h, "\tdescription \"%s\";\n", c->desc);
		h_fmt(&h, "\tlocal as %s;\n\tneighbor %s as %s;\n", c->las,
		    c->nbr, c->nas);
		if (c->src[0] != '\0')
			h_fmt(&h, "\tsource address %s;\n", c->src);
		if (strcmp(c->multihop, "0") == 0)
			h_raw(&h, "\tmultihop;\n");
		else if (c->multihop[0] != '\0')
			h_fmt(&h, "\tmultihop %s;\n", c->multihop);
		if (c->pass[0] != '\0')
			h_fmt(&h, "\tauthentication md5;\n\tpassword \"%s\";\n",
			    c->pass);
		if (c->bfd)
			h_raw(&h, "\tbfd on;\n");
		if (c->passive)
			h_raw(&h, "\tpassive on;\n");
		for (i = 0; i < 2; i++) {
			if (!c->ch[i])
				continue;
			h_fmt(&h, "\t%s {\n", chn[i]);
			if (c->imp[i][0] != '\0')
				h_fmt(&h, "\t\timport %s;\n", c->imp[i]);
			if (c->exp[i][0] != '\0')
				h_fmt(&h, "\t\texport %s;\n", c->exp[i]);
			if (c->nhself[i])
				h_raw(&h, "\t\tnext hop self;\n");
			h_raw(&h, "\t};\n");
		}
	} else if (strcmp(c->kind, "ospf") == 0) {
		h_fmt(&h, "protocol ospf %s %s {\n\t%s {\n", c->ver, c->name,
		    chn[c->chan]);
		if (c->imp[0][0] != '\0')
			h_fmt(&h, "\t\timport %s;\n", c->imp[0]);
		if (c->exp[0][0] != '\0')
			h_fmt(&h, "\t\texport %s;\n", c->exp[0]);
		h_fmt(&h, "\t};\n\tarea %s {\n", c->area);
		for (i = 0; i < c->nifs; i++) {
			x = &c->ifs[i];
			if (x->cost[0] == '\0' && x->type[0] == '\0' &&
			    x->hello[0] == '\0' && x->dead[0] == '\0' &&
			    !x->bfd && !x->stub) {
				h_fmt(&h, "\t\tinterface \"%s\";\n", x->name);
				continue;
			}
			h_fmt(&h, "\t\tinterface \"%s\" {\n", x->name);
			if (x->cost[0] != '\0')
				h_fmt(&h, "\t\t\tcost %s;\n", x->cost);
			if (x->type[0] != '\0')
				h_fmt(&h, "\t\t\ttype %s;\n", x->type);
			if (x->hello[0] != '\0')
				h_fmt(&h, "\t\t\thello %s;\n", x->hello);
			if (x->dead[0] != '\0')
				h_fmt(&h, "\t\t\tdead %s;\n", x->dead);
			if (x->bfd)
				h_raw(&h, "\t\t\tbfd on;\n");
			if (x->stub)
				h_raw(&h, "\t\t\tstub yes;\n");
			h_raw(&h, "\t\t};\n");
		}
		h_raw(&h, "\t};\n");
	} else {
		h_fmt(&h, "protocol bfd %s {\n", c->name);
		for (i = 0; i < c->nifs; i++) {
			x = &c->ifs[i];
			if (x->rx[0] == '\0' && x->tx[0] == '\0' &&
			    x->mult[0] == '\0') {
				h_fmt(&h, "\tinterface \"%s\";\n", x->name);
				continue;
			}
			h_fmt(&h, "\tinterface \"%s\" {\n", x->name);
			if (x->rx[0] != '\0')
				h_fmt(&h, "\t\tmin rx interval %s ms;\n", x->rx);
			if (x->tx[0] != '\0')
				h_fmt(&h, "\t\tmin tx interval %s ms;\n", x->tx);
			if (x->mult[0] != '\0')
				h_fmt(&h, "\t\tmultiplier %s;\n", x->mult);
			h_raw(&h, "\t};\n");
		}
		for (i = 0; i < c->nnbrs; i++) {
			h_fmt(&h, "\tneighbor %s", c->nbrs[i].addr);
			if (c->nbrs[i].dev[0] != '\0')
				h_fmt(&h, " dev \"%s\"", c->nbrs[i].dev);
			if (c->nbrs[i].local[0] != '\0')
				h_fmt(&h, " local %s", c->nbrs[i].local);
			h_fmt(&h, "%s;\n", c->nbrs[i].multihop ? " multihop" :
			    "");
		}
	}
	h_raw(&h, "}");
	return (h.s);
}

/* What a list says of the protocol, short: its neighbour, its area. */
void
bf_summary(char *buf, size_t len, const struct bfconf *c)
{
	char	ifs[96];
	int	i;

	ifs[0] = '\0';
	for (i = 0; i < c->nifs; i++)
		snprintf(ifs + strlen(ifs), sizeof(ifs) - strlen(ifs), "%s%s",
		    i > 0 ? ", " : "", c->ifs[i].name);
	if (strcmp(c->kind, "bgp") == 0)
		snprintf(buf, len, "%s%s → %s %s%s%s%s", isdigit((unsigned
		    char)c->las[0]) ? "AS" : "", c->las, c->nbr,
		    isdigit((unsigned char)c->nas[0]) ? "AS" : "", c->nas, c->bfd ? " · BFD" : "", c->ch[0] && c->ch[1] ?
		    " · IPv4, IPv6" : c->ch[1] ? " · IPv6" : " · IPv4");
	else if (strcmp(c->kind, "ospf") == 0)
		snprintf(buf, len, "OSPF%s area %s · %s", c->ver, c->area, ifs);
	else
		snprintf(buf, len, "%s%s%d neighbour%s of its own", ifs,
		    ifs[0] != '\0' ? " · " : "", c->nnbrs, c->nnbrs == 1 ?
		    "" : "s");
}
