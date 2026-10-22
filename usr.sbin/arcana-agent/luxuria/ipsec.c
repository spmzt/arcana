/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: IPsec through strongSwan, by swanctl(8), IKEv2 only.  A host
 * has a key of its own, ECDSA P-256 made here, whose private half never
 * leaves it: what is told is the public half, in base64, for its peers
 * to be given.  Two hosts know each other by their keys alone, no CA
 * between them.  A connection arcana writes is a file of its own in
 * conf.d, arcana-<name>.conf, with the peer's key beside the host's in
 * pubkey/; the daemon reads them all again after each change, so what
 * is there is what runs, and is there after a boot.
 *
 * Each connection has one child of the same name: tunnel mode, or
 * transport mode for what another tunnel (gre, gif, a WireGuard port)
 * carries between the two addresses.  With a reqid it serves the
 * ipsec(4) interface made with that reqid: the interface has the
 * policies, strongSwan only the security associations (policies = no).
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "agent.h"

static char	*bio_text(struct work *, BIO *);
static ucl_object_t *model_load(struct work *, const char *);
static void	 certs_of(struct work *, const char *, ucl_object_t *);

#define	IPSEC_PROPOSALS	"aes256gcm16-prfsha384-ecp384,aes256-sha384-ecp384"
#define	ESP_PROPOSALS	"aes256gcm16-ecp384,aes256-sha384-ecp384"
#define	OWN_KEY		"pkcs8/arcana.pem"
#define	OWN_PUB		"pubkey/arcana.pub"
#define	REQID_MAX	16383	/* what ipsec(4) takes */

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	/* Replaced when there: a repeated key would make an array. */
	ucl_object_replace_key(o, v, key, 0, true);
}

static char *
sw_path(struct work *w, const char *sub)
{

	return (wfmt(w, "%s/%s", opts.swanctl_dir, sub));
}

static bool
conn_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > 32)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_')
			return (false);
	return (true);
}

static bool
addr_ok(const char *s)
{
	unsigned char	raw[16];

	return (s != NULL && (inet_pton(AF_INET, s, raw) == 1 ||
	    inet_pton(AF_INET6, s, raw) == 1));
}

static int
addr_family(const char *s)
{
	unsigned char	raw[16];

	return (inet_pton(AF_INET, s, raw) == 1 ? AF_INET : AF_INET6);
}

/* Traffic selectors as swanctl.conf(5) writes them: no more than that. */
static bool
ts_ok(const char *s)
{

	return (s[0] != '\0' && s[0] != '-' && s[strspn(s,
	    "0123456789abcdefABCDEF.:/,[]%-_ghijklmnopqrstuvwxyz")] == '\0');
}

/* An identity: one word, nothing the configuration's syntax uses. */
static bool
id_ok(const char *s)
{
	size_t	i;

	if (s[0] == '\0' || strlen(s) > 128)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isgraph((unsigned char)s[i]) || strchr("{}\"'#=,;\\",
		    s[i]) != NULL)
			return (false);
	return (true);
}

/* A certificate's file name under swanctl's x509 or x509ca: no path. */
static bool
file_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '.' || strlen(s) > 128)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("._-@", s[i]) ==
		    NULL)
			return (false);
	return (true);
}

/* A public key in base64 (DER), and what it is; NULL for none. */
static EVP_PKEY *
pubkey_of(const char *b64)
{
	EVP_PKEY		*k;
	const unsigned char	*p;
	unsigned char		*der;
	size_t			 len;
	int			 n;

	len = strlen(b64);
	if (len == 0 || len % 4 != 0 || len > 1024 || b64[strspn(b64,
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")]
	    != '\0')
		return (NULL);
	if ((der = malloc(len)) == NULL)
		return (NULL);
	if ((n = EVP_DecodeBlock(der, (const unsigned char *)b64,
	    (int)len)) <= 0) {
		free(der);
		return (NULL);
	}
	/* What padding the decoder counted as bytes is not the key's. */
	n -= (b64[len - 1] == '=') + (b64[len - 2] == '=');
	p = der;
	k = d2i_PUBKEY(NULL, &p, n);
	free(der);
	return (k);
}

/* NULL when the job may run, or what is wrong with it. */
const char *
ipsec_check(const struct arc_job_spec *sp)
{
	EVP_PKEY	*k;
	int		 ways;

	if (sp->verb == NULL)
		return ("ipsec: say init, start, conn, unconn, child, unchild, "
		    "up or down");
	if (strcmp(sp->verb, "init") == 0 || strcmp(sp->verb, "start") == 0)
		return (NULL);
	if (strcmp(sp->verb, "conn") != 0 && strcmp(sp->verb, "unconn") !=
	    0 && strcmp(sp->verb, "child") != 0 && strcmp(sp->verb,
	    "unchild") != 0 && strcmp(sp->verb, "up") != 0 && strcmp(sp->verb,
	    "down") != 0)
		return ("ipsec: say init, start, conn, unconn, child, unchild, "
		    "up or down");
	if (!conn_ok(sp->conn))
		return ("ipsec: a connection is named with letters, digits, - "
		    "and _, 32 at most");
	if (strcmp(sp->verb, "child") == 0 || strcmp(sp->verb, "unchild") ==
	    0) {
		if (!conn_ok(sp->child))
			return ("ipsec: a child is named with letters, digits, "
			    "- and _, 32 at most");
		if (strcmp(sp->verb, "unchild") == 0)
			return (NULL);
		if (sp->ipsec_mode == NULL)
			return ("ipsec: a child's mode is tunnel or transport");
	} else if (strcmp(sp->verb, "conn") != 0)
		return (NULL);
	if (strcmp(sp->verb, "conn") == 0) {
		if (!addr_ok(sp->tunnel_local) || !addr_ok(sp->tunnel_remote))
			return ("ipsec: a connection is between two addresses, "
			    "tunnel-local and tunnel-remote");
		if (addr_family(sp->tunnel_local) != addr_family(
		    sp->tunnel_remote))
			return ("ipsec: both addresses are IPv4, or both IPv6");
		/* How the peer is known: one way of the three. */
		ways = (sp->pubkey != NULL) + (sp->remote_cert != NULL) +
		    (sp->remote_ca != NULL);
		if (ways != 1)
			return ("ipsec: the peer is known one way: its public "
			    "key (pubkey), its certificate in x509 "
			    "(remote-cert), or the CA in x509ca that signed it "
			    "(remote-ca)");
		if (sp->pubkey != NULL) {
			if ((k = pubkey_of(sp->pubkey)) == NULL)
				return ("ipsec: the peer's public key, in "
				    "base64, as its host tells it");
			EVP_PKEY_free(k);
		}
		if ((sp->remote_cert != NULL && !file_ok(sp->remote_cert)) ||
		    (sp->remote_ca != NULL && !file_ok(sp->remote_ca)) ||
		    (sp->local_cert != NULL && !file_ok(sp->local_cert)))
			return ("ipsec: a certificate is named by its file in "
			    "swanctl's x509 or x509ca, without a path");
		if (sp->remote_ca != NULL && (sp->remote_id == NULL ||
		    sp->remote_id[0] == '\0'))
			return ("ipsec: with a CA, the peer's identity "
			    "(remote-id) says which certificate of the CA's is "
			    "the peer's");
		if ((sp->local_id != NULL && !id_ok(sp->local_id)) ||
		    (sp->remote_id != NULL && !id_ok(sp->remote_id)))
			return ("ipsec: an identity is one word, without "
			    "quotes, braces, =, # or ;");
		if (sp->ipsec_mode == NULL)
			return (NULL);	/* the connection alone, its children kept */
	}
	if (strcmp(sp->ipsec_mode, "tunnel") != 0 && strcmp(sp->ipsec_mode,
	    "transport") != 0)
		return ("ipsec: the mode is tunnel or transport");
	if ((sp->local_ts != NULL && !ts_ok(sp->local_ts)) ||
	    (sp->remote_ts != NULL && !ts_ok(sp->remote_ts)))
		return ("ipsec: traffic selectors are networks, with commas, "
		    "each with a protocol or a port in [ ] if need be");
	if (sp->has_reqid && (sp->reqid < 1 || sp->reqid > REQID_MAX))
		return ("ipsec: a reqid is from 1 to 16383");
	if (sp->has_reqid && strcmp(sp->ipsec_mode, "tunnel") != 0)
		return ("ipsec: an ipsec(4) interface's connection is in "
		    "tunnel mode");
	if (sp->start_action != NULL && strcmp(sp->start_action, "start") !=
	    0 && strcmp(sp->start_action, "trap") != 0 &&
	    strcmp(sp->start_action, "none") != 0)
		return ("ipsec: start-action is start, trap or none");
	return (NULL);
}

static int
swanctl(struct work *w, struct execres *res, const char *a, const char *b,
    const char *c, const char *d, const char *e)
{
	char	*argv[8];
	int	 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.swanctl_bin;
	argv[n++] = (char *)(uintptr_t)a;
	if (b != NULL)
		argv[n++] = (char *)(uintptr_t)b;
	if (c != NULL)
		argv[n++] = (char *)(uintptr_t)c;
	if (d != NULL)
		argv[n++] = (char *)(uintptr_t)d;
	if (e != NULL)
		argv[n++] = (char *)(uintptr_t)e;
	argv[n] = NULL;
	return (run_exec(w, argv, res));
}

/* swanctl could not reach the daemon: it is not running. */
static bool
not_running(const struct execres *res)
{

	return ((res->err != NULL && strstr(res->err, "connecting to") !=
	    NULL) || (res->out != NULL && strstr(res->out, "connecting to") !=
	    NULL));
}

/* A section of named sections as an array, each with its name. */
static ucl_object_t *
named(const ucl_object_t *o)
{
	ucl_object_t		*arr, *cur;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		cur = ucl_object_copy(v);
		if (ucl_object_lookup(cur, "name") == NULL)
			put(cur, "name", ucl_object_fromstring(ucl_object_key(v)));
		ucl_array_append(arr, cur);
	}
	return (arr);
}

/*
 * One "--pretty" listing: sections "name {", "key = value", lists
 * "key = [" a line each "]".  The top sections named event are its
 * answers: what each holds is appended to arr, with its name, and its
 * section kids (children, child-sas) as the array "children".
 */
static void
pretty(struct work *w, const char *out, const char *event, ucl_object_t *arr,
    const char *kids)
{
	ucl_object_t		*stack[16], *o, *list, *items, *cur;
	const ucl_object_t	*k;
	ucl_object_iter_t	 it;
	char			*text, *line, *eq, *key, *val, *end;
	int			 depth;

	text = wstrdup(w, out != NULL ? out : "");
	depth = 0;
	list = NULL;
	while ((line = strsep(&text, "\n")) != NULL) {
		line += strspn(line, " \t");
		end = line + strlen(line);
		while (end > line && isspace((unsigned char)end[-1]))
			*--end = '\0';
		if (line[0] == '\0')
			continue;
		if (list != NULL) {
			if (strcmp(line, "]") == 0)
				list = NULL;
			else
				ucl_array_append(list,
				    ucl_object_fromstring(line));
			continue;
		}
		if (strcmp(line, "}") == 0) {
			if (depth == 0)
				continue;
			o = stack[--depth];
			if (depth > 0)
				continue;
			/* An answer: what it holds, each with its name. */
			if (ucl_object_lookup(o, "\x01") != NULL && strcmp(
			    ucl_object_tostring_forced(ucl_object_lookup(o,
			    "\x01")), event) == 0) {
				ucl_object_delete_key(o, "\x01");
				items = named(o);
				it = NULL;
				while ((cur = (ucl_object_t *)(uintptr_t)
				    ucl_object_iterate(items, &it, true)) !=
				    NULL) {
					k = ucl_object_lookup(cur, kids);
					list = k != NULL ? named(k) :
					    ucl_object_typed_new(UCL_ARRAY);
					ucl_object_delete_key(cur, kids);
					put(cur, "children", list);
					list = NULL;
					ucl_array_append(arr, ucl_object_ref(
					    cur));
				}
				ucl_object_unref(items);
			}
			ucl_object_unref(o);
			continue;
		}
		if (end[-1] == '{') {
			*--end = '\0';
			while (end > line && end[-1] == ' ')
				*--end = '\0';
			if (depth == (int)nitems(stack))
				return;
			o = ucl_object_typed_new(UCL_OBJECT);
			if (depth == 0)
				put(o, "\x01", ucl_object_fromstring(line));
			else
				ucl_object_insert_key(stack[depth - 1], o, line,
				    0, true);
			stack[depth++] = o;
			continue;
		}
		if (depth == 0 || (eq = strstr(line, " = ")) == NULL)
			continue;
		*eq = '\0';
		key = line;
		val = eq + 3;
		if (strcmp(val, "[") == 0) {
			list = ucl_object_typed_new(UCL_ARRAY);
			put(stack[depth - 1], key, list);
		} else if (strcmp(val, "[]") == 0)
			put(stack[depth - 1], key, ucl_object_typed_new(
			    UCL_ARRAY));
		else if (val[0] != '\0' && val[strspn(val, "0123456789")] ==
		    '\0' && strlen(val) < 19 && strstr(key, "spi") == NULL)
			put(stack[depth - 1], key, ucl_object_fromint(
			    strtoll(val, NULL, 10)));
		else
			put(stack[depth - 1], key, ucl_object_fromstring(val));
	}
	/* Cut short: what was open is let go. */
	while (depth > 0)
		ucl_object_unref(stack[--depth]);
}

/* The host's own public key, in base64; NULL when it has none. */
static char *
own_pub(struct work *w)
{
	char	*pem, *b, *p, *q;

	if ((pem = scope_slurp(w, sw_path(w, OWN_PUB), NULL)) == NULL ||
	    (p = strstr(pem, "-----BEGIN PUBLIC KEY-----")) == NULL ||
	    (q = strstr(p, "-----END PUBLIC KEY-----")) == NULL)
		return (NULL);
	p += strlen("-----BEGIN PUBLIC KEY-----");
	b = wmalloc(w, (size_t)(q - p) + 1);
	for (q = b; *p != '-'; p++)
		if (!isspace((unsigned char)*p))
			*q++ = *p;
	*q = '\0';
	return (b);
}

/*
 * Has the kernel IPsec: built in, or the module loaded?  It is the
 * host's: a jail cannot load it, and has it only when the host does.
 */
static bool
in_kernel(void)
{

	return (feature_present("ipsec") || modfind("ipsec") != -1);
}

/*
 * {"running", "kernel", "public-key", "connections": [{"name", "version",
 * "local_addrs", "remote_addrs", "local-id", "remote-id", "arcana",
 * "children": [{"name", "mode", "local-ts", "remote-ts", ...}]}],
 * "sas": [{"name", "state", "local-host", "remote-host", ...,
 * "children": [{"name", "state", "mode", "reqid", "bytes-in", ...}]}]}
 */
int
do_ipsec(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres		 res;
	ucl_object_t		*top, *conns, *sas, *certs;
	const ucl_object_t	*c, *side;
	ucl_object_iter_t	 it;
	unsigned char		*json;
	const char		*name;
	char			*pub;
	bool			 running;

	rsp->has_ok = true;
	rsp->ok = false;
	running = true;
	conns = ucl_object_typed_new(UCL_ARRAY);
	sas = ucl_object_typed_new(UCL_ARRAY);
	if (swanctl(w, &res, "--list-conns", "--pretty", NULL, NULL, NULL) !=
	    0) {
		if (!not_running(&res)) {
			ucl_object_unref(conns);
			ucl_object_unref(sas);
			if ((rsp->error = scope_missing(w, &res, "swanctl(8)",
			    "strongswan")) == NULL)
				rsp->error = wtext(w, exec_error(w, &res,
				    "swanctl"));
			return (0);
		}
		running = false;
	} else {
		pretty(w, res.out, "list-conn event", conns, "children");
		if (swanctl(w, &res, "--list-sas", "--pretty", NULL, NULL,
		    NULL) == 0)
			pretty(w, res.out, "list-sa event", sas, "child-sas");
	}
	/* Who each side is, and whether arcana wrote it. */
	it = NULL;
	while ((c = ucl_object_iterate(conns, &it, true)) != NULL) {
		if ((side = ucl_object_lookup(c, "local-1")) != NULL &&
		    ucl_object_lookup(side, "id") != NULL)
			put((ucl_object_t *)(uintptr_t)c, "local-id",
			    ucl_object_copy(ucl_object_lookup(side, "id")));
		if ((side = ucl_object_lookup(c, "remote-1")) != NULL &&
		    ucl_object_lookup(side, "id") != NULL)
			put((ucl_object_t *)(uintptr_t)c, "remote-id",
			    ucl_object_copy(ucl_object_lookup(side, "id")));
		name = ucl_object_tostring(ucl_object_lookup(c, "name"));
		put((ucl_object_t *)(uintptr_t)c, "arcana",
		    ucl_object_frombool(name != NULL && conn_ok(name) &&
		    scope_slurp(w, sw_path(w, wfmt(w, "conf.d/arcana-%s.conf",
		    name)), NULL) != NULL));
	}
	/* What arcana knows of its own: how the peer is known, and the
	 * children as it wrote them. */
	it = NULL;
	while ((c = ucl_object_iterate(conns, &it, true)) != NULL) {
		ucl_object_t	*m;

		if (!ucl_object_toboolean(ucl_object_lookup(c, "arcana")) ||
		    (m = model_load(w, ucl_object_tostring(ucl_object_lookup(c,
		    "name")))) == NULL)
			continue;
		(void)ucl_object_delete_key(m, "local");
		(void)ucl_object_delete_key(m, "remote");
		put((ucl_object_t *)(uintptr_t)c, "model", m);
	}
	certs = ucl_object_typed_new(UCL_ARRAY);
	certs_of(w, "x509", certs);
	certs_of(w, "x509ca", certs);
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "running", ucl_object_frombool(running));
	put(top, "kernel", ucl_object_frombool(in_kernel()));
	if ((pub = own_pub(w)) != NULL)
		put(top, "public-key", ucl_object_fromstring(pub));
	put(top, "certificates", certs);
	put(top, "connections", conns);
	put(top, "sas", sas);
	put(top, "now", ucl_object_fromint(time(NULL)));
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "the connections are more than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* A certificate's name, one line as RFC 2253 writes it. */
static char *
name_text(struct work *w, X509_NAME *n)
{
	BIO	*b;
	char	*t;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return (wstrdup(w, ""));
	X509_NAME_print_ex(b, n, 0, XN_FLAG_RFC2253);
	t = bio_text(w, b);
	BIO_free(b);
	return (t);
}

/*
 * The certificates in swanctl's x509 (hosts', this one's and its
 * peers') and x509ca (the CAs), each PEM file's first: its file, where,
 * subject, issuer, when it is valid from and until, its names (SAN),
 * whether it is a CA, and its SHA-256 fingerprint.
 */
static void
certs_of(struct work *w, const char *dir, ucl_object_t *arr)
{
	DIR		*d;
	struct dirent	*e;
	X509		*x;
	BIO		*b;
	GENERAL_NAMES	*sans;
	ucl_object_t	*o, *names;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen, i;
	char		*text, fp[EVP_MAX_MD_SIZE * 3 + 1], *p;
	struct tm	 tm;
	int		 fd, k;

	if ((fd = scope_dirfd(w, sw_path(w, dir))) == -1)
		return;
	if ((d = fdopendir(fd)) == NULL) {
		close(fd);
		return;
	}
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.' || e->d_type == DT_DIR)
			continue;
		if ((text = scope_slurp(w, sw_path(w, wfmt(w, "%s/%s", dir,
		    e->d_name)), NULL)) == NULL)
			continue;
		if ((b = BIO_new_mem_buf(text, -1)) == NULL)
			continue;
		x = PEM_read_bio_X509(b, NULL, NULL, NULL);
		BIO_free(b);
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "file", ucl_object_fromstring(e->d_name));
		put(o, "where", ucl_object_fromstring(dir));
		if (x == NULL) {
			put(o, "error", ucl_object_fromstring("not a "
			    "certificate in PEM"));
			ucl_array_append(arr, o);
			continue;
		}
		put(o, "subject", ucl_object_fromstring(name_text(w,
		    X509_get_subject_name(x))));
		put(o, "issuer", ucl_object_fromstring(name_text(w,
		    X509_get_issuer_name(x))));
		if (ASN1_TIME_to_tm(X509_get0_notBefore(x), &tm) == 1)
			put(o, "not_before", ucl_object_fromint(timegm(&tm)));
		if (ASN1_TIME_to_tm(X509_get0_notAfter(x), &tm) == 1)
			put(o, "not_after", ucl_object_fromint(timegm(&tm)));
		put(o, "ca", ucl_object_frombool(X509_check_ca(x) > 0));
		put(o, "self_signed", ucl_object_frombool(X509_NAME_cmp(
		    X509_get_subject_name(x), X509_get_issuer_name(x)) == 0));
		names = ucl_object_typed_new(UCL_ARRAY);
		if ((sans = X509_get_ext_d2i(x, NID_subject_alt_name, NULL,
		    NULL)) != NULL) {
			for (k = 0; k < sk_GENERAL_NAME_num(sans); k++) {
				GENERAL_NAME	*g = sk_GENERAL_NAME_value(sans, k);
				char		 ip[64];

				if (g->type == GEN_DNS || g->type == GEN_EMAIL)
					ucl_array_append(names,
					    ucl_object_fromlstring((const char *)
					    ASN1_STRING_get0_data(g->d.ia5),
					    (size_t)ASN1_STRING_length(
					    g->d.ia5)));
				else if (g->type == GEN_IPADD && (
				    ASN1_STRING_length(g->d.ip) == 4 ||
				    ASN1_STRING_length(g->d.ip) == 16) &&
				    inet_ntop(ASN1_STRING_length(g->d.ip) == 4 ?
				    AF_INET : AF_INET6, ASN1_STRING_get0_data(
				    g->d.ip), ip, sizeof(ip)) != NULL)
					ucl_array_append(names,
					    ucl_object_fromstring(ip));
			}
			GENERAL_NAMES_free(sans);
		}
		put(o, "names", names);
		if (X509_digest(x, EVP_sha256(), md, &mdlen) == 1) {
			for (i = 0, p = fp; i < mdlen; i++)
				p += snprintf(p, sizeof(fp) - (size_t)(p - fp),
				    "%s%02x", i > 0 ? ":" : "", md[i]);
			put(o, "sha256", ucl_object_fromstring(fp));
		}
		X509_free(x);
		ucl_array_append(arr, o);
	}
	closedir(d);
}

/* What a BIO holds, as text of w's. */
static char *
bio_text(struct work *w, BIO *b)
{
	char	*p;
	long	 n;

	n = BIO_get_mem_data(b, &p);
	return (n > 0 ? wstrndup(w, p, (size_t)n) : NULL);
}

/*
 * The host's key: made when it has none, ECDSA P-256, the private half
 * mode 0600 where swanctl reads PKCS#8 keys; the public half beside
 * what peers' keys are, written again from the private one.
 */
static int
own_key(struct work *w, const char **errp)
{
	EVP_PKEY	*k;
	BIO		*b;
	char		*pem, *key;
	int		 step, rc;

	k = NULL;
	if ((key = scope_slurp(w, sw_path(w, OWN_KEY), NULL)) != NULL) {
		if ((b = BIO_new_mem_buf(key, -1)) != NULL) {
			k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
			BIO_free(b);
		}
		explicit_bzero(key, strlen(key));
		if (k == NULL) {
			*errp = wfmt(w, "%s is not a key", sw_path(w, OWN_KEY));
			return (-1);
		}
	} else {
		step = step_begin(w, ARC_STEP_KIND_FILE, "private key", "made %s, "
		    "ECDSA P-256", w->jail != NULL ? "in the jail" :
		    "on this host");
		k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
		pem = NULL;
		if (k != NULL && (b = BIO_new(BIO_s_mem())) != NULL) {
			if (PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL,
			    NULL) == 1)
				pem = bio_text(w, b);
			BIO_free(b);
		}
		rc = pem != NULL ? scope_replace(w, sw_path(w, OWN_KEY), pem,
		    strlen(pem), 0600, NULL) : -1;
		if (pem != NULL)
			explicit_bzero(pem, strlen(pem));
		step_end(w, step, rc == 0, rc == 0 ? NULL : "%s", pem == NULL ?
		    "no key could be made" : strerror(errno));
		if (rc != 0) {
			EVP_PKEY_free(k);
			*errp = wfmt(w, "%s: %s", sw_path(w, OWN_KEY), pem ==
			    NULL ? "no key could be made" : strerror(errno));
			return (-1);
		}
	}
	pem = NULL;
	if ((b = BIO_new(BIO_s_mem())) != NULL) {
		if (PEM_write_bio_PUBKEY(b, k) == 1)
			pem = bio_text(w, b);
		BIO_free(b);
	}
	EVP_PKEY_free(k);
	if (pem == NULL || scope_replace(w, sw_path(w, OWN_PUB), pem,
	    strlen(pem), 0644, NULL) != 0) {
		*errp = wfmt(w, "%s: %s", sw_path(w, OWN_PUB), pem == NULL ?
		    "no public key" : strerror(errno));
		return (-1);
	}
	return (0);
}

/* base64 as PEM: its lines of 64 between the armour. */
static char *
pem_of(struct work *w, const char *b64)
{
	char	*s;
	size_t	 i, n;

	n = strlen(b64);
	s = wstrdup(w, "-----BEGIN PUBLIC KEY-----\n");
	for (i = 0; i < n; i += 64)
		s = wfmt(w, "%s%.64s\n", s, b64 + i);
	return (wfmt(w, "%s-----END PUBLIC KEY-----\n", s));
}

static const char *
then(const char *start)
{

	/* After a peer is lost, or the SA closed: as it was started. */
	if (start == NULL || strcmp(start, "trap") == 0)
		return ("trap");
	return (strcmp(start, "start") == 0 ? "start" : "none");
}

/*
 * A connection as arcana keeps it beside its file, conf.d/
 * arcana-<conn>.json: the two addresses and identities, how the peer
 * is known (its key, its certificate, or a CA), this host's
 * certificate when it has one, and its children, each with its mode,
 * traffic, reqid and how it starts.  The .conf is made from it.
 */
static ucl_object_t *
model_load(struct work *w, const char *conn)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			*text;

	if ((text = scope_slurp(w, sw_path(w, wfmt(w,
	    "conf.d/arcana-%s.json", conn)), NULL)) == NULL)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	if (o != NULL && ucl_object_type(o) != UCL_OBJECT) {
		ucl_object_unref(o);
		o = NULL;
	}
	if (o != NULL && ucl_object_lookup(o, "children") == NULL)
		put(o, "children", ucl_object_typed_new(UCL_OBJECT));
	return (o);
}

static void
model_str(ucl_object_t *m, const char *key, const char *v)
{

	if (v != NULL && v[0] != '\0')
		put(m, key, ucl_object_fromstring(v));
	else
		(void)ucl_object_delete_key(m, key);
}

/* A child as the spec says it, into the model under its name. */
static void
model_child(ucl_object_t *m, const char *name, const struct arc_job_spec *sp)
{
	ucl_object_t	*c, *kids;

	kids = (ucl_object_t *)(uintptr_t)ucl_object_lookup(m, "children");
	c = ucl_object_typed_new(UCL_OBJECT);
	put(c, "mode", ucl_object_fromstring(sp->ipsec_mode));
	model_str(c, "local_ts", sp->local_ts);
	model_str(c, "remote_ts", sp->remote_ts);
	if (sp->has_reqid)
		put(c, "reqid", ucl_object_fromint(sp->reqid));
	model_str(c, "start", sp->start_action != NULL ? sp->start_action :
	    "trap");
	(void)ucl_object_delete_key(kids, name);
	ucl_object_insert_key(kids, c, name, 0, true);
}

static const char *
mstr(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, key)) != NULL && ucl_object_type(v)
	    == UCL_STRING ? ucl_object_tostring(v) : NULL);
}

/* The connection's file, as arcana writes it from the model. */
static char *
conn_text(struct work *w, const char *conn, const ucl_object_t *m)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	const char		*lts, *rts, *start, *local, *remote, *kids;
	bool			 iface;

	local = mstr(m, "local");
	remote = mstr(m, "remote");
	kids = "";
	it = NULL;
	while ((c = ucl_object_iterate(ucl_object_lookup(m, "children"), &it,
	    true)) != NULL) {
		iface = ucl_object_lookup(c, "reqid") != NULL;
		start = mstr(c, "start") != NULL ? mstr(c, "start") : "trap";
		lts = mstr(c, "local_ts") != NULL ? mstr(c, "local_ts") : iface ?
		    "0.0.0.0/0,::/0" : NULL;
		rts = mstr(c, "remote_ts") != NULL ? mstr(c, "remote_ts") :
		    iface ? "0.0.0.0/0,::/0" : NULL;
		kids = wfmt(w, "%s"
		    "\t\t\t%s {\n"
		    "\t\t\t\tmode = %s\n"
		    "%s%s%s%s"
		    "\t\t\t\tesp_proposals = " ESP_PROPOSALS "\n"
		    "\t\t\t\tstart_action = %s\n"
		    "\t\t\t\tdpd_action = %s\n"
		    "\t\t\t\tclose_action = %s\n"
		    "\t\t\t}\n", kids, ucl_object_key(c), mstr(c, "mode"),
		    iface ? wfmt(w, "\t\t\t\treqid = %jd\n\t\t\t\tpolicies = no\n",
		    (intmax_t)ucl_object_toint(ucl_object_lookup(c, "reqid"))) :
		    "", lts != NULL ? wfmt(w, "\t\t\t\tlocal_ts = %s\n", lts) :
		    "", rts != NULL ? wfmt(w, "\t\t\t\tremote_ts = %s\n", rts) :
		    "", "", start, strcmp(start, "none") == 0 ? "clear" :
		    then(start), strcmp(start, "none") == 0 ? "none" :
		    then(start));
	}
	return (wfmt(w,
	    "# Written by arcana-agent (ipsec conn %s): changed by it, and\n"
	    "# taken away by ipsec unconn; its children by ipsec child and\n"
	    "# unchild.  IKEv2 only.\n"
	    "connections {\n"
	    "\t%s {\n"
	    "\t\tversion = 2\n"
	    "\t\tlocal_addrs = %s\n"
	    "\t\tremote_addrs = %s\n"
	    "\t\tproposals = " IPSEC_PROPOSALS "\n"
	    "\t\tdpd_delay = 10s\n"
	    "\t\tlocal {\n"
	    "\t\t\tauth = pubkey\n"
	    "\t\t\t%s = %s\n"
	    "\t\t\tid = %s\n"
	    "\t\t}\n"
	    "\t\tremote {\n"
	    "\t\t\tauth = pubkey\n"
	    "\t\t\t%s = %s\n"
	    "\t\t\tid = %s\n"
	    "\t\t}\n"
	    "\t\tchildren {\n"
	    "%s"
	    "\t\t}\n"
	    "\t}\n"
	    "}\n",
	    conn, conn, local, remote,
	    mstr(m, "local_cert") != NULL ? "certs" : "pubkeys",
	    mstr(m, "local_cert") != NULL ? mstr(m, "local_cert") :
	    "arcana.pub",
	    mstr(m, "local_id") != NULL ? mstr(m, "local_id") : local,
	    mstr(m, "remote_cert") != NULL ? "certs" : mstr(m, "remote_ca") !=
	    NULL ? "cacerts" : "pubkeys",
	    mstr(m, "remote_cert") != NULL ? mstr(m, "remote_cert") : mstr(m,
	    "remote_ca") != NULL ? mstr(m, "remote_ca") : wfmt(w,
	    "arcana-%s.pub", conn),
	    mstr(m, "remote_id") != NULL ? mstr(m, "remote_id") : remote,
	    kids));
}

/* The daemon reads conf.d again: what was taken out is unloaded. */
static int
reload(struct work *w, const char **errp)
{
	struct execres	res;

	if (swanctl(w, &res, "--load-all", "--noprompt", NULL, NULL, NULL) ==
	    0)
		return (0);
	*errp = not_running(&res) ? "strongSwan is not running: start the "
	    "strongswan service first" : wtext(w, exec_error(w, &res,
	    "swanctl --load-all"));
	return (-1);
}

/* A file put back as it was: from its copy, or gone if it was not. */
static void
put_back(struct work *w, const char *path, const char *keep, bool had)
{
	const char	*base;

	base = strrchr(path, '/') + 1;
	if (had)
		(void)scope_rename(w, path, keep, base);
	else
		(void)scope_rename(w, path, base, NULL);
}

/*
 * The model written, and the .conf made from it; the daemon reads
 * conf.d again, and both files go back as they were if it refuses.
 */
static int
model_write(struct work *w, const char *conn, const ucl_object_t *m,
    const char **errp)
{
	const char	*conf, *json, *text, *e;
	unsigned char	*emitted;
	bool		 had_conf, had_json;
	int		 step;

	conf = sw_path(w, wfmt(w, "conf.d/arcana-%s.conf", conn));
	json = sw_path(w, wfmt(w, "conf.d/arcana-%s.json", conn));
	had_conf = scope_slurp(w, conf, NULL) != NULL;
	had_json = scope_slurp(w, json, NULL) != NULL;
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", conf);
	emitted = ucl_object_emit(m, UCL_EMIT_JSON_COMPACT);
	text = emitted != NULL ? wtext(w, wadopt(w, emitted)) : "{}";
	if (scope_replace(w, json, text, strlen(text), 0644, wfmt(w,
	    ".arcana-%s.json.was", conn)) != 0) {
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", json, strerror(errno));
		return (-1);
	}
	text = conn_text(w, conn, m);
	if (scope_replace(w, conf, text, strlen(text), 0644, wfmt(w,
	    ".arcana-%s.conf.was", conn)) != 0) {
		e = strerror(errno);
		put_back(w, json, wfmt(w, ".arcana-%s.json.was", conn),
		    had_json);
		step_end(w, step, false, "%s", e);
		*errp = wfmt(w, "%s: %s", conf, e);
		return (-1);
	}
	step_end(w, step, true, NULL);
	if (reload(w, errp) == 0)
		return (0);
	/* Refused: the files as they were, and read again. */
	put_back(w, conf, wfmt(w, ".arcana-%s.conf.was", conn), had_conf);
	put_back(w, json, wfmt(w, ".arcana-%s.json.was", conn), had_json);
	e = NULL;
	(void)reload(w, &e);
	return (-1);
}

/* A certificate named is one in swanctl's x509 or x509ca. */
static bool
cert_there(struct work *w, const char *dir, const char *file)
{

	return (file == NULL || scope_slurp(w, sw_path(w, wfmt(w, "%s/%s",
	    dir, file)), NULL) != NULL);
}

static int
do_conn(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	ucl_object_t	*m;
	const char	*pub, *text;
	bool		 had_pub;
	int		 rc;

	if (!cert_there(w, "x509", sp->local_cert) || !cert_there(w, "x509",
	    sp->remote_cert) || !cert_there(w, "x509ca", sp->remote_ca)) {
		*errp = wfmt(w, "%s is not in swanctl's %s", sp->remote_ca !=
		    NULL && !cert_there(w, "x509ca", sp->remote_ca) ?
		    sp->remote_ca : !cert_there(w, "x509", sp->local_cert) ?
		    sp->local_cert : sp->remote_cert, sp->remote_ca != NULL &&
		    !cert_there(w, "x509ca", sp->remote_ca) ? "x509ca" :
		    "x509");
		return (-1);
	}
	/* As it was, its children kept; the connection's own anew. */
	if ((m = model_load(w, sp->conn)) == NULL) {
		m = ucl_object_typed_new(UCL_OBJECT);
		put(m, "children", ucl_object_typed_new(UCL_OBJECT));
	}
	model_str(m, "local", sp->tunnel_local);
	model_str(m, "remote", sp->tunnel_remote);
	model_str(m, "local_id", sp->local_id);
	model_str(m, "remote_id", sp->remote_id);
	model_str(m, "local_cert", sp->local_cert);
	model_str(m, "remote_cert", sp->remote_cert);
	model_str(m, "remote_ca", sp->remote_ca);
	put(m, "pubkey", ucl_object_frombool(sp->pubkey != NULL));
	/* With a mode, a child of the connection's name, as before. */
	if (sp->ipsec_mode != NULL)
		model_child(m, sp->conn, sp);
	pub = sw_path(w, wfmt(w, "pubkey/arcana-%s.pub", sp->conn));
	had_pub = scope_slurp(w, pub, NULL) != NULL;
	if (sp->pubkey != NULL) {
		text = pem_of(w, sp->pubkey);
		if (scope_replace(w, pub, text, strlen(text), 0644, wfmt(w,
		    ".arcana-%s.pub.was", sp->conn)) != 0) {
			*errp = wfmt(w, "%s: %s", pub, strerror(errno));
			ucl_object_unref(m);
			return (-1);
		}
	} else if (had_pub)
		(void)scope_rename(w, pub, strrchr(pub, '/') + 1, NULL);
	rc = model_write(w, sp->conn, m, errp);
	if (rc != 0 && sp->pubkey != NULL)
		put_back(w, pub, wfmt(w, ".arcana-%s.pub.was", sp->conn),
		    had_pub);
	ucl_object_unref(m);
	return (rc);
}

/* A child of a connection arcana wrote: added or changed, or gone. */
static int
do_child(struct work *w, const struct arc_job_spec *sp, bool remove,
    const char **errp)
{
	ucl_object_t	*m;
	int		 rc;

	if ((m = model_load(w, sp->conn)) == NULL) {
		*errp = wfmt(w, "no connection %s of arcana's: ipsec conn "
		    "makes one", sp->conn);
		return (-1);
	}
	if (remove) {
		if (ucl_object_lookup(ucl_object_lookup(m, "children"),
		    sp->child) == NULL) {
			*errp = wfmt(w, "connection %s has no child %s",
			    sp->conn, sp->child);
			ucl_object_unref(m);
			return (-1);
		}
		(void)ucl_object_delete_key((ucl_object_t *)(uintptr_t)
		    ucl_object_lookup(m, "children"), sp->child);
	} else
		model_child(m, sp->child, sp);
	rc = model_write(w, sp->conn, m, errp);
	ucl_object_unref(m);
	return (rc);
}

static int
do_unconn(struct work *w, const char *conn, const char **errp)
{
	struct execres	 res;
	const char	*conf, *pub;
	int		 step;
	bool		 ok;

	/* Its SAs end first: unloaded, a connection leaves them up. */
	(void)swanctl(w, &res, "--terminate", "--ike", conn, "--force",
	    NULL);
	conf = sw_path(w, wfmt(w, "conf.d/arcana-%s.conf", conn));
	pub = sw_path(w, wfmt(w, "pubkey/arcana-%s.pub", conn));
	step = step_begin(w, ARC_STEP_KIND_FILE, "remove", "%s, %s", conf,
	    pub);
	ok = (scope_rename(w, conf, strrchr(conf, '/') + 1, NULL) == 0 ||
	    errno == ENOENT);
	conf = sw_path(w, wfmt(w, "conf.d/arcana-%s.json", conn));
	ok = (scope_rename(w, conf, strrchr(conf, '/') + 1, NULL) == 0 ||
	    errno == ENOENT) && ok;
	ok = (scope_rename(w, pub, strrchr(pub, '/') + 1, NULL) == 0 ||
	    errno == ENOENT) && ok;
	step_end(w, step, ok, ok ? NULL : "%s", strerror(errno));
	if (!ok) {
		*errp = wfmt(w, "%s: %s", conf, strerror(errno));
		return (-1);
	}
	return (reload(w, errp));
}

/*
 * The daemon started, there or in the jail w works in (whose own rc.d
 * script it is, run in it), whether it is enabled or not.
 */
static int
start_daemon(struct work *w, const char **errp)
{
	struct execres	 res;
	char		*argv[6];
	int		 n;

	if (swanctl(w, &res, "--stats", NULL, NULL, NULL, NULL) == 0)
		return (0);
	n = 0;
	if (w->jail != NULL) {
		argv[n++] = (char *)(uintptr_t)opts.jexec_bin;
		argv[n++] = wfmt(w, "%d", w->jid);
	}
	argv[n++] = (char *)(uintptr_t)opts.service_bin;
	argv[n++] = (char *)(uintptr_t)"strongswan";
	argv[n++] = (char *)(uintptr_t)"onestart";
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "service strongswan"));
		return (-1);
	}
	return (0);
}

int
do_ipsec_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres	res;

	if ((*errp = ipsec_check(sp)) != NULL)
		return (-1);
	if (strcmp(sp->verb, "init") == 0) {
		if (own_key(w, errp) != 0)
			return (-1);
		/* Read now, when the daemon runs; else when it starts. */
		if (swanctl(w, &res, "--load-creds", "--noprompt", NULL, NULL,
		    NULL) != 0 && !not_running(&res)) {
			*errp = wtext(w, exec_error(w, &res,
			    "swanctl --load-creds"));
			return (-1);
		}
		if (sp->persist && rc_set(w, "strongswan_enable", "=", "YES",
		    errp) != 0)
			return (-1);
		return (0);
	}
	if (strcmp(sp->verb, "start") == 0)
		return (start_daemon(w, errp));
	if (strcmp(sp->verb, "conn") == 0)
		return (do_conn(w, sp, errp));
	if (strcmp(sp->verb, "unconn") == 0)
		return (do_unconn(w, sp->conn, errp));
	if (strcmp(sp->verb, "child") == 0 || strcmp(sp->verb, "unchild") == 0)
		return (do_child(w, sp, strcmp(sp->verb, "unchild") == 0, errp));
	if (strcmp(sp->verb, "up") == 0) {
		if (swanctl(w, &res, "--initiate", "--child", sp->conn,
		    "--timeout", "20") != 0) {
			*errp = not_running(&res) ? "strongSwan is not "
			    "running" : wtext(w, exec_error(w, &res,
			    "swanctl --initiate"));
			return (-1);
		}
		return (0);
	}
	if (swanctl(w, &res, "--terminate", "--ike", sp->conn, "--timeout",
	    "10") != 0) {
		*errp = not_running(&res) ? "strongSwan is not running" :
		    wtext(w, exec_error(w, &res, "swanctl --terminate"));
		return (-1);
	}
	return (0);
}

/*
 * A safe change to a connection: the files it is made of, for the
 * snapshot taken before and put back after, and what the daemon is
 * then told.
 */
void
ipsec_conn_files(struct work *w, const char *conn, const char **confp,
    const char **jsonp, const char **pubp)
{

	*confp = sw_path(w, wfmt(w, "conf.d/arcana-%s.conf", conn));
	*jsonp = sw_path(w, wfmt(w, "conf.d/arcana-%s.json", conn));
	*pubp = sw_path(w, wfmt(w, "pubkey/arcana-%s.pub", conn));
}

/*
 * The files are back as they were: the daemon reads conf.d again, after
 * the SAs of a connection that was not there before are ended (loaded,
 * it may have started them; unloaded, it would leave them up).
 */
int
ipsec_undo(struct work *w, const char *conn, bool was_new, const char **errp)
{
	struct execres	res;

	if (was_new)
		(void)swanctl(w, &res, "--terminate", "--ike", conn, "--force",
		    NULL);
	return (reload(w, errp));
}

/* up undone is down, and down up. */
int
ipsec_toggle(struct work *w, const char *conn, bool up, const char **errp)
{
	struct execres	res;

	if (swanctl(w, &res, up ? "--initiate" : "--terminate", up ? "--child" :
	    "--ike", conn, "--timeout", up ? "20" : "10") != 0) {
		*errp = not_running(&res) ? "strongSwan is not running" :
		    wtext(w, exec_error(w, &res, up ? "swanctl --initiate" :
		    "swanctl --terminate"));
		return (-1);
	}
	return (0);
}
