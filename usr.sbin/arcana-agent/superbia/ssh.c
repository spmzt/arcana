/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the base system's sshd(8), of the host or of a jail.  What
 * it is set to, as sshd -T says (or as its file has it, where sshd
 * cannot say); its banner; its host keys, each with its fingerprint and
 * the certificate a CA key signed for it; and who may sign in, each
 * user with the keys in their authorized_keys.  Keys and certificates
 * are read here, not by ssh-keygen: a fingerprint is the SHA-256 of
 * the key's blob, as OpenSSH prints it.
 *
 * A change to sshd_config is read by sshd -t before it is put in place,
 * the file before it kept beside it (sshd_config.arcana-before), and
 * sshd reloaded; in safe mode, that file is put back unless the change
 * is confirmed.  A CA key given to sign the host keys is on the disk
 * only while ssh-keygen reads it, in /etc/ssh, readable by root alone.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <ucl.h>

#include "agent.h"

#define	SSH_DIR		"/etc/ssh"
#define	SSHD_CONFIG	SSH_DIR "/sshd_config"
#define	BEFORE		"sshd_config.arcana-before"
#define	BANNER		SSH_DIR "/banner"
#define	USER_CAS	SSH_DIR "/trusted_user_ca_keys"
#define	TEXT_MAX	(64 * 1024)

/* What is read of sshd -T, and what may be set from here. */
static const char *const shown[] = {
	"port", "listenaddress", "permitrootlogin", "passwordauthentication",
	"kbdinteractiveauthentication", "pubkeyauthentication", "allowusers",
	"allowgroups", "denyusers", "denygroups", "maxauthtries", "banner",
	"x11forwarding", "authorizedkeysfile", "trustedusercakeys",
	"hostkey", "hostcertificate",
};
static const struct {
	const char	*name;
	const char	*values;	/* those it takes, | between; NULL: names */
	bool		 many;
} settable[] = {
	{ "AllowUsers", NULL, true },
	{ "AllowGroups", NULL, true },
	{ "DenyUsers", NULL, true },
	{ "DenyGroups", NULL, true },
	{ "PermitRootLogin", "yes|no|prohibit-password|forced-commands-only",
	    false },
	{ "PasswordAuthentication", "yes|no", false },
	{ "KbdInteractiveAuthentication", "yes|no", false },
	{ "PubkeyAuthentication", "yes|no", false },
	{ "X11Forwarding", "yes|no", false },
	{ "MaxAuthTries", "#", false },
	{ "Port", "#", true },
};

/* The tests' sshd, as certctl's: its files beside them. */
static const char *
root(struct work *w)
{
	char	abs[MAXPATHLEN];

	if (w->jail != NULL || opts.tools_dir == NULL)
		return ("");
	if (realpath(opts.tools_dir, abs) == NULL)
		snprintf(abs, sizeof(abs), "%s", opts.tools_dir);
	return (wfmt(w, "%s/sshroot", abs));
}

static const char *
at(struct work *w, const char *path)
{

	return (wfmt(w, "%s%s", root(w), path));
}

/* --- keys, as OpenSSH writes them ------------------------------------ */

struct blob {
	const unsigned char	*p;
	size_t			 n;
};

static bool
b_u32(struct blob *b, uint32_t *v)
{

	if (b->n < 4)
		return (false);
	*v = (uint32_t)b->p[0] << 24 | (uint32_t)b->p[1] << 16 |
	    (uint32_t)b->p[2] << 8 | b->p[3];
	b->p += 4;
	b->n -= 4;
	return (true);
}

static bool
b_u64(struct blob *b, uint64_t *v)
{
	uint32_t	hi, lo;

	if (!b_u32(b, &hi) || !b_u32(b, &lo))
		return (false);
	*v = (uint64_t)hi << 32 | lo;
	return (true);
}

static bool
b_str(struct blob *b, struct blob *s)
{
	uint32_t	len;

	if (!b_u32(b, &len) || len > b->n)
		return (false);
	s->p = b->p;
	s->n = len;
	b->p += len;
	b->n -= len;
	return (true);
}

static unsigned char *
unbase64(struct work *w, const char *s, size_t len, size_t *np)
{
	unsigned char	*out;
	int		 n;
	size_t		 pad;

	if (len == 0 || len % 4 != 0)
		return (NULL);
	out = wmalloc(w, len / 4 * 3 + 1);
	if ((n = EVP_DecodeBlock(out, (const unsigned char *)s, (int)len)) < 0)
		return (NULL);
	for (pad = 0; pad < 2 && s[len - 1 - pad] == '='; pad++)
		;
	*np = (size_t)n - pad;
	return (out);
}

/* SHA256:..., as ssh-keygen -l prints it. */
static const char *
fingerprint(struct work *w, const unsigned char *p, size_t n)
{
	unsigned char	md[SHA256_DIGEST_LENGTH];
	char		b64[64], *e;

	SHA256(p, n, md);
	EVP_EncodeBlock((unsigned char *)b64, md, sizeof(md));
	if ((e = strchr(b64, '=')) != NULL)
		*e = '\0';
	return (wfmt(w, "SHA256:%s", b64));
}

static int
mpint_bits(const struct blob *m)
{
	size_t	i;
	int	bits;
	unsigned char	c;

	for (i = 0; i < m->n && m->p[i] == 0; i++)
		;
	if (i == m->n)
		return (0);
	bits = (int)(m->n - i - 1) * 8;
	for (c = m->p[i]; c != 0; c >>= 1)
		bits++;
	return (bits);
}

/* The size of a key whose blob, past its type, is b. */
static int
key_bits(const char *type, struct blob *b)
{
	struct blob	e, n;

	if (strstr(type, "mldsa") != NULL)
		return (0);		/* a hybrid: no one size */
	if (strstr(type, "ed25519") != NULL)
		return (256);
	if (strstr(type, "nistp256") != NULL)
		return (256);
	if (strstr(type, "nistp384") != NULL)
		return (384);
	if (strstr(type, "nistp521") != NULL)
		return (521);
	if (strncmp(type, "ssh-rsa", 7) == 0 && b_str(b, &e) && b_str(b, &n))
		return (mpint_bits(&n));
	if (strncmp(type, "ssh-dss", 7) == 0)
		return (1024);
	return (0);
}

/* The key's own fields in a certificate, passed over. */
static bool
skip_key(const char *base, struct blob *b)
{
	struct blob	s;
	int		i, n;

	n = strstr(base, "ed25519") != NULL ? 1 : strstr(base, "ecdsa") !=
	    NULL ? 2 : strncmp(base, "ssh-rsa", 7) == 0 ? 2 :
	    strncmp(base, "ssh-dss", 7) == 0 ? 4 : -1;
	if (n < 0)
		return (false);
	if (strncmp(base, "sk-", 3) == 0)
		n++;			/* its application */
	for (i = 0; i < n; i++)
		if (!b_str(b, &s))
			return (false);
	return (true);
}

/*
 * A line of a .pub, an authorized_keys or a -cert.pub: [options] type
 * base64 [comment].  Its object, NULL for one that is none.
 */
static ucl_object_t *
key_obj(struct work *w, const char *line)
{
	static const char *const types[] = { "ssh-", "ecdsa-", "sk-" };
	ucl_object_t	*o, *c, *pr;
	struct blob	 b, t, s, p;
	const char	*l, *opt, *type, *b64, *cm;
	unsigned char	*raw;
	uint64_t	 serial, after, before;
	uint32_t	 ctype;
	size_t		 i, n, olen, tlen, blen;
	bool		 quoted, cert;

	l = line + strspn(line, " \t");
	if (*l == '\0' || *l == '#')
		return (NULL);
	opt = NULL;
	olen = 0;
	for (i = 0; i < nitems(types); i++)
		if (strncmp(l, types[i], strlen(types[i])) == 0)
			break;
	if (i == nitems(types)) {
		/* Options first: up to the first blank not in quotes. */
		quoted = false;
		for (opt = l; *l != '\0' && (quoted || (*l != ' ' && *l !=
		    '\t')); l++) {
			if (*l == '\\' && l[1] != '\0')
				l++;
			else if (*l == '"')
				quoted = !quoted;
		}
		olen = (size_t)(l - opt);
		l += strspn(l, " \t");
	}
	type = l;
	tlen = strcspn(l, " \t");
	l += tlen;
	l += strspn(l, " \t");
	b64 = l;
	blen = strcspn(l, " \t\r\n");
	l += blen;
	l += strspn(l, " \t");
	cm = l;
	if (tlen == 0 || blen == 0 || (raw = unbase64(w, b64, blen, &n)) ==
	    NULL)
		return (NULL);
	b.p = raw;
	b.n = n;
	if (!b_str(&b, &t) || t.n != tlen || memcmp(t.p, type, tlen) != 0)
		return (NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	type = wstrndup(w, type, tlen);
	cert = strstr(type, "-cert-v01@openssh.com") != NULL;
	ucl_object_insert_key(o, ucl_object_fromstring(type), "type", 0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(fingerprint(w, raw, n)),
	    "fingerprint", 0, false);
	if (opt != NULL)
		ucl_object_insert_key(o, ucl_object_fromlstring(opt, olen),
		    "options", 0, false);
	if (*cm != '\0')
		ucl_object_insert_key(o, ucl_object_fromlstring(cm, strcspn(cm,
		    "\r\n")), "comment", 0, false);
	if (!cert) {
		ucl_object_insert_key(o, ucl_object_fromint(key_bits(type, &b)),
		    "bits", 0, false);
		return (o);
	}
	/* A certificate: the key it is of, then what was signed. */
	if (!b_str(&b, &s) || !skip_key(type, &b) || !b_u64(&b, &serial) ||
	    !b_u32(&b, &ctype))
		return (o);
	c = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(c, ucl_object_fromint((int64_t)serial), "serial",
	    0, false);
	ucl_object_insert_key(c, ucl_object_fromstring(ctype == 2 ? "host" :
	    "user"), "kind", 0, false);
	if (b_str(&b, &s))
		ucl_object_insert_key(c, ucl_object_fromlstring((const char *)
		    s.p, s.n), "id", 0, false);
	pr = ucl_object_typed_new(UCL_ARRAY);
	if (b_str(&b, &s)) {
		while (b_str(&s, &p))
			ucl_array_append(pr, ucl_object_fromlstring((const char *)
			    p.p, p.n));
	}
	ucl_object_insert_key(c, pr, "principals", 0, false);
	if (b_u64(&b, &after) && b_u64(&b, &before)) {
		ucl_object_insert_key(c, ucl_object_fromint((int64_t)after),
		    "valid_after", 0, false);
		/* Forever is all ones. */
		ucl_object_insert_key(c, ucl_object_fromint(before >
		    (uint64_t)INT64_MAX ? -1 : (int64_t)before),
		    "valid_before", 0, false);
	}
	if (b_str(&b, &s) && b_str(&b, &s) && b_str(&b, &s) && b_str(&b, &s))
		ucl_object_insert_key(c, ucl_object_fromstring(fingerprint(w,
		    s.p, s.n)), "ca", 0, false);
	ucl_object_insert_key(o, c, "certificate", 0, false);
	return (o);
}

/* Each key of a file of them, one a line. */
static ucl_object_t *
keys_of(struct work *w, const char *text)
{
	ucl_object_t	*arr, *k;
	const char	*l, *e;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (l = text; l != NULL && *l != '\0'; l = *e != '\0' ? e + 1 :
	    NULL) {
		e = l + strcspn(l, "\n");
		if ((k = key_obj(w, wstrndup(w, l, (size_t)(e - l)))) != NULL)
			ucl_array_append(arr, k);
	}
	return (arr);
}

/* --- sshd's settings ------------------------------------------------- */

static bool
is_shown(const char *k)
{
	size_t	i;

	for (i = 0; i < nitems(shown); i++)
		if (strcmp(k, shown[i]) == 0)
			return (true);
	return (false);
}

static void
setting_put(ucl_object_t *top, const char *k, const char *v)
{
	ucl_object_t	*a;

	if ((a = (ucl_object_t *)(uintptr_t)ucl_object_lookup(top, k)) ==
	    NULL) {
		a = ucl_object_typed_new(UCL_ARRAY);
		ucl_object_insert_key(top, a, k, 0, true);
	}
	ucl_array_append(a, ucl_object_fromstring(v));
}

/* "key value", lower-cased keys, into settings; Match blocks left. */
static void
settings_of(struct work *w, const char *text, ucl_object_t *set,
    bool file)
{
	const char	*l, *e;
	char		*line, *k, *v;
	size_t		 i;

	for (l = text; l != NULL && *l != '\0'; l = *e != '\0' ? e + 1 :
	    NULL) {
		e = l + strcspn(l, "\n");
		line = wstrndup(w, l, (size_t)(e - l));
		k = line + strspn(line, " \t");
		if (*k == '#' || *k == '\0')
			continue;
		v = k + strcspn(k, " \t=");
		if (*v != '\0')
			*v++ = '\0';
		v += strspn(v, " \t=");
		v[strcspn(v, "\r")] = '\0';
		for (i = 0; k[i] != '\0'; i++)
			k[i] = (char)tolower((unsigned char)k[i]);
		if (file && strcmp(k, "match") == 0)
			break;
		if (!is_shown(k))
			continue;
		/* In the file, the first says (but for lists, each). */
		if (file && ucl_object_lookup(set, k) != NULL &&
		    strcmp(k, "hostkey") != 0 && strcmp(k, "hostcertificate") !=
		    0 && strcmp(k, "port") != 0 && strcmp(k, "listenaddress") !=
		    0 && strncmp(k, "allow", 5) != 0 && strncmp(k, "deny", 4) !=
		    0)
			continue;
		setting_put(set, k, v);
	}
}

static const char *
first(const ucl_object_t *set, const char *k)
{
	const ucl_object_t	*a;

	if ((a = ucl_object_lookup(set, k)) == NULL || ucl_array_size(a) == 0)
		return (NULL);
	return (ucl_object_tostring(ucl_array_find_index(a, 0)));
}

/* Is value one of the setting's? */
static bool
listed(const ucl_object_t *set, const char *k, const char *value)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(set, k), &it, true)) !=
	    NULL)
		if (strcmp(ucl_object_tostring(v), value) == 0)
			return (true);
	return (false);
}

/* sshd -T, or what the file says where sshd cannot say. */
static ucl_object_t *
settings(struct work *w, const char **whyp)
{
	struct execres	 res;
	ucl_object_t	*set;
	const char	*prog;
	char		*argv[5], *text;

	set = ucl_object_typed_new(UCL_OBJECT);
	*whyp = NULL;
	if ((prog = tool(w, "sshd")) != NULL) {
		argv[0] = (char *)(uintptr_t)prog;
		argv[1] = (char *)(uintptr_t)"-T";
		argv[2] = (char *)(uintptr_t)"-f";
		argv[3] = (char *)(uintptr_t)at(w, SSHD_CONFIG);
		argv[4] = NULL;
		if (run_exec(w, scope_jexec(w, argv), &res) == 0 && res.out !=
		    NULL) {
			settings_of(w, res.out, set, false);
			return (set);
		}
		*whyp = res.errlen > 0 ? wstrndup(w, res.err, strcspn(res.err,
		    "\r\n")) : "sshd -T said nothing";
	} else
		*whyp = "there is no sshd here";
	if ((text = scope_slurp(w, at(w, SSHD_CONFIG), NULL)) != NULL)
		settings_of(w, text, set, true);
	if (ucl_object_lookup(set, "hostkey") == NULL) {
		setting_put(set, "hostkey", SSH_DIR "/ssh_host_rsa_key");
		setting_put(set, "hostkey", SSH_DIR "/ssh_host_ecdsa_key");
		setting_put(set, "hostkey", SSH_DIR "/ssh_host_ed25519_key");
	}
	return (set);
}

/* --- users ----------------------------------------------------------- */

struct pwent {
	const char	*name, *home, *shell;
	uid_t		 uid;
	gid_t		 gid;
};

/* Those of passwd who may sign in: root, and the people. */
static size_t
users(struct work *w, struct pwent **vp)
{
	struct pwent	*v;
	const char	*l, *e;
	char		*line, *f[7], *p;
	size_t		 n, cap;
	int		 i;

	*vp = NULL;
	n = cap = 0;
	v = NULL;
	for (l = scope_slurp(w, at(w, "/etc/passwd"), NULL); l != NULL &&
	    *l != '\0'; l = *e != '\0' ? e + 1 : NULL) {
		e = l + strcspn(l, "\n");
		line = wstrndup(w, l, (size_t)(e - l));
		if (line[0] == '#')
			continue;
		for (i = 0, p = line; i < 7; i++) {
			f[i] = p;
			p += strcspn(p, ":");
			if (*p == '\0' && i < 6)
				break;
			if (*p != '\0')
				*p++ = '\0';
		}
		if (i < 7 || f[0][0] == '\0' || f[0][0] == '+' || f[0][0] == '-')
			continue;
		if (strstr(f[6], "nologin") != NULL || strstr(f[6], "/false") !=
		    NULL || (atoi(f[2]) != 0 && atoi(f[2]) < 1000) ||
		    atoi(f[2]) == 65534)
			continue;
		if (n == cap) {
			struct pwent	*nv;

			cap = cap == 0 ? 16 : cap * 2;
			nv = wcalloc(w, cap, sizeof(*nv));
			if (n > 0)
				memcpy(nv, v, n * sizeof(*v));
			v = nv;
		}
		v[n].name = f[0];
		v[n].uid = (uid_t)atoi(f[2]);
		v[n].gid = (gid_t)atoi(f[3]);
		v[n].home = f[5];
		v[n].shell = f[6];
		n++;
	}
	*vp = v;
	return (n);
}

/* A path with no part that is empty, . or .. after its first /. */
static bool
plain_path(const char *p)
{
	const char	*e;
	size_t		 n;

	if (*p == '/')
		p++;
	if (*p == '\0')
		return (true);
	for (; ; p = e + 1) {
		e = p + strcspn(p, "/");
		n = (size_t)(e - p);
		if (n == 0 || (n == 1 && p[0] == '.') || (n == 2 && p[0] ==
		    '.' && p[1] == '.'))
			return (false);
		if (*e == '\0')
			return (true);
	}
}

/* The user's authorized_keys, by AuthorizedKeysFile's first. */
static const char *
akeys_path(struct work *w, const struct pwent *u, const ucl_object_t *set)
{
	const char	*f, *s;
	char		*out;
	size_t		 len;

	f = first(set, "authorizedkeysfile");
	if (f == NULL || f[0] == '\0' || strcasecmp(f, "none") == 0)
		f = ".ssh/authorized_keys";
	len = strcspn(f, " \t");
	/* What a jail's passwd and sshd say is the jail's: the path is
	 * made a piece at a time, as long as it comes out. */
	out = f[0] != '/' && f[0] != '%' ? wfmt(w, "%s/", u->home) : wstrdup(w, "");
	for (s = f; (size_t)(s - f) < len && strlen(out) < MAXPATHLEN; s++) {
		if (*s == '%' && (size_t)(s - f) + 1 < len) {
			s++;
			if (*s == 'h')
				out = wfmt(w, "%s%s", out, u->home);
			else if (*s == 'u')
				out = wfmt(w, "%s%s", out, u->name);
			else if (*s == '%')
				out = wfmt(w, "%s%%", out);
		} else
			out = wfmt(w, "%s%c", out, *s);
	}
	return (strlen(out) < MAXPATHLEN ? out : NULL);
}

/* --- the read -------------------------------------------------------- */

void
do_ssh(struct work *w, struct arc_ssh_rsp *rsp)
{
	ucl_object_t		*top, *set, *hk, *k, *ul, *u, *ks;
	const ucl_object_t	*a, *v;
	ucl_object_iter_t	 it;
	struct pwent		*pw;
	const char		*why, *p, *b;
	char			*text, *json;
	size_t			 n, i;

	top = ucl_object_typed_new(UCL_OBJECT);
	set = settings(w, &why);
	ucl_object_insert_key(top, ucl_object_fromstring(SSHD_CONFIG),
	    "config", 0, false);
	if (why != NULL)
		ucl_object_insert_key(top, ucl_object_fromstring(why),
		    "settings_from_file", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(scope_slurp(w, at(w,
	    SSH_DIR "/" BEFORE), NULL) != NULL), "before_kept", 0, false);
	/* The banner's text. */
	b = first(set, "banner");
	if (b != NULL && strcasecmp(b, "none") != 0 && (text = scope_slurp(w,
	    at(w, b), &n)) != NULL && n <= TEXT_MAX)
		ucl_object_insert_key(top, ucl_object_fromlstring(text, n),
		    "banner_text", 0, false);
	/* Each host key, its fingerprint and its certificate. */
	hk = ucl_object_typed_new(UCL_ARRAY);
	a = ucl_object_lookup(set, "hostkey");
	it = NULL;
	while ((v = ucl_object_iterate(a, &it, true)) != NULL) {
		p = ucl_object_tostring(v);
		if ((text = scope_slurp(w, at(w, wfmt(w, "%s.pub", p)), NULL)) ==
		    NULL || (k = key_obj(w, text)) == NULL)
			continue;
		ucl_object_insert_key(k, ucl_object_fromstring(p), "path", 0,
		    false);
		if ((text = scope_slurp(w, at(w, wfmt(w, "%s-cert.pub", p)),
		    NULL)) != NULL && (ks = key_obj(w, text)) != NULL) {
			ucl_object_insert_key(k, ucl_object_ref(
			    (ucl_object_t *)(uintptr_t)ucl_object_lookup(ks,
			    "certificate")), "certificate", 0, false);
			ucl_object_insert_key(k, ucl_object_frombool(listed(set,
			    "hostcertificate", wfmt(w, "%s-cert.pub", p))),
			    "certificate_used", 0, false);
			ucl_object_unref(ks);
		}
		ucl_array_append(hk, k);
	}
	ucl_object_insert_key(top, hk, "host_keys", 0, false);
	/* Who may sign in, and with which keys. */
	ul = ucl_object_typed_new(UCL_ARRAY);
	n = users(w, &pw);
	for (i = 0; i < n; i++) {
		u = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(u, ucl_object_fromstring(pw[i].name),
		    "name", 0, false);
		ucl_object_insert_key(u, ucl_object_fromint(pw[i].uid), "uid",
		    0, false);
		ucl_object_insert_key(u, ucl_object_fromstring(pw[i].home),
		    "home", 0, false);
		ucl_object_insert_key(u, ucl_object_fromstring(pw[i].shell),
		    "shell", 0, false);
		p = akeys_path(w, &pw[i], set);
		ucl_object_insert_key(u, ucl_object_fromstring(p != NULL ? p :
		    ""), "keys_file", 0, false);
		/* Only a plain path is read: no part of it .. or . */
		text = p != NULL && p[0] == '/' && plain_path(p) ?
		    scope_slurp(w, at(w, p), NULL) : NULL;
		ucl_object_insert_key(u, keys_of(w, text), "keys", 0, false);
		ucl_array_append(ul, u);
	}
	ucl_object_insert_key(top, ul, "users", 0, false);
	/* The CA keys whose user certificates are taken. */
	if ((p = first(set, "trustedusercakeys")) != NULL && strcasecmp(p,
	    "none") != 0 && (text = scope_slurp(w, at(w, p), &n)) != NULL) {
		ucl_object_insert_key(top, keys_of(w, text), "user_cas", 0,
		    false);
		if (n <= TEXT_MAX)
			ucl_object_insert_key(top, ucl_object_fromlstring(text,
			    n), "user_cas_text", 0, false);
	}
	ucl_object_insert_key(top, set, "settings", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	rsp->json = json != NULL ? wtext(w, wstrdup(w, json)) : NULL;
	free(json);
	ucl_object_unref(top);
	rsp->ok = rsp->json != NULL;
	if (!rsp->ok)
		rsp->error = "sshd was not read";
}

/* --- changes --------------------------------------------------------- */

static bool
word_ok(const char *s, const char *extra)
{

	if (s == NULL || s[0] == '\0' || strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr(extra, *s) == NULL)
			return (false);
	return (true);
}

static int
settable_of(const char *name)
{
	size_t	i;

	for (i = 0; name != NULL && i < nitems(settable); i++)
		if (strcasecmp(name, settable[i].name) == 0)
			return ((int)i);
	return (-1);
}

static bool
value_ok(int i, const char *v)
{
	const char	*p, *e;
	size_t		 n;
	long		 l;
	char		*end;

	if (settable[i].values == NULL)
		return (word_ok(v, "._-@*?!%:/"));
	if (strcmp(settable[i].values, "#") == 0) {
		l = strtol(v, &end, 10);
		return (*v != '\0' && *end == '\0' && l >= 1 && l <= 65535);
	}
	n = strlen(v);
	for (p = settable[i].values; *p != '\0'; p = *e != '\0' ? e + 1 : e) {
		e = p + strcspn(p, "|");
		if ((size_t)(e - p) == n && strncmp(p, v, n) == 0)
			return (true);
	}
	return (false);
}

const char *
ssh_check(const struct arc_job_spec *sp)
{
	size_t	i;
	int	k;

	if (sp->verb == NULL)
		return ("ssh: a verb, banner, user-cas, set, authorize, "
		    "unauthorize or sign");
	if (strcmp(sp->verb, "banner") == 0) {
		if (sp->text != NULL && strlen(sp->text) > TEXT_MAX)
			return ("ssh: a banner of 64 KiB at most");
		return (NULL);
	}
	if (strcmp(sp->verb, "user-cas") == 0) {
		if (sp->text != NULL && strlen(sp->text) > TEXT_MAX)
			return ("ssh: the CA keys, 64 KiB at most");
		if (sp->text != NULL && strstr(sp->text, "PRIVATE KEY") != NULL)
			return ("ssh: the CAs' public keys, not a private one");
		return (NULL);
	}
	if (strcmp(sp->verb, "set") == 0) {
		if ((k = settable_of(sp->path)) < 0)
			return ("ssh: set is of AllowUsers, AllowGroups, "
			    "DenyUsers, DenyGroups, PermitRootLogin, "
			    "PasswordAuthentication, KbdInteractiveAuthentication, "
			    "PubkeyAuthentication, X11Forwarding, MaxAuthTries or "
			    "Port");
		if (sp->names.n == 0 && (strcmp(settable[k].name, "Port") == 0 ||
		    settable[k].values != NULL))
			return ("ssh: a value, or (for a list of names) none to "
			    "take the line away");
		if (sp->names.n > 1 && !settable[k].many)
			return ("ssh: that one takes one value");
		for (i = 0; i < sp->names.n; i++)
			if (!value_ok(k, sp->names.v[i]))
				return (settable[k].values == NULL ? "ssh: a name "
				    "or pattern of letters, digits and ._-@*?!%:/" :
				    strcmp(settable[k].values, "#") == 0 ? "ssh: a "
				    "number" : "ssh: a value it takes");
		return (NULL);
	}
	if (strcmp(sp->verb, "options") == 0) {
		/* A key's options changed: its fingerprint, and the
		 * options as authorized_keys has them (none: empty). */
		if (!word_ok(sp->user, "._-"))
			return ("ssh: a user's name");
		if (sp->safe)
			return ("ssh: a key is not taken back by itself: not in "
			    "safe mode");
		if (sp->names.n != 1 || strncmp(sp->names.v[0], "SHA256:", 7) !=
		    0)
			return ("ssh: the key's fingerprint, SHA256:...");
		if (sp->text != NULL && (strpbrk(sp->text, "\r\n") != NULL ||
		    strlen(sp->text) > 8192))
			return ("ssh: options are one line, as authorized_keys "
			    "has them: principals=\"a,b\",from=\"10.0.0.0/8\"");
		return (NULL);
	}
	if (strcmp(sp->verb, "authorize") == 0 || strcmp(sp->verb,
	    "unauthorize") == 0) {
		if (!word_ok(sp->user, "._-"))
			return ("ssh: a user's name");
		if (sp->safe)
			return ("ssh: a key is not taken back by itself: not in "
			    "safe mode");
		if (sp->text == NULL || sp->text[0] == '\0' || strchr(sp->text,
		    '\n') != NULL || strlen(sp->text) > 16384)
			return (strcmp(sp->verb, "authorize") == 0 ? "ssh: a key, "
			    "one line of authorized_keys" : "ssh: the key's "
			    "fingerprint, SHA256:...");
		if (strcmp(sp->verb, "unauthorize") == 0 && strncmp(sp->text,
		    "SHA256:", 7) != 0)
			return ("ssh: the key's fingerprint, SHA256:...");
		return (NULL);
	}
	if (strcmp(sp->verb, "sign") == 0) {
		if (sp->text == NULL || strstr(sp->text, "PRIVATE KEY") == NULL)
			return ("ssh: the CA's private key, as ssh-keygen wrote "
			    "it");
		/* None would be a certificate for any name at all. */
		if (sp->names.n == 0)
			return ("ssh: the names clients reach it by, one at "
			    "least: a certificate for none is good for any");
		for (i = 0; i < sp->names.n; i++)
			if (!word_ok(sp->names.v[i], "._-*"))
				return ("ssh: a principal is a host's name");
		return (NULL);
	}
	return ("ssh: a verb, banner, user-cas, set, authorize, unauthorize "
	    "or sign");
}

/*
 * text with key's lines (those before any Match) taken out, and with
 * value, the line "key value" where the first was, or before the first
 * Match, or at the end.  With add, the others are left, and the line is
 * only added when none says the same.
 */
static char *
conf_edit(struct work *w, const char *text, const char *key,
    const char *value, bool add)
{
	const char	*l, *e, *k;
	char		*out, *line;
	size_t		 o, klen;
	bool		 inmatch, put;

	out = wmalloc(w, strlen(text) + strlen(key) + (value != NULL ?
	    strlen(value) : 0) + 4);
	o = 0;
	inmatch = put = false;
	klen = strlen(key);
	line = value != NULL ? wfmt(w, "%s %s\n", key, value) : NULL;
	for (l = text; *l != '\0'; l = e) {
		e = l + strcspn(l, "\n");
		if (*e == '\n')
			e++;
		k = l + strspn(l, " \t");
		if (!inmatch && strncasecmp(k, "match", 5) == 0 && (k[5] == ' ' ||
		    k[5] == '\t')) {
			inmatch = true;
			if (line != NULL && !put) {
				o += (size_t)sprintf(out + o, "%s", line);
				put = true;
			}
		}
		if (!inmatch && strncasecmp(k, key, klen) == 0 && (k[klen] ==
		    ' ' || k[klen] == '\t' || k[klen] == '=')) {
			if (add) {
				if (line != NULL && strncmp(k + klen + strspn(k +
				    klen, " \t="), value, strlen(value)) == 0) {
					put = true;
				}
			} else {
				if (line != NULL && !put) {
					o += (size_t)sprintf(out + o, "%s", line);
					put = true;
				}
				continue;
			}
		}
		memcpy(out + o, l, (size_t)(e - l));
		o += (size_t)(e - l);
	}
	if (line != NULL && !put) {
		if (o > 0 && out[o - 1] != '\n')
			out[o++] = '\n';
		o += (size_t)sprintf(out + o, "%s", line);
	}
	out[o] = '\0';
	return (out);
}

/*
 * sshd reloaded where it runs, enabled in rc.conf or not (reload alone
 * says it cannot and exits 0); one that does not run is left.
 */
static int
reload(struct work *w, const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"sshd";
	argv[2] = (char *)(uintptr_t)"onereload";
	argv[3] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) == 0)
		return (0);
	if ((res.err != NULL && strstr(res.err, "not running") != NULL) ||
	    (res.out != NULL && strstr(res.out, "not running") != NULL))
		return (0);
	*errp = wtext(w, exec_error(w, &res, "service sshd onereload"));
	return (-1);
}

/* text as sshd_config, once sshd -t has read it, and sshd reloaded. */
static int
conf_put(struct work *w, const char *text, const char **errp)
{
	struct execres	 res;
	const char	*prog, *check;
	char		*argv[5];
	int		 rc;

	if ((prog = tool(w, "sshd")) == NULL) {
		*errp = "there is no sshd here";
		return (-1);
	}
	check = at(w, SSH_DIR "/.sshd_config.arcana");
	if (scope_replace(w, check, text, strlen(text), 0600, NULL) != 0) {
		*errp = wfmt(w, "%s: %s", SSH_DIR, strerror(errno));
		return (-1);
	}
	argv[0] = (char *)(uintptr_t)prog;
	argv[1] = (char *)(uintptr_t)"-t";
	argv[2] = (char *)(uintptr_t)"-f";
	argv[3] = (char *)(uintptr_t)check;
	argv[4] = NULL;
	rc = run_exec(w, scope_jexec(w, argv), &res);
	(void)scope_rename(w, check, ".sshd_config.arcana", NULL);
	if (rc != 0) {
		*errp = res.errlen > 0 ? wfmt(w, "sshd -t: %s", wstrndup(w,
		    res.err, strcspn(res.err, "\r\n"))) : wtext(w, exec_error(w,
		    &res, "sshd -t"));
		return (-1);
	}
	if (scope_replace(w, at(w, SSHD_CONFIG), text, strlen(text), 0644,
	    BEFORE) != 0) {
		*errp = wfmt(w, "%s: %s", SSHD_CONFIG, strerror(errno));
		return (-1);
	}
	return (reload(w, errp));
}

/* The safe change taken back: the file before it, and sshd reloaded. */
int
ssh_undo(struct work *w, const struct arc_job_spec *sp, const char **errp)
{

	if (scope_rename(w, at(w, SSHD_CONFIG), BEFORE, "sshd_config") != 0) {
		*errp = wfmt(w, "%s/%s: %s", SSH_DIR, BEFORE, strerror(errno));
		return (-1);
	}
	if (strcmp(sp->verb, "banner") == 0)
		(void)scope_rename(w, at(w, BANNER), "banner.arcana-before",
		    "banner");
	if (strcmp(sp->verb, "user-cas") == 0)
		(void)scope_rename(w, at(w, USER_CAS),
		    "trusted_user_ca_keys.arcana-before", "trusted_user_ca_keys");
	return (reload(w, errp));
}

/* A file in dfd, written whole and moved in, the user's own. */
static int
put_at(int dfd, const char *name, const char *text, size_t len, uid_t uid,
    gid_t gid)
{
	char	tmp[NAME_MAX + 1];
	int	fd, e;

	snprintf(tmp, sizeof(tmp), ".%s.%08x", name, arc4random());
	if ((fd = openat(dfd, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600)) == -1)
		return (-1);
	if (write(fd, text, len) != (ssize_t)len || fsync(fd) == -1 ||
	    (fchown(fd, uid, gid) == -1 && geteuid() == 0)) {
		e = errno;
		close(fd);
		(void)unlinkat(dfd, tmp, 0);
		errno = e;
		return (-1);
	}
	close(fd);
	if (renameat(dfd, tmp, dfd, name) == -1) {
		e = errno;
		(void)unlinkat(dfd, tmp, 0);
		errno = e;
		return (-1);
	}
	return (0);
}

/*
 * Where a line of authorized_keys has its key: after its options, if it
 * has any (words up to a blank outside quotes, the first not a key's
 * type).  sshd(8)'s AUTHORIZED_KEYS FILE FORMAT.
 */
static const char *
key_start(const char *l)
{
	const char	*p;
	bool		 q;

	l += strspn(l, " \t");
	if (strncmp(l, "ssh-", 4) == 0 || strncmp(l, "ecdsa-", 6) == 0 ||
	    strncmp(l, "sk-", 3) == 0)
		return (l);
	for (p = l, q = false; *p != '\0'; p++) {
		if (*p == '\\' && p[1] != '\0')
			p++;
		else if (*p == '"')
			q = !q;
		else if (!q && (*p == ' ' || *p == '\t'))
			break;
	}
	return (p + strspn(p, " \t"));
}

enum { AK_REMOVE, AK_ADD, AK_OPTIONS };

/*
 * A user's authorized_keys changed: the key added, each line with the
 * fingerprint taken away, or that line's options changed, the key and
 * its comment as they are.  Its directory is opened beneath the user's
 * home, never through a link, and must be theirs or root's.
 */
static int
authorize(struct work *w, const struct arc_job_spec *sp, int how,
    const char **errp)
{
	bool		 add = how == AK_ADD;
	struct stat	 sb;
	struct pwent	*pw;
	ucl_object_t	*set, *k;
	const char	*why, *path, *name, *dir, *fp, *l, *e;
	char		*text, *out;
	size_t		 n, i, o, len;
	int		 hfd, dfd, cut;

	n = users(w, &pw);
	for (i = 0; i < n && strcmp(pw[i].name, sp->user) != 0; i++)
		;
	if (i == n) {
		*errp = wfmt(w, "ssh: %s is no user who signs in here", sp->user);
		return (-1);
	}
	set = settings(w, &why);
	path = akeys_path(w, &pw[i], set);
	ucl_object_unref(set);
	if (path == NULL || pw[i].home[0] != '/' || strncmp(path, pw[i].home,
	    strlen(pw[i].home)) != 0 || path[strlen(pw[i].home)] != '/' ||
	    !plain_path(pw[i].home) || !plain_path(path + strlen(
	    pw[i].home))) {
		*errp = wfmt(w, "ssh: %s's keys file is not a path in their "
		    "home", sp->user);
		return (-1);
	}
	name = strrchr(path, '/') + 1;
	dir = wstrndup(w, path + strlen(pw[i].home) + 1, (size_t)(name - path -
	    strlen(pw[i].home) - 1));
	if ((hfd = scope_dirfd(w, at(w, pw[i].home))) == -1) {
		*errp = wfmt(w, "ssh: %s: %s", pw[i].home, strerror(errno));
		return (-1);
	}
	dfd = hfd;
	if (dir[0] != '\0') {
		dir = wstrndup(w, dir, strlen(dir) - 1);	/* its / */
		if (strchr(dir, '/') != NULL) {
			close(hfd);
			*errp = "ssh: a keys file in the home or one directory "
			    "of it";
			return (-1);
		}
		if (add && mkdirat(hfd, dir, 0700) == 0 && fchownat(hfd, dir,
		    pw[i].uid, pw[i].gid, AT_SYMLINK_NOFOLLOW) == -1 &&
		    geteuid() == 0) {
			*errp = wfmt(w, "ssh: %s: %s", dir, strerror(errno));
			close(hfd);
			return (-1);
		}
		dfd = openat(hfd, dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
		    O_CLOEXEC | O_RESOLVE_BENEATH);
		close(hfd);
		if (dfd == -1) {
			*errp = wfmt(w, "ssh: %s/%s: %s", pw[i].home, dir,
			    strerror(errno));
			return (-1);
		}
	}
	if (fstat(dfd, &sb) == -1 || (sb.st_uid != pw[i].uid && sb.st_uid !=
	    0)) {
		close(dfd);
		*errp = wfmt(w, "ssh: %s is not %s's", path, sp->user);
		return (-1);
	}
	/*
	 * What is there now: read without a link, and not blocking on a
	 * FIFO; a file with links of another name (a hard link to one the
	 * user cannot read) or of another's is left alone.
	 */
	text = NULL;
	len = 0;
	{
		int	fd;

		if ((fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
		    O_CLOEXEC)) != -1) {
			if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
			    sb.st_nlink != 1 || (sb.st_uid != pw[i].uid &&
			    sb.st_uid != 0) || sb.st_size > 1024 * 1024) {
				close(fd);
				close(dfd);
				*errp = wfmt(w, "ssh: %s is not a file of %s's "
				    "alone: left as it is", path, sp->user);
				return (-1);
			}
			text = wmalloc(w, (size_t)sb.st_size + 1);
			len = (size_t)read(fd, text, (size_t)sb.st_size);
			if (len > (size_t)sb.st_size)
				len = 0;
			text[len] = '\0';
			close(fd);
		} else if (errno != ENOENT) {
			close(dfd);
			*errp = wfmt(w, "ssh: %s: %s", path, strerror(errno));
			return (-1);
		}
	}
	if (text == NULL)
		text = wstrdup(w, "");
	if (add) {
		if ((k = key_obj(w, sp->text)) == NULL) {
			close(dfd);
			*errp = "ssh: that is no key OpenSSH reads";
			return (-1);
		}
		fp = wstrdup(w, ucl_object_tostring(ucl_object_lookup(k,
		    "fingerprint")));
		ucl_object_unref(k);
		out = wfmt(w, "%s%s%s\n", text, len > 0 && text[len - 1] != '\n' ?
		    "\n" : "", sp->text);
		/* Not twice. */
		for (l = text; *l != '\0'; l = *e != '\0' ? e + 1 : e) {
			e = l + strcspn(l, "\n");
			if ((k = key_obj(w, wstrndup(w, l, (size_t)(e - l)))) !=
			    NULL) {
				cut = strcmp(ucl_object_tostring(
				    ucl_object_lookup(k, "fingerprint")), fp) == 0;
				ucl_object_unref(k);
				if (cut) {
					close(dfd);
					*errp = wfmt(w, "ssh: %s has that key "
					    "already (%s)", sp->user, fp);
					return (-1);
				}
			}
		}
	} else if (how == AK_OPTIONS) {
		/* The line of the key, rewritten in place. */
		cut = 0;
		out = wstrdup(w, "");
		for (l = text; *l != '\0'; l = e) {
			const char	*line;
			size_t		 ll;
			bool		 nlf;

			ll = strcspn(l, "\n");
			nlf = l[ll] == '\n';
			e = l + ll + (nlf ? 1 : 0);
			line = wstrndup(w, l, ll);
			if ((k = key_obj(w, line)) != NULL) {
				if (strcmp(ucl_object_tostring(ucl_object_lookup(
				    k, "fingerprint")), sp->names.v[0]) == 0) {
					const char	*nl;
					ucl_object_t	*k2;

					nl = wfmt(w, "%s%s%s", sp->text != NULL ?
					    sp->text : "", sp->text != NULL &&
					    sp->text[0] != '\0' ? " " : "",
					    key_start(line));
					/* Read back as the same key, or not
					 * written: options sshd would not
					 * take are refused here. */
					k2 = key_obj(w, nl);
					if (k2 == NULL || strcmp(
					    ucl_object_tostring(ucl_object_lookup(
					    k2, "fingerprint")), sp->names.v[0]) !=
					    0) {
						if (k2 != NULL)
							ucl_object_unref(k2);
						ucl_object_unref(k);
						close(dfd);
						*errp = "ssh: with those options the "
						    "line is no key OpenSSH reads";
						return (-1);
					}
					ucl_object_unref(k2);
					line = nl;
					cut++;
				}
				ucl_object_unref(k);
			}
			out = wfmt(w, "%s%s%s", out, line, nlf ? "\n" : "");
		}
		if (cut == 0) {
			close(dfd);
			*errp = wfmt(w, "ssh: %s has no key %s", sp->user,
			    sp->names.v[0]);
			return (-1);
		}
	} else {
		out = wmalloc(w, len + 1);
		o = 0;
		cut = 0;
		for (l = text; *l != '\0'; l = e) {
			e = l + strcspn(l, "\n");
			if (*e == '\n')
				e++;
			if ((k = key_obj(w, wstrndup(w, l, strcspn(l, "\n")))) !=
			    NULL) {
				if (strcmp(ucl_object_tostring(ucl_object_lookup(
				    k, "fingerprint")), sp->text) == 0) {
					ucl_object_unref(k);
					cut++;
					continue;
				}
				ucl_object_unref(k);
			}
			memcpy(out + o, l, (size_t)(e - l));
			o += (size_t)(e - l);
		}
		out[o] = '\0';
		if (cut == 0) {
			close(dfd);
			*errp = wfmt(w, "ssh: %s has no key %s", sp->user,
			    sp->text);
			return (-1);
		}
	}
	if (put_at(dfd, name, out, strlen(out), pw[i].uid, pw[i].gid) != 0) {
		*errp = wfmt(w, "ssh: %s: %s", path, strerror(errno));
		close(dfd);
		return (-1);
	}
	close(dfd);
	return (0);
}

/* A file of the host's own, whole: one of the signing's directory. */
static char *
slurp_host(struct work *w, const char *path, size_t *lenp)
{
	struct stat	 sb;
	char		*buf;
	ssize_t		 n;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
	    O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) || sb.st_size >
	    TEXT_MAX) {
		close(fd);
		return (NULL);
	}
	buf = wmalloc(w, (size_t)sb.st_size + 1);
	n = read(fd, buf, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size)
		return (NULL);
	buf[n] = '\0';
	*lenp = (size_t)n;
	return (buf);
}

/* A file of dir, written whole, root's alone. */
static int
put_tmp(const char *path, const char *text, size_t len)
{
	int	fd, e;

	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600)) == -1)
		return (-1);
	if (write(fd, text, len) != (ssize_t)len) {
		e = errno;
		close(fd);
		(void)unlink(path);
		errno = e;
		return (-1);
	}
	close(fd);
	return (0);
}

/* The CA key's file overwritten and taken away, and the rest of dir. */
static void
tmp_gone(struct work *w, const char *dir, const char *ca, int nkeys)
{
	struct stat	sb;
	char		zero[4096];
	int		fd, i;

	if ((fd = open(ca, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)) != -1) {
		off_t	left;
		ssize_t	wr;

		memset(zero, 0, sizeof(zero));
		if (fstat(fd, &sb) == 0)
			for (left = sb.st_size; left > 0; left -= wr)
				if ((wr = write(fd, zero, (size_t)MIN(left,
				    (off_t)sizeof(zero)))) <= 0)
					break;
		(void)fsync(fd);
		close(fd);
	}
	(void)unlink(ca);
	for (i = 0; i < nkeys; i++) {
		(void)unlink(wfmt(w, "%s/k%d.pub", dir, i));
		(void)unlink(wfmt(w, "%s/k%d-cert.pub", dir, i));
	}
	(void)rmdir(dir);
}

/*
 * Each host key signed by the CA key given, its certificate beside it,
 * and sshd told of each (HostCertificate).  The signing is the host's,
 * through an ssh-agent of its own whose socket is in a directory of
 * /tmp only root reads: the CA's key is in that agent's memory alone,
 * for two minutes at most, never in a file and never in a jail, whose
 * root could read it there; of a jail, only its public host keys come
 * out, and only their certificates go in.
 */
/* The signing's ssh-agent ended, and what it left taken away. */
static void
agent_stop(struct work *w, pid_t apid, const char *sock, const char *dir,
    const char *ca)
{

	(void)kill(apid, SIGTERM);
	exec_set_env(w, NULL, NULL);
	(void)unlink(sock);
	tmp_gone(w, dir, ca, 0);
}

static int
sign(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres		 res;
	ucl_object_t		*set;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*why, *prog, *ca, *id, *p, *pr, *pub, *cert,
				*sock, *agent, *add;
	pid_t			 apid;
	char			*argv[16], *text, host[MAXHOSTNAMELEN],
				 dir[MAXPATHLEN];
	size_t			 i, len;
	int			 n, rc, signed_, k;

	if ((prog = tool(w, "ssh-keygen")) == NULL) {
		*errp = "there is no ssh-keygen here";
		return (-1);
	}
	snprintf(dir, sizeof(dir), "%s/tmp", opts.tools_dir != NULL ?
	    opts.tools_dir : "");
	(void)mkdir(dir, 0755);
	strlcat(dir, "/.arcana-sign.XXXXXXXX", sizeof(dir));
	if (mkdtemp(dir) == NULL) {
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		return (-1);
	}
	/*
	 * The CA's key is never written to a file: on ZFS a block written
	 * over is a new block, the old one kept until freed, or for good
	 * in a snapshot.  It goes to an ssh-agent(1) of this signing's own
	 * through ssh-add(1)'s standard input, lives there for two minutes
	 * at most, and ssh-keygen -U signs with it there; only the CA's
	 * public key is in the directory.
	 */
	ca = wfmt(w, "%s/ca.pub", dir);
	sock = wfmt(w, "%s/agent", dir);
	if ((agent = tool(w, "ssh-agent")) == NULL || (add = tool(w,
	    "ssh-add")) == NULL) {
		*errp = "there is no ssh-agent or ssh-add here";
		(void)rmdir(dir);
		return (-1);
	}
	if (strlen(sock) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
		*errp = wfmt(w, "%s: too long a path for a socket", sock);
		(void)rmdir(dir);
		return (-1);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)agent;
	argv[n++] = (char *)(uintptr_t)"-a";
	argv[n++] = (char *)(uintptr_t)sock;
	argv[n++] = (char *)(uintptr_t)"-t";
	argv[n++] = (char *)(uintptr_t)"120";
	argv[n] = NULL;
	apid = -1;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL || (p = strstr(
	    res.out, "SSH_AGENT_PID=")) == NULL || (apid = (pid_t)strtol(p +
	    14, NULL, 10)) <= 1) {
		*errp = wtext(w, exec_error(w, &res, "ssh-agent"));
		(void)unlink(sock);
		(void)rmdir(dir);
		return (-1);
	}
	exec_set_env(w, "SSH_AUTH_SOCK", sock);
	/* A copy of its own, with its last line ended, zeroed after:
	 * not by wfmt, whose own copy is not. */
	len = strlen(sp->text);
	text = wmalloc(w, len + 2);
	memcpy(text, sp->text, len);
	if (len == 0 || text[len - 1] != '\n')
		text[len++] = '\n';
	n = 0;
	argv[n++] = (char *)(uintptr_t)add;
	argv[n++] = (char *)(uintptr_t)"-q";
	argv[n++] = (char *)(uintptr_t)"-";
	argv[n] = NULL;
	exec_set_secret(true);
	exec_set_stdin(text, len);
	rc = run_exec(w, argv, &res);
	exec_set_stdin(NULL, 0);
	exec_set_secret(false);
	explicit_bzero(text, len);
	if (rc != 0) {
		*errp = "ssh-add: not a private key it can read";
		agent_stop(w, apid, sock, dir, ca);
		return (-1);
	}
	/* Its public key, for ssh-keygen to name the one to sign with. */
	argv[1] = (char *)(uintptr_t)"-L";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL ||
	    put_tmp(ca, res.out, res.outlen) != 0) {
		*errp = wfmt(w, "ssh-add -L: %s", res.errlen > 0 ? wstrndup(w,
		    res.err, strcspn(res.err, "\r\n")) : "no key");
		agent_stop(w, apid, sock, dir, ca);
		return (-1);
	}
	if (w->jail != NULL)
		id = w->jail;
	else {
		gethostname(host, sizeof(host));
		id = wstrdup(w, host);
	}
	pr = NULL;
	for (i = 0; i < sp->names.n; i++)
		pr = pr == NULL ? sp->names.v[i] : wfmt(w, "%s,%s", pr,
		    sp->names.v[i]);
	set = settings(w, &why);
	signed_ = k = 0;
	rc = 0;
	it = NULL;
	while (rc == 0 && (v = ucl_object_iterate(ucl_object_lookup(set,
	    "hostkey"), &it, true)) != NULL) {
		p = ucl_object_tostring(v);
		if ((text = scope_slurp(w, at(w, wfmt(w, "%s.pub", p)), &len)) ==
		    NULL)
			continue;
		pub = wfmt(w, "%s/k%d.pub", dir, k);
		cert = wfmt(w, "%s/k%d-cert.pub", dir, k);
		k++;
		if (put_tmp(pub, text, len) != 0) {
			*errp = wfmt(w, "%s: %s", pub, strerror(errno));
			rc = -1;
			break;
		}
		n = 0;
		argv[n++] = (char *)(uintptr_t)prog;
		argv[n++] = (char *)(uintptr_t)"-q";
		argv[n++] = (char *)(uintptr_t)"-s";
		argv[n++] = (char *)(uintptr_t)ca;
		argv[n++] = (char *)(uintptr_t)"-U";
		argv[n++] = (char *)(uintptr_t)"-I";
		argv[n++] = (char *)(uintptr_t)wfmt(w, "arcana:%s", id);
		argv[n++] = (char *)(uintptr_t)"-h";
		if (pr != NULL) {
			argv[n++] = (char *)(uintptr_t)"-n";
			argv[n++] = (char *)(uintptr_t)pr;
		}
		argv[n++] = (char *)(uintptr_t)"-V";
		argv[n++] = (char *)(uintptr_t)"+52w";
		argv[n++] = (char *)(uintptr_t)pub;
		argv[n] = NULL;
		/* The host's ssh-keygen: run_exec puts it in no jail. */
		if (run_exec(w, argv, &res) != 0) {
			*errp = res.errlen > 0 ? wfmt(w, "ssh-keygen: %s",
			    wstrndup(w, res.err, strcspn(res.err, "\r\n"))) :
			    wtext(w, exec_error(w, &res, "ssh-keygen"));
			rc = -1;
			break;
		}
		if ((text = slurp_host(w, cert, &len)) == NULL ||
		    scope_replace(w, at(w, wfmt(w, "%s-cert.pub", p)), text,
		    len, 0644, NULL) != 0) {
			*errp = wfmt(w, "%s-cert.pub: %s", p, strerror(errno));
			rc = -1;
			break;
		}
		signed_++;
	}
	(void)kill(apid, SIGTERM);
	exec_set_env(w, NULL, NULL);
	(void)unlink(sock);
	tmp_gone(w, dir, ca, k);
	if (rc != 0) {
		ucl_object_unref(set);
		return (-1);
	}
	if (signed_ == 0) {
		ucl_object_unref(set);
		*errp = "ssh: no host key to sign";
		return (-1);
	}
	/* sshd told of each certificate. */
	if ((text = scope_slurp(w, at(w, SSHD_CONFIG), NULL)) == NULL) {
		ucl_object_unref(set);
		*errp = wfmt(w, "%s: %s", SSHD_CONFIG, strerror(errno));
		return (-1);
	}
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(set, "hostkey"), &it,
	    true)) != NULL) {
		p = ucl_object_tostring(v);
		if (scope_slurp(w, at(w, wfmt(w, "%s-cert.pub", p)), NULL) !=
		    NULL && !listed(set, "hostcertificate", wfmt(w,
		    "%s-cert.pub", p)))
			text = conf_edit(w, text, "HostCertificate", wfmt(w,
			    "%s-cert.pub", p), true);
	}
	ucl_object_unref(set);
	return (conf_put(w, text, errp));
}

/*
 * The CA keys whose user certificates sshd takes: each line a public
 * key, a comment or blank; none, the TrustedUserCAKeys line taken away.
 */
static int
user_cas(struct work *w, const char *text, const char *conf,
    const char **errp)
{
	ucl_object_t	*k;
	const char	*l, *e;
	char		*line;
	int		 nkeys;

	if (text == NULL || text[strspn(text, " \t\r\n")] == '\0')
		return (conf_put(w, conf_edit(w, conf, "TrustedUserCAKeys",
		    NULL, false), errp));
	nkeys = 0;
	for (l = text; *l != '\0'; l = *e != '\0' ? e + 1 : e) {
		e = l + strcspn(l, "\n");
		line = wstrndup(w, l, (size_t)(e - l));
		if (line[strspn(line, " \t\r")] == '\0' || line[strspn(line,
		    " \t")] == '#')
			continue;
		k = key_obj(w, line);
		if (k == NULL || ucl_object_lookup(k, "options") != NULL ||
		    ucl_object_lookup(k, "certificate") != NULL ||
		    strstr(ucl_object_tostring(ucl_object_lookup(k, "type")),
		    "-cert-") != NULL) {
			if (k != NULL)
				ucl_object_unref(k);
			*errp = wfmt(w, "not a CA's public key: %.60s", line);
			return (-1);
		}
		ucl_object_unref(k);
		nkeys++;
	}
	if (nkeys == 0) {
		*errp = "no key among the lines";
		return (-1);
	}
	if (text[strlen(text) - 1] != '\n')
		text = wfmt(w, "%s\n", text);
	if (scope_replace(w, at(w, USER_CAS), text, strlen(text), 0644,
	    "trusted_user_ca_keys.arcana-before") != 0) {
		*errp = wfmt(w, "%s: %s", USER_CAS, strerror(errno));
		return (-1);
	}
	if (conf_put(w, conf_edit(w, conf, "TrustedUserCAKeys", USER_CAS,
	    false), errp) != 0) {
		(void)scope_rename(w, at(w, USER_CAS),
		    "trusted_user_ca_keys.arcana-before", "trusted_user_ca_keys");
		return (-1);
	}
	return (0);
}

int
do_ssh_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*text, *v;
	size_t		 i;
	int		 k;

	if ((*errp = ssh_check(sp)) != NULL)
		return (-1);
	if (strcmp(sp->verb, "authorize") == 0)
		return (authorize(w, sp, AK_ADD, errp));
	if (strcmp(sp->verb, "unauthorize") == 0)
		return (authorize(w, sp, AK_REMOVE, errp));
	if (strcmp(sp->verb, "options") == 0)
		return (authorize(w, sp, AK_OPTIONS, errp));
	if (strcmp(sp->verb, "sign") == 0) {
		int	rc;

		rc = sign(w, sp, errp);
		/* The CA's key is not kept with the job, which is. */
		explicit_bzero((char *)(uintptr_t)sp->text, strlen(sp->text));
		return (rc);
	}
	if ((text = scope_slurp(w, at(w, SSHD_CONFIG), NULL)) == NULL) {
		*errp = wfmt(w, "%s: %s", SSHD_CONFIG, strerror(errno));
		return (-1);
	}
	if (strcmp(sp->verb, "user-cas") == 0)
		return (user_cas(w, sp->text, text, errp));
	if (strcmp(sp->verb, "banner") == 0) {
		if (sp->text == NULL || sp->text[0] == '\0')
			text = conf_edit(w, text, "Banner", "none", false);
		else {
			if (scope_replace(w, at(w, BANNER), sp->text,
			    strlen(sp->text), 0644, "banner.arcana-before") != 0) {
				*errp = wfmt(w, "%s: %s", BANNER, strerror(errno));
				return (-1);
			}
			text = conf_edit(w, text, "Banner", BANNER, false);
			if (conf_put(w, text, errp) != 0) {
				(void)scope_rename(w, at(w, BANNER),
				    "banner.arcana-before", "banner");
				return (-1);
			}
			return (0);
		}
		return (conf_put(w, text, errp));
	}
	/* set */
	k = settable_of(sp->path);
	v = NULL;
	for (i = 0; i < sp->names.n; i++)
		v = v == NULL ? sp->names.v[i] : wfmt(w, "%s %s", v,
		    sp->names.v[i]);
	if (strcmp(settable[k].name, "Port") == 0 && sp->names.n > 1) {
		/* Ports are each a line. */
		text = conf_edit(w, text, "Port", NULL, false);
		for (i = 0; i < sp->names.n; i++)
			text = conf_edit(w, text, "Port", sp->names.v[i], true);
	} else
		text = conf_edit(w, text, settable[k].name, v, false);
	return (conf_put(w, text, errp));
}
