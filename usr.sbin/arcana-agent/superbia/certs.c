/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the certificates OpenSSL trusts, as certctl(8) keeps them,
 * of the host or of a jail.  What is in effect is /etc/ssl/certs, each
 * trusted one, and /etc/ssl/untrusted; certctl rehash makes both again
 * from the certificates FreeBSD comes with and those the host was
 * given, in ${LOCALBASE}/share/certs/trusted and .../untrusted.  So a
 * change is made there, and rehashed: certctl trust and untrust alone
 * are undone by the next rehash.  Each one is read with OpenSSL, for
 * whom it is, who signed it, when it ends and its key.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ucl.h>

#include "agent.h"

#define	CERT_MAX	(64 * 1024)
#define	PATH_TRUSTED	"/etc/ssl/certs"
#define	PATH_UNTRUSTED	"/etc/ssl/untrusted"

/*
 * Where the store is: / of the host or of the jail, or for the tests
 * (a tools directory) one beside them, as certctl's -D says.
 */
static const char *
destdir(struct work *w)
{

	char	abs[MAXPATHLEN];

	if (w->jail != NULL || opts.tools_dir == NULL)
		return ("");
	/* Whole, as the store's paths are taken from /. */
	if (realpath(opts.tools_dir, abs) == NULL)
		snprintf(abs, sizeof(abs), "%s", opts.tools_dir);
	return (wfmt(w, "%s/certroot", abs));
}

static const char *
localbase(struct work *w)
{
	char	 lb[MAXPATHLEN];
	size_t	 len;

	len = sizeof(lb);
	if (sysctlbyname("user.localbase", lb, &len, NULL, 0) != 0 || len < 2 ||
	    lb[0] != '/')
		return ("/usr/local");
	lb[len - 1] = '\0';
	return (wstrdup(w, lb));
}

static const char *
local_dir(struct work *w, const char *kind)
{

	return (wfmt(w, "%s%s/share/certs/%s", destdir(w), localbase(w), kind));
}

/* A certificate's file name as the job names it: one of the directory. */
static bool
name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '.' || strlen(s) > 64)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!(s[i] >= 'a' && s[i] <= 'z') && !(s[i] >= 'A' && s[i] <=
		    'Z') && !(s[i] >= '0' && s[i] <= '9') && strchr("._-",
		    s[i]) == NULL)
			return (false);
	return (true);
}

static X509 *
pem_x509(const char *buf, size_t len)
{
	BIO	*b;
	X509	*x;

	if ((b = BIO_new_mem_buf(buf, (int)len)) == NULL)
		return (NULL);
	x = PEM_read_bio_X509(b, NULL, NULL, NULL);
	BIO_free(b);
	return (x);
}

/* The certificate alone, as PEM: nothing else of the text it came in. */
static char *
x509_pem(struct work *w, X509 *x, size_t *lenp)
{
	BIO	*b;
	char	*p, *r;
	long	 n;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return (NULL);
	r = NULL;
	if (PEM_write_bio_X509(b, x) == 1 && (n = BIO_get_mem_data(b, &p)) >
	    0) {
		r = wstrndup(w, p, (size_t)n);
		*lenp = (size_t)n;
	}
	BIO_free(b);
	return (r);
}

static const char *
name_line(struct work *w, const X509_NAME *n)
{
	BIO	*b;
	char	*p;
	long	 len;
	const char *r;

	if ((b = BIO_new(BIO_s_mem())) == NULL)
		return ("");
	X509_NAME_print_ex(b, n, 0, XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB);
	len = BIO_get_mem_data(b, &p);
	r = len > 0 ? wstrndup(w, p, (size_t)len) : "";
	BIO_free(b);
	return (r);
}

static const char *
name_part(struct work *w, const X509_NAME *n, int nid)
{
	unsigned char	*u;
	const char	*r;
	int		 i, len;

	if ((i = X509_NAME_get_index_by_NID(n, nid, -1)) < 0)
		return (NULL);
	if ((len = ASN1_STRING_to_UTF8(&u, X509_NAME_ENTRY_get_data(
	    X509_NAME_get_entry(n, i)))) < 0)
		return (NULL);
	r = wstrndup(w, (char *)u, (size_t)len);
	OPENSSL_free(u);
	return (r);
}

static int64_t
when(const ASN1_TIME *t)
{
	struct tm	tm;

	if (t == NULL || ASN1_TIME_to_tm(t, &tm) != 1)
		return (0);
	return ((int64_t)timegm(&tm));
}

static const char *
sha256_hex(struct work *w, X509 *x)
{
	unsigned char	md[EVP_MAX_MD_SIZE];
	unsigned int	n, i;
	char		*s;

	if (X509_digest(x, EVP_sha256(), md, &n) != 1)
		return ("");
	s = wmalloc(w, n * 2 + 1);
	for (i = 0; i < n; i++)
		snprintf(s + i * 2, 3, "%02x", md[i]);
	return (s);
}

static const char *
key_of(struct work *w, X509 *x)
{
	EVP_PKEY	*k;
	char		 g[64];

	if ((k = X509_get0_pubkey(x)) == NULL)
		return ("");
	switch (EVP_PKEY_get_base_id(k)) {
	case EVP_PKEY_RSA:
		return (wfmt(w, "RSA %d", EVP_PKEY_get_bits(k)));
	case EVP_PKEY_EC:
		if (EVP_PKEY_get_group_name(k, g, sizeof(g), NULL) == 1)
			return (wfmt(w, "EC %s", g));
		return (wfmt(w, "EC %d", EVP_PKEY_get_bits(k)));
	case EVP_PKEY_ED25519:
		return ("Ed25519");
	case EVP_PKEY_ED448:
		return ("Ed448");
	default:
		return (wfmt(w, "%s %d", OBJ_nid2sn(EVP_PKEY_get_base_id(k)),
		    EVP_PKEY_get_bits(k)));
	}
}

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

/* One certificate as the reply has it; NULL for text that is none. */
static ucl_object_t *
cert_obj(struct work *w, const char *file, const char *buf, size_t len,
    const char **shap)
{
	ucl_object_t	*o;
	const X509_NAME	*sn;
	X509		*x;
	const char	*sha;

	if ((x = pem_x509(buf, len)) == NULL)
		return (NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	put_s(o, "file", file);
	sn = X509_get_subject_name(x);
	put_s(o, "subject", name_line(w, sn));
	put_s(o, "cn", name_part(w, sn, NID_commonName));
	put_s(o, "org", name_part(w, sn, NID_organizationName));
	put_s(o, "country", name_part(w, sn, NID_countryName));
	put_s(o, "issuer", name_line(w, X509_get_issuer_name(x)));
	ucl_object_insert_key(o, ucl_object_fromint(when(X509_get0_notBefore(
	    x))), "not_before", 0, false);
	ucl_object_insert_key(o, ucl_object_fromint(when(X509_get0_notAfter(
	    x))), "not_after", 0, false);
	sha = sha256_hex(w, x);
	put_s(o, "sha256", sha);
	put_s(o, "key", key_of(w, x));
	ucl_object_insert_key(o, ucl_object_frombool(X509_check_ca(x) > 0),
	    "ca", 0, false);
	ucl_object_insert_key(o, ucl_object_frombool(X509_check_issued(x, x) ==
	    X509_V_OK), "self_signed", 0, false);
	X509_free(x);
	if (shap != NULL)
		*shap = sha;
	return (o);
}

/*
 * A file of a directory of the store: a copy, or a link to one as an
 * older certctl made them, an absolute one taken from the jail's root.
 */
static char *
read_entry(struct work *w, int dfd, const char *dir, const char *name,
    size_t *lenp)
{
	struct stat	 sb;
	char		 to[MAXPATHLEN], *buf;
	ssize_t		 n;
	int		 fd;

	if (fstatat(dfd, name, &sb, AT_SYMLINK_NOFOLLOW) == -1)
		return (NULL);
	if (S_ISLNK(sb.st_mode)) {
		if ((n = readlinkat(dfd, name, to, sizeof(to) - 1)) <= 0)
			return (NULL);
		to[n] = '\0';
		buf = scope_slurp(w, to[0] == '/' ? wfmt(w, "%s%s", destdir(w),
		    to) : wfmt(w, "%s/%s", dir, to), lenp);
		return (buf != NULL && *lenp <= CERT_MAX ? buf : NULL);
	}
	if (!S_ISREG(sb.st_mode) || sb.st_size > CERT_MAX)
		return (NULL);
	if ((fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
	    O_CLOEXEC)) == -1)
		return (NULL);
	buf = wmalloc(w, (size_t)sb.st_size + 1);
	n = read(fd, buf, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size)
		return (NULL);
	buf[n] = '\0';
	*lenp = (size_t)n;
	return (buf);
}

/* Each certificate of a directory, into arr; with shas, their SHA-256s
 * mapped to their paths. */
static void
read_dir(struct work *w, const char *dir, ucl_object_t *arr,
    ucl_object_t *shas)
{
	struct dirent	*d;
	ucl_object_t	*o;
	DIR		*dp;
	const char	*sha;
	char		*buf;
	size_t		 len;
	int		 dfd;

	if ((dfd = scope_dirfd(w, dir)) == -1)
		return;
	if ((dp = fdopendir(dfd)) == NULL) {
		close(dfd);
		return;
	}
	while ((d = readdir(dp)) != NULL) {
		if (d->d_name[0] == '.')
			continue;
		if ((buf = read_entry(w, dirfd(dp), dir, d->d_name, &len)) ==
		    NULL)
			continue;
		if ((o = cert_obj(w, d->d_name, buf, len, &sha)) == NULL)
			continue;
		if (shas != NULL)
			ucl_object_insert_key(shas, ucl_object_fromstring(wfmt(w,
			    "%s/%s", dir + strlen(destdir(w)), d->d_name)), sha,
			    0, true);
		if (arr != NULL)
			ucl_array_append(arr, o);
		else
			ucl_object_unref(o);
	}
	closedir(dp);
}

/* Each of arr that the host was given, by its copy among local. */
static void
mark_local(ucl_object_t *arr, const ucl_object_t *local)
{
	ucl_object_iter_t	 it;
	const ucl_object_t	*c, *p, *s;

	it = NULL;
	while ((c = ucl_object_iterate(arr, &it, true)) != NULL) {
		if ((s = ucl_object_lookup(c, "sha256")) == NULL || (p =
		    ucl_object_lookup(local, ucl_object_tostring(s))) == NULL)
			continue;
		ucl_object_insert_key((ucl_object_t *)(uintptr_t)c,
		    ucl_object_copy(p), "local", 0, false);
	}
}

void
do_certs(struct work *w, struct arc_certs_rsp *rsp)
{
	ucl_object_t	*top, *tr, *un, *lt, *lu;
	const char	*dd;
	char		*json;

	dd = destdir(w);
	top = ucl_object_typed_new(UCL_OBJECT);
	tr = ucl_object_typed_new(UCL_ARRAY);
	un = ucl_object_typed_new(UCL_ARRAY);
	lt = ucl_object_typed_new(UCL_OBJECT);
	lu = ucl_object_typed_new(UCL_OBJECT);
	read_dir(w, wfmt(w, "%s%s", dd, PATH_TRUSTED), tr, NULL);
	read_dir(w, wfmt(w, "%s%s", dd, PATH_UNTRUSTED), un, NULL);
	read_dir(w, local_dir(w, "trusted"), NULL, lt);
	read_dir(w, wfmt(w, "%s%s/share/certs", dd, localbase(w)), NULL, lt);
	read_dir(w, local_dir(w, "untrusted"), NULL, lu);
	mark_local(tr, lt);
	mark_local(un, lu);
	put_s(top, "localbase", localbase(w));
	put_s(top, "trusted_dir", PATH_TRUSTED);
	put_s(top, "untrusted_dir", PATH_UNTRUSTED);
	put_s(top, "added_dir", wfmt(w, "%s/share/certs/trusted",
	    localbase(w)));
	put_s(top, "distrusted_dir", wfmt(w, "%s/share/certs/untrusted",
	    localbase(w)));
	ucl_object_insert_key(top, ucl_object_frombool(tool(w, "certctl") !=
	    NULL), "certctl", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint((int64_t)time(NULL)),
	    "now", 0, false);
	ucl_object_insert_key(top, tr, "trusted", 0, false);
	ucl_object_insert_key(top, un, "untrusted", 0, false);
	ucl_object_unref(lt);
	ucl_object_unref(lu);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	rsp->json = json != NULL ? wtext(w, wstrdup(w, json)) : NULL;
	free(json);
	ucl_object_unref(top);
	rsp->ok = rsp->json != NULL;
	if (!rsp->ok)
		rsp->error = "the certificates were not read";
}

const char *
cert_check(const struct arc_job_spec *sp)
{
	X509	*x;

	if (sp->verb == NULL || (strcmp(sp->verb, "add") != 0 &&
	    strcmp(sp->verb, "remove") != 0 && strcmp(sp->verb, "trust") != 0 &&
	    strcmp(sp->verb, "untrust") != 0 && strcmp(sp->verb, "rehash") !=
	    0))
		return ("a certificate is added, removed, trusted, untrusted, "
		    "or the store rehashed");
	if (sp->safe)
		return ("a certificate is not put back by itself: not in safe "
		    "mode");
	if (strcmp(sp->verb, "rehash") == 0)
		return (NULL);
	if (!name_ok(sp->path))
		return ("a certificate is named by its file: letters, digits "
		    "and ._- only");
	if (strcmp(sp->verb, "add") != 0)
		return (NULL);
	if (sp->text == NULL || strstr(sp->text, "PRIVATE KEY") != NULL)
		return ("a certificate is added as its PEM text, and no key "
		    "with it");
	if ((x = pem_x509(sp->text, strlen(sp->text))) == NULL)
		return ("the text is no PEM certificate");
	X509_free(x);
	return (NULL);
}

/* dir, made where it is not, beneath the store's root. */
static int
mkdirs(struct work *w, const char *dir)
{
	char	*p, *c, *next;
	int	 fd, nfd;

	if ((fd = scope_dirfd(w, "/")) == -1)
		return (-1);
	p = wstrdup(w, dir);
	for (c = p + strspn(p, "/"); *c != '\0'; c = next) {
		next = c + strcspn(c, "/");
		if (*next == '/')
			*next++ = '\0';
		if (mkdirat(fd, c, 0755) == -1 && errno != EEXIST)
			break;
		nfd = openat(fd, c, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
		    O_CLOEXEC | O_RESOLVE_BENEATH);
		close(fd);
		if ((fd = nfd) == -1)
			return (-1);
		next += strspn(next, "/");
	}
	if (*c != '\0') {
		close(fd);
		return (-1);
	}
	close(fd);
	return (0);
}

static int
rehash(struct work *w, const char **errp)
{
	struct execres	 res;
	const char	*prog, *e;
	char		*argv[5];
	int		 n;

	if ((prog = tool(w, "certctl")) == NULL) {
		*errp = "the host has no certctl(8)";
		return (-1);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)prog;
	if (destdir(w)[0] != '\0') {
		argv[n++] = (char *)(uintptr_t)"-D";
		argv[n++] = (char *)(uintptr_t)destdir(w);
	}
	argv[n++] = (char *)(uintptr_t)"rehash";
	argv[n] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		e = scope_missing(w, &res, "certctl", NULL);
		*errp = e != NULL ? e : wtext(w, exec_error(w, &res,
		    "certctl"));
		return (-1);
	}
	return (0);
}

/* The PEM of a file of the store as it is in effect, with its X509. */
static char *
store_pem(struct work *w, const char *dir, const char *name, size_t *lenp,
    const char **shap)
{
	X509	*x;
	char	*buf, *pem;
	size_t	 len;
	int	 dfd;

	if ((dfd = scope_dirfd(w, dir)) == -1)
		return (NULL);
	buf = read_entry(w, dfd, dir, name, &len);
	close(dfd);
	if (buf == NULL || (x = pem_x509(buf, len)) == NULL)
		return (NULL);
	pem = x509_pem(w, x, lenp);
	if (shap != NULL)
		*shap = sha256_hex(w, x);
	X509_free(x);
	return (pem);
}

/* Take away, of dir, each copy of the certificate whose SHA-256 is sha;
 * how many. */
static int
unlink_copies(struct work *w, const char *dir, const char *sha)
{
	ucl_object_t		*shas;
	const ucl_object_t	*p;
	ucl_object_iter_t	 it;
	const char		*path, *base;
	int			 n;

	shas = ucl_object_typed_new(UCL_OBJECT);
	read_dir(w, dir, NULL, shas);
	n = 0;
	it = NULL;
	while ((p = ucl_object_iterate(shas, &it, true)) != NULL) {
		if (strcmp(ucl_object_key(p), sha) != 0)
			continue;
		path = wfmt(w, "%s%s", destdir(w), ucl_object_tostring(p));
		base = strrchr(path, '/') + 1;
		if (scope_rename(w, path, base, NULL) == 0)
			n++;
	}
	ucl_object_unref(shas);
	return (n);
}

int
do_cert(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*dir, *name, *sha;
	char		*pem;
	size_t		 len;
	X509		*x;
	int		 n;

	if ((*errp = cert_check(sp)) != NULL)
		return (-1);
	if (strcmp(sp->verb, "add") == 0) {
		x = pem_x509(sp->text, strlen(sp->text));
		pem = x509_pem(w, x, &len);
		X509_free(x);
		dir = local_dir(w, "trusted");
		name = strlen(sp->path) > 4 && (strcmp(sp->path + strlen(
		    sp->path) - 4, ".pem") == 0 || strcmp(sp->path + strlen(
		    sp->path) - 4, ".crt") == 0) ? sp->path : wfmt(w, "%s.pem",
		    sp->path);
		if (pem == NULL || mkdirs(w, dir) != 0 || scope_replace(w,
		    wfmt(w, "%s/%s", dir, name), pem, len, 0444, NULL) != 0) {
			*errp = wfmt(w, "%s/%s: %s", dir + strlen(destdir(w)),
			    name, strerror(errno));
			return (-1);
		}
	} else if (strcmp(sp->verb, "remove") == 0) {
		n = 0;
		dir = local_dir(w, "trusted");
		if (scope_rename(w, wfmt(w, "%s/%s", dir, sp->path), sp->path,
		    NULL) == 0)
			n++;
		dir = wfmt(w, "%s%s/share/certs", destdir(w), localbase(w));
		if (scope_rename(w, wfmt(w, "%s/%s", dir, sp->path), sp->path,
		    NULL) == 0)
			n++;
		if (n == 0) {
			*errp = wfmt(w, "%s was not given to this host (%s)",
			    sp->path, local_dir(w, "trusted") + strlen(destdir(
			    w)));
			return (-1);
		}
	} else if (strcmp(sp->verb, "untrust") == 0) {
		if ((pem = store_pem(w, wfmt(w, "%s%s", destdir(w),
		    PATH_TRUSTED), sp->path, &len, NULL)) == NULL) {
			*errp = wfmt(w, "%s is no certificate trusted here",
			    sp->path);
			return (-1);
		}
		dir = local_dir(w, "untrusted");
		if (mkdirs(w, dir) != 0 || scope_replace(w, wfmt(w, "%s/%s.pem",
		    dir, sp->path), pem, len, 0444, NULL) != 0) {
			*errp = wfmt(w, "%s/%s.pem: %s", dir + strlen(destdir(w)),
			    sp->path, strerror(errno));
			return (-1);
		}
	} else if (strcmp(sp->verb, "trust") == 0) {
		if (store_pem(w, wfmt(w, "%s%s", destdir(w), PATH_UNTRUSTED),
		    sp->path, &len, &sha) == NULL) {
			*errp = wfmt(w, "%s is no certificate untrusted here",
			    sp->path);
			return (-1);
		}
		if (unlink_copies(w, local_dir(w, "untrusted"), sha) == 0) {
			*errp = wfmt(w, "%s is untrusted by FreeBSD itself "
			    "(/usr/share/certs/untrusted), not by this host: it "
			    "is not trusted again here", sp->path);
			return (-1);
		}
	}
	return (rehash(w, errp));
}
