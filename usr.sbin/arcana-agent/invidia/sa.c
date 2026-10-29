/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Manually keyed security associations for an ipsec(4) interface, by
 * the base system's setkey(8) (Mplify 119 §10: ESP in tunnel mode, ESN,
 * ESP in UDP, the keys given, R41-R50, R55).  The two SAs of a tunnel,
 * out and in, each its SPI and keys, with the interface's reqid so its
 * policies take them; written as a file setkey reads, 0600 and taken
 * out again, and the keys never in a trace or a title.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>

#include <ucl.h>

#include "agent.h"

/*
 * Each tunnel end's key pair (Mplify 119 R51-R53): X25519, the private
 * half a PEM file beside the agent's kept files, 0600, never read by
 * anything but this; the public half, 32 bytes as base64, told in the
 * sdwan read for the console to pass to the far end.  The SA keys and
 * SPIs of both directions come from the agreement with the far public
 * half by HKDF-SHA256 (NIST SP 800-56A, R54), the same on both ends:
 * the end whose public half sorts lower is A, the other B, and the
 * material is laid out A to B first.
 */
#define	KEY_FILE	"sdwan-key-%s.pem"
#define	NEXT_FILE	"sdwan-key-%s-next.pem"	/* the pair to come (R110) */
#define	STATE_FILE	"sdwan-sa-%s.json"	/* the SPIs set, when, for how long */
#define	HKDF_SALT	"arcana uswe v1"
#define	PUB_B64		44	/* 32 bytes as base64 */

/* What the words say: the SAs of the two directions. */
struct sa_words {
	uint32_t	 spi_in, spi_out;
	const char	*enc, *auth;
	const char	*key_in, *key_out, *akey_in, *akey_out;
	const char	*peer;		/* derive: the far public half */
	uint32_t	 epoch;		/* derive: which keys of the pair */
	uint32_t	 lifetime;	/* seconds the keys are good for */
	int		 install;	/* 0 both directions, 1 in only, 2 out */
	bool		 encap, esn;
	bool		 next;		/* derive: from the next pair */
};

static const struct {
	const char	*name;
	int		 keylens[3];	/* hex digits allowed, 0 ends */
	bool		 aead;
} encs[] = {
	{ "aes-cbc", { 32, 48, 64 }, false },
	{ "aes-gcm-16", { 40, 56, 72 }, true },
}, auths[] = {
	{ "hmac-sha1", { 40, 0, 0 }, false },
	{ "hmac-sha2-256", { 64, 0, 0 }, false },
	{ "hmac-sha2-512", { 128, 0, 0 }, false },
};

static const char *
key_path(struct work *w, const char *ifname, bool next)
{
	char	buf[MAXPATHLEN];

	sdwan_conf_path(wfmt(w, next ? NEXT_FILE : KEY_FILE, ifname), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* The pair of an interface, read; NULL and why when there is none. */
static EVP_PKEY *
key_load(struct work *w, const char *ifname, bool next, const char **errp)
{
	EVP_PKEY	*k;
	FILE		*fp;

	if ((fp = fopen(key_path(w, ifname, next), "r")) == NULL) {
		*errp = wfmt(w, next ? "%s has no next pair yet: ipsec-sa key "
		    "next first" : "%s has no key pair yet: ipsec-sa key first",
		    ifname);
		return (NULL);
	}
	k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (k == NULL)
		*errp = wfmt(w, "%s: the key file is not a private key", ifname);
	return (k);
}

/* The public half of a pair as base64 (44 characters); false if not X25519. */
static bool
key_public(EVP_PKEY *k, char *b64, size_t len)
{
	unsigned char	raw[32];
	size_t		 n = sizeof(raw);

	if (len < PUB_B64 + 1 || EVP_PKEY_get_raw_public_key(k, raw, &n) != 1
	    || n != sizeof(raw))
		return (false);
	EVP_EncodeBlock((unsigned char *)b64, raw, (int)n);
	return (true);
}

/*
 * A pair made for an interface unless it has one, or its next pair made
 * anew (R110: a new pair for the keys to come); its public half.
 */
static int
key_make(struct work *w, const char *ifname, bool next, char *pub,
    size_t plen, const char **errp)
{
	EVP_PKEY	*k;
	FILE		*fp;
	const char	*path;
	int		 fd, step;

	path = key_path(w, ifname, next);
	if (next)
		(void)unlink(path);
	else if (access(path, F_OK) == 0) {
		if ((k = key_load(w, ifname, false, errp)) == NULL)
			return (-1);
		if (!key_public(k, pub, plen)) {
			EVP_PKEY_free(k);
			*errp = wfmt(w, "%s: the key is not an X25519 one", ifname);
			return (-1);
		}
		EVP_PKEY_free(k);
		return (0);
	}
	step = step_begin(w, STEP_FILE, "write", "%s", path);
	if ((k = EVP_PKEY_Q_keygen(NULL, NULL, "X25519")) == NULL) {
		step_end(w, step, false, "no key made");
		*errp = "OpenSSL made no X25519 key";
		return (-1);
	}
	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600)) == -1 || (fp =
	    fdopen(fd, "w")) == NULL) {
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		EVP_PKEY_free(k);
		if (fd != -1)
			close(fd);
		return (-1);
	}
	if (PEM_write_PrivateKey(fp, k, NULL, NULL, 0, NULL, NULL) != 1) {
		fclose(fp);
		(void)unlink(path);
		step_end(w, step, false, "not written");
		*errp = wfmt(w, "%s: the key was not written", path);
		EVP_PKEY_free(k);
		return (-1);
	}
	fclose(fp);
	step_end(w, step, true, NULL);
	(void)key_public(k, pub, plen);
	EVP_PKEY_free(k);
	return (0);
}

/*
 * The SA material of both directions from this end's pair and the far
 * public half: HKDF-SHA256 of the X25519 agreement, salted, with both
 * public halves in order and the epoch as the info; the keys for A to B
 * first.  *lower says this end is A.
 */
static int
key_derive(struct work *w, const char *ifname, const char *peer_b64,
    uint32_t epoch, bool next, unsigned char *okm, size_t okmlen,
    bool *lower, const char **errp)
{
	EVP_PKEY	*me, *far = NULL;
	EVP_PKEY_CTX	*ctx = NULL;
	EVP_KDF		*kdf;
	EVP_KDF_CTX	*kctx;
	OSSL_PARAM	 params[5];
	unsigned char	 peer[33], shared[32], info[72], mypub[32];
	char		 myb64[PUB_B64 + 1];
	size_t		 n;
	int		 len, rc = -1;

	if (strlen(peer_b64) != PUB_B64 || (len = EVP_DecodeBlock(peer,
	    (const unsigned char *)peer_b64, PUB_B64)) < 32) {
		*errp = "peer is the far end's public half, 44 characters of "
		    "base64";
		return (-1);
	}
	if ((me = key_load(w, ifname, next, errp)) == NULL)
		return (-1);
	n = sizeof(mypub);
	if (EVP_PKEY_get_raw_public_key(me, mypub, &n) != 1 || !key_public(me,
	    myb64, sizeof(myb64))) {
		EVP_PKEY_free(me);
		*errp = wfmt(w, "%s: the key is not an X25519 one", ifname);
		return (-1);
	}
	if (memcmp(mypub, peer, 32) == 0) {
		EVP_PKEY_free(me);
		*errp = "peer is this end's own public half";
		return (-1);
	}
	*lower = memcmp(mypub, peer, 32) < 0;
	far = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
	ctx = far != NULL ? EVP_PKEY_CTX_new(me, NULL) : NULL;
	n = sizeof(shared);
	if (ctx == NULL || EVP_PKEY_derive_init(ctx) != 1 ||
	    EVP_PKEY_derive_set_peer(ctx, far) != 1 || EVP_PKEY_derive(ctx,
	    shared, &n) != 1 || n != sizeof(shared)) {
		*errp = "the agreement with the far public half failed";
		goto out;
	}
	/* info: the two public halves in order, then the epoch. */
	memcpy(info, *lower ? mypub : peer, 32);
	memcpy(info + 32, *lower ? peer : mypub, 32);
	info[64] = (unsigned char)(epoch >> 24);
	info[65] = (unsigned char)(epoch >> 16);
	info[66] = (unsigned char)(epoch >> 8);
	info[67] = (unsigned char)epoch;
	kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	kctx = kdf != NULL ? EVP_KDF_CTX_new(kdf) : NULL;
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
	    (char *)(uintptr_t)"SHA256", 0);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, shared,
	    sizeof(shared));
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
	    (char *)(uintptr_t)HKDF_SALT, strlen(HKDF_SALT));
	params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info,
	    68);
	params[4] = OSSL_PARAM_construct_end();
	if (kctx == NULL || EVP_KDF_derive(kctx, okm, okmlen, params) != 1) {
		*errp = "HKDF gave no keys";
		if (kctx != NULL)
			EVP_KDF_CTX_free(kctx);
		if (kdf != NULL)
			EVP_KDF_free(kdf);
		goto out;
	}
	EVP_KDF_CTX_free(kctx);
	EVP_KDF_free(kdf);
	rc = 0;
out:
	OPENSSL_cleanse(shared, sizeof(shared));
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);
	if (far != NULL)
		EVP_PKEY_free(far);
	EVP_PKEY_free(me);
	return (rc);
}

static void
hex_of(const unsigned char *raw, size_t n, char *out)
{
	static const char	digits[] = "0123456789abcdef";
	size_t			i;

	for (i = 0; i < n; i++) {
		out[2 * i] = digits[raw[i] >> 4];
		out[2 * i + 1] = digits[raw[i] & 15];
	}
	out[2 * n] = 0;
}

/* An SPI from four bytes: 256 or more. */
static uint32_t
spi_of(const unsigned char *b)
{
	uint32_t	n;

	n = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 |
	    b[3];
	return (n < 256 ? n + 256 : n);
}

/* What an interface's SAs are, as kept beside its keys: the SPIs set
 * (and the next ones, between a derive with next and the commit), when,
 * and the lifetime; NULL when nothing is kept. */
static ucl_object_t *
sa_state_load(struct work *w, const char *ifname)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	FILE			*fp;
	char			 path[MAXPATHLEN], buf[600];
	size_t			 n;

	sdwan_conf_path(wfmt(w, STATE_FILE, ifname), path, sizeof(path));
	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	n = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	buf[n] = '\0';
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, buf, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

static const char	*sstr(const ucl_object_t *, const char *);
static ucl_object_t	*derive_words(const struct sa_words *);

static int
sa_state_save(struct work *w, const char *ifname, const ucl_object_t *o,
    const char **errp)
{
	char	 path[MAXPATHLEN], *json;
	FILE	*fp;
	int	 fd;

	sdwan_conf_path(wfmt(w, STATE_FILE, ifname), path, sizeof(path));
	if (o == NULL) {
		(void)unlink(path);
		return (0);
	}
	json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == -1 ||
	    (fp = fdopen(fd, "w")) == NULL) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		if (fd != -1)
			close(fd);
		free(json);
		return (-1);
	}
	fputs(json, fp);
	fclose(fp);
	free(json);
	return (0);
}

static uint32_t
u32(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = o != NULL ? ucl_object_lookup(o, key) : NULL;
	return (v == NULL ? 0 : (uint32_t)ucl_object_toint(v));
}

/* The public halves this host keeps, for the sdwan read: keys, each an
 * interface, its public, its next when one waits, and what was set
 * (keyed_at, lifetime, spi_in, spi_out, pending). */
void
sa_keys_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o, *stt;
	EVP_PKEY	*k;
	DIR		*d;
	struct dirent	*de;
	FILE		*fp;
	char		 dir[MAXPATHLEN], pub[PUB_B64 + 1], *slash, ifn[32];
	size_t		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	sdwan_conf_path("sdwan-key-x.pem", dir, sizeof(dir));
	if ((slash = strrchr(dir, '/')) != NULL)
		*slash = 0;
	else
		snprintf(dir, sizeof(dir), ".");
	if ((d = opendir(dir)) != NULL) {
		while ((de = readdir(d)) != NULL) {
			if (strncmp(de->d_name, "sdwan-key-", 10) != 0)
				continue;
			n = strlen(de->d_name);
			if (n < 15 || strcmp(de->d_name + n - 4, ".pem") != 0 ||
			    n - 14 >= sizeof(ifn) || (n > 19 && strcmp(de->d_name +
			    n - 9, "-next.pem") == 0))
				continue;
			snprintf(ifn, sizeof(ifn), "%.*s", (int)(n - 14),
			    de->d_name + 10);
			if ((fp = fopen(wfmt(w, "%s/%s", dir, de->d_name), "r")) ==
			    NULL)
				continue;
			k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
			fclose(fp);
			if (k == NULL)
				continue;
			if (key_public(k, pub, sizeof(pub))) {
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromstring(ifn),
				    "interface", 0, false);
				ucl_object_insert_key(o, ucl_object_fromstring(pub),
				    "public", 0, false);
				EVP_PKEY_free(k);
				k = NULL;
				if ((fp = fopen(wfmt(w, "%s/sdwan-key-%s-next.pem",
				    dir, ifn), "r")) != NULL) {
					k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
					fclose(fp);
					if (k != NULL && key_public(k, pub, sizeof(pub)))
						ucl_object_insert_key(o,
						    ucl_object_fromstring(pub), "next",
						    0, false);
				}
				if ((stt = sa_state_load(w, ifn)) != NULL) {
					static const char *const nums[] = { "at",
					    "lifetime", "spi_in", "spi_out" };

					for (size_t i = 0; i < nitems(nums); i++)
						if (ucl_object_lookup(stt, nums[i]) !=
						    NULL)
							ucl_object_insert_key(o,
							    ucl_object_fromint(u32(stt,
							    nums[i])), i == 0 ? "keyed_at"
							    : nums[i], 0, false);
					ucl_object_insert_key(o, ucl_object_frombool(
					    ucl_object_lookup(stt, "next_spi_in") !=
					    NULL), "pending", 0, false);
					ucl_object_unref(stt);
				}
				ucl_array_append(arr, o);
			}
			if (k != NULL)
				EVP_PKEY_free(k);
		}
		closedir(d);
	}
	ucl_object_insert_key(top, arr, "keys", 0, false);
}

static bool
hex_ok(const char *s, const int *lens)
{
	size_t	i, n;

	if (s == NULL)
		return (false);
	n = strlen(s);
	for (i = 0; i < n; i++)
		if (!isxdigit((unsigned char)s[i]))
			return (false);
	for (i = 0; i < 3 && lens[i] != 0; i++)
		if ((size_t)lens[i] == n)
			return (true);
	return (false);
}

static bool
addr_ok(const char *s, int *af)
{
	unsigned char	raw[16];

	if (s == NULL)
		return (false);
	if (inet_pton(AF_INET, s, raw) == 1) {
		*af = AF_INET;
		return (true);
	}
	if (inet_pton(AF_INET6, s, raw) == 1) {
		*af = AF_INET6;
		return (true);
	}
	return (false);
}

/*
 * The words parsed: "spi-in n spi-out n enc a auth a key-in hex key-out
 * hex akey-in hex akey-out hex encap esn", a key's pair in either order;
 * NULL or what is wrong.
 */
static const char *
sa_parse(const struct arc_job_spec *sp, struct sa_words *w, bool derive)
{
	const char	*k, *v, *e;
	size_t		 i, j;
	unsigned long long n;

	memset(w, 0, sizeof(*w));
	for (i = 0; i < sp->names.n; i++) {
		k = sp->names.v[i];
		if (strcmp(k, "encap") == 0) {
			w->encap = true;
			continue;
		}
		if (strcmp(k, "esn") == 0) {
			w->esn = true;
			continue;
		}
		if (strcmp(k, "next") == 0) {
			if (!derive)
				return ("next is derive's: the SAs from the next "
				    "pair");
			w->next = true;
			continue;
		}
		if (i + 1 >= sp->names.n)
			return ("a word's value is missing");
		v = sp->names.v[++i];
		if (strcmp(k, "peer") == 0) {
			w->peer = v;
			continue;
		}
		if (strcmp(k, "install") == 0) {
			if (strcmp(v, "both") == 0)
				w->install = 0;
			else if (strcmp(v, "in") == 0)
				w->install = 1;
			else if (strcmp(v, "out") == 0)
				w->install = 2;
			else
				return ("install is both, in or out: the directions "
				    "set");
			continue;
		}
		if (strcmp(k, "lifetime") == 0) {
			errno = 0;
			n = strtoull(v, (char **)(uintptr_t)&e, 10);
			if (errno != 0 || e == v || *e != 0 || n < 60 || n >
			    0xffffffffULL)
				return ("a lifetime is seconds, 60 or more");
			w->lifetime = (uint32_t)n;
			continue;
		}
		if (strcmp(k, "epoch") == 0) {
			errno = 0;
			n = strtoull(v, (char **)(uintptr_t)&e, 10);
			if (errno != 0 || e == v || *e != 0 || n > 0xffffffffULL)
				return ("an epoch is a number, 0 to 4294967295");
			w->epoch = (uint32_t)n;
			continue;
		}
		if (strcmp(k, "spi-in") == 0 || strcmp(k, "spi-out") == 0) {
			errno = 0;
			n = strtoull(v, (char **)(uintptr_t)&e, 0);
			if (errno != 0 || e == v || *e != '\0' || n < 256 || n >
			    0xffffffffULL)
				return ("an SPI is a number from 256 to "
				    "4294967295, 0x for hex");
			if (k[4] == 'i')
				w->spi_in = (uint32_t)n;
			else
				w->spi_out = (uint32_t)n;
		} else if (strcmp(k, "enc") == 0)
			w->enc = v;
		else if (strcmp(k, "auth") == 0)
			w->auth = v;
		else if (strcmp(k, "key-in") == 0)
			w->key_in = v;
		else if (strcmp(k, "key-out") == 0)
			w->key_out = v;
		else if (strcmp(k, "akey-in") == 0)
			w->akey_in = v;
		else if (strcmp(k, "akey-out") == 0)
			w->akey_out = v;
		else
			return ("the words are spi-in, spi-out, enc, auth, key-in, "
			    "key-out, akey-in, akey-out, peer, epoch, encap, esn, "
			    "next, install and lifetime");
	}
	for (j = 0; j < nitems(encs); j++)
		if (w->enc != NULL && strcmp(w->enc, encs[j].name) == 0)
			break;
	if (j == nitems(encs))
		return ("enc is aes-cbc or aes-gcm-16");
	if (derive) {
		/* The far public half says the rest: SPIs and keys come
		 * from the agreement. */
		if (w->peer == NULL || strlen(w->peer) != PUB_B64)
			return ("derive takes peer, the far end's public half, 44 "
			    "characters of base64");
		if (w->spi_in != 0 || w->spi_out != 0 || w->key_in != NULL ||
		    w->key_out != NULL || w->akey_in != NULL || w->akey_out !=
		    NULL)
			return ("derive takes no SPIs or keys: they come from the "
			    "agreement");
	} else {
		if (w->peer != NULL)
			return ("peer is derive's word");
		if (w->spi_in == 0 || w->spi_out == 0 || w->spi_in == w->spi_out)
			return ("spi-in and spi-out are needed, and differ");
		if (!hex_ok(w->key_in, encs[j].keylens) || !hex_ok(w->key_out,
		    encs[j].keylens))
			return ("key-in and key-out are hex of the algorithm's "
			    "length: 32, 48 or 64 digits for aes-cbc, 40, 56 or 72 "
			    "(the nonce after the key) for aes-gcm-16");
	}
	if (encs[j].aead) {
		if (w->auth != NULL || w->akey_in != NULL || w->akey_out != NULL)
			return ("aes-gcm-16 authenticates by itself: no auth");
		return (NULL);
	}
	for (j = 0; j < nitems(auths); j++)
		if (w->auth != NULL && strcmp(w->auth, auths[j].name) == 0)
			break;
	if (j == nitems(auths))
		return ("auth is hmac-sha1, hmac-sha2-256 or hmac-sha2-512 with "
		    "aes-cbc");
	if (!derive && (!hex_ok(w->akey_in, auths[j].keylens) || !hex_ok(
	    w->akey_out, auths[j].keylens)))
		return ("akey-in and akey-out are hex of the algorithm's length: "
		    "40 digits for hmac-sha1, 64 for hmac-sha2-256, 128 for "
		    "hmac-sha2-512");
	return (NULL);
}

/* What is wrong with the job, or NULL. */
const char *
sa_check(const struct arc_job_spec *sp)
{
	struct sa_words	w;
	int		af1, af2;

	if (sp->verb == NULL || (strcmp(sp->verb, "set") != 0 && strcmp(
	    sp->verb, "clear") != 0 && strcmp(sp->verb, "key") != 0 && strcmp(
	    sp->verb, "derive") != 0 && strcmp(sp->verb, "commit") != 0))
		return ("ipsec-sa: say key, set, derive, commit or clear");
	if (sp->interface == NULL || strncmp(sp->interface, "ipsec", 5) != 0 ||
	    sp->interface[5 + strspn(sp->interface + 5, "0123456789")] != '\0'
	    || sp->interface[5] == '\0')
		return ("ipsec-sa: the interface is an ipsec(4) one, ipsec0");
	if (strcmp(sp->verb, "key") == 0) {
		for (size_t i = 0; i < sp->names.n; i++)
			if (strcmp(sp->names.v[i], "next") != 0)
				return ("ipsec-sa key takes next at most: the pair "
				    "to come");
		return (NULL);
	}
	if (!sp->has_reqid || sp->reqid < 1 || sp->reqid > 16383)
		return ("ipsec-sa: the interface's reqid, 1 to 16383");
	if (!addr_ok(sp->tunnel_local, &af1) || !addr_ok(sp->tunnel_remote,
	    &af2) || af1 != af2)
		return ("ipsec-sa: tunnel-local and tunnel-remote are the outer "
		    "addresses, of one family");
	if (strcmp(sp->verb, "clear") == 0 || strcmp(sp->verb, "commit") == 0)
		return (NULL);
	return (sa_parse(sp, &w, strcmp(sp->verb, "derive") == 0));
}

static bool
word_next(const struct arc_job_spec *sp)
{

	for (size_t i = 0; i < sp->names.n; i++)
		if (strcmp(sp->names.v[i], "next") == 0)
			return (true);
	return (false);
}

/* A file for setkey -f, 0600, taken out again; what it said when strict. */
static int
sa_setkey(struct work *w, const char *text, bool strict, const char **errp)
{
	struct execres	 res;
	char		 path[] = "/tmp/arcana-sa.XXXXXX", *argv[4];
	FILE		*fp;
	int		 fd, rc;

	if ((fd = mkstemp(path)) == -1 || (fp = fdopen(fd, "w")) == NULL) {
		*errp = wfmt(w, "a file for setkey: %s", strerror(errno));
		if (fd != -1) {
			close(fd);
			(void)unlink(path);
		}
		return (-1);
	}
	(void)fchmod(fd, 0600);
	fputs(text, fp);
	fclose(fp);
	argv[0] = (char *)(uintptr_t)opts.setkey_bin;
	argv[1] = (char *)(uintptr_t)"-f";
	argv[2] = path;
	argv[3] = NULL;
	/* The file has the keys: what setkey says of it is not kept. */
	exec_set_secret(true);
	rc = run_exec(w, argv, &res);
	exec_set_secret(false);
	(void)unlink(path);
	if (rc != 0 && strict) {
		*errp = wfmt(w, "setkey: exit status %d%s%.200s", res.status,
		    res.errlen > 0 ? ": " : "", res.errlen > 0 ? res.err : "");
		return (-1);
	}
	return (0);
}

/*
 * One SA's line: ESP in tunnel mode on the interface's reqid, with an
 * anti-replay window of 1024 packets (R47) always: ESN without one has
 * the kernel's two ends disagree on the AAD of an AEAD cipher
 * (xform_esp.c, the window checked on input only), and every ICV
 * fails.
 */
static void
sa_add_line(char *buf, size_t len, const struct sa_words *sw, uint32_t reqid,
    const char *src, const char *dst, uint32_t spi, const char *key,
    const char *akey)
{
	size_t	n;

	n = strlen(buf);
	n += (size_t)snprintf(buf + n, len - n, "add %s %s esp %#x -m tunnel -u "
	    "%u -r 128%s", src, dst, spi, reqid, sw->esn ? " -esn" : "");
	if (sw->encap && n < len)
		n += (size_t)snprintf(buf + n, len - n, " -natt %s[4500] "
		    "%s[4500]", src, dst);
	if (n < len)
		n += (size_t)snprintf(buf + n, len - n, " -E %s 0x%s", sw->enc,
		    key);
	if (sw->auth != NULL && n < len)
		n += (size_t)snprintf(buf + n, len - n, " -A %s 0x%s", sw->auth,
		    akey);
	if (n < len)
		(void)snprintf(buf + n, len - n, " ;\n");
}

static void
sa_del_line(char *buf, size_t len, const char *src, const char *dst,
    uint32_t spi)
{
	size_t	n;

	n = strlen(buf);
	if (spi != 0 && n < len)
		(void)snprintf(buf + n, len - n, "delete %s %s esp %#x ;\n", src,
		    dst, spi);
}

/*
 * The SAs set, derived, turned or cleared.  set and derive put both
 * directions in (the old ones kept here taken out first, so a step
 * can be run again); derive with next, from the next pair, puts in
 * the directions install says and keeps the SPIs as the next ones, the
 * old outbound SA taken out with the new one in (the kernel keeps
 * sending on the old one otherwise, net.key.preferred_oldsa); commit
 * takes the old inbound SA out, makes the next pair the pair, and the
 * next SPIs the SPIs: a rotation in three steps on each end, in, out,
 * commit, so neither end sends on keys the other has not got, nor
 * drops what the other still sends (R110, R112).  The file for setkey
 * is 0600 and taken out again.
 */
static int
sa_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct sa_words	 sw;
	ucl_object_t	*stt;
	const char	*e, *l, *r;
	char		 pub[PUB_B64 + 1], kout[80], kin[80], aout[136], ain[136];
	char		 text[1600], del[400];
	unsigned char	 okm[2 * (36 + 64) + 8];
	size_t		 enclen, authlen, at;
	int		 step, rc;
	bool		 clear, derive, commit, rotate, lower, in, out;

	if ((e = sa_check(sp)) != NULL) {
		*errp = e;
		return (-1);
	}
	if (strcmp(sp->verb, "key") == 0) {
		rotate = word_next(sp);
		step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: "
		    "its %skey pair", sp->interface, rotate ? "next " : "");
		if (key_make(w, sp->interface, rotate, pub, sizeof(pub), errp) !=
		    0) {
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		step_end(w, step, true, "public %s", pub);
		return (0);
	}
	clear = strcmp(sp->verb, "clear") == 0;
	commit = strcmp(sp->verb, "commit") == 0;
	derive = strcmp(sp->verb, "derive") == 0;
	l = sp->tunnel_local;
	r = sp->tunnel_remote;
	memset(&sw, 0, sizeof(sw));
	kout[0] = kin[0] = aout[0] = ain[0] = '\0';
	text[0] = del[0] = '\0';
	if (!clear && !commit)
		(void)sa_parse(sp, &sw, derive);
	if ((stt = sa_state_load(w, sp->interface)) == NULL)
		stt = ucl_object_typed_new(UCL_OBJECT);
	rotate = derive && sw.next;
	in = sw.install != 2;
	out = sw.install != 1;
	if (clear) {
		snprintf(text, sizeof(text), "deleteall %s %s esp ;\ndeleteall %s "
		    "%s esp ;\n", l, r, r, l);
		(void)sa_setkey(w, text, false, errp);
		(void)unlink(key_path(w, sp->interface, true));
		(void)sa_state_save(w, sp->interface, NULL, errp);
		ucl_object_unref(stt);
		return (0);
	}
	if (commit) {
		if (ucl_object_lookup(stt, "next_spi_in") == NULL ||
		    ucl_object_lookup(stt, "next_spi_out") == NULL) {
			*errp = wfmt(w, "%s: nothing to commit: derive with next, "
			    "install in and out, first", sp->interface);
			ucl_object_unref(stt);
			return (-1);
		}
		if (access(key_path(w, sp->interface, true), F_OK) != 0) {
			*errp = wfmt(w, "%s has no next pair to commit",
			    sp->interface);
			ucl_object_unref(stt);
			return (-1);
		}
		step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: "
		    "the next keys the keys", sp->interface);
		/* The old inbound SA out (the outbound went with the new one
		 * in), the next pair the pair. */
		sa_del_line(del, sizeof(del), r, l, u32(stt, "spi_in"));
		if (del[0] != '\0')
			(void)sa_setkey(w, del, false, errp);
		if (rename(key_path(w, sp->interface, true), key_path(w,
		    sp->interface, false)) != 0) {
			*errp = wfmt(w, "%s: the next pair not made the pair: %s",
			    sp->interface, strerror(errno));
			step_end(w, step, false, "%s", *errp);
			ucl_object_unref(stt);
			return (-1);
		}
		ucl_object_replace_key(stt, ucl_object_fromint(u32(stt,
		    "next_spi_in")), "spi_in", 0, false);
		ucl_object_replace_key(stt, ucl_object_fromint(u32(stt,
		    "next_spi_out")), "spi_out", 0, false);
		ucl_object_replace_key(stt, ucl_object_fromint((int64_t)time(NULL)),
		    "at", 0, false);
		(void)ucl_object_delete_key(stt, "next_spi_in");
		(void)ucl_object_delete_key(stt, "next_spi_out");
		if (ucl_object_lookup(stt, "next_derive") != NULL)
			ucl_object_replace_key(stt, ucl_object_copy(ucl_object_lookup(
			    stt, "next_derive")), "derive", 0, false);
		else
			(void)ucl_object_delete_key(stt, "derive");
		(void)ucl_object_delete_key(stt, "next_derive");
		rc = sa_state_save(w, sp->interface, stt, errp);
		if (rc == 0)
			step_end(w, step, true, "spi in %#x out %#x", u32(stt,
			    "spi_in"), u32(stt, "spi_out"));
		else
			step_end(w, step, false, "%s", *errp);
		ucl_object_unref(stt);
		return (rc);
	}
	if (derive) {
		/* 256-bit AES, or GCM with its nonce; the HMAC of its size. */
		enclen = strcmp(sw.enc, "aes-gcm-16") == 0 ? 36 : 32;
		authlen = sw.auth == NULL ? 0 : strcmp(sw.auth, "hmac-sha1") == 0
		    ? 20 : strcmp(sw.auth, "hmac-sha2-256") == 0 ? 32 : 64;
		if (key_derive(w, sp->interface, sw.peer, sw.epoch, sw.next, okm,
		    2 * (enclen + authlen) + 8, &lower, errp) != 0) {
			ucl_object_unref(stt);
			return (-1);
		}
		/* A to B first: out for A, in for B. */
		at = 0;
		hex_of(okm + at, enclen, lower ? kout : kin);
		at += enclen;
		if (authlen > 0)
			hex_of(okm + at, authlen, lower ? aout : ain);
		at += authlen;
		hex_of(okm + at, enclen, lower ? kin : kout);
		at += enclen;
		if (authlen > 0)
			hex_of(okm + at, authlen, lower ? ain : aout);
		at += authlen;
		sw.spi_out = spi_of(okm + at + (lower ? 0 : 4));
		sw.spi_in = spi_of(okm + at + (lower ? 4 : 0));
		if (sw.spi_in == sw.spi_out)
			sw.spi_in ^= 1;
		sw.key_out = kout;
		sw.key_in = kin;
		sw.akey_out = authlen > 0 ? aout : NULL;
		sw.akey_in = authlen > 0 ? ain : NULL;
		OPENSSL_cleanse(okm, sizeof(okm));
	}
	/* What is being put in, taken out first where it is in already. */
	if (rotate) {
		if (in)
			sa_del_line(del, sizeof(del), r, l, u32(stt, "next_spi_in"));
		if (out)
			sa_del_line(del, sizeof(del), l, r, u32(stt,
			    "next_spi_out"));
	} else {
		sa_del_line(del, sizeof(del), r, l, u32(stt, "spi_in"));
		sa_del_line(del, sizeof(del), l, r, u32(stt, "spi_out"));
	}
	if (del[0] != '\0')
		(void)sa_setkey(w, del, false, errp);
	/* Out, then in. */
	if (out)
		sa_add_line(text, sizeof(text), &sw, sp->reqid, l, r, sw.spi_out,
		    sw.key_out, sw.akey_out);
	if (in)
		sa_add_line(text, sizeof(text), &sw, sp->reqid, r, l, sw.spi_in,
		    sw.key_in, sw.akey_in);
	rc = sa_setkey(w, text, true, errp);
	/* A rotation's new outbound SA in: the old one out at once, so this
	 * end sends on the new keys from here on, whatever the kernel
	 * prefers; the far end has the new inbound one already. */
	if (rc == 0 && rotate && out && u32(stt, "spi_out") != 0 && u32(stt,
	    "spi_out") != sw.spi_out) {
		del[0] = '\0';
		sa_del_line(del, sizeof(del), l, r, u32(stt, "spi_out"));
		(void)sa_setkey(w, del, false, errp);
	}
	OPENSSL_cleanse(text, sizeof(text));
	OPENSSL_cleanse(kout, sizeof(kout));
	OPENSSL_cleanse(kin, sizeof(kin));
	OPENSSL_cleanse(aout, sizeof(aout));
	OPENSSL_cleanse(ain, sizeof(ain));
	if (rc != 0) {
		ucl_object_unref(stt);
		return (-1);
	}
	/* Kept: the SPIs put in, for a rotation to take out; when; for how
	 * long; and a derive's words, so that a safe job not confirmed can
	 * put the SAs in again as they were (set by hand, they cannot be). */
	if (derive) {
		ucl_object_t	*d = derive_words(&sw);

		/* A rotation derives in, then out: both, once both are. */
		if (rotate && sw.install != 0 && ucl_object_lookup(stt,
		    "next_derive") != NULL && sstr(ucl_object_lookup(stt,
		    "next_derive"), "install") != NULL && strcmp(sstr(
		    ucl_object_lookup(stt, "next_derive"), "install"), sstr(d,
		    "install")) != 0)
			ucl_object_replace_key(d, ucl_object_fromstring("both"),
			    "install", 0, false);
		ucl_object_replace_key(stt, d, rotate ? "next_derive" : "derive",
		    0, false);
	} else
		(void)ucl_object_delete_key(stt, "derive");
	if (in)
		ucl_object_replace_key(stt, ucl_object_fromint(sw.spi_in), rotate ?
		    "next_spi_in" : "spi_in", 0, false);
	if (out)
		ucl_object_replace_key(stt, ucl_object_fromint(sw.spi_out), rotate ?
		    "next_spi_out" : "spi_out", 0, false);
	if (!rotate)
		ucl_object_replace_key(stt, ucl_object_fromint((int64_t)time(NULL)),
		    "at", 0, false);
	if (sw.lifetime != 0)
		ucl_object_replace_key(stt, ucl_object_fromint(sw.lifetime),
		    "lifetime", 0, false);
	rc = sa_state_save(w, sp->interface, stt, errp);
	ucl_object_unref(stt);
	return (rc);
}

/* ---- Safe mode ------------------------------------------------------ */

static const char *
sstr(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = o != NULL ? ucl_object_lookup(o, key) : NULL;
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* A derive's words as the state file keeps them: nothing secret, the
 * keys come from the pair and the peer's public half. */
static ucl_object_t *
derive_words(const struct sa_words *sw)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(sw->peer), "peer", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromint(sw->epoch), "epoch", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(sw->enc), "enc", 0,
	    false);
	if (sw->auth != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(sw->auth), "auth",
		    0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(sw->install == 1 ? "in" :
	    sw->install == 2 ? "out" : "both"), "install", 0, false);
	if (sw->encap)
		ucl_object_insert_key(o, ucl_object_frombool(true), "encap", 0,
		    false);
	if (sw->esn)
		ucl_object_insert_key(o, ucl_object_frombool(true), "esn", 0,
		    false);
	if (sw->lifetime != 0)
		ucl_object_insert_key(o, ucl_object_fromint(sw->lifetime),
		    "lifetime", 0, false);
	return (o);
}

/* The SAs derived again from the words kept, the pair's or the next's. */
static int
sa_rederive(struct work *w, const struct arc_job_spec *sp,
    const ucl_object_t *d, bool next, const char **errp)
{
	struct arc_job_spec	 s;
	const char		*v[20];
	size_t			 n;

	if (sstr(d, "peer") == NULL || sstr(d, "enc") == NULL) {
		*errp = wfmt(w, "%s: the words of its SAs were not kept whole",
		    sp->interface);
		return (-1);
	}
	n = 0;
	v[n++] = "peer";
	v[n++] = sstr(d, "peer");
	v[n++] = "epoch";
	v[n++] = wfmt(w, "%u", u32(d, "epoch"));
	v[n++] = "enc";
	v[n++] = sstr(d, "enc");
	if (sstr(d, "auth") != NULL) {
		v[n++] = "auth";
		v[n++] = sstr(d, "auth");
	}
	v[n++] = "install";
	v[n++] = sstr(d, "install") != NULL ? sstr(d, "install") : "both";
	if (ucl_object_toboolean(ucl_object_lookup(d, "encap")))
		v[n++] = "encap";
	if (ucl_object_toboolean(ucl_object_lookup(d, "esn")))
		v[n++] = "esn";
	if (u32(d, "lifetime") != 0) {
		v[n++] = "lifetime";
		v[n++] = wfmt(w, "%u", u32(d, "lifetime"));
	}
	if (next)
		v[n++] = "next";
	s = *sp;
	s.verb = "derive";
	s.names.n = n;
	s.names.v = v;
	return (sa_job(w, &s, errp));
}

/* The files a safe job puts back: the pair, the next pair, the state. */
void
sa_files(struct work *w, const char *ifname, const char **key,
    const char **next, const char **state)
{
	char	buf[MAXPATHLEN];

	*key = key_path(w, ifname, false);
	*next = key_path(w, ifname, true);
	sdwan_conf_path(wfmt(w, STATE_FILE, ifname), buf, sizeof(buf));
	*state = wstrdup(w, buf);
}

/*
 * Can a safe job of this spec be undone?  A key pair made is put back
 * from its file; the SAs in place come back only when they were
 * derived, their words kept: set by hand, their keys are nowhere.
 * NULL, or why not.
 */
const char *
sa_undo_check(struct work *w, const struct arc_job_spec *sp)
{
	ucl_object_t	*stt;
	const char	*e;

	if (sp->verb == NULL || sp->interface == NULL || strcmp(sp->verb,
	    "key") == 0)
		return (NULL);
	if ((stt = sa_state_load(w, sp->interface)) == NULL)
		return (NULL);
	e = NULL;
	if (((u32(stt, "spi_in") != 0 || u32(stt, "spi_out") != 0) &&
	    ucl_object_lookup(stt, "derive") == NULL) || ((u32(stt,
	    "next_spi_in") != 0 || u32(stt, "next_spi_out") != 0) &&
	    ucl_object_lookup(stt, "next_derive") == NULL))
		e = wfmt(w, "%s: the SAs in place were set by hand, not "
		    "derived, and could not be put back: not in safe mode",
		    sp->interface);
	ucl_object_unref(stt);
	return (e);
}

/*
 * After the files are back as they were: the kernel's SAs of the pair
 * gone, and those the state file says were in derived again, the
 * pair's and the next pair's.
 */
int
sa_undo(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	ucl_object_t	*stt;
	char		 text[400];
	int		 step, rc;
	bool		 any;

	if (strcmp(sp->verb, "key") == 0)
		return (0);
	step = step_begin(w, STEP_DAEMON, "arcana-agent", "%s: its "
	    "SAs as they were", sp->interface);
	snprintf(text, sizeof(text), "deleteall %s %s esp ;\ndeleteall %s %s "
	    "esp ;\n", sp->tunnel_local, sp->tunnel_remote, sp->tunnel_remote,
	    sp->tunnel_local);
	(void)sa_setkey(w, text, false, errp);
	rc = 0;
	any = false;
	if ((stt = sa_state_load(w, sp->interface)) != NULL) {
		if ((u32(stt, "spi_in") != 0 || u32(stt, "spi_out") != 0) &&
		    ucl_object_lookup(stt, "derive") != NULL) {
			rc = sa_rederive(w, sp, ucl_object_lookup(stt, "derive"),
			    false, errp);
			any = true;
		}
		if (rc == 0 && (u32(stt, "next_spi_in") != 0 || u32(stt,
		    "next_spi_out") != 0) && ucl_object_lookup(stt,
		    "next_derive") != NULL) {
			rc = sa_rederive(w, sp, ucl_object_lookup(stt,
			    "next_derive"), true, errp);
			any = true;
		}
		ucl_object_unref(stt);
	}
	if (rc != 0)
		step_end(w, step, false, "%s", *errp);
	else
		step_end(w, step, true, any ? "derived again as kept" : "none "
		    "were in: none put in");
	return (rc);
}

/* A rotation that fails is a fault on the interface, until one is done. */
int
do_sa_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	int	rc;
	bool	rotation;

	rc = sa_job(w, sp, errp);
	rotation = sp->verb != NULL && sp->interface != NULL && (strcmp(sp->verb,
	    "commit") == 0 || (strcmp(sp->verb, "derive") == 0 && word_next(sp)));
	if (rotation && rc != 0)
		fault_set("key-rotation", "Major", sp->interface, "arcana-agent",
		    "the keys of %s were not turned: %s", sp->interface, *errp);
	else if (rotation && strcmp(sp->verb, "commit") == 0)
		fault_clear("key-rotation", sp->interface, "the keys of %s turned",
		    sp->interface);
	return (rc);
}
