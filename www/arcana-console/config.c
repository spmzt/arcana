/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <sys/types.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"

struct config cfg;

static char	*get(const ucl_object_t *, const char *, const char *);
static int	 android_load(const ucl_object_t *, const char *);
static int	 hexval(int);
static int	 check_pem(const char *, const char *, bool, int *);

static char *
get(const ucl_object_t *top, const char *path, const char *def)
{
	const ucl_object_t	*o;
	const char		*s;

	o = ucl_object_lookup_path(top, path);
	s = o != NULL ? ucl_object_tostring_forced(o) : def;
	return (s != NULL ? kore_strdup(s) : NULL);
}

/*
 * web.conf:
 *
 *	rp_id = "console.example";		# WebAuthn relying party
 *	origin = "https://console.example";
 *	datadir = "/var/db/arcana";
 *	cookie_secure = true;
 *	tls { ca = "..."; cert = "..."; key = "..."; }	# for arcana-agent
 *
 * Without tls, the console runs its own CA from datadir (pki.c).  With
 * it, tls.ca_key names the CA's key when the console is to enrol hosts.
 * update_check = false stops the release checks; update_url names
 * another feed in GitHub's releases/latest shape.  sendmail names what
 * mail goes out by (/usr/sbin/sendmail), mail_tick the seconds between
 * reads of the hosts' events for it (15); mail_to, mail_from,
 * mail_faults, mail_jobs, mail_runs and mail_limits what Settings
 * starts from.
 *
 *	android { package = "..."; fingerprints = [ "AB:CD:..." ]; }
 *
 * names the Android app that may log in (android_load()).
 */
int
config_load(const char *path)
{
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*o;
	char			*url;
	bool			 check;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO);
	if (!ucl_parser_add_file(p, path)) {
		kore_log(LOG_ERR, "%s: %s", path, ucl_parser_get_error(p));
		ucl_parser_free(p);
		return (-1);
	}
	top = ucl_parser_get_object(p);
	ucl_parser_free(p);

	cfg.rp_id = get(top, "rp_id", NULL);
	cfg.session_idle = SESSION_IDLE;
	cfg.session_max = SESSION_MAX;
	cfg.rp_name = get(top, "rp_name", "Arcana");
	cfg.origin = get(top, "origin", NULL);
	cfg.datadir = get(top, "datadir", "/var/db/arcana");
	o = ucl_object_lookup(top, "cookie_secure");
	cfg.cookie_secure = o == NULL || ucl_object_toboolean(o);
	cfg.tls_ca = get(top, "tls.ca", NULL);
	cfg.tls_ca_key = get(top, "tls.ca_key", NULL);
	cfg.tls_cert = get(top, "tls.cert", NULL);
	cfg.tls_key = get(top, "tls.key", NULL);
	cfg.tls_own = ucl_object_lookup(top, "tls") == NULL;
	o = ucl_object_lookup(top, "update_check");
	check = o == NULL || ucl_object_toboolean(o);
	url = get(top, "update_url", ARCW_RELEASES);
	cfg.agent_binary = get(top, "agent_binary", ARCW_AGENT_BINARY);
	cfg.agent_source = get(top, "agent_source", NULL);
	cfg.agent_ref = get(top, "agent_ref", NULL);
	cfg.agent_ssh_key = get(top, "agent_ssh_key", NULL);
	cfg.sendmail = get(top, "sendmail", "/usr/sbin/sendmail");
	/* What Settings shows as web.conf's; the settings' own checks. */
	cfg.mail_to = get(top, "mail_to", "");
	cfg.mail_from = get(top, "mail_from", "");
	cfg.mail_faults = get(top, "mail_faults", "Major");
	cfg.mail_jobs = get(top, "mail_jobs", "failed");
	cfg.mail_runs = get(top, "mail_runs", "failed");
	o = ucl_object_lookup(top, "mail_limits");
	cfg.mail_limits = o == NULL || ucl_object_toboolean(o);
	o = ucl_object_lookup(top, "mail_tick");
	cfg.mail_tick = o != NULL && ucl_object_toint(o) >= 1 &&
	    ucl_object_toint(o) <= 3600 ? (int)ucl_object_toint(o) : 15;
	/* Empty says: do not look for an agent beside the console. */
	cfg.local_agent = get(top, "local_agent", ARCW_LOCAL_AGENT);
	if (cfg.local_agent != NULL && cfg.local_agent[0] == '\0')
		cfg.local_agent = NULL;
	if (android_load(top, path) == -1) {
		ucl_object_unref(top);
		return (-1);
	}
	ucl_object_unref(top);

	if (cfg.rp_id == NULL || cfg.origin == NULL) {
		kore_log(LOG_ERR, "%s: rp_id and origin are required", path);
		return (-1);
	}
	/* What the console itself changed overrides some of that. */
	settings_init(check ? "true" : "false", url);
	return (0);
}

/*
 * The Android app: its package name and the SHA-256 fingerprints of
 * the certificates it is signed with, as apksigner(1) or keytool(1)
 * print them, with or without colons.  A login made in the app comes
 * with the origin android:apk-key-hash:<base64url of one of them>
 * (auth.c), and /.well-known/assetlinks.json names the app with them,
 * which Android asks before it lets the app use the console's keys.
 */
static int
android_load(const ucl_object_t *top, const char *path)
{
	const ucl_object_t	*a, *fps, *fp;
	ucl_object_iter_t	 it;
	const char		*s;
	int			 n, hi, lo;

	cfg.android_package = NULL;
	cfg.nandroid_keys = 0;
	if ((a = ucl_object_lookup(top, "android")) == NULL)
		return (0);
	cfg.android_package = get(a, "package", NULL);
	if (cfg.android_package == NULL || cfg.android_package[0] == '\0' ||
	    strspn(cfg.android_package, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") !=
	    strlen(cfg.android_package)) {
		kore_log(LOG_ERR, "%s: android.package must be the app's "
		    "package name", path);
		return (-1);
	}
	fps = ucl_object_lookup(a, "fingerprints");
	it = NULL;
	while (fps != NULL && (fp = ucl_object_iterate(fps, &it, true)) !=
	    NULL) {
		if (cfg.nandroid_keys == ANDROID_KEYS) {
			kore_log(LOG_ERR, "%s: android.fingerprints: at most %d",
			    path, ANDROID_KEYS);
			return (-1);
		}
		s = ucl_object_tostring_forced(fp);
		for (n = 0; *s != '\0' && n < 32; n++) {
			if (*s == ':')
				s++;
			hi = hexval((unsigned char)s[0]);
			lo = hi != -1 ? hexval((unsigned char)s[1]) : -1;
			if (lo == -1)
				break;
			cfg.android_keys[cfg.nandroid_keys][n] =
			    (uint8_t)(hi << 4 | lo);
			s += 2;
		}
		if (*s != '\0' || n != 32) {
			kore_log(LOG_ERR, "%s: android.fingerprints: %s is not "
			    "a SHA-256 fingerprint", path,
			    ucl_object_tostring_forced(fp));
			return (-1);
		}
		cfg.nandroid_keys++;
	}
	if (cfg.nandroid_keys == 0) {
		kore_log(LOG_ERR, "%s: android.fingerprints names no key", path);
		return (-1);
	}
	kore_log(LOG_INFO, "the Android app %s may log in (%d signing key%s)",
	    cfg.android_package, cfg.nandroid_keys,
	    cfg.nandroid_keys == 1 ? "" : "s");
	return (0);
}

static int
hexval(int c)
{

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return (-1);
}

/*
 * Read a PEM certificate or key at path; *keytype gets the key's
 * EVP_PKEY type.  A file the worker may not read is reported but not
 * an error: Kore's key manager reads the server's keys as root.
 */
static int
check_pem(const char *what, const char *path, bool cert, int *keytype)
{
	FILE		*fp;
	X509		*x;
	EVP_PKEY	*pk;

	if (path == NULL)
		return (0);
	if ((fp = fopen(path, "r")) == NULL) {
		if (errno == EACCES) {
			kore_log(LOG_NOTICE, "%s %s: not readable by the worker; "
			    "not checked", what, path);
			return (0);
		}
		kore_log(LOG_ERR, "%s %s: %s", what, path, strerror(errno));
		return (-1);
	}
	if (cert) {
		x = PEM_read_X509(fp, NULL, NULL, NULL);
		pk = x != NULL ? X509_get_pubkey(x) : NULL;
		X509_free(x);
	} else
		pk = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (pk == NULL) {
		kore_log(LOG_ERR, "%s %s: not a PEM %s: %s", what, path,
		    cert ? "certificate" : "private key",
		    ERR_reason_error_string(ERR_get_error()));
		ERR_clear_error();
		return (-1);
	}
	*keytype = EVP_PKEY_get_base_id(pk);
	EVP_PKEY_free(pk);
	return (0);
}

/*
 * Check the certificates before serving: the console's own in Kore's
 * domains, which its key manager signs with only when they are RSA and
 * otherwise refuses with "unknown public key in certificate" once the
 * workers are up, and the client certificate and CA of web.conf.
 */
int
config_check_certs(void)
{
	struct kore_server	*srv;
	struct kore_domain	*dom;
	int			 type, rc;

	rc = 0;
	LIST_FOREACH(srv, &kore_servers, list) {
		TAILQ_FOREACH(dom, &srv->domains, list) {
			type = EVP_PKEY_NONE;
			if (check_pem("certfile", dom->certfile, true,
			    &type) == -1)
				rc = -1;
			else if (type != EVP_PKEY_NONE && type != EVP_PKEY_RSA) {
				kore_log(LOG_ERR, "certfile %s: not an RSA "
				    "certificate; kore(1) serves no other kind",
				    dom->certfile);
				rc = -1;
			}
			if (check_pem("certkey", dom->certkey, false,
			    &type) == -1)
				rc = -1;
		}
	}
	if (check_pem("tls.ca", cfg.tls_ca, true, &type) == -1 ||
	    check_pem("tls.ca_key", cfg.tls_ca_key, false, &type) == -1 ||
	    check_pem("tls.cert", cfg.tls_cert, true, &type) == -1 ||
	    check_pem("tls.key", cfg.tls_key, false, &type) == -1)
		rc = -1;
	return (rc);
}
