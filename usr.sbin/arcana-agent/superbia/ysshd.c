/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: sshd as YANG, arcana-sshd: the ssh operation's JSON
 * (ssh.c) read back into the module's structs.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32], *p;
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

#define	ALLOC_N(a, p, n)	(((p) = cbl_yarena_alloc((a), ((n) + 1) * \
	sizeof(*(p)))) != NULL)

int
ysshd_from_json(const char *json, cbl_yarena *a,
    struct arcana_sshd_sshd *out)
{
	struct arcana_sshd_sshd_setting			*st;
	struct arcana_sshd_sshd_host_key		*hk;
	struct arcana_sshd_sshd_host_key_certificate	*ce;
	struct arcana_sshd_sshd_user			*us;
	struct arcana_sshd_sshd_user_key		*uk;
	const ucl_object_t				*e, *o, *ee;
	ucl_object_iter_t				 it, eit;
	ucl_object_t					*top;
	int64_t						 n;
	size_t						 k, m;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	/* The settings: an object, each key an array of values. */
	o = ucl_object_lookup(top, "settings");
	if (!ALLOC_N(a, st, o != NULL ? ucl_object_type(o) == UCL_OBJECT ?
	    (size_t)64 : 0 : 0))
		goto nomem;
	k = 0;
	it = NULL;
	while (o != NULL && ucl_object_type(o) == UCL_OBJECT && k < 64 && (e =
	    ucl_object_iterate(o, &it, true)) != NULL) {
		const char	*key = ucl_object_key(e);
		char		*d;

		if (key == NULL)
			continue;
		memset(&st[k], 0, sizeof(st[k]));
		if ((d = cbl_yarena_alloc(a, strlen(key) + 1)) == NULL)
			goto nomem;
		memcpy(d, key, strlen(key) + 1);
		st[k].name = d;
		if (ucl_object_type(e) == UCL_ARRAY) {
			if (yj_strs(a, e, &st[k].value.n, &st[k].value.v) != 0)
				goto nomem;
		} else {
			const char	**one;
			const char	 *s = ucl_object_tostring_forced(e);

			if (!ALLOC_N(a, one, 1) || (d = cbl_yarena_alloc(a,
			    strlen(s) + 1)) == NULL)
				goto nomem;
			memcpy(d, s, strlen(s) + 1);
			one[0] = d;
			st[k].value.n = 1;
			st[k].value.v = one;
		}
		k++;
	}
	out->setting.n = k;
	out->setting.v = st;
	out->settings_from_file = yj_str(a, top, "settings_from_file");
	out->banner = yj_str(a, top, "banner_text");
	/* The host keys. */
	if (!ALLOC_N(a, hk, yj_count(ucl_object_lookup(top, "host_keys"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "host_keys"), it, e) {
		memset(&hk[k], 0, sizeof(hk[k]));
		if ((hk[k].path = yj_str(a, e, "path")) == NULL)
			continue;
		hk[k].type = yj_str(a, e, "type");
		YJ_NUM(e, "bits", &hk[k], bits);
		hk[k].fingerprint = yj_str(a, e, "fingerprint");
		hk[k].comment = yj_str(a, e, "comment");
		if ((o = ucl_object_lookup(e, "certificate")) != NULL &&
		    ucl_object_type(o) == UCL_OBJECT) {
			if (!ALLOC_N(a, ce, 0))
				goto nomem;
			memset(ce, 0, sizeof(*ce));
			ce->kind = yj_str(a, o, "kind");
			ce->id = yj_str(a, o, "id");
			if (yj_strs(a, ucl_object_lookup(o, "principals"),
			    &ce->principal.n, &ce->principal.v) != 0)
				goto nomem;
			/* -1: forever. */
			if (yj_num(o, "valid_after", &n) && n >= 0)
				ce->valid_after = datetime(a, n);
			if (yj_num(o, "valid_before", &n) && n >= 0)
				ce->valid_before = datetime(a, n);
			ce->ca = yj_str(a, o, "ca");
			hk[k].certificate = ce;
		}
		hk[k].certificate_used = yj_yes(e, "certificate_used",
		    &hk[k].has_certificate_used);
		k++;
	}
	out->host_key.n = k;
	out->host_key.v = hk;
	/* The users. */
	if (!ALLOC_N(a, us, yj_count(ucl_object_lookup(top, "users"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "users"), it, e) {
		memset(&us[k], 0, sizeof(us[k]));
		if ((us[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		YJ_NUM(e, "uid", &us[k], uid);
		us[k].home = yj_str(a, e, "home");
		us[k].shell = yj_str(a, e, "shell");
		us[k].keys_file = yj_str(a, e, "keys_file");
		if (!ALLOC_N(a, uk, yj_count(ucl_object_lookup(e, "keys"))))
			goto nomem;
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "keys"), eit, ee) {
			memset(&uk[m], 0, sizeof(uk[m]));
			if ((uk[m].fingerprint = yj_str(a, ee, "fingerprint")) ==
			    NULL)
				continue;
			uk[m].type = yj_str(a, ee, "type");
			YJ_NUM(ee, "bits", &uk[m], bits);
			uk[m].comment = yj_str(a, ee, "comment");
			uk[m].options = yj_str(a, ee, "options");
			m++;
		}
		us[k].key.n = m;
		us[k].key.v = uk;
		k++;
	}
	out->user.n = k;
	out->user.v = us;
	if (yj_strs(a, ucl_object_lookup(top, "user_cas"), &out->user_ca.n,
	    &out->user_ca.v) != 0)
		goto nomem;
	out->before_kept = yj_yes(top, "before_kept", &out->has_before_kept);
	ucl_object_unref(top);
	return (0);
nomem:
	ucl_object_unref(top);
	return (ENOMEM);
}
