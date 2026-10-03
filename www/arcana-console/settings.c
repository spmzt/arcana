/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's settings, changed from the console.
 *
 * web.conf is the administrator's and often not the worker's to write,
 * so what is set here goes to settings.json in the data directory and
 * overrides web.conf for the settings that can change while the console
 * runs.  The others are shown and not changed: the relying party and
 * the origin, which every registered key is bound to, the data
 * directory and the certificates.  A wrong value there locks everyone
 * out, and they are read once, at the start.
 *
 * Other workers see a change at their next request: config_refresh()
 * reads the file again when it has changed.  Values are replaced and
 * the old ones not freed, as a task thread may still hold one.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "console.h"

#define	SETTINGS_FILE	"settings.json"

enum kind { K_TEXT, K_BOOL };

static const char	*v_name(const char *);
static const char	*v_url(const char *);
static const char	*v_path(const char *);
static const char	*v_source(const char *);
static const char	*v_ref(const char *);

static struct setting {
	const char	*key;
	enum kind	 kind;
	const char	*label;
	const char	*help;
	const char	*(*valid)(const char *);	/* NULL, or why not */
	char		*base;				/* from web.conf */
	char		*over;				/* from settings.json */
} settings[] = {
	{ "rp_name", K_TEXT, "Name shown by security keys",
	    "What a key or passkey calls this console when it asks.", v_name,
	    NULL, NULL },
	{ "update_check", K_BOOL, "Check for new releases",
	    "Ask the release feed every few hours and say when a newer "
	    "version is out.", NULL, NULL, NULL },
	{ "update_url", K_TEXT, "Release feed",
	    "A URL in the shape of GitHub's releases/latest.", v_url, NULL,
	    NULL },
	{ "agent_binary", K_TEXT, "arcana-agent to send",
	    "The program sent to hosts when they are updated, until a host "
	    "has built one from the repository below.", v_path, NULL, NULL },
	{ "agent_source", K_TEXT, "Repository to build arcana-agent from",
	    "A git repository with the Arcana tree. With one set, a host can "
	    "be asked to build the agent; empty for none. Whoever sets this "
	    "decides what runs as root on every host.", v_source, NULL,
	    NULL },
	{ "agent_ref", K_TEXT, "Branch or tag to build",
	    "Empty for the repository's own.", v_ref, NULL, NULL },
};

static struct timespec	loaded;		/* settings.json's mtime when read */

static const char *
v_name(const char *s)
{

	if (s[0] == '\0' || strlen(s) > 64)
		return ("a name of 1 to 64 characters");
	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return ("no control characters");
	return (NULL);
}

static const char *
v_url(const char *s)
{

	if (strncmp(s, "https://", 8) != 0 || strlen(s) > 512)
		return ("an https:// URL");
	for (; *s != '\0'; s++)
		if (!isgraph((unsigned char)*s))
			return ("an https:// URL");
	return (NULL);
}

static const char *
v_path(const char *s)
{

	if (s[0] != '/' || strlen(s) > 512)
		return ("an absolute path");
	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return ("an absolute path");
	return (NULL);
}

/* What git clone takes, and never an option; empty for none. */
static const char *
v_source(const char *s)
{

	if (s[0] == '-' || strlen(s) > 1024)
		return ("a git repository");
	for (; *s != '\0'; s++)
		if (!isgraph((unsigned char)*s))
			return ("a git repository, without blanks");
	return (NULL);
}

static const char *
v_ref(const char *s)
{

	if (s[0] == '-' || strlen(s) > 128)
		return ("a branch or tag name");
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("._/-", *s) == NULL)
			return ("a branch or tag name");
	return (NULL);
}

static struct setting *
find(const char *key)
{
	size_t	i;

	for (i = 0; i < nitems(settings); i++)
		if (strcmp(settings[i].key, key) == 0)
			return (&settings[i]);
	return (NULL);
}

/* What is in force: the override, or what web.conf says. */
static const char *
value(const char *key)
{
	struct setting	*s;

	s = find(key);
	return (s->over != NULL ? s->over : s->base != NULL ? s->base : "");
}

static bool
truth(const char *v)
{

	return (strcmp(v, "true") == 0);
}

/* Put what is in force into cfg.  Old strings stay: see above. */
static void
apply(void)
{
	const char	*v;

	cfg.rp_name = kore_strdup(value("rp_name"));
	cfg.update_url = truth(value("update_check")) ?
	    kore_strdup(value("update_url")) : NULL;
	cfg.agent_binary = kore_strdup(value("agent_binary"));
	v = value("agent_source");
	cfg.agent_source = v[0] != '\0' ? kore_strdup(v) : NULL;
	v = value("agent_ref");
	cfg.agent_ref = v[0] != '\0' ? kore_strdup(v) : NULL;
}

static void
load(void)
{
	ucl_object_t		*o;
	const ucl_object_t	*v;
	struct stat		 sb;
	char			 path[1024];
	size_t			 i;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SETTINGS_FILE);
	memset(&loaded, 0, sizeof(loaded));
	if (stat(path, &sb) == 0)
		loaded = sb.st_mtim;
	o = store_load(SETTINGS_FILE);
	for (i = 0; i < nitems(settings); i++) {
		settings[i].over = NULL;
		if (o == NULL || (v = ucl_object_lookup(o,
		    settings[i].key)) == NULL)
			continue;
		settings[i].over = kore_strdup(settings[i].kind == K_BOOL ?
		    (ucl_object_toboolean(v) ? "true" : "false") :
		    ucl_object_tostring_forced(v));
		/* A hand-edited file is checked as a request is. */
		if (settings[i].valid != NULL && settings[i].over[0] != '\0' &&
		    settings[i].valid(settings[i].over) != NULL) {
			kore_log(LOG_WARNING, "%s: %s: not %s; ignored", path,
			    settings[i].key,
			    settings[i].valid(settings[i].over));
			settings[i].over = NULL;
		}
	}
	if (o != NULL)
		ucl_object_unref(o);
	apply();
}

/*
 * After web.conf is read: remember what it says for the settings that
 * can change, then read the overrides.
 */
void
settings_init(const char *update_check, const char *update_url)
{

	find("rp_name")->base = cfg.rp_name;
	find("update_check")->base = kore_strdup(update_check);
	find("update_url")->base = kore_strdup(update_url);
	find("agent_binary")->base = cfg.agent_binary;
	find("agent_source")->base = cfg.agent_source;
	find("agent_ref")->base = cfg.agent_ref;
	load();
}

/* Another worker may have changed the settings: read them again. */
void
config_refresh(void)
{
	struct stat	sb;
	char		path[1024];

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SETTINGS_FILE);
	if (stat(path, &sb) == -1) {
		if (loaded.tv_sec != 0)
			load();
		return;
	}
	if (sb.st_mtim.tv_sec != loaded.tv_sec || sb.st_mtim.tv_nsec !=
	    loaded.tv_nsec)
		load();
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, false);
}

static ucl_object_t *
fixed(const char *key, const char *label, const char *v)
{
	ucl_object_t	*e;

	e = ucl_object_typed_new(UCL_OBJECT);
	put(e, "key", ucl_object_fromstring(key));
	put(e, "label", ucl_object_fromstring(label));
	put(e, "value", ucl_object_fromstring(v != NULL ? v : ""));
	put(e, "editable", ucl_object_frombool(false));
	return (e);
}

static int
reply(struct http_request *req)
{
	ucl_object_t	*o, *a, *e;
	char		 path[1024];
	size_t		 i;

	o = ucl_object_typed_new(UCL_OBJECT);
	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nitems(settings); i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "key", ucl_object_fromstring(settings[i].key));
		put(e, "label", ucl_object_fromstring(settings[i].label));
		put(e, "help", ucl_object_fromstring(settings[i].help));
		put(e, "type", ucl_object_fromstring(settings[i].kind ==
		    K_BOOL ? "bool" : "text"));
		put(e, "value", ucl_object_fromstring(value(settings[i].key)));
		put(e, "base", ucl_object_fromstring(settings[i].base != NULL ?
		    settings[i].base : ""));
		put(e, "overridden", ucl_object_frombool(settings[i].over !=
		    NULL));
		put(e, "editable", ucl_object_frombool(true));
		ucl_array_append(a, e);
	}
	/* Read once, at the start, from web.conf alone. */
	ucl_array_append(a, fixed("rp_id", "Relying party", cfg.rp_id));
	ucl_array_append(a, fixed("origin", "Origin", cfg.origin));
	ucl_array_append(a, fixed("datadir", "Data directory", cfg.datadir));
	ucl_array_append(a, fixed("cookie_secure", "Session cookie over "
	    "HTTPS only", cfg.cookie_secure ? "true" : "false"));
	ucl_array_append(a, fixed("tls", "Certificates for the agents",
	    cfg.tls_own ? "the console's own CA, in the data directory" :
	    cfg.tls_cert));
	put(o, "settings", a);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SETTINGS_FILE);
	put(o, "file", ucl_object_fromstring(path));
	return (reply_json(req, 200, o));
}

/*
 * GET /api/settings: every setting with its value, what web.conf says,
 * and whether it can be changed here.
 * POST, {"set": {"agent_source": "https://…", "update_check": false}}:
 * change some.  A value equal to web.conf's, or null, drops the
 * override.
 */
int
api_settings(struct http_request *req)
{
	ucl_object_t		*body, *out;
	const ucl_object_t	*set, *v;
	ucl_object_iter_t	 it;
	struct setting		*s;
	const char		*val, *why;
	char			*next[nitems(settings)];
	size_t			 i;

	if (!guard(req, req->method == HTTP_METHOD_POST))
		return (KORE_RESULT_OK);
	if (req->method != HTTP_METHOD_POST)
		return (reply(req));
	if ((body = read_json(req)) == NULL || (set = ucl_object_lookup(body,
	    "set")) == NULL || ucl_object_type(set) != UCL_OBJECT) {
		if (body != NULL)
			ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a \"set\" object is "
		    "needed"));
	}
	/* All of it is checked before any of it is kept. */
	for (i = 0; i < nitems(settings); i++)
		next[i] = settings[i].over;
	it = NULL;
	while ((v = ucl_object_iterate(set, &it, true)) != NULL) {
		if ((s = find(ucl_object_key(v))) == NULL) {
			reply_error(req, 400, "invalid", "%s cannot be set "
			    "here", ucl_object_key(v));
			ucl_object_unref(body);
			return (KORE_RESULT_OK);
		}
		i = (size_t)(s - settings);
		if (ucl_object_type(v) == UCL_NULL) {
			next[i] = NULL;
			continue;
		}
		val = s->kind == K_BOOL ? (ucl_object_toboolean(v) ? "true" :
		    "false") : ucl_object_tostring_forced(v);
		/* Empty means none, where there can be none. */
		why = s->valid != NULL && !(val[0] == '\0' && (s->valid ==
		    v_source || s->valid == v_ref)) ? s->valid(val) : NULL;
		if (why != NULL) {
			reply_error(req, 400, "invalid", "%s: not %s", s->label,
			    why);
			ucl_object_unref(body);
			return (KORE_RESULT_OK);
		}
		next[i] = strcmp(val, s->base != NULL ? s->base : "") == 0 ?
		    NULL : kore_strdup(val);
	}
	ucl_object_unref(body);

	out = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; i < nitems(settings); i++) {
		if (next[i] == NULL)
			continue;
		put(out, settings[i].key, settings[i].kind == K_BOOL ?
		    ucl_object_frombool(truth(next[i])) :
		    ucl_object_fromstring(next[i]));
	}
	if (store_save(SETTINGS_FILE, out) == -1) {
		ucl_object_unref(out);
		return (reply_error(req, 500, "io", "cannot write %s in the "
		    "data directory", SETTINGS_FILE));
	}
	ucl_object_unref(out);
	kore_log(LOG_NOTICE, "settings changed from the console");
	load();
	return (reply(req));
}
