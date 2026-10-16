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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "console.h"

#define	SETTINGS_FILE	"settings.json"

/* K_SECRET: text kept, and never sent back: only whether it is set. */
enum kind { K_TEXT, K_BOOL, K_SECRET };

static const char	*v_name(const char *);
static const char	*v_url(const char *);
static const char	*v_path(const char *);
static const char	*v_binary(const char *);
static const char	*v_source(const char *);
static const char	*v_ref(const char *);
static const char	*v_keypath(const char *);
static const char	*v_minutes(const char *);
static const char	*v_hours(const char *);
static const char	*v_mails(const char *);
static const char	*v_mail(const char *);
static const char	*v_severity(const char *);
static const char	*v_which(const char *);
static const char	*v_via(const char *);
static const char	*v_host(const char *);
static const char	*v_port(const char *);
static const char	*v_security(const char *);
static const char	*v_user(const char *);
static const char	*v_secret(const char *);
static const char	*v_safe(const char *);
static const char	*v_tgtoken(const char *);
static const char	*v_chats(const char *);
static const char	*v_sender(const char *);

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
	    "has built one from the repository below.", v_binary, NULL, NULL },
	{ "agent_source", K_TEXT, "Repository to build arcana-agent from",
	    "A git repository with the Arcana tree. With one set, a host can "
	    "be asked to build the agent; empty for none. Whoever sets this "
	    "decides what runs as root on every host.", v_source, NULL,
	    NULL },
	{ "agent_ref", K_TEXT, "Branch or tag to build",
	    "Empty for the repository's own.", v_ref, NULL, NULL },
	{ "agent_ssh_key", K_TEXT, "SSH key for git, on the host that builds",
	    "For a repository reached over SSH: the path of a private key "
	    "on the build host, readable by nobody, whom git runs as. Empty "
	    "for a key the host makes for itself and shows you, to allow as "
	    "a deploy key.", v_keypath, NULL, NULL },
	{ "session_idle", K_TEXT, "Signed out after, idle, in minutes",
	    "A sign-in not used for this long ends: from 5 to 1440 minutes.",
	    v_minutes, NULL, NULL },
	{ "session_max", K_TEXT, "A sign-in lasts at most, in hours",
	    "However much it is used: from 1 to 720 hours. Changed, it holds "
	    "for the sign-ins there are too.", v_hours, NULL, NULL },
	{ "mail_to", K_TEXT, "Mail to",
	    "Addresses, a comma between them; empty for no mail. Sent by "
	    "sendmail(8) on the console's host: dma(8) as FreeBSD comes, "
	    "relaying as /etc/dma/dma.conf says.", v_mails, NULL, NULL },
	{ "mail_from", K_TEXT, "Mail from",
	    "The sender's address; empty for arcana@ this host's name.",
	    v_mail, NULL, NULL },
	{ "mail_faults", K_TEXT, "Faults mailed",
	    "The least severity mailed, and their clearing: Critical, Major, "
	    "Minor or Warning; none for none.", v_severity, NULL, NULL },
	{ "mail_jobs", K_TEXT, "Jobs mailed",
	    "failed, all or none.", v_which, NULL, NULL },
	{ "mail_runs", K_TEXT, "Workflow runs mailed",
	    "failed, all or none.", v_which, NULL, NULL },
	{ "mail_limits", K_BOOL, "Limits crossed mailed",
	    "A figure of history (CPU, memory, a disk, a jail's) over its "
	    "limit, and back under.", NULL, NULL, NULL },
	{ "mail_via", K_TEXT, "Mail sent by",
	    "sendmail: the console's host's own, dma(8) as FreeBSD comes; "
	    "smtp: the relay below, by SMTP from the console itself.", v_via,
	    NULL, NULL },
	{ "smtp_host", K_TEXT, "SMTP relay",
	    "Its name, as its certificate says: smtp.example.org.", v_host,
	    NULL, NULL },
	{ "smtp_port", K_TEXT, "SMTP port",
	    "587 for STARTTLS, 465 for TLS, 25 in the clear.", v_port, NULL,
	    NULL },
	{ "smtp_security", K_TEXT, "SMTP security",
	    "starttls, tls or none; a password goes over TLS only, and the "
	    "relay's certificate is checked against the system's CAs and its "
	    "name.", v_security, NULL, NULL },
	{ "smtp_user", K_TEXT, "SMTP user",
	    "Empty for a relay that takes mail without signing in.", v_user,
	    NULL, NULL },
	{ "smtp_password", K_SECRET, "SMTP password",
	    "Kept in the data directory, readable by the console alone; never "
	    "shown again: typed again to change it.", v_secret, NULL, NULL },
	{ "telegram_chats", K_TEXT, "Telegram chats",
	    "Where the bot writes: chat ids (a number; a group's is negative) "
	    "or @channel names, a space between them; empty for none. Ask "
	    "@userinfobot for yours, and write to the bot once first.",
	    v_chats, NULL, NULL },
	{ "telegram_token", K_SECRET, "Telegram bot token",
	    "As BotFather gave it. Kept in the data directory, readable by "
	    "the console alone; never shown again.", v_tgtoken, NULL, NULL },
	{ "telegram_via", K_TEXT, "Telegram sent from",
	    "The host whose agent sends the messages to api.telegram.org "
	    "over HTTPS (its name or id): one that reaches the world "
	    "outside. Empty for the agent beside the console.", v_sender,
	    NULL, NULL },
	{ "telegram_faults", K_TEXT, "Faults to Telegram",
	    "The least severity sent, and their clearing: Critical, Major, "
	    "Minor or Warning; none for none.", v_severity, NULL, NULL },
	{ "telegram_jobs", K_TEXT, "Jobs to Telegram",
	    "failed, all or none.", v_which, NULL, NULL },
	{ "telegram_runs", K_TEXT, "Workflow runs to Telegram",
	    "failed, all or none.", v_which, NULL, NULL },
	{ "telegram_limits", K_BOOL, "Limits crossed to Telegram",
	    "A figure of history over its limit, and back under.", NULL, NULL,
	    NULL },
	{ "safe_wait", K_TEXT, "Rollback timer, every host, in seconds",
	    "How long a change made in safe mode waits for the console to be "
	    "heard from again before the host undoes it, for every host "
	    "without a timer of its own: 10 to 3600. Sent with each change, "
	    "so it holds from the next one on. Empty: each agent's own (-w, "
	    "60 unless its flags say).", v_safe, NULL, NULL },
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
v_count(const char *s, long lo, long hi)
{
	char	*end;
	long	 n;

	if (s[0] == '\0' || strlen(s) > 6)
		return ("");
	n = strtol(s, &end, 10);
	return (*end != '\0' || n < lo || n > hi ? "" : NULL);
}

/* An address: something@somewhere, nothing a header could be made of. */
static const char *
v_mail(const char *s)
{
	const char	*at;

	if (s[0] == '\0')
		return (NULL);
	if (strlen(s) > 254 || (at = strchr(s, '@')) == NULL || at == s ||
	    at[1] == '\0' || strchr(at + 1, '@') != NULL)
		return ("an address, name@domain");
	for (; *s != '\0'; s++)
		if ((unsigned char)*s <= 0x20 || *s == 0x7f || strchr("<>(),;:\\\"[]",
		    *s) != NULL)
			return ("an address, name@domain");
	return (NULL);
}

static const char *
v_mails(const char *s)
{
	char		 one[256];
	const char	*e;
	size_t		 n;

	if (strlen(s) > 1000)
		return ("1000 characters at most");
	for (n = 0; *s != '\0'; s = e, n++) {
		s += strspn(s, " ,");
		if (*s == '\0')
			break;
		e = s + strcspn(s, " ,");
		if ((size_t)(e - s) >= sizeof(one) || n >= 16)
			return ("16 addresses at most, a comma between them");
		snprintf(one, sizeof(one), "%.*s", (int)(e - s), s);
		if (v_mail(one) != NULL)
			return ("addresses, name@domain, a comma between them");
	}
	return (NULL);
}

static const char *
v_severity(const char *s)
{

	return (strcmp(s, "Critical") == 0 || strcmp(s, "Major") == 0 ||
	    strcmp(s, "Minor") == 0 || strcmp(s, "Warning") == 0 ||
	    strcmp(s, "none") == 0 ? NULL : "Critical, Major, Minor, Warning "
	    "or none");
}

static const char *
v_which(const char *s)
{

	return (strcmp(s, "failed") == 0 || strcmp(s, "all") == 0 ||
	    strcmp(s, "none") == 0 ? NULL : "failed, all or none");
}

static const char *
v_via(const char *s)
{

	return (strcmp(s, "sendmail") == 0 || strcmp(s, "smtp") == 0 ? NULL :
	    "sendmail or smtp");
}

static const char *
v_host(const char *s)
{

	/* An IPv6 address as it is, without brackets: getaddrinfo(3) and
	 * the certificate's check take it so. */
	if (s[0] == '\0' || strlen(s) > 253 || s[strspn(s,
	    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:")]
	    != '\0')
		return ("a host's name or address");
	return (NULL);
}

static const char *
v_port(const char *s)
{

	/* Empty: the relay's usual port for its security. */
	if (s[0] == '\0')
		return (NULL);
	return (v_count(s, 1, 65535) != NULL ? "a port, 1 to 65535" : NULL);
}

static const char *
v_security(const char *s)
{

	return (strcmp(s, "starttls") == 0 || strcmp(s, "tls") == 0 ||
	    strcmp(s, "none") == 0 ? NULL : "starttls, tls or none");
}

static const char *
v_user(const char *s)
{

	if (strlen(s) > 256)
		return ("256 characters at most");
	for (; *s != '\0'; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return ("no control characters");
	return (NULL);
}

static const char *
v_secret(const char *s)
{

	return (strlen(s) > 1024 ? "1024 characters at most" : NULL);
}

/* A bot's token: digits, a colon, then letters, digits, _ and -. */
static const char *
v_tgtoken(const char *s)
{
	size_t	n;

	if (s[0] == '\0')
		return (NULL);
	n = strspn(s, "0123456789");
	if (n == 0 || s[n] != ':' || s[n + 1] == '\0' || strlen(s) > 128 ||
	    strspn(s + n + 1, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST"
	    "UVWXYZ0123456789_-") != strlen(s + n + 1))
		return ("digits, a colon and letters, digits, _ and -, as "
		    "BotFather gives it");
	return (NULL);
}

/* Chats: numbers (negative for a group) or @names, 8 at most. */
static const char *
v_chats(const char *s)
{
	const char	*e;
	size_t		 n, k;

	for (n = 0; *s != '\0'; s = e, n++) {
		s += strspn(s, " ,");
		if (*s == '\0')
			break;
		e = s + strcspn(s, " ,");
		k = (size_t)(e - s);
		if (n == 8)
			return ("8 chats at most");
		if (s[0] == '@' ? k < 6 || k > 33 || strspn(s + 1,
		    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		    "_") < k - 1 : k > 20 || k == (s[0] == '-' ? 1u : 0u) ||
		    strspn(s + (s[0] == '-'), "0123456789") < k - (s[0] == '-'))
			return ("a chat is a number (negative for a group) or "
			    "@ and a channel's name");
	}
	return (NULL);
}

/* A host by its name or id: letters, digits, . _ and -. */
static const char *
v_sender(const char *s)
{

	return (strlen(s) > 64 || strspn(s, "abcdefghijklmnopqrstuvwxyzABCD"
	    "EFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != strlen(s) ? "a host's "
	    "name or id" : NULL);
}

static const char *
v_safe(const char *s)
{

	/* Empty: each agent's own. */
	if (s[0] == '\0')
		return (NULL);
	return (v_count(s, SAFE_WAIT_MIN, SAFE_WAIT_MAX) != NULL ? "a number "
	    "of seconds, 10 to 3600" : NULL);
}

static const char *
v_minutes(const char *s)
{

	return (v_count(s, 5, 1440) != NULL ? "a number of minutes, 5 to "
	    "1440" : NULL);
}

static const char *
v_hours(const char *s)
{

	return (v_count(s, 1, 720) != NULL ? "a number of hours, 1 to 720" :
	    NULL);
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

/*
 * The program sent to hosts: a file of its own, never one of the
 * console's.  What is in the data directory is its keys, and the agent
 * a host built, which the console must not run.
 */
static const char *
v_binary(const char *s)
{
	struct stat	st;
	char		real[PATH_MAX], data[PATH_MAX];
	size_t		len;

	if (v_path(s) != NULL)
		return ("an absolute path");
	if (realpath(s, real) == NULL)
		strlcpy(real, s, sizeof(real));
	else if (stat(real, &st) == 0 && !S_ISREG(st.st_mode))
		return ("a program, not a directory or a device");
	if (realpath(cfg.datadir, data) == NULL)
		strlcpy(data, cfg.datadir, sizeof(data));
	len = strlen(data);
	if (strncmp(real, data, len) == 0 && (real[len] == '/' || real[len] ==
	    '\0'))
		return ("a program outside the console's data directory");
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

/* A path on another machine: only its form can be checked; or empty. */
static const char *
v_keypath(const char *s)
{

	return (s[0] == '\0' ? NULL : v_path(s) != NULL || strchr(s, ' ') !=
	    NULL ? "an absolute path without blanks" : NULL);
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

/*
 * What a setting is now, for a thread that is not the worker's (mail's):
 * read from settings.json itself, else web.conf's, nothing shared
 * changed.  To be freed.
 */
char *
settings_peek(const char *key)
{
	struct ucl_parser	*p;
	struct setting		*s;
	ucl_object_t		*o;
	const ucl_object_t	*v;
	const char		*t;
	char			 path[1024], *r;

	if ((s = find(key)) == NULL)
		return (strdup(""));
	r = NULL;
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, SETTINGS_FILE);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO);
	if (access(path, R_OK) == 0 && ucl_parser_add_file(p, path) &&
	    (o = ucl_parser_get_object(p)) != NULL) {
		if ((v = ucl_object_lookup(o, key)) != NULL) {
			t = s->kind == K_BOOL ? (ucl_object_toboolean(v) ?
			    "true" : "false") : ucl_object_tostring_forced(v);
			if (t[0] == '\0' || s->valid == NULL || s->valid(t) ==
			    NULL)
				r = strdup(t);
		}
		ucl_object_unref(o);
	}
	ucl_parser_free(p);
	if (r == NULL)
		r = strdup(s->base != NULL ? s->base : "");
	if (r == NULL)
		abort();
	return (r);
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
	v = value("agent_ssh_key");
	cfg.agent_ssh_key = v[0] != '\0' ? kore_strdup(v) : NULL;
	cfg.session_idle = v_minutes(value("session_idle")) == NULL ? atoi(
	    value("session_idle")) * 60 : SESSION_IDLE;
	cfg.session_max = v_hours(value("session_max")) == NULL ? atoi(
	    value("session_max")) * 3600 : SESSION_MAX;
	/* The mail's are read where they are used: settings_peek(). */
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
	find("agent_ssh_key")->base = cfg.agent_ssh_key;
	find("session_idle")->base = kore_strdup("30");
	find("session_max")->base = kore_strdup("12");
	find("telegram_faults")->base = kore_strdup("Major");
	find("telegram_jobs")->base = kore_strdup("failed");
	find("telegram_runs")->base = kore_strdup("failed");
	find("telegram_limits")->base = kore_strdup("false");
	find("mail_to")->base = cfg.mail_to;
	find("mail_from")->base = cfg.mail_from;
	find("mail_faults")->base = cfg.mail_faults;
	find("mail_jobs")->base = cfg.mail_jobs;
	find("mail_runs")->base = cfg.mail_runs;
	find("mail_limits")->base = kore_strdup(cfg.mail_limits ? "true" :
	    "false");
	find("mail_via")->base = kore_strdup("sendmail");
	find("smtp_port")->base = kore_strdup("587");
	find("smtp_security")->base = kore_strdup("starttls");
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
		    K_BOOL ? "bool" : settings[i].kind == K_SECRET ? "secret" :
		    "text"));
		/* A secret's value is never sent: whether it is set. */
		if (settings[i].kind == K_SECRET) {
			put(e, "value", ucl_object_fromstring(""));
			put(e, "set", ucl_object_frombool(value(
			    settings[i].key)[0] != '\0'));
		} else
			put(e, "value", ucl_object_fromstring(value(
			    settings[i].key)));
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
		/* A secret left empty is left as it is; null clears it. */
		if (s->kind == K_SECRET && val[0] == '\0')
			continue;
		/* Empty means none, where there can be none. */
		why = s->valid != NULL && !(val[0] == '\0' && (s->valid ==
		    v_source || s->valid == v_ref || s->valid == v_keypath ||
		    s->valid == v_host)) ?
		    s->valid(val) : NULL;
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
