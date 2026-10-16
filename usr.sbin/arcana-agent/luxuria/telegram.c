/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Telegram: a message sent to a chat by a bot, for the console's alerts
 * and a workflow's notify step, from a host that reaches the world
 * outside.  The Bot API's sendMessage, POSTed as JSON over HTTPS by the
 * base system's fetch(3), which checks api.telegram.org's certificate
 * against the host's CAs (certctl(8)'s).  The token is the bot's: it is
 * used for the request and forgotten, and is in no trace nor log.
 */

#include <sys/param.h>

#include <ctype.h>
#include <stdio.h>
#include <fetch.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

#include "agent.h"

#define	TG_REPLY_MAX	(64 * 1024)
#define	TG_WAIT_S	15

/* digits, a colon, then letters, digits, _ and -: as BotFather gives. */
static bool
token_ok(const char *s)
{
	size_t	i, n;

	n = strspn(s, "0123456789");
	if (n == 0 || s[n] != ':' || s[n + 1] == '\0' || strlen(s) > 128)
		return (false);
	for (i = n + 1; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
			return (false);
	return (true);
}

/* A chat: a number, negative for a group, or @ and a channel's name. */
static bool
chat_ok(const char *s)
{
	size_t	i;

	if (s[0] == '@') {
		if (strlen(s) < 6 || strlen(s) > 33)
			return (false);
		for (i = 1; s[i] != '\0'; i++)
			if (!isalnum((unsigned char)s[i]) && s[i] != '_')
				return (false);
		return (true);
	}
	i = s[0] == '-' ? 1 : 0;
	return (s[i] != '\0' && strlen(s) <= 20 && strspn(s + i,
	    "0123456789") == strlen(s + i));
}

int
do_notify(struct work *w, const char *token, const char *chat,
    const char *text, const char **errp)
{
	struct url		*u;
	ucl_object_t		*body, *ans;
	struct ucl_parser	*p;
	FILE			*f;
	char			*json, *url, buf[TG_REPLY_MAX];
	const char		*desc;
	size_t			 n;
	int			 step;
	bool			 ok;

	if (!token_ok(token)) {
		*errp = "a bot's token is digits, a colon and letters, digits, "
		    "_ and -, as BotFather gives it";
		return (-1);
	}
	if (!chat_ok(chat)) {
		*errp = "a chat is a number (negative for a group), or @ and a "
		    "channel's name";
		return (-1);
	}
	if (text[0] == '\0' || strlen(text) > 4096) {
		*errp = "a message is 1 to 4096 characters";
		return (-1);
	}
	body = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(body, chat[0] == '@' ? ucl_object_fromstring(
	    chat) : ucl_object_fromint(strtoll(chat, NULL, 10)), "chat_id", 0,
	    false);
	ucl_object_insert_key(body, ucl_object_fromstring(text), "text", 0,
	    false);
	ucl_object_insert_key(body, ucl_object_frombool(true),
	    "disable_web_page_preview", 0, false);
	json = (char *)ucl_object_emit(body, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(body);
	if (json == NULL) {
		*errp = "out of memory";
		return (-1);
	}
	if (asprintf(&url, "%s/bot%s/sendMessage", opts.telegram_api,
	    token) == -1) {
		free(json);
		*errp = "out of memory";
		return (-1);
	}
	u = fetchParseURL(url);
	explicit_bzero(url, strlen(url));
	free(url);
	if (u == NULL) {
		free(json);
		*errp = "the Bot API's address is not one";
		return (-1);
	}
	step = step_begin(w, ARC_STEP_KIND_LIB, "libfetch fetchReqHTTP()",
	    "Telegram sendMessage to chat %s, %zu characters", chat,
	    strlen(text));
	fetchTimeout = TG_WAIT_S;
	f = fetchReqHTTP(u, "POST", "", "application/json", json);
	explicit_bzero(u->doc, strlen(u->doc));
	fetchFreeURL(u);
	free(json);
	if (f == NULL) {
		*errp = wfmt(w, "the Bot API: %s%s", fetchLastErrString,
		    fetchLastErrCode == FETCH_AUTH || strstr(fetchLastErrString,
		    "Unauthorized") != NULL ? " (the bot's token is not "
		    "right)" : strstr(fetchLastErrString, "Bad Request") !=
		    NULL ? " (no such chat, or the bot is not in it)" : "");
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	ans = ucl_parser_add_string(p, buf, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	ok = ans != NULL && ucl_object_toboolean(ucl_object_lookup(ans,
	    "ok"));
	if (!ok) {
		desc = ans != NULL && ucl_object_lookup(ans, "description") !=
		    NULL ? ucl_object_tostring_forced(ucl_object_lookup(ans,
		    "description")) : "it did not say it was sent";
		*errp = wfmt(w, "the Bot API: %s", desc);
	}
	if (ans != NULL)
		ucl_object_unref(ans);
	if (ok)
		step_end(w, step, true, NULL);
	else
		step_end(w, step, false, "%s", *errp);
	return (ok ? 0 : -1);
}
