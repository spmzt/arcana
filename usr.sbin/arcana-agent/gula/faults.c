/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Faults (Mplify 119 §11.3): each with the time it was seen or
 * cleared, a type (Table 4: interface-down, bfd, bgp-neighbor, cpu,
 * memory, storage; and ours: tunnel, bird-instance, ospf-neighbor,
 * tca; luxuria/birdwatch.c's for the host's BIRD; crash, kmsg.c's,
 * a program the kernel saw die of a signal), a severity
 * (Warning, Minor, Major, Critical; Cleared when it is), what it is
 * of, who saw it and a line of description (Table 5).  One open fault
 * of a type and object at a time; set and cleared are events
 * (sdwan-fault, R71) besides.  Kept 24 hours (D5), on disk too.
 */

#include <sys/param.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <ucl.h>

#include "agent.h"

#define	FAULTS_FILE	"sdwan-faults.json"
#define	FAULTS_MAX	2048
#define	FAULTS_KEEP	(24 * 3600)

struct fault {
	time_t	t, cleared_at;
	char	type[24];
	char	severity[12];
	char	object[128];
	char	by[12];
	char	descr[200];
	bool	cleared;
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct fault	*faults;
static int		 nfaults;

/* A string as JSON's: quotes and backslashes escaped. */
static const char *
jq(const char *s, char *buf, size_t len)
{
	size_t	i, n;

	for (i = 0, n = 0; s != NULL && s[i] != '\0' && n + 2 < len; i++) {
		if (s[i] == '"' || s[i] == '\\')
			buf[n++] = '\\';
		buf[n++] = s[i] < 0x20 ? ' ' : s[i];
	}
	buf[n] = '\0';
	return (buf);
}

/* The day's faults as JSON, the oldest first. */
static ucl_object_t *
faults_array(time_t since)
{
	ucl_object_t	*arr, *o;
	int		 i;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < nfaults; i++) {
		if (faults[i].t < since && (!faults[i].cleared ||
		    faults[i].cleared_at < since))
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint(faults[i].t), "t", 0,
		    false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].type),
		    "type", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].cleared ?
		    "Cleared" : faults[i].severity), "severity", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].severity),
		    "was", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].object),
		    "object", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].by), "by",
		    0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(faults[i].descr),
		    "description", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(faults[i].cleared),
		    "cleared", 0, false);
		if (faults[i].cleared)
			ucl_object_insert_key(o, ucl_object_fromint(
			    faults[i].cleared_at), "cleared_at", 0, false);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* With the lock held: the old ones dropped, the rest written down. */
static void
faults_keep(void)
{
	ucl_object_t	*arr;
	unsigned char	*json;
	const char	*e;
	time_t		 since;
	int		 i, k;

	since = time(NULL) - FAULTS_KEEP;
	for (i = k = 0; i < nfaults; i++)
		if (faults[i].t >= since || (faults[i].cleared &&
		    faults[i].cleared_at >= since) || !faults[i].cleared)
			faults[k++] = faults[i];
	nfaults = k;
	arr = faults_array(0);
	json = ucl_object_emit(arr, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(arr);
	if (json != NULL) {
		e = NULL;
		if (sdwan_conf_write(FAULTS_FILE, (const char *)json, &e) != 0)
			logmsg(LOG_WARNING, "faults: %s: %s", FAULTS_FILE, e);
		free(json);
	}
}

static int
fault_find(const char *type, const char *object)
{
	int	i;

	for (i = 0; i < nfaults; i++)
		if (!faults[i].cleared && strcmp(faults[i].type, type) == 0 &&
		    strcmp(faults[i].object, object) == 0)
			return (i);
	return (-1);
}

/* A fault seen: once, until it is cleared. */
void
fault_set(const char *type, const char *severity, const char *object,
    const char *by, const char *fmt, ...)
{
	struct fault	*f;
	va_list		 ap;
	char		 qo[300], qd[500];

	pthread_mutex_lock(&lock);
	if (fault_find(type, object) >= 0) {
		pthread_mutex_unlock(&lock);
		return;
	}
	if (faults == NULL && (faults = calloc(FAULTS_MAX, sizeof(*faults))) ==
	    NULL) {
		pthread_mutex_unlock(&lock);
		return;
	}
	if (nfaults == FAULTS_MAX) {
		memmove(faults, faults + 1, sizeof(*faults) * (FAULTS_MAX - 1));
		nfaults--;
	}
	f = &faults[nfaults++];
	memset(f, 0, sizeof(*f));
	f->t = time(NULL);
	snprintf(f->type, sizeof(f->type), "%s", type);
	snprintf(f->severity, sizeof(f->severity), "%s", severity);
	snprintf(f->object, sizeof(f->object), "%s", object);
	snprintf(f->by, sizeof(f->by), "%s", by);
	va_start(ap, fmt);
	vsnprintf(f->descr, sizeof(f->descr), fmt, ap);
	va_end(ap);
	faults_keep();
	pthread_mutex_unlock(&lock);
	event_add("sdwan-fault", "{\"type\":\"%s\",\"severity\":\"%s\",\"object\":"
	    "\"%s\",\"by\":\"%s\",\"description\":\"%s\",\"state\":\"set\"}", type,
	    severity, jq(object, qo, sizeof(qo)), by, jq(f->descr, qd,
	    sizeof(qd)));
	logmsg(LOG_WARNING, "fault %s (%s) %s: %s", type, severity, object,
	    f->descr);
}

/* A fault cleared, if one of the type and object is open. */
void
fault_clear(const char *type, const char *object, const char *fmt, ...)
{
	struct fault	*f;
	va_list		 ap;
	char		 qo[300], qd[500], descr[200];
	int		 i;

	pthread_mutex_lock(&lock);
	if ((i = fault_find(type, object)) < 0) {
		pthread_mutex_unlock(&lock);
		return;
	}
	f = &faults[i];
	f->cleared = true;
	f->cleared_at = time(NULL);
	va_start(ap, fmt);
	vsnprintf(descr, sizeof(descr), fmt, ap);
	va_end(ap);
	snprintf(f->descr, sizeof(f->descr), "%s", descr);
	faults_keep();
	pthread_mutex_unlock(&lock);
	event_add("sdwan-fault", "{\"type\":\"%s\",\"severity\":\"Cleared\","
	    "\"object\":\"%s\",\"description\":\"%s\",\"state\":\"cleared\"}", type,
	    jq(object, qo, sizeof(qo)), jq(descr, qd, sizeof(qd)));
	logmsg(LOG_NOTICE, "fault %s %s cleared: %s", type, object, descr);
}

/*
 * An open fault's line said anew, as what it is of goes on (a program
 * that crashes again): no event, the fault being the same one.  false
 * when none of the type and object is open.
 */
bool
fault_update(const char *type, const char *object, const char *fmt, ...)
{
	va_list	ap;
	int	i;

	pthread_mutex_lock(&lock);
	if ((i = fault_find(type, object)) < 0) {
		pthread_mutex_unlock(&lock);
		return (false);
	}
	va_start(ap, fmt);
	vsnprintf(faults[i].descr, sizeof(faults[i].descr), fmt, ap);
	va_end(ap);
	faults_keep();
	pthread_mutex_unlock(&lock);
	return (true);
}

/* The day's faults into the sdwan reply. */
void
faults_json(ucl_object_t *top)
{

	pthread_mutex_lock(&lock);
	ucl_object_insert_key(top, faults_array(time(NULL) - FAULTS_KEEP),
	    "faults", 0, false);
	pthread_mutex_unlock(&lock);
}

/* At the start: the day's faults read back. */
void
faults_start(void)
{
	struct ucl_parser	*p;
	ucl_object_t		*arr;
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;
	char			*json;
	struct fault		*f;

	if ((json = sdwan_kept_read(FAULTS_FILE)) == NULL)
		return;
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	arr = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	free(json);
	if (arr == NULL)
		return;
	pthread_mutex_lock(&lock);
	if (faults == NULL)
		faults = calloc(FAULTS_MAX, sizeof(*faults));
	it = NULL;
	while (faults != NULL && nfaults < FAULTS_MAX && (o =
	    ucl_object_iterate(arr, &it, true)) != NULL) {
		f = &faults[nfaults];
		memset(f, 0, sizeof(*f));
		f->t = (time_t)ucl_object_toint(ucl_object_lookup(o, "t"));
#define	STR(field, key) snprintf(f->field, sizeof(f->field), "%s", \
	ucl_object_tostring(ucl_object_lookup(o, key)) != NULL ? \
	ucl_object_tostring(ucl_object_lookup(o, key)) : "")
		STR(type, "type");
		STR(severity, "was");
		STR(object, "object");
		STR(by, "by");
		STR(descr, "description");
#undef STR
		f->cleared = ucl_object_toboolean(ucl_object_lookup(o,
		    "cleared"));
		f->cleared_at = (time_t)ucl_object_toint(ucl_object_lookup(o,
		    "cleared_at"));
		if (f->type[0] != '\0')
			nfaults++;
	}
	pthread_mutex_unlock(&lock);
	ucl_object_unref(arr);
}
