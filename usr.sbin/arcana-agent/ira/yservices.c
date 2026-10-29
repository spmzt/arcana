/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the services as arcana-services has them: the list (do_services():
 * the rc.d scripts, each enabled or not, running or not), the read
 * action's one service (service_read(): enabled by its rcvar, its
 * status, what it says of itself, its extra commands).  The other
 * actions are a service's start, stop, restart and reload (services.c);
 * a configuration wanted becomes what the commit writes, by
 * yservices_diff().
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>

#include "agent.h"
#include "collect.h"

typedef struct arcana_services_services_service yservice;
typedef struct arcana_services_services_service_variable yvar;

/* The strings point into the list's; a's the rest. */
int
yservices_from(const struct services_rsp *list, cbl_yarena *a,
    struct arcana_services *out)
{
	struct arcana_services_services *ss;
	yservice *v = NULL;

	memset(out, 0, sizeof(*out));
	if ((ss = cbl_yarena_alloc(a, sizeof(*ss))) == NULL ||
	    (list->services.n > 0 && (v = cbl_yarena_alloc(a,
	    list->services.n * sizeof(*v))) == NULL))
		return (ENOMEM);
	memset(ss, 0, sizeof(*ss));
	for (size_t i = 0; i < list->services.n; i++) {
		const struct arc_service *s = &list->services.v[i];
		yservice *y = &v[i];

		memset(y, 0, sizeof(*y));
		y->name = s->name;
		if ((y->has_enabled = s->has_enabled))
			y->enabled = s->enabled;
		y->path = s->path;
		y->rcvar = s->rcvar;
		if ((y->has_running = s->has_running))
			y->running = s->running;
		if ((y->has_pid = s->has_pid))
			y->pid = s->pid;
		y->status = s->status;
	}
	ss->service.n = list->services.n;
	ss->service.v = v;
	out->services = ss;
	return (0);
}

/* The read action's output from service_read()'s r; its strings r's. */
void
yservices_read(const struct service_config_rsp *r,
    struct arcana_services_services_service_read_output *out)
{
	const struct arc_service *s = r->service_result;

	memset(out, 0, sizeof(*out));
	if (s != NULL) {
		if ((out->has_enabled = s->has_enabled))
			out->enabled = s->enabled;
		out->path = s->path;
		out->rcvar = s->rcvar;
		if ((out->has_running = s->has_running))
			out->running = s->running;
		if ((out->has_pid = s->has_pid))
			out->pid = s->pid;
		out->status = s->status;
	}
	out->description = r->description;
	out->command.n = r->commands.n;
	out->command.v = r->commands.v;
}

static const yvar *
var_of(const yservice *s, const char *name)
{

	for (size_t i = 0; s != NULL && i < s->variable.n; i++)
		if (strcmp(s->variable.v[i].name, name) == 0)
			return (&s->variable.v[i]);
	return (NULL);
}

/*
 * What makes service have's configuration want's: *enable 1 to enable
 * it, -1 to disable it, 0 neither; the variables to set, or unset
 * (remove), a's.  Its own rcvar is
 * enabled's alone, never a variable.  EINVAL: two different services.
 */
int
yservices_diff(const yservice *have, const yservice *want, cbl_yarena *a,
    int *enable, struct arc_variable **vars, size_t *nvars)
{
	struct arc_variable *v;
	size_t n = 0;

	*enable = 0;
	*vars = NULL;
	*nvars = 0;
	if (have != NULL && strcmp(have->name, want->name) != 0)
		return (EINVAL);
	if (want->has_enabled && (have == NULL || !have->has_enabled ||
	    have->enabled != want->enabled))
		*enable = want->enabled ? 1 : -1;
	if ((v = cbl_yarena_alloc(a, (want->variable.n + (have != NULL ?
	    have->variable.n : 0) + 1) * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < want->variable.n; i++) {
		const yvar *w = &want->variable.v[i], *h;

		if (have != NULL && have->rcvar != NULL &&
		    strcmp(w->name, have->rcvar) == 0)
			return (EINVAL);
		h = var_of(have, w->name);
		if (h != NULL && h->value != NULL && w->value != NULL &&
		    strcmp(h->value, w->value) == 0)
			continue;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].key = w->name;
		v[n++].value = w->value != NULL ? w->value : "";
	}
	for (size_t i = 0; have != NULL && i < have->variable.n; i++) {
		const yvar *h = &have->variable.v[i];

		if (var_of(want, h->name) != NULL)
			continue;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].key = h->name;
		v[n++].remove = true;
	}
	*vars = n > 0 ? v : NULL;
	*nvars = n;
	return (0);
}
