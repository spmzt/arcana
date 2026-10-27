/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Ira: the services as arcana-services has them:
 * the services operation's reply (do_services(): the rc.d scripts, each
 * enabled or not, running or not), each with its service-config reply
 * where one was read (do_service_config(): its rc.conf variables as
 * sysrc(8) reads them, what it says of itself, its extra commands).
 * The actions are service-action's (services.c); a configuration wanted
 * becomes what service-config and service-action take, by
 * yservices_diff().
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"

typedef struct arcana_services_services_service yservice;
typedef struct arcana_services_services_service_variable yvar;

static void
from_config(yservice *y, const struct arc_service_config_rsp *c, yvar *v)
{

	for (size_t k = 0; k < c->variables.n; k++) {
		v[k].name = c->variables.v[k].key;
		v[k].value = c->variables.v[k].value;
	}
	y->variable.n = c->variables.n;
	y->variable.v = v;
	y->description = c->description;
	y->command.n = c->commands.n;
	y->command.v = c->commands.v;
}

/* The strings point into the replies'; a's the rest. */
int
yservices_from(const struct arc_services_rsp *list,
    const struct arc_service_config_rsp *const *cfg, size_t ncfg,
    cbl_yarena *a, struct arcana_services *out)
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
		for (size_t k = 0; k < ncfg; k++) {
			const struct arc_service_config_rsp *c = cfg[k];
			yvar *vv = NULL;

			if (c->service_result == NULL ||
			    c->service_result->name == NULL ||
			    strcmp(c->service_result->name, s->name) != 0)
				continue;
			if (c->variables.n > 0 && (vv = cbl_yarena_alloc(a,
			    c->variables.n * sizeof(*vv))) == NULL)
				return (ENOMEM);
			from_config(y, c, vv);
			break;
		}
	}
	ss->service.n = list->services.n;
	ss->service.v = v;
	out->services = ss;
	return (0);
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
 * (remove), as service-config takes them, a's.  Its own rcvar is
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
