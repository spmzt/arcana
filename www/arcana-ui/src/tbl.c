/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What every table of rows has: a head whose columns sort it when
 * picked, one way and then the other, and the filter typed above it
 * leaving the rows that have the text in any column.  A table is known
 * by a name, under which its order is kept while the page lives.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	TBL_MAX	160

static struct {
	char	id[24];
	int	col;		/* -1: as the host gave them */
	bool	desc;
} state[TBL_MAX];
static int	nstate;

static int
find(const char *id, bool make)
{
	int	i;

	for (i = 0; i < nstate; i++)
		if (strcmp(state[i].id, id) == 0)
			return (i);
	if (!make || nstate == TBL_MAX)
		return (-1);
	snprintf(state[nstate].id, sizeof(state[0].id), "%s", id);
	state[nstate].col = -1;
	state[nstate].desc = false;
	return (nstate++);
}

/* Is the table in an order somebody asked for? */
bool
tbl_sorted(const char *id)
{
	int	i;

	return ((i = find(id, false)) != -1 && state[i].col >= 0);
}

/* <thead>, with extra empty columns after those named, for buttons. */
void
tbl_head(struct html *h, const char *id, const struct tcol *cols, int n,
    int extra)
{
	int	i, s;

	s = find(id, true);
	h_raw(h, "<thead><tr>");
	for (i = 0; i < n; i++) {
		if (cols[i].key == NULL) {
			h_fmt(h, "<th>%s</th>", cols[i].title);
			continue;
		}
		h_fmt(h, "<th class=\"sortable%s\" data-act=\"t-sort\"", s !=
		    -1 && state[s].col == i ? state[s].desc ? " desc" :
		    " asc" : "");
		h_attr(h, "data-arg", id);
		h_fmt(h, " data-value=\"%d\">%s</th>", i, cols[i].title);
	}
	for (i = 0; i < extra; i++)
		h_raw(h, "<th></th>");
	h_raw(h, "</tr></thead>");
}

static const struct tcol	*by;
static bool			 by_desc;

static int
cmp(const void *a, const void *b)
{
	const ucl_object_t	*x, *y;
	const char		*sx, *sy;
	char			*ex, *ey;
	double			 nx, ny;
	int			 r;

	x = *(const ucl_object_t *const *)a;
	y = *(const ucl_object_t *const *)b;
	sx = jget(x, by->key) != NULL ? ucl_object_tostring_forced(jget(x,
	    by->key)) : "";
	sy = jget(y, by->key) != NULL ? ucl_object_tostring_forced(jget(y,
	    by->key)) : "";
	/* Numbers as numbers, whether they came as numbers or as text. */
	nx = strtod(sx, &ex);
	ny = strtod(sy, &ey);
	if (by->num || (*sx != '\0' && *sy != '\0' && *ex == '\0' && *ey ==
	    '\0'))
		r = nx < ny ? -1 : nx > ny ? 1 : 0;
	else
		r = strcmp(sx, sy);
	return (by_desc ? -r : r);
}

/*
 * The rows of arr to show, in the order asked for: those that have
 * filter in a column, or all with filter NULL or empty.  To be freed;
 * NULL ends them.
 */
const ucl_object_t **
tbl_rows(const char *id, const ucl_object_t *arr, const struct tcol *cols,
    int n, const char *filter)
{
	const ucl_object_t	**v, *o, *f;
	ucl_object_iter_t	  it;
	size_t			  cnt;
	int			  i, s;
	bool			  hit;

	if ((v = calloc(ucl_array_size(arr) + 1, sizeof(*v))) == NULL)
		abort();
	cnt = 0;
	it = NULL;
	while ((o = ucl_object_iterate(arr, &it, true)) != NULL) {
		hit = filter == NULL || filter[0] == '\0';
		for (i = 0; !hit && i < n; i++)
			if (cols[i].key != NULL && (f = jget(o,
			    cols[i].key)) != NULL && strstr(
			    ucl_object_tostring_forced(f), filter) != NULL)
				hit = true;
		if (hit)
			v[cnt++] = o;
	}
	v[cnt] = NULL;
	if ((s = find(id, true)) != -1 && state[s].col >= 0 && state[s].col <
	    n && cols[state[s].col].key != NULL) {
		by = &cols[state[s].col];
		by_desc = state[s].desc;
		qsort(v, cnt, sizeof(*v), cmp);
	}
	return (v);
}

/* The table in the order of one column, or with col -1 as it came. */
void
tbl_set(const char *id, int col, bool desc)
{
	int	s;

	if ((s = find(id, true)) == -1)
		return;
	state[s].col = col;
	state[s].desc = desc;
}

/* The column the table is in the order of, or -1; *desc, which way. */
int
tbl_col(const char *id, bool *desc)
{
	int	s;

	if ((s = find(id, false)) == -1)
		return (-1);
	*desc = state[s].desc;
	return (state[s].col);
}

/* A column picked: sorted by it; again, the other way; a third time, not. */
bool
tbl_action(const char *act, const char *arg, const char *value)
{
	int	s, col;

	if (strcmp(act, "t-sort") != 0)
		return (false);
	if ((s = find(arg, true)) == -1)
		return (true);
	col = atoi(value);
	if (state[s].col != col) {
		state[s].col = col;
		state[s].desc = false;
	} else if (!state[s].desc)
		state[s].desc = true;
	else
		state[s].col = -1;
	return (true);
}
