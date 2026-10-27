/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yhw: a host's hardware as ietf-hardware has it (yhw.c), for
 * agent_test.sh: a component a line, through YANG-CBOR and back.
 *
 *	yhw file
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "collect.h"

static char *
slurp(const char *path)
{
	static char buf[1 << 16];
	ssize_t r;
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);
	if ((r = read(fd, buf, sizeof(buf) - 1)) < 0)
		err(1, "%s", path);
	close(fd);
	buf[r] = '\0';
	return (buf);
}

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

/* An identity's name, by its SID. */
static const char *
ident(uint64_t sid)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return ("?");
}

int
main(int argc, char **argv)
{
	struct ietf_hardware h;
	struct ietf_hardware_hardware back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	const struct ietf_hardware_hardware_component *c;
	cbl_yarena *a;
	char why[256];
	int error;

	if (argc != 2)
		errx(2, "usage: yhw file");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yhw_from_json(slurp(argv[1]), a, &h)) != 0)
		errc(1, error, "yhw_from_json");
	for (size_t i = 0; i < h.hardware->component.n; i++) {
		c = &h.hardware->component.v[i];
		printf("%s %s parent=%s pos=%d mfg=%s model=%s serial=%s "
		    "hw=%s fw=%s sw=%s uuid=%s fru=%s descr=%s", c->name,
		    ident(c->class), str(c->parent), c->has_parent_rel_pos ?
		    c->parent_rel_pos : -1, str(c->mfg_name),
		    str(c->model_name), str(c->serial_num),
		    str(c->hardware_rev), str(c->firmware_rev),
		    str(c->software_rev), str(c->uuid), c->has_is_fru ?
		    (c->is_fru ? "yes" : "no") : "-", str(c->description));
		if (c->contains_child.n > 0) {
			printf(" children=");
			for (size_t k = 0; k < c->contains_child.n; k++)
				printf("%s%s", k > 0 ? "," : "",
				    c->contains_child.v[k]);
		}
		if (c->sensor_data != NULL)
			printf(" value=%d precision=%d type=%d",
			    c->sensor_data->value,
			    c->sensor_data->value_precision,
			    (int)c->sensor_data->value_type);
		printf("\n");
	}
	if (ietf_hardware_hardware_encode(h.hardware, &b1) != 0 ||
	    ietf_hardware_hardware_decode(b1.p, b1.len, &back, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0 ||
	    ietf_hardware_hardware_encode(&back, &b2) != 0)
		errx(1, "the round trip: %s", why);
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" :
	    "not the same");
	return (0);
}
