/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the host's hardware as RFC 8348's components.  The chassis
 * is what SMBIOS says of the system
 * (kenv(2)'s smbios.*, as the loader put it there), the running
 * kernel's release its software; a component per logical CPU (hw.ncpu,
 * hw.model), with its temperature as a sensor where coretemp(4) or
 * amdtemp(4) gives one (dev.cpu.N.temperature, decikelvin); a
 * storage drive per disk of GEOM's DISK class, its description as the
 * model and its ident as the serial number.
 *
 * yhw_json() reads the host into
 *
 *	{"chassis": {"maker", "product", "version", "serial", "uuid",
 *	 "bios", "os"}, "model": hw.model, "cpus": [decicelsius | null],
 *	 "disks": [{"name", "descr", "ident", "rotation", "size"}]}
 *
 * and yhw_from_json() makes the components of it, the part a test can
 * feed.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <kenv.h>

#include <ctype.h>
#include <errno.h>
#include <libgeom.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "collect.h"
#include "yjson.h"

typedef struct ietf_hardware_hardware_component	ycomp;

/* What firmware writes where it has nothing to say. */
static const char *const filler[] = {
	"To be filled by O.E.M.", "To Be Filled By O.E.M.", "Not Specified",
	"Not Applicable", "Default string", "System Product Name",
	"System Version", "System Serial Number", "System manufacturer",
	"None", "0123456789", "Unknown",
};

/* A SMBIOS string, NULL when absent, blank or filler. */
static const char *
smbios(ucl_object_t *o, const char *key, const char *var)
{
	char	 buf[256];
	size_t	 i;

	if (kenv(KENV_GET, var, buf, sizeof(buf)) <= 0)
		return (NULL);
	buf[sizeof(buf) - 1] = '\0';
	for (i = strlen(buf); i > 0 && isspace((unsigned char)buf[i - 1]); i--)
		buf[i - 1] = '\0';
	if (buf[0] == '\0')
		return (NULL);
	for (i = 0; i < nitems(filler); i++)
		if (strcasecmp(buf, filler[i]) == 0)
			return (NULL);
	ucl_object_insert_key(o, ucl_object_fromstring(buf), key, 0, true);
	return (ucl_object_tostring(ucl_object_lookup(o, key)));
}

static const char *
gconf(struct gprovider *pp, const char *name)
{
	struct gconfig	*c;

	LIST_FOREACH(c, &pp->lg_config, lg_config)
		if (strcmp(c->lg_name, name) == 0)
			return (c->lg_val);
	return (NULL);
}

int
yhw_json(char **jsonp)
{
	ucl_object_t		*top, *ch, *cpus, *disks, *d;
	struct gmesh		 mesh;
	struct gclass		*cls;
	struct ggeom		*gp;
	struct gprovider	*pp;
	const char		*v;
	char			 buf[256], name[64];
	size_t			 len;
	int			 ncpu, dk, i;

	*jsonp = NULL;
	top = ucl_object_typed_new(UCL_OBJECT);
	ch = ucl_object_typed_new(UCL_OBJECT);
	smbios(ch, "maker", "smbios.system.maker");
	smbios(ch, "product", "smbios.system.product");
	smbios(ch, "version", "smbios.system.version");
	smbios(ch, "serial", "smbios.system.serial");
	smbios(ch, "uuid", "smbios.system.uuid");
	smbios(ch, "bios", "smbios.bios.version");
	len = sizeof(buf);
	if (sysctlbyname("kern.osrelease", buf, &len, NULL, 0) == 0)
		ucl_object_insert_key(ch, ucl_object_fromstring(buf), "os", 0,
		    false);
	ucl_object_insert_key(top, ch, "chassis", 0, false);
	len = sizeof(buf);
	if (sysctlbyname("hw.model", buf, &len, NULL, 0) == 0)
		ucl_object_insert_key(top, ucl_object_fromstring(buf), "model",
		    0, false);
	cpus = ucl_object_typed_new(UCL_ARRAY);
	len = sizeof(ncpu);
	if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) != 0)
		ncpu = 0;
	for (i = 0; i < ncpu; i++) {
		snprintf(name, sizeof(name), "dev.cpu.%d.temperature", i);
		len = sizeof(dk);
		if (sysctlbyname(name, &dk, &len, NULL, 0) == 0 && dk > 0)
			ucl_array_append(cpus, ucl_object_fromint(dk - 2731));
		else
			ucl_array_append(cpus, ucl_object_typed_new(UCL_NULL));
	}
	ucl_object_insert_key(top, cpus, "cpus", 0, false);
	disks = ucl_object_typed_new(UCL_ARRAY);
	if (geom_gettree(&mesh) == 0) {
		LIST_FOREACH(cls, &mesh.lg_class, lg_class) {
			if (strcmp(cls->lg_name, "DISK") != 0)
				continue;
			LIST_FOREACH(gp, &cls->lg_geom, lg_geom) {
				if ((pp = LIST_FIRST(&gp->lg_provider)) == NULL)
					continue;
				d = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(d, ucl_object_fromstring(
				    pp->lg_name), "name", 0, false);
				if ((v = gconf(pp, "descr")) != NULL)
					ucl_object_insert_key(d,
					    ucl_object_fromstring(v), "descr", 0,
					    false);
				if ((v = gconf(pp, "ident")) != NULL)
					ucl_object_insert_key(d,
					    ucl_object_fromstring(v), "ident", 0,
					    false);
				if ((v = gconf(pp, "rotationrate")) != NULL)
					ucl_object_insert_key(d,
					    ucl_object_fromstring(v), "rotation",
					    0, false);
				ucl_object_insert_key(d, ucl_object_fromint(
				    pp->lg_mediasize), "size", 0, false);
				ucl_array_append(disks, d);
			}
		}
		geom_deletetree(&mesh);
	}
	ucl_object_insert_key(top, disks, "disks", 0, false);
	*jsonp = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (*jsonp != NULL ? 0 : ENOMEM);
}

/* An identity's SID, by its module and name; 0: none. */
static uint64_t
ident_sid(const char *mod, const char *name)
{
	const struct cbl_yident	*id;
	uint32_t		 i;

	for (i = 0; i < ymodel_schema.nident; i++) {
		id = &ymodel_schema.ident[i];
		if (strcmp(id->name, name) == 0 &&
		    strcmp(id->module->name, mod) == 0)
			return (id->sid);
	}
	return (0);
}

static const char *
afmt(cbl_yarena *a, const char *fmt, ...) __printflike(2, 3);

static const char *
afmt(cbl_yarena *a, const char *fmt, ...)
{
	va_list	 ap;
	char	 buf[256], *p;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

/* yang:uuid's pattern: 8-4-4-4-12 hexadecimal digits. */
static bool
is_uuid(const char *s)
{
	size_t	 i;

	if (s == NULL || strlen(s) != 36)
		return (false);
	for (i = 0; i < 36; i++)
		if (i == 8 || i == 13 || i == 18 || i == 23 ? s[i] != '-' :
		    !isxdigit((unsigned char)s[i]))
			return (false);
	return (true);
}

/* A size the way a disk's label says it: decimal, GB or TB. */
static const char *
disk_size(cbl_yarena *a, int64_t bytes)
{

	if (bytes >= INT64_C(1000000000000))
		return (afmt(a, "%.1f TB", (double)bytes / 1e12));
	return (afmt(a, "%.0f GB", (double)bytes / 1e9));
}

int
yhw_from_json(const char *json, cbl_yarena *a, struct ietf_hardware *out)
{
	struct ietf_hardware_hardware			*hw;
	struct ietf_hardware_hardware_component_sensor_data *sd;
	const ucl_object_t				*ch, *cpus, *disks, *e;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	ycomp						*v;
	const char					**kids, *model, *rot,
							*now;
	int64_t						 t, size;
	size_t						 n, nk, ncpu, i;
	uint64_t					 chassis, cpu, drive,
							 sensor;
	int						 error;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	error = ENOMEM;
	ch = ucl_object_lookup(top, "chassis");
	cpus = ucl_object_lookup(top, "cpus");
	disks = ucl_object_lookup(top, "disks");
	ncpu = yj_count(cpus);
	/* The chassis, each CPU and its sensor, each disk. */
	n = 1 + 2 * ncpu + yj_count(disks);
	if ((hw = cbl_yarena_alloc(a, sizeof(*hw))) == NULL ||
	    (v = cbl_yarena_alloc(a, n * sizeof(*v))) == NULL ||
	    (kids = cbl_yarena_alloc(a, n * sizeof(*kids))) == NULL)
		goto out;
	memset(v, 0, n * sizeof(*v));
	chassis = ident_sid("iana-hardware", "chassis");
	cpu = ident_sid("iana-hardware", "cpu");
	drive = ident_sid("iana-hardware", "storage-drive");
	sensor = ident_sid("iana-hardware", "sensor");
	now = NULL;
	{
		struct tm	 tm;
		time_t		 tt = time(NULL);
		char		 buf[32];

		if (gmtime_r(&tt, &tm) != NULL) {
			strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
			now = afmt(a, "%s", buf);
		}
	}

	n = nk = 0;
	v[n].name = "chassis";
	v[n].has_class = true;
	v[n].class = chassis;
	v[n].description = "the host";
	v[n].mfg_name = yj_str(a, ch, "maker");
	v[n].model_name = yj_str(a, ch, "product");
	v[n].hardware_rev = yj_str(a, ch, "version");
	v[n].serial_num = yj_str(a, ch, "serial");
	v[n].firmware_rev = yj_str(a, ch, "bios");
	v[n].software_rev = yj_str(a, ch, "os");
	if (is_uuid(yj_str(a, ch, "uuid")))
		v[n].uuid = yj_str(a, ch, "uuid");
	v[n].has_is_fru = true;
	v[n].is_fru = false;
	n++;
	model = yj_str(a, top, "model");
	i = 0;
	YJ_EACH(cpus, it, e) {
		v[n].name = afmt(a, "cpu%zu", i);
		v[n].has_class = true;
		v[n].class = cpu;
		v[n].description = afmt(a, "logical CPU %zu", i);
		v[n].model_name = model;
		v[n].parent = "chassis";
		v[n].has_parent_rel_pos = true;
		v[n].parent_rel_pos = (int32_t)i;
		v[n].has_is_fru = true;
		v[n].is_fru = false;
		kids[nk++] = v[n].name;
		n++;
		if (ucl_object_type(e) == UCL_INT) {
			/* Its temperature, a tenth of a degree's precision. */
			t = ucl_object_toint(e);
			if ((sd = cbl_yarena_alloc(a, sizeof(*sd))) == NULL)
				goto out;
			memset(sd, 0, sizeof(*sd));
			sd->has_value = true;
			sd->value = (int32_t)t;
			sd->has_value_type = true;
			sd->value_type =
			    IETF_HARDWARE_HARDWARE_COMPONENT_SENSOR_DATA_VALUE_TYPE_CELSIUS;
			sd->has_value_scale = true;
			sd->value_scale =
			    IETF_HARDWARE_HARDWARE_COMPONENT_SENSOR_DATA_VALUE_SCALE_UNITS;
			sd->has_value_precision = true;
			sd->value_precision = 1;
			sd->has_oper_status = true;
			sd->oper_status =
			    IETF_HARDWARE_HARDWARE_COMPONENT_SENSOR_DATA_OPER_STATUS_OK;
			sd->units_display = "degrees Celsius";
			sd->value_timestamp = now;
			/* Read when asked: on demand. */
			sd->has_value_update_rate = true;
			sd->value_update_rate = 0;
			v[n].name = afmt(a, "cpu%zu-temperature", i);
			v[n].has_class = true;
			v[n].class = sensor;
			v[n].description = afmt(a, "the temperature of CPU %zu",
			    i);
			v[n].parent = v[n - 1].name;
			v[n].has_parent_rel_pos = true;
			v[n].parent_rel_pos = 0;
			v[n].sensor_data = sd;
			v[n - 1].contains_child.n = 1;
			v[n - 1].contains_child.v = &v[n].name;
			n++;
		}
		i++;
	}
	i = 0;
	YJ_EACH(disks, it, e) {
		if ((v[n].name = yj_str(a, e, "name")) == NULL)
			continue;
		v[n].has_class = true;
		v[n].class = drive;
		rot = yj_str(a, e, "rotation");
		size = 0;
		(void)yj_num(e, "size", &size);
		/* GEOM's rotationrate: 0 solid state, else rpm. */
		if (rot == NULL || strcmp(rot, "unknown") == 0)
			v[n].description = disk_size(a, size);
		else
			v[n].description = afmt(a, "%s, %s", disk_size(a,
			    size), strcmp(rot, "0") == 0 ? "solid state" :
			    afmt(a, "%s rpm", rot));
		v[n].model_name = yj_str(a, e, "descr");
		v[n].serial_num = yj_str(a, e, "ident");
		v[n].parent = "chassis";
		v[n].has_parent_rel_pos = true;
		v[n].parent_rel_pos = (int32_t)i++;
		v[n].has_is_fru = true;
		v[n].is_fru = true;
		kids[nk++] = v[n].name;
		n++;
	}
	v[0].contains_child.n = nk;
	v[0].contains_child.v = nk > 0 ? kids : NULL;
	hw->component.n = n;
	hw->component.v = v;
	out->hardware = hw;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}
