/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's own configuration, of the system read (GET
 * /api/servers/<id>/system): the System tab (NTP, Linux compatibility,
 * service jails, periodic, devd, resource limits), the Security tab
 * (auditd, Kerberos, MAC, securelevel), and what the Storage tab (GEOM,
 * GELI, devfs), the Logs tab (syslog), the Sysctl tab (hardening) and
 * IPsec (setkey) show of it.  Its files are written whole by sysfile
 * jobs; the rest by the jobs that own it (ntp, kmod, sysctl,
 * service-action, geom), a service's rcvar and variables (Linux, auditd,
 * a service jail) by arcana-services' commit (ycommit.c).
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	struct res	 r;		/* the system read */
	bool		 logconf;	/* the Logs tab: syslog's configuration */
	bool		 hardening;	/* the Sysctl tab: the hardening helper */
	int		 storage;	/* the Storage tab: 1 GEOM, 2 GELI, 3 devfs */
	struct ycommit	 yc;		/* a service's configuration */
	char		 ycfor[16];	/* its section: linux, svcj, auditd */
	char		 ycsvc[64];	/* and service */
	bool		 ycstart;	/* started once enabled */
} sv;

static struct server *sv_server(void);

/* A service's configuration saved: started where asked; read again. */
static void
svc_saved(struct ycommit *yc, int how)
{
	struct server	*s = NULL;
	char		 title[96], *q, *json;

	for (int i = 0; s == NULL && i < app.nservers; i++)
		if (strcmp(app.servers[i].id, yc->sid) == 0)
			s = &app.servers[i];
	if (s == NULL)
		return;
	if (how == YC_SAVED && sv.ycstart) {
		q = json_quote(sv.ycsvc);
		if (asprintf(&json, "{\"kind\":\"service-action\","
		    "\"service\":%s,\"action\":\"start\"}", q) == -1)
			abort();
		free(q);
		snprintf(title, sizeof(title), "service %s start", sv.ycsvc);
		job_send(s, json, title, JOB_SYSTEM, s->name);
	}
	sv.ycstart = false;
	if (how != YC_REFUSED)
		refresh_system(s, true);
}

/* Service svc of host s, its entry merged with body and committed, for
 * section what; with start, started once it is saved. */
static void
svc_commit(struct server *s, const char *what, const char *svc,
    const char *body, bool start)
{

	sv.yc.act = "sv-yc";
	sv.yc.saved = "Saved: Arcana's rc.conf file has it.";
	sv.yc.undone = "Undone: as it was.";
	sv.yc.done = svc_saved;
	if (sv.yc.busy) {
		toast(true, "A change of the configuration is on its way");
		return;
	}
	snprintf(sv.ycfor, sizeof(sv.ycfor), "%s", what);
	snprintf(sv.ycsvc, sizeof(sv.ycsvc), "%s", svc);
	sv.ycstart = start;
	(void)service_commit(s->id, svc, "PATCH", NULL, body, &sv.yc);
}

/* Service svc enabled or not, committed; on, started after. */
static void
svc_enable(struct server *s, const char *what, const char *svc, bool on)
{
	char	*q, *body;

	q = json_quote(svc);
	if (asprintf(&body, "{\"arcana-services:service\":[{\"name\":%s,"
	    "\"enabled\":%s}]}", q, on ? "true" : "false") == -1)
		abort();
	free(q);
	svc_commit(s, what, svc, body, on);
	free(body);
}

/* A service stopped by its job (JOB_SVC_OFF): now disabled. */
void
sysview_svc_off(struct server *s, const char *svc)
{

	svc_enable(s, strcmp(svc, "auditd") == 0 ? "auditd" : "linux", svc,
	    false);
}

/* How a section's commit went, under it. */
static void
yc_note(struct html *h, const char *what)
{
	const struct server	*s = sv_server();

	if (s != NULL && strcmp(sv.yc.sid, s->id) == 0 &&
	    strcmp(sv.ycfor, what) == 0)
		ycommit_note(h, &sv.yc);
}

void
sysview_tick(double now)
{

	ycommit_tick(&sv.yc, now);
}

/* Another tab's own view is shown: ours of it is not. */
void
sysview_hide(void)
{

	sv.logconf = false;
	sv.hardening = false;
	sv.storage = 0;
}

/* Which of the other tabs' views of it is shown: logconf, hardening,
 * geom, geli, devfs. */
bool
sysview_shown(const char *which)
{

	if (strcmp(which, "logconf") == 0)
		return (sv.logconf);
	if (strcmp(which, "hardening") == 0)
		return (sv.hardening);
	if (strcmp(which, "geom") == 0)
		return (sv.storage == 1);
	if (strcmp(which, "geli") == 0)
		return (sv.storage == 2);
	if (strcmp(which, "devfs") == 0)
		return (sv.storage == 3);
	if (strcmp(which, "storage") == 0)
		return (sv.storage != 0);
	return (false);
}

static void
sv_load(const char *sid)
{
	char	url[96];

	snprintf(url, sizeof(url), "/api/servers/%s/system", sid);
	res_load(&sv.r, sid, url);
}

void
refresh_system(struct server *s, bool again)
{

	/* Again, after a job: asked whatever is on its way, which may be
	 * from before the job (res's generation drops its answer). */
	if (s == NULL || (!again && sv.r.o != NULL && strcmp(sv.r.sid,
	    s->id) == 0) || (!again && sv.r.loading && strcmp(sv.r.sid,
	    s->id) == 0))
		return;
	sv_load(s->id);
}

/* The read, when it is this host's; else asked for, and NULL. */
static const ucl_object_t *
data(struct html *h, struct server *s)
{

	return (res_shown(h, &sv.r, s->id, sv_load, "sv-retry") ? sv.r.o :
	    NULL);
}

static void
send(struct server *s, char *json, const char *title)
{

	job_send(s, json, title, JOB_SYSTEM, s->name);
}

/* A sysfile job: file written whole from text. */
static void
send_file(struct server *s, const char *file, const char *text)
{
	char	title[96];

	snprintf(title, sizeof(title), "%s written", file);
	send(s, job_json("sysfile", file, NULL, 0, text != NULL ? text : "",
	    NULL), title);
}

/* A job of words: kind, verb (or none), its args. */
static void
send_words(struct server *s, const char *kind, const char *verb,
    const char *const *w, size_t n, const char *extra, const char *title)
{

	send(s, job_json(kind, verb, w, n, NULL, extra), title);
}

static void
chip(struct html *h, bool on, const char *yes, const char *no)
{

	h_fmt(h, "<span class=\"chip %s\">%s</span> ", on ? "st-up" : "st-down",
	    on ? yes : no);
}

static void
pre(struct html *h, const char *title, const char *text)
{

	if (text == NULL || text[0] == '\0')
		return;
	if (title != NULL) {
		h_raw(h, "<h4>");
		h_txt(h, title);
		h_raw(h, "</h4>");
	}
	h_raw(h, "<pre class=\"mono naspre\">");
	h_txt(h, text);
	h_raw(h, "</pre>");
}

/* One of the table's files: its text to edit, its daemon, what shows
 * it at work. */
static void
file_editor(struct html *h, const ucl_object_t *o, const char *file,
    const char *title, const char *help, int rows)
{
	const ucl_object_t	*f = jget(jget(o, "files"), file);

	h_fmt(h, "<form class=\"secform\" data-form=\"sv-file\"><h4>%s "
	    "<small class=\"dim mono\">", title);
	h_txt(h, jstr(f, "path"));
	h_raw(h, "</small></h4><input type=\"hidden\" name=\"file\"");
	h_attr(h, "value", file);
	h_fmt(h, "><label class=\"wide\">%s <textarea name=\"text\" rows="
	    "\"%d\" spellcheck=\"false\">", help, rows);
	h_txt(h, jstr(f, "text"));
	h_raw(h, "</textarea>");
	if (jstr(f, "service") != NULL) {
		h_raw(h, "<small class=\"help\">saved, ");
		h_txt(h, jstr(f, "service"));
		h_raw(h, jbool(f, "running") ? " reads it again" : " reads it as "
		    "it starts");
		h_raw(h, "</small>");
	}
	h_raw(h, "</label><div class=\"actions\"><button type=\"submit\" "
	    "class=\"primary\">Save</button></div></form>");
	if (jstr(f, "shows") != NULL)
		pre(h, NULL, jstr(f, "shows"));
}

/* ---- System ---------------------------------------------------------- */

static const char *const svcj_opts[] = { "net_basic", "net_all", "netv4",
    "netv6", "nfsd", "routing", "sysvipc", "mlock", "vmm" };

static void
view_ntp(struct html *h, const ucl_object_t *o)
{
	const ucl_object_t	*n = jget(o, "ntp");
	const char		*conf, *p;
	char			 servers[512], word[128];
	size_t			 len;

	/* Its servers, as ntp.conf's server and pool lines name them. */
	servers[0] = '\0';
	len = 0;
	conf = jstr(n, "conf");
	for (p = conf; p != NULL && *p != '\0'; p = strchr(p, '\n') != NULL ?
	    strchr(p, '\n') + 1 : NULL)
		if ((strncmp(p, "server ", 7) == 0 || strncmp(p, "pool ", 5) ==
		    0) && sscanf(p + (p[0] == 's' ? 7 : 5), "%127s", word) ==
		    1 && len < sizeof(servers) - 130)
			len += (size_t)snprintf(servers + len, sizeof(servers) -
			    len, "%s%s", len > 0 ? ", " : "", word);
	h_raw(h, "<h3 class=\"secsub\">Time (NTP)</h3><p>");
	chip(h, jbool(n, "running"), "ntpd running", "ntpd stopped");
	h_raw(h, "</p><form class=\"secform\" data-form=\"sv-ntp\"><label "
	    "class=\"wide\">Its servers <input name=\"servers\" spellcheck=\"false\" placeholder="
	    "\"0.freebsd.pool.ntp.org, 1.freebsd.pool.ntp.org\"");
	h_attr(h, "value", servers);
	h_raw(h, "><small class=\"help\">ntpd(8) keeps time by them, 8 at most "
	    "(ntp.conf); ntpd enabled and restarted</small></label><div class="
	    "\"actions\"><button type=\"submit\" class=\"primary\">Save</button>"
	    "</div></form>");
	pre(h, "Its peers (ntpq -pn)", jstr(n, "peers"));
}

static void
view_linux(struct html *h, const ucl_object_t *o)
{
	const ucl_object_t	*l = jget(o, "linux"), *e;
	ucl_object_iter_t	 it;

	h_raw(h, "<h3 class=\"secsub\">Linux compatibility</h3><p>");
	chip(h, jbool(l, "enabled"), "enabled", "not enabled");
	it = NULL;
	while ((e = ucl_object_iterate(jget(l, "modules"), &it, true)) != NULL)
		chip(h, ucl_object_toboolean(e), ucl_object_key(e),
		    ucl_object_key(e));
	h_fmt(h, "<button class=\"ghost small\" data-act=\"sv-linux\" data-arg="
	    "\"%s\">%s</button></p><p class=\"dim\">linux(4): Linux binaries run "
	    "on FreeBSD's kernel (linux_enable: its modules, linprocfs, "
	    "linsysfs, fdescfs). Their userland is a package or a jail of its "
	    "own (debootstrap); Arcana installs none.</p>", jbool(l,
	    "enabled") ? "off" : "on", jbool(l, "enabled") ? "Disable" :
	    "Enable and start");
	yc_note(h, "linux");
}

static void
view_svcj(struct html *h, const ucl_object_t *o)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	size_t			 i, n;

	h_raw(h, "<h3 class=\"secsub\">Service jails</h3><p class=\"dim\">"
	    "rc(8) runs a service in a jail of its own (NAME_svcj): the "
	    "host's files, but its own processes, and the network only as "
	    "its options give it.</p>");
	n = 0;
	it = NULL;
	h_raw(h, "<table class=\"net svcj\"><thead><tr><th>Variable</th><th>"
	    "Value</th></tr></thead><tbody>");
	while ((e = ucl_object_iterate(jget(o, "svcj"), &it, true)) != NULL) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, ucl_object_key(e));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, ucl_object_tostring_forced(e));
		h_raw(h, "</td></tr>");
		n++;
	}
	if (n == 0)
		h_raw(h, "<tr><td colspan=\"2\" class=\"dim\">No service runs "
		    "in a jail of its own.</td></tr>");
	h_raw(h, "</tbody></table><form class=\"secform\" data-form=\""
	    "sv-svcj\"><div class=\"rowform\"><label>Service <input name=\""
	    "service\" required spellcheck=\"false\" placeholder=\"named\" "
	    "pattern=\"[a-z0-9_]{1,32}\"></label><label class=\"check\"><input "
	    "type=\"checkbox\" name=\"on\" checked> In a jail</label></div>"
	    "<div class=\"checks\">");
	for (i = 0; i < nitems(svcj_opts); i++)
		h_fmt(h, "<label class=\"check\"><input type=\"checkbox\" name=\""
		    "o_%s\"%s> %s</label>", svcj_opts[i], i == 0 ? " checked" :
		    "", svcj_opts[i]);
	h_raw(h, "</div><div class=\"actions\"><button type=\"submit\" class="
	    "\"primary\">Save</button></div></form>");
	yc_note(h, "svcj");
}

static void
view_periodic(struct html *h, const ucl_object_t *o)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	const char		*v;

	h_raw(h, "<h3 class=\"secsub\">periodic(8)</h3><p class=\"dim\">The "
	    "daily, weekly, monthly and security runs of cron(8): each "
	    "script on or off (periodic.conf), its default beside.</p>");
	h_raw(h, "<table class=\"net periodic\"><thead><tr><th>Variable</th>"
	    "<th>Default</th><th>Here</th><th></th></tr></thead><tbody>");
	it = NULL;
	while ((e = ucl_object_iterate(jget(o, "periodic"), &it, true)) !=
	    NULL) {
		v = jstr(e, "value") != NULL ? jstr(e, "value") : jstr(e,
		    "default");
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(e, "name"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(e, "default"));
		h_raw(h, "</td><td>");
		chip(h, v != NULL && strcasecmp(v, "YES") == 0, "on", "off");
		h_raw(h, "</td><td class=\"acts\"><button class=\"ghost small\" "
		    "data-act=\"sv-periodic\"");
		h_attr(h, "data-arg", jstr(e, "name"));
		h_attr(h, "data-value", v != NULL && strcasecmp(v, "YES") == 0 ?
		    "NO" : "YES");
		h_fmt(h, ">%s</button></td></tr>", v != NULL && strcasecmp(v,
		    "YES") == 0 ? "Turn off" : "Turn on");
	}
	h_raw(h, "</tbody></table>");
	file_editor(h, o, "periodic.conf", "periodic.conf", "Its own settings "
	    "besides (daily_output, daily_status_security_inline...)", 5);
}

static const char *const rctl_res[] = { "memoryuse", "vmemoryuse",
    "swapuse", "maxproc", "nthr", "openfiles", "pcpu", "cputime",
    "readbps", "writebps", "readiops", "writeiops", "datasize",
    "stacksize", "memorylocked", "pseudoterminals", "wallclock",
    "shmsize", "nshm", "msgqsize", "nsem" };
static const char *const rctl_act[] = { "deny", "log", "devctl", "sigterm",
    "sigkill", "throttle" };

static void
view_rctl(struct html *h, const ucl_object_t *o, struct server *s)
{
	size_t	i;
	int	j;

	h_raw(h, "<h3 class=\"secsub\">Resource limits (rctl)</h3>");
	if (jint(o, "racct", 0) == 0)
		h_raw(h, "<div class=\"notice warn\">racct is off: rctl(8) "
		    "needs kern.racct.enable=1, a tunable of the boot. <button "
		    "class=\"ghost small\" data-act=\"sv-racct\">Turn it on at "
		    "the next boot</button></div>");
	h_raw(h, "<form class=\"secform\" data-form=\"sv-rctl\"><h4>A limit"
	    "</h4><div class=\"rowform\"><label>Of <select name=\"subject\">"
	    "<option>jail</option><option>user</option><option>loginclass"
	    "</option><option>process</option></select></label><label>"
	    "<select name=\"id\">");
	/* Its jails, picked; or a name typed. */
	for (j = 0; s->list != NULL && j < (int)ucl_array_size(jget(s->list,
	    "jails")); j++) {
		const ucl_object_t	*jl = ucl_array_find_index(jget(s->list,
		    "jails"), (unsigned)j);

		h_raw(h, "<option>");
		h_txt(h, jstr(jl, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select><input name=\"other\" spellcheck=\"false\" "
	    "placeholder=\"or a name, a uid\" pattern=\"[A-Za-z0-9_.-]{1,64}\">"
	    "</label><label>Resource <select name=\"resource\">");
	for (i = 0; i < nitems(rctl_res); i++)
		h_fmt(h, "<option>%s</option>", rctl_res[i]);
	h_raw(h, "</select></label><label>Action <select name=\"action\">");
	for (i = 0; i < nitems(rctl_act); i++)
		h_fmt(h, "<option>%s</option>", rctl_act[i]);
	h_raw(h, "</select></label><label>Amount <input name=\"amount\" "
	    "required spellcheck=\"false\" placeholder=\"2g, 100, 50\" "
	    "pattern=\"[0-9]+[kmgtKMGT]?(/[a-z]+)?\"></label></div><small class="
	    "\"help\">throttle is the bps and iops ones'; pcpu a percentage of "
	    "a CPU</small><div class=\"actions\"><button type=\"submit\" "
	    "class=\"primary\">Add</button></div></form>");
	file_editor(h, o, "rctl.conf", "rctl.conf", "Its rules, a line each "
	    "(subject:id:resource:action=amount); rctl restarted applies them, "
	    "what is limited now below", 6);
}

void
view_system(struct html *h, struct server *s)
{
	const ucl_object_t	*o;

	/* The host's power, before what is read: there while it comes. */
	h_raw(h, "<section class=\"sysview\"><h3 class=\"secsub\">Power</h3>"
	    "<p><button class=\"ghost small\" data-act=\"host-reboot\" "
	    "title=\"Reboot this host: shutdown -r, a minute after\">Reboot"
	    "</button> <span class=\"dim\">shutdown(8) -r, a minute after it "
	    "is asked; never undone, so never in safe mode.</span></p>"
	    "</section>");
	if ((o = data(h, s)) == NULL)
		return;
	h_raw(h, "<section class=\"sysview\">");
	view_ntp(h, o);
	view_linux(h, o);
	view_svcj(h, o);
	view_periodic(h, o);
	h_raw(h, "<h3 class=\"secsub\">devd(8)</h3>");
	file_editor(h, o, "devd", "Its own rules", "devd.conf(5) rules beside "
	    "the system's: notify, attach, detach, nomatch, each with an action",
	    6);
	view_rctl(h, o, s);
	h_raw(h, "</section>");
}

/* ---- Security --------------------------------------------------------- */

static const struct {
	const char	*mod, *what;
	bool		 boot;
} macs[] = {
	{ "mac_bsdextended", "file system firewall: rules by user and group "
	    "(ugidfw)", false },
	{ "mac_portacl", "ports below 1024 bound by named users "
	    "(security.mac.portacl.rules)", false },
	{ "mac_seeotheruids", "users see their own processes and sockets",
	    false },
	{ "mac_partition", "processes in partitions see their own", false },
	{ "mac_ifoff", "interfaces silenced", false },
	{ "mac_ntpd", "ntpd run as its own user, setting the clock", false },
	{ "mac_do", "users become others by rules, mdo(1)", false },
	{ "mac_mls", "Multi-Level Security: labels of secrecy", true },
	{ "mac_biba", "Biba: labels of integrity", true },
	{ "mac_lomac", "low watermark integrity", true },
};

void
view_hostsec(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *sl, *ad;
	size_t			 i;
	int			 k, now;

	h_raw(h, "<section class=\"sysview\">");
	view_nacm(h, s);
	h_raw(h, "</section>");
	if ((o = data(h, s)) == NULL)
		return;
	h_raw(h, "<section class=\"sysview\"><h3 class=\"secsub\">Audit "
	    "(auditd)</h3><p>");
	ad = jget(o, "auditd");
	chip(h, jbool(ad, "running"), "auditd running", "auditd stopped");
	h_fmt(h, "<button class=\"ghost small\" data-act=\"sv-auditd\" "
	    "data-arg=\"%s\">%s</button></p><p class=\"dim\">audit(4): the "
	    "kernel's record of what was done and by whom (BSM), in "
	    "/var/audit; auditreduce(1) and praudit(1) read it.</p>",
	    jbool(ad, "running") ? "off" : "on", jbool(ad, "running") ?
	    "Stop and disable" : "Enable and start");
	yc_note(h, "auditd");
	file_editor(h, o, "audit_control", "audit_control", "What is "
	    "recorded of everyone (flags: lo, aa, ex...), where, how much", 6);
	file_editor(h, o, "audit_user", "audit_user", "Of a user, more or less "
	    "(user:always:never)", 3);
	h_raw(h, "<h3 class=\"secsub\">Kerberos</h3>");
	file_editor(h, o, "krb5.conf", "krb5.conf", "Its realms and their KDCs "
	    "(Heimdal's, MIT's from a package)", 8);
	h_raw(h, "<h3 class=\"secsub\">MAC policies</h3><p class=\"dim\">"
	    "mac(4): the kernel's Mandatory Access Control, a module a policy; "
	    "those loaded are kept in kld_list for the next boot.</p><table "
	    "class=\"net macs\"><thead><tr><th>Module</th><th>What</th><th>"
	    "</th><th></th></tr></thead><tbody>");
	for (i = 0; i < nitems(macs); i++) {
		bool	on = jbool(jget(o, "mac"), macs[i].mod);

		h_fmt(h, "<tr><td class=\"mono\">%s</td><td>%s%s</td><td>",
		    macs[i].mod, macs[i].what, macs[i].boot ? " <small class="
		    "\"dim\">(loaded at boot alone: loader.conf)</small>" : "");
		chip(h, on, "loaded", "not loaded");
		h_raw(h, "</td><td class=\"acts\">");
		if (!macs[i].boot)
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "sv-mac\" data-arg=\"%s\" data-value=\"%s\">%s"
			    "</button>", macs[i].mod, on ? "unload" : "load",
			    on ? "Unload" : "Load");
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table>");
	sl = jget(o, "securelevel");
	now = (int)jint(sl, "now", -1);
	h_fmt(h, "<h3 class=\"secsub\">securelevel</h3><p>Now <b>%d</b>. "
	    "<small class=\"dim\">security(7): at 1 and above, the "
	    "immutable flags hold and kernel modules stay as they are; at 2 "
	    "disks are not written raw and the time does not go back by more "
	    "than a second; at 3 the firewall's rules are kept. It is raised "
	    "while the host runs, never lowered.</small></p>", now);
	h_raw(h, "<form class=\"secform\" data-form=\"sv-securelevel\"><div "
	    "class=\"rowform\"><label class=\"check\"><input type=\"checkbox\" "
	    "name=\"enable\"");
	if (jstr(sl, "kern_securelevel_enable") != NULL && strcasecmp(jstr(sl,
	    "kern_securelevel_enable"), "YES") == 0)
		h_raw(h, " checked");
	h_raw(h, "> Raised at boot</label><label>To <select name=\"level\">");
	for (k = -1; k <= 3; k++)
		h_fmt(h, "<option%s>%d</option>", jstr(sl, "kern_securelevel") !=
		    NULL && atoi(jstr(sl, "kern_securelevel")) == k ? " selected" :
		    "", k);
	h_raw(h, "</select></label><label class=\"check\"><input type=\""
	    "checkbox\" name=\"now\"> And now</label></div><div class=\""
	    "actions\"><button type=\"submit\" class=\"primary\">Save</button>"
	    "</div></form></section>");
}

/* ---- What other tabs show of it --------------------------------------- */

static const char *const gclasses[] = { "mirror", "stripe", "concat",
    "raid3", "label", "nop", "multipath", "shsec", "virstor", "cache",
    "journal", "eli", "union" };

/* GEOM, GELI and devfs: the Storage tab's own sections. */
void
view_storage_geom(struct html *h, struct server *s, int which)
{
	const ucl_object_t	*o, *e;
	ucl_object_iter_t	 it;
	size_t			 i;

	if ((o = data(h, s)) == NULL)
		return;
	if (which == 2) {
		file_editor(h, o, "devfs.rules", "devfs rules", "devfs.rules(5): "
		    "what each rule set shows of /dev, a jail's by its "
		    "devfs_ruleset", 10);
		return;
	}
	if (which == 0) {
		h_raw(h, "<p class=\"dim\">GEOM: the kernel's stack of storage "
		    "classes, each a module (geom_mirror...) loaded when it is "
		    "first used. gpart has the Disks view.</p>");
		it = NULL;
		while ((e = ucl_object_iterate(jget(o, "geom_classes"), &it,
		    true)) != NULL) {
			char	t[64];

			snprintf(t, sizeof(t), "%s (geom %s status)",
			    ucl_object_key(e), ucl_object_key(e));
			pre(h, t, ucl_object_tostring(e));
		}
		pre(h, "The tree (geom -t)", jstr(o, "geom"));
	} else
		pre(h, "GELI's providers (geli list)", jstr(o, "geli"));
	h_raw(h, "<form class=\"secform\" data-form=\"sv-geom\"><h4>A class's "
	    "command</h4><div class=\"rowform\"><label>Class <select name=\""
	    "class\">");
	for (i = 0; i < nitems(gclasses); i++)
		h_fmt(h, "<option%s>%s</option>", (which == 1 && strcmp(
		    gclasses[i], "eli") == 0) ? " selected" : "", gclasses[i]);
	h_raw(h, "</select></label><label>Subcommand <input name=\"sub\" "
	    "required spellcheck=\"false\" list=\"gsubs\" placeholder=\"label\">"
	    "<datalist id=\"gsubs\"><option>label<option>create<option>insert"
	    "<option>remove<option>rebuild<option>configure<option>destroy"
	    "<option>stop<option>clear<option>init<option>attach<option>detach"
	    "<option>onetime<option>setkey<option>load<option>unload</datalist>"
	    "</label><label class=\"grow\">Words <input name=\"words\" "
	    "spellcheck=\"false\" placeholder=\"-v -b round-robin gm0 /dev/ada1 "
	    "/dev/ada2\"></label></div><div class=\"rowform\"><label>Passphrase "
	    "<input name=\"pass\" type=\"password\" autocomplete=\"off\"><small "
	    "class=\"help\">geli init, attach and setkey's, by a file of the "
	    "job's own on the host</small></label></div><small class=\"help\">"
	    "geom(8) runs the class's command: gmirror(8), gstripe(8), geli(8) "
	    "and the others' manuals say its words. label, clear, destroy, "
	    "init and kill write over what was there.</small><div class=\""
	    "actions\"><button type=\"submit\" class=\"primary\">Run</button>"
	    "</div></form>");
}

/* syslog: the Logs tab's configuration. */
void
view_syslogconf(struct html *h, struct server *s)
{
	const ucl_object_t	*o;

	if ((o = data(h, s)) == NULL)
		return;
	h_raw(h, "<form class=\"secform\" data-form=\"sv-remote\"><h4>Sent to "
	    "another host</h4><div class=\"rowform\"><label>What <input name=\""
	    "what\" spellcheck=\"false\" value=\"*.*\"></label><label class=\""
	    "grow\">To <input name=\"host\" required spellcheck=\"false\" "
	    "placeholder=\"logs.example.org, 10.0.0.9:514\" pattern=\"[A-Za-z0-9"
	    ".:\\[\\]-]{1,128}\"></label></div><small class=\"help\">a line "
	    "*.* @host added to syslog.conf: syslogd(8) sends it there by "
	    "UDP</small><div class=\"actions\"><button type=\"submit\" class=\""
	    "primary\">Add</button></div></form>");
	file_editor(h, o, "syslog.conf", "syslog.conf", "syslog.conf(5): what "
	    "of whom goes where, a line each (facility.level destination)", 12);
	file_editor(h, o, "newsyslog.conf", "newsyslog.conf", "newsyslog.conf"
	    "(5): when each log is turned over, how many are kept, compressed",
	    8);
}

/* The Sysctl tab's helper: sysctls of hardening, what each should be. */
static const struct {
	const char	*name;
	int		 want;
	const char	*why;
} hard[] = {
	{ "security.bsd.see_other_uids", 0, "users see their own processes "
	    "alone" },
	{ "security.bsd.see_other_gids", 0, "nor their groups' others'" },
	{ "security.bsd.see_jail_proc", 0, "nor a jail's" },
	{ "security.bsd.unprivileged_read_msgbuf", 0, "dmesg is root's" },
	{ "security.bsd.unprivileged_proc_debug", 0, "no ptrace(2) or ktrace "
	    "by users" },
	{ "security.bsd.hardlink_check_uid", 1, "no hard link to another "
	    "user's file" },
	{ "security.bsd.hardlink_check_gid", 1, "nor to another group's" },
	{ "security.bsd.unprivileged_get_quota", 0, "others' quotas root's" },
	{ "kern.elf64.aslr.enable", 1, "address space layout randomized" },
	{ "kern.elf64.aslr.pie_enable", 1, "for position-independent ones "
	    "too" },
	{ "kern.elf64.aslr.stack", 1, "the stack's too" },
	{ "kern.elf64.allow_wx", 0, "no memory writable and executable at "
	    "once (some JITs need it)" },
	{ "kern.elf32.aslr.enable", 1, "32-bit programs' too" },
	{ "kern.sugid_coredump", 0, "no core of a set-uid program" },
	{ "net.inet.tcp.blackhole", 2, "a closed TCP port answers nothing" },
	{ "net.inet.udp.blackhole", 1, "nor a closed UDP port" },
	{ "net.inet.icmp.drop_redirect", 1, "ICMP redirects ignored" },
	{ "net.inet6.icmp6.rediraccept", 0, "ICMPv6's too" },
	{ "net.inet.ip.redirect", 0, "none sent (not a router)" },
	{ "net.inet6.ip6.redirect", 0, "nor IPv6's" },
	{ "net.inet.ip.random_id", 1, "IP IDs random" },
	{ "net.inet.tcp.drop_synfin", 1, "SYN with FIN dropped" },
	{ "net.inet.ip.sourceroute", 0, "no source routing" },
	{ "net.inet.ip.accept_sourceroute", 0, "nor accepted" },
	{ "net.inet.icmp.bmcastecho", 0, "no echo to broadcast" },
};

void
view_hardening(struct html *h, struct server *s)
{
	const ucl_object_t	*o, *hv, *v;
	size_t			 i;
	int			 differ;

	if ((o = data(h, s)) == NULL)
		return;
	hv = jget(o, "hardening");
	differ = 0;
	for (i = 0; i < nitems(hard); i++)
		if ((v = ucl_object_lookup(hv, hard[i].name)) != NULL && ucl_object_toint(v) !=
		    hard[i].want)
			differ++;
	h_fmt(h, "<h3 class=\"secsub\">Hardening</h3><p class=\"dim\">Sysctls "
	    "security(7) and hardening guides set, as this host has them; "
	    "applied, each is kept in sysctl.conf. %d of them differ.</p>",
	    differ);
	if (differ > 0)
		h_raw(h, "<div class=\"toolbar\"><span class=\"grow\"></span>"
		    "<button class=\"ghost\" data-act=\"sv-harden-all\">Apply "
		    "those that differ</button></div>");
	h_raw(h, "<table class=\"net hardening\"><thead><tr><th>Sysctl</th><th>"
	    "Now</th><th>Hardened</th><th>Why</th><th></th></tr></thead>"
	    "<tbody>");
	for (i = 0; i < nitems(hard); i++) {
		if ((v = ucl_object_lookup(hv, hard[i].name)) == NULL)
			continue;
		h_fmt(h, "<tr><td class=\"mono\">%s</td><td class=\"mono\">%lld"
		    "</td><td class=\"mono\">%d</td><td>%s</td><td class=\"acts"
		    "\">", hard[i].name, (long long)ucl_object_toint(v),
		    hard[i].want, hard[i].why);
		if (ucl_object_toint(v) != hard[i].want)
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "sv-harden\" data-arg=\"%s\" data-value=\"%d\">Apply"
			    "</button>", hard[i].name, hard[i].want);
		else
			h_raw(h, "<span class=\"chip st-up\">set</span>");
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table>");
}

/* setkey(8): IPsec's own, beside strongSwan's. */
void
view_setkey(struct html *h, struct server *s)
{
	const ucl_object_t	*o;

	if ((o = data(h, s)) == NULL)
		return;
	h_raw(h, "<h3 class=\"secsub\">setkey(8)</h3><p class=\"dim\">The "
	    "kernel's IPsec by hand: security policies and, for manual "
	    "keying, security associations, as ipsec.conf has them "
	    "(ipsec_enable runs it at boot). IKE (strongSwan) makes them for "
	    "you; this is for those it does not.</p>");
	file_editor(h, o, "ipsec.conf", "ipsec.conf", "setkey's commands: "
	    "spdadd, add (manual keys), flush, spdflush; root's alone, its "
	    "keys in it. Its policies now (setkey -DP) below", 10);
}

/* ---- Forms and actions ------------------------------------------------ */

static struct server *
sv_server(void)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sv.r.sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

static bool
safe_word(const char *v, const char *more)
{
	size_t	n, i;

	n = v != NULL ? strlen(v) : 0;
	if (n == 0 || n > 128)
		return (false);
	/* Each character a letter, a digit, or one of more. */
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)v[i]) && strchr(more, v[i]) == NULL)
			return (false);
	return (true);
}

/* The current text of a file, for what is added to it. */
static const char *
cur_text(const char *file)
{
	const char	*t = jstr(jget(jget(sv.r.o, "files"), file), "text");

	return (t != NULL ? t : "");
}

static char *
appended(const char *text, const char *line)
{
	char	*t;
	size_t	 n;

	n = strlen(text);
	if (asprintf(&t, "%s%s%s\n", text, n > 0 && text[n - 1] != '\n' ?
	    "\n" : "", line) == -1)
		abort();
	return (t);
}

/* The console's own host: its agent writes dma's files. */
static struct server *
local_server(void)
{
	int	i;

	for (i = 0; i < app.nservers; i++)
		if (app.servers[i].local)
			return (&app.servers[i]);
	return (NULL);
}

/*
 * Settings' mail, relayed by dma(8) on the console's host: its smart
 * host, port, TLS and sign-in, as dma.conf and auth.conf say them, read
 * from that host and written there by its agent (a sysfile job).
 */
void
dma_settings(struct html *h)
{
	static const char *const tls[][2] = {
		{ "none", "none: plain SMTP" },
		{ "starttls", "STARTTLS, required (587)" },
		{ "opportunistic", "STARTTLS when the relay offers it" },
		{ "tls", "TLS from the start (465)" },
	};
	struct server		*s;
	const ucl_object_t	*o, *d;
	size_t			 i;

	h_raw(h, "<h4>Relayed by dma</h4>");
	if ((s = local_server()) == NULL) {
		h_raw(h, "<p class=\"dim\">No agent beside the console: dma's "
		    "relay is set in /etc/dma/dma.conf and auth.conf on the "
		    "console's host by hand.</p>");
		return;
	}
	if ((o = res_shown(h, &sv.r, s->id, sv_load, "sv-retry") ? sv.r.o :
	    NULL) == NULL)
		return;
	d = jget(o, "dma");
	h_raw(h, "<form data-form=\"dma\" data-clear-secrets class=\"settings "
	    "set-form\"><p class="
	    "\"dim\">dma(8), FreeBSD's own mail agent, sends the console's "
	    "mail: straight to each domain's servers, or through a smart host "
	    "that signs it in. Set in <code>/etc/dma/dma.conf</code> (its other "
	    "lines kept) and <code>/etc/dma/auth.conf</code> (root's and the "
	    "mail group's alone) on the console's host by its agent; the "
	    "password is never shown again.</p><div class=\"rowform\"><label>"
	    "Smart host<input name=\"smarthost\" spellcheck=\"false\" "
	    "autocomplete=\"off\" placeholder=\"smtp.example.net, or empty: "
	    "straight\"");
	h_attr(h, "value", jstr(d, "smarthost") != NULL ? jstr(d, "smarthost") :
	    "");
	h_raw(h, "></label><label>Port<input name=\"port\" inputmode=\"numeric\" "
	    "size=\"6\" placeholder=\"587\"");
	h_attr(h, "value", jstr(d, "port") != NULL ? jstr(d, "port") : "");
	h_raw(h, "></label><label>TLS<select name=\"tls\">");
	for (i = 0; i < nitems(tls); i++) {
		h_raw(h, "<option");
		h_attr(h, "value", tls[i][0]);
		if (jstr(d, "tls") != NULL && strcmp(jstr(d, "tls"), tls[i][0]) ==
		    0)
			h_raw(h, " selected");
		h_raw(h, ">");
		h_txt(h, tls[i][1]);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label></div><div class=\"rowform\"><label>User"
	    "<input name=\"user\" spellcheck=\"false\" autocomplete=\"off\" "
	    "placeholder=\"alerts@example.net, or empty: no sign-in\"");
	h_attr(h, "value", jstr(d, "user") != NULL ? jstr(d, "user") : "");
	h_fmt(h, "></label><label>Password<input name=\"password\" "
	    "type=\"password\" autocomplete=\"new-password\" placeholder=\"%s\">"
	    "</label></div><div class=\"actions\"><button class=\"primary\">"
	    "Save</button></div></form>", jbool(d, "password_set") ? "set: "
	    "empty keeps it" : "");
}

/* The dma form: a sysfile job on the console's host. */
static bool
dma_form(const ucl_object_t *f)
{
	struct server	*s;
	const char	*w[4];
	char		*a[4];
	int		 i;

	if ((s = local_server()) == NULL)
		return (true);
	if (asprintf(&a[0], "smarthost=%s", jstr(f, "smarthost") != NULL ?
	    jstr(f, "smarthost") : "") == -1 || asprintf(&a[1], "port=%s",
	    jstr(f, "port") != NULL ? jstr(f, "port") : "") == -1 ||
	    asprintf(&a[2], "tls=%s", jstr(f, "tls") != NULL ? jstr(f, "tls") :
	    "none") == -1 || asprintf(&a[3], "user=%s", jstr(f, "user") !=
	    NULL ? jstr(f, "user") : "") == -1)
		abort();
	for (i = 0; i < 4; i++)
		w[i] = a[i];
	/* The password in the job's text alone: empty keeps the one there. */
	send(s, job_json("sysfile", "dma", w, 4, jstr(f, "password") != NULL &&
	    jstr(f, "password")[0] != '\0' ? jstr(f, "password") : NULL, NULL),
	    "dma's smart host");
	for (i = 0; i < 4; i++)
		free(a[i]);
	return (true);
}

bool
sysview_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	const char	*w[40];
	char		*buf[40], *t, *copy, *p, *tok;
	size_t		 n, i;

	if (strcmp(form, "dma") == 0)
		return (dma_form(f));
	if (strncmp(form, "sv-", 3) != 0)
		return (false);
	if ((s = sv_server()) == NULL)
		return (true);
	if (strcmp(form, "sv-file") == 0) {
		send_file(s, jstr(f, "file"), jstr(f, "text"));
		return (true);
	}
	if (strcmp(form, "sv-ntp") == 0) {
		copy = strdup(jstr(f, "servers") != NULL ? jstr(f, "servers") :
		    "");
		n = 0;
		for (p = copy; (tok = strsep(&p, ", ")) != NULL && n < 8;)
			if (tok[0] != '\0')
				w[n++] = tok;
		if (n == 0)
			send_words(s, "ntp", NULL, w, 0, ",\"remove\":true",
			    "ntp: arcana's servers taken out");
		else
			send_words(s, "ntp", NULL, w, n, NULL, "ntp servers");
		free(copy);
		return (true);
	}
	if (strcmp(form, "sv-svcj") == 0) {
		const char	*svc = jstr(f, "service");
		char		 opts[200], k[32], yes[300], how[500], *json;

		if (!safe_word(svc, "_")) {
			toast(true, "A service is named by letters, digits and _");
			return (true);
		}
		opts[0] = '\0';
		for (i = 0; i < nitems(svcj_opts); i++) {
			snprintf(k, sizeof(k), "o_%s", svcj_opts[i]);
			if (jbool(f, k)) {
				strlcat(opts, opts[0] != '\0' ? " " : "",
				    sizeof(opts));
				strlcat(opts, svcj_opts[i], sizeof(opts));
			}
		}
		/*
		 * Its variables in its configuration, a YANG Patch committed:
		 * on, NAME_svcj YES and its options (none: taken out); off,
		 * both taken out, never NO written, rc.subr's default.
		 * "remove" takes one that is not there as done.
		 */
		if (jbool(f, "on")) {
			snprintf(yes, sizeof(yes), "{\"edit-id\":\"on\","
			    "\"operation\":\"merge\",\"target\":\"/variable="
			    "%s_svcj\",\"value\":{\"arcana-services:variable\":"
			    "[{\"name\":\"%s_svcj\",\"value\":\"YES\"}]}}", svc,
			    svc);
		} else
			snprintf(yes, sizeof(yes), "{\"edit-id\":\"off\","
			    "\"operation\":\"remove\",\"target\":\"/variable="
			    "%s_svcj\"}", svc);
		if (jbool(f, "on") && opts[0] != '\0')
			snprintf(how, sizeof(how), "{\"edit-id\":\"options\","
			    "\"operation\":\"merge\",\"target\":\"/variable="
			    "%s_svcj_options\",\"value\":{\"arcana-services:"
			    "variable\":[{\"name\":\"%s_svcj_options\",\"value\":"
			    "\"%s\"}]}}", svc, svc, opts);
		else
			snprintf(how, sizeof(how), "{\"edit-id\":\"options\","
			    "\"operation\":\"remove\",\"target\":\"/variable="
			    "%s_svcj_options\"}", svc);
		if (asprintf(&json, "{\"ietf-yang-patch:yang-patch\":{"
		    "\"patch-id\":\"svcj\",\"edit\":[%s,%s]}}", yes, how) == -1)
			abort();
		svc_commit(s, "svcj", svc, json, false);
		free(json);
		return (true);
	}
	if (strcmp(form, "sv-rctl") == 0) {
		const char	*id = jstr(f, "other") != NULL && jstr(f,
		    "other")[0] != '\0' ? jstr(f, "other") : jstr(f, "id");
		char		 line[200];

		if (!safe_word(id, "_.-") || !safe_word(jstr(f, "amount"),
		    "/") || !safe_word(jstr(f, "resource"), "") ||
		    !safe_word(jstr(f, "action"), "") || !safe_word(jstr(f,
		    "subject"), "")) {
			toast(true, "A limit names its subject and amount");
			return (true);
		}
		snprintf(line, sizeof(line), "%s:%s:%s:%s=%s", jstr(f,
		    "subject"), id, jstr(f, "resource"), jstr(f, "action"),
		    jstr(f, "amount"));
		t = appended(cur_text("rctl.conf"), line);
		send_file(s, "rctl.conf", t);
		free(t);
		return (true);
	}
	if (strcmp(form, "sv-remote") == 0) {
		char	line[300];

		if (!safe_word(jstr(f, "host"), ":.[]-") || !safe_word(jstr(f,
		    "what"), "*.,;!=")) {
			toast(true, "A host, and what of the logs");
			return (true);
		}
		snprintf(line, sizeof(line), "%s\t@%s", jstr(f, "what"), jstr(f,
		    "host"));
		t = appended(cur_text("syslog.conf"), line);
		send_file(s, "syslog.conf", t);
		free(t);
		return (true);
	}
	if (strcmp(form, "sv-securelevel") == 0) {
		const char	*lv = jstr(f, "level") != NULL ? jstr(f, "level") :
		    "-1";
		char		 body[400], val[80];
		int		 now_lv, want;

		now_lv = (int)jint(jget(sv.r.o, "securelevel"), "now", -1);
		want = atoi(lv);
		if (jbool(f, "now") && want <= now_lv) {
			toast(true, "securelevel is %d now and is never lowered "
			    "while the host runs: only raised", now_lv);
			return (true);
		}
		snprintf(val, sizeof(val), "%s|%s", jbool(f, "enable") ? "YES" :
		    "NO", lv);
		if (!jbool(f, "now")) {
			sysview_action("sv-securelevel-yes", "boot", val);
			return (true);
		}
		snprintf(body, sizeof(body), "securelevel goes from %d to %d now, "
		    "and cannot come down until the host reboots. At 1 and above "
		    "the immutable flags hold and kernel modules stay as they "
		    "are; at 2 disks are not written raw (gpart, newfs, geli "
		    "init fail); at 3 the firewall's rules are frozen (the "
		    "Firewall tab and IDS divert fail). Type %d to confirm.",
		    now_lv, want, want);
		confirm("Raise securelevel now?", body, "Raise", true, lv,
		    "sv-securelevel-yes", "now", val);
		return (true);
	}
	if (strcmp(form, "sv-geom") == 0) {
		char	*json, *tt, *q;

		n = 0;
		w[n++] = jstr(f, "sub") != NULL ? jstr(f, "sub") : "";
		copy = strdup(jstr(f, "words") != NULL ? jstr(f, "words") : "");
		for (p = copy; (tok = strsep(&p, " \t")) != NULL && n < 32;)
			if (tok[0] != '\0')
				w[n++] = tok;
		if (asprintf(&json, "{\"kind\":\"geom\",\"verb\":%s,\"args\":[",
		    (q = json_quote(jstr(f, "class") != NULL ? jstr(f, "class") :
		    ""))) == -1)
			abort();
		free(q);
		for (i = 0; i < n; i++) {
			q = json_quote(w[i]);
			if (asprintf(&tt, "%s%s%s", json, i > 0 ? "," : "", q) ==
			    -1)
				abort();
			free(json);
			free(q);
			json = tt;
		}
		if (jstr(f, "pass") != NULL && jstr(f, "pass")[0] != '\0') {
			q = json_quote(jstr(f, "pass"));
			if (asprintf(&tt, "%s],\"text\":%s}", json, q) == -1)
				abort();
			free(q);
		} else if (asprintf(&tt, "%s]}", json) == -1)
			abort();
		free(json);
		free(copy);
		{
			char	title[96];

			snprintf(title, sizeof(title), "geom %s %s", jstr(f,
			    "class"), w[0]);
			send(s, tt, title);
		}
		return (true);
	}
	(void)buf;
	return (false);
}

bool
sysview_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	const char	*w[4];
	char		 a[160], *json, *q;
	size_t		 i;

	if (strcmp(act, "sv-show") == 0) {
		if (strcmp(arg, "logconf") == 0)
			sv.logconf = !sv.logconf;
		else if (strcmp(arg, "hardening") == 0)
			sv.hardening = !sv.hardening;
		else if (strcmp(arg, "storage") == 0)
			sv.storage = value != NULL ? atoi(value) : 0;
		render();
		return (true);
	}
	/* The other tabs' own views leave these. */
	if (strcmp(act, "st-kind") == 0)
		sv.storage = 0;
	if (strcmp(act, "sy-tree") == 0)
		sv.hardening = false;
	if (strcmp(act, "lg-jail") == 0 || strcmp(act, "input:lg-file") == 0)
		sv.logconf = false;
	if (strncmp(act, "sv-", 3) != 0)
		return (false);
	if (ycommit_action(&sv.yc, act))
		return (true);
	if ((s = sv_server()) == NULL)
		return (true);
	if (strcmp(act, "sv-retry") == 0) {
		refresh_system(s, true);
		render();
		return (true);
	}
	if (strcmp(act, "sv-auditd") == 0 && strcmp(arg, "off") == 0) {
		confirm("Stop auditing?", "auditd is stopped and disabled: "
		    "nothing is recorded of what is done until it is started "
		    "again.", "Stop", true, NULL, "sv-auditd-yes", "off", "");
		return (true);
	}
	if (strcmp(act, "sv-linux") == 0 || strcmp(act, "sv-auditd") == 0 ||
	    strcmp(act, "sv-auditd-yes") == 0) {
		const char	*svc = strcmp(act, "sv-linux") == 0 ? "linux" :
		    "auditd";

		/* On: enabled by a commit, then started; off: stopped, then
		 * disabled by a commit (JOB_SVC_OFF): rc.subr starts and
		 * stops only an enabled service. */
		if (strcmp(arg, "on") == 0) {
			svc_enable(s, svc, svc, true);
			return (true);
		}
		q = json_quote(svc);
		if (asprintf(&json, "{\"kind\":\"service-action\","
		    "\"service\":%s,\"action\":\"stop\"}", q) == -1)
			abort();
		free(q);
		snprintf(a, sizeof(a), "service %s stop", svc);
		job_send(s, json, a, JOB_SVC_OFF, svc);
		return (true);
	}
	if (strcmp(act, "sv-securelevel-yes") == 0) {
		/* value: enable|level; arg: boot, or now as well. */
		char	a[64], b[64], lv[8];

		snprintf(lv, sizeof(lv), "%.7s", strchr(value, '|') != NULL ?
		    strchr(value, '|') + 1 : "-1");
		snprintf(a, sizeof(a), "kern_securelevel_enable=%.3s", value);
		snprintf(b, sizeof(b), "kern_securelevel=%s", lv);
		w[0] = a;
		w[1] = b;
		send_words(s, "sysfile", "rc", w, 2, NULL, "securelevel at boot");
		if (strcmp(arg, "now") == 0) {
			w[0] = "kern.securelevel";
			w[1] = lv;
			send_words(s, "sysctl", NULL, w, 2, ",\"persist\":false",
			    "securelevel raised");
		}
		return (true);
	}
	if (strcmp(act, "sv-periodic") == 0) {
		snprintf(a, sizeof(a), "%s=%s", arg, value != NULL ? value : "NO");
		w[0] = a;
		send_words(s, "sysfile", "periodic", w, 1, NULL,
		    "periodic.conf's variables written");
		return (true);
	}
	if (strcmp(act, "sv-mac") == 0 && strcmp(value, "unload") == 0) {
		char	body[200];

		snprintf(body, sizeof(body), "%s is unloaded now and taken out of "
		    "kld_list: its policy stops holding at once.", arg);
		confirm("Unload the policy?", body, "Unload", true, NULL,
		    "sv-mac-yes", arg, "unload");
		return (true);
	}
	if (strcmp(act, "sv-mac") == 0 || strcmp(act, "sv-mac-yes") == 0) {
		w[0] = arg;
		snprintf(a, sizeof(a), "kld%s %s", strcmp(value, "load") == 0 ?
		    "load" : "unload", arg);
		send_words(s, "kmod", strcmp(value, "load") == 0 ? "load" :
		    "unload", w, 1, ",\"persist\":true", a);
		return (true);
	}
	if (strcmp(act, "sv-racct") == 0) {
		char	*t;

		/* Once: a line there already is not written again. */
		if (strstr(cur_text("loader.conf.d"), "kern.racct.enable=1") !=
		    NULL) {
			toast(false, "It is set for the next boot already");
			return (true);
		}
		t = appended(cur_text("loader.conf.d"), "kern.racct.enable=1");
		send_file(s, "loader.conf.d", t);
		free(t);
		return (true);
	}
	if (strcmp(act, "sv-harden") == 0) {
		w[0] = arg;
		w[1] = value;
		snprintf(a, sizeof(a), "sysctl %s=%s", arg, value);
		send_words(s, "sysctl", NULL, w, 2, ",\"persist\":true", a);
		return (true);
	}
	if (strcmp(act, "sv-harden-all") == 0) {
		const ucl_object_t	*v;
		char			 body[300];
		int			 d;

		for (i = 0, d = 0; i < nitems(hard); i++)
			if ((v = ucl_object_lookup(jget(sv.r.o, "hardening"),
			    hard[i].name)) != NULL && ucl_object_toint(v) !=
			    hard[i].want)
				d++;
		snprintf(body, sizeof(body), "%d sysctls are set to their "
		    "hardened value, a job each, and kept in sysctl.conf. Some "
		    "change what programs may do: no memory writable and "
		    "executable at once breaks JITs, and users no longer see "
		    "others' processes.", d);
		confirm("Apply the hardening?", body, "Apply", true, NULL,
		    "sv-harden-all-yes", "", "");
		return (true);
	}
	if (strcmp(act, "sv-harden-all-yes") == 0) {
		const ucl_object_t	*v;
		char			 num[16];

		for (i = 0; i < nitems(hard); i++) {
			if ((v = ucl_object_lookup(jget(sv.r.o, "hardening"),
			    hard[i].name)) ==
			    NULL || ucl_object_toint(v) == hard[i].want)
				continue;
			snprintf(num, sizeof(num), "%d", hard[i].want);
			w[0] = hard[i].name;
			w[1] = num;
			snprintf(a, sizeof(a), "sysctl %s=%s", hard[i].name, num);
			send_words(s, "sysctl", NULL, w, 2, ",\"persist\":true", a);
		}
		return (true);
	}
	return (false);
}
