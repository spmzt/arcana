/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: WireGuard.  The interfaces and their peers are read from
 * what wg(8) shows, and set up by running wg(8).  A private key is made
 * here, on the host it is for, and stays here: what is told of an
 * interface is its public key, and what wg(8) prints with keys in it is
 * kept out of the trace.  To be there after a boot, an interface is
 * written as wg-quick(8) reads it, for the rc.d script that comes with
 * wg-quick to bring up.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "agent.h"

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

/* A WireGuard key as text: 32 bytes in base64, 44 characters. */
bool
wg_key_ok(const char *s)
{
	size_t	i;

	if (s == NULL || strlen(s) != 44 || s[43] != '=')
		return (false);
	for (i = 0; i < 43; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '+' && s[i] != '/')
			return (false);
	return (true);
}

static bool
wg_ifname(const char *s)
{

	return (s != NULL && strncmp(s, "wg", 2) == 0 && s[2] != '\0' &&
	    s[2 + strspn(s + 2, "0123456789")] == '\0' && strlen(s) < IFNAMSIZ);
}

/* "address:port", "[address]:port" or "name:port": no more than that. */
static bool
endpoint_ok(const char *s)
{
	const char	*colon;

	if (s[0] == '-' || (colon = strrchr(s, ':')) == NULL || colon == s ||
	    colon[1] == '\0' || colon[1 + strspn(colon + 1, "0123456789")] !=
	    '\0')
		return (false);
	for (; s < colon; s++)
		if (!isalnum((unsigned char)*s) && strchr(".-:[]", *s) == NULL)
			return (false);
	return (true);
}

/* Networks with their prefix lengths, with commas between them. */
static bool
allowed_ok(struct work *w, const char *s)
{
	unsigned char	 raw[16];
	const char	*errstr;
	char		*copy, *p, *tok, *slash;
	int		 max;

	copy = wstrdup(w, s);
	p = copy;
	while ((tok = strsep(&p, ",")) != NULL) {
		if ((slash = strchr(tok, '/')) != NULL)
			*slash = '\0';
		if (inet_pton(AF_INET, tok, raw) == 1)
			max = 32;
		else if (inet_pton(AF_INET6, tok, raw) == 1)
			max = 128;
		else
			return (false);
		if (slash != NULL) {
			(void)strtonum(slash + 1, 0, max, &errstr);
			if (errstr != NULL)
				return (false);
		}
	}
	return (true);
}

/* NULL when the job may run, or what is wrong with it. */
const char *
wg_check(struct work *w, const struct arc_job_spec *sp)
{

	if (!wg_ifname(sp->interface))
		return ("wireguard: the interface is wg and its number");
	if (sp->verb == NULL)
		return ("wireguard: say init, peer or unpeer");
	if (strcmp(sp->verb, "init") == 0) {
		if (sp->has_listen_port && (sp->listen_port < 1 ||
		    sp->listen_port > 65535))
			return ("wireguard: a port is between 1 and 65535");
		return (NULL);
	}
	if (strcmp(sp->verb, "peer") != 0 && strcmp(sp->verb, "unpeer") != 0)
		return ("wireguard: say init, peer or unpeer");
	if (!wg_key_ok(sp->peer))
		return ("wireguard: a peer is named by its public key, 44 "
		    "characters of base64");
	if (sp->endpoint != NULL && !endpoint_ok(sp->endpoint))
		return ("wireguard: an endpoint is an address or a name, and "
		    "a port");
	if (sp->allowed_ips != NULL && sp->allowed_ips[0] != '\0' &&
	    !allowed_ok(w, sp->allowed_ips))
		return ("wireguard: allowed-ips are addresses with their "
		    "prefix lengths, with commas between them");
	if (sp->has_keepalive && sp->keepalive > 65535)
		return ("wireguard: a keepalive is at most 65535 seconds");
	return (NULL);
}

/* One field of a line of tabs; the next one's start is left in *pp. */
static char *
field(char **pp)
{

	return (*pp != NULL ? strsep(pp, "\t") : NULL);
}

/*
 * {"interfaces": [{"name", "public-key", "private-key": bool,
 * "listen-port", "peers": [{"public-key", "preshared-key": bool,
 * "endpoint", "allowed-ips": [], "latest-handshake", "rx", "tx",
 * "keepalive"}]}]}, from "wg show all dump": an interface's line has
 * five fields, a peer's nine, each after the interface's name.
 */
int
do_wireguard(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *arr, *o, *peers, *p, *ips;
	unsigned char	*json;
	char		*argv[5], *text, *line, *rest, *f[9], *ip, *list;
	int		 n;

	rsp->has_ok = true;
	rsp->ok = false;
	argv[0] = (char *)(uintptr_t)opts.wg_bin;
	argv[1] = (char *)(uintptr_t)"show";
	argv[2] = (char *)(uintptr_t)"all";
	argv[3] = (char *)(uintptr_t)"dump";
	argv[4] = NULL;
	/* The dump has the private keys in it: not for the trace. */
	exec_set_secret(true);
	n = run_exec(w, argv, &res);
	exec_set_secret(false);
	if (n != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "wg"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	peers = NULL;
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		rest = line;
		for (n = 0; n < 9 && (f[n] = field(&rest)) != NULL; n++)
			;
		if (n == 5) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "name", ucl_object_fromstring(f[0]));
			put(o, "private-key", ucl_object_frombool(wg_key_ok(
			    f[1])));
			if (wg_key_ok(f[2]))
				put(o, "public-key", ucl_object_fromstring(f[2]));
			put(o, "listen-port", ucl_object_fromint(atoi(f[3])));
			peers = ucl_object_typed_new(UCL_ARRAY);
			put(o, "peers", peers);
			ucl_array_append(arr, o);
		} else if (n == 9 && peers != NULL) {
			p = ucl_object_typed_new(UCL_OBJECT);
			put(p, "public-key", ucl_object_fromstring(f[1]));
			put(p, "preshared-key", ucl_object_frombool(wg_key_ok(
			    f[2])));
			if (strcmp(f[3], "(none)") != 0)
				put(p, "endpoint", ucl_object_fromstring(f[3]));
			ips = ucl_object_typed_new(UCL_ARRAY);
			list = f[4];
			while (strcmp(f[4], "(none)") != 0 && (ip = strsep(&list,
			    ",")) != NULL)
				ucl_array_append(ips, ucl_object_fromstring(ip));
			put(p, "allowed-ips", ips);
			put(p, "latest-handshake", ucl_object_fromint(strtoll(
			    f[5], NULL, 10)));
			put(p, "rx", ucl_object_fromint(strtoll(f[6], NULL, 10)));
			put(p, "tx", ucl_object_fromint(strtoll(f[7], NULL, 10)));
			put(p, "keepalive", ucl_object_fromint(atoi(f[8])));
			ucl_array_append(peers, p);
		}
	}
	put(top, "interfaces", arr);
	put(top, "now", ucl_object_fromint(time(NULL)));
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "the interfaces are more than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* Does the interface have a private key?  -1 when wg(8) cannot say. */
static int
has_key(struct work *w, const char *ifname)
{
	struct execres	 res;
	char		*argv[5];
	int		 rc;

	argv[0] = (char *)(uintptr_t)opts.wg_bin;
	argv[1] = (char *)(uintptr_t)"show";
	argv[2] = (char *)(uintptr_t)ifname;
	argv[3] = (char *)(uintptr_t)"private-key";
	argv[4] = NULL;
	exec_set_secret(true);
	rc = run_exec(w, argv, &res);
	exec_set_secret(false);
	if (rc != 0 || res.out == NULL)
		return (-1);
	return (wg_key_ok(wstrndup(w, res.out, strcspn(res.out, "\n"))));
}

/*
 * A private key, made here: 32 random bytes shaped as Curve25519 wants
 * them.  wg(8) reads it from a file, which is there only that long.
 */
static int
new_key(struct work *w, const char *ifname, const char **errp)
{
	struct execres	 res;
	unsigned char	 raw[32], text[48];
	char		*path, *argv[6];
	int		 fd, rc, step;

	step = step_begin(w, ARC_STEP_KIND_FILE, "private key", "made on this "
	    "host, for %s", ifname);
	arc4random_buf(raw, sizeof(raw));
	raw[0] &= 248;
	raw[31] = (raw[31] & 127) | 64;
	EVP_EncodeBlock(text, raw, sizeof(raw));
	explicit_bzero(raw, sizeof(raw));
	path = wfmt(w, "%s/.%s.key.XXXXXX", opts.wg_dir, ifname);
	if ((fd = mkstemp(path)) == -1) {
		step_end(w, step, false, "%s: %s", path, strerror(errno));
		*errp = wfmt(w, "%s: %s", opts.wg_dir, strerror(errno));
		explicit_bzero(text, sizeof(text));
		return (-1);
	}
	rc = write(fd, text, 44) == 44 && write(fd, "\n", 1) == 1 ? 0 : -1;
	close(fd);
	explicit_bzero(text, sizeof(text));
	step_end(w, step, rc == 0, NULL);
	if (rc == 0) {
		argv[0] = (char *)(uintptr_t)opts.wg_bin;
		argv[1] = (char *)(uintptr_t)"set";
		argv[2] = (char *)(uintptr_t)ifname;
		argv[3] = (char *)(uintptr_t)"private-key";
		argv[4] = path;
		argv[5] = NULL;
		if ((rc = run_exec(w, argv, &res)) != 0)
			*errp = wtext(w, exec_error(w, &res, "wg"));
	} else
		*errp = "cannot write the key";
	(void)unlink(path);
	return (rc == 0 ? 0 : -1);
}

/* The file wg-quick(8) reads for the interface. */
static char *
conf_path(struct work *w, const char *ifname)
{

	return (wfmt(w, "%s/%s.conf", opts.wg_dir, ifname));
}

/*
 * The interface as it is now, written for wg-quick(8): what wg(8)
 * showconf prints, and after its first line the addresses and the MTU,
 * which wg(8) knows nothing of.  rc.conf is told to bring it up.
 */
static int
wg_save(struct work *w, const char *ifname, const char **errp)
{
	struct execres	 res;
	struct ifaddrs	*ifap, *ifa;
	const unsigned char *m;
	const char	*nl, *e;
	char		*argv[4], *path, *tmp, buf[NI_MAXHOST], *extra;
	unsigned int	 mtu;
	size_t		 i, len;
	FILE		*fp;
	int		 fd, rc, step, plen;

	argv[0] = (char *)(uintptr_t)opts.wg_bin;
	argv[1] = (char *)(uintptr_t)"showconf";
	argv[2] = (char *)(uintptr_t)ifname;
	argv[3] = NULL;
	exec_set_secret(true);
	rc = run_exec(w, argv, &res);
	exec_set_secret(false);
	if (rc != 0 || res.out == NULL || (nl = strchr(res.out, '\n')) ==
	    NULL) {
		*errp = wtext(w, exec_error(w, &res, "wg showconf"));
		return (-1);
	}
	extra = wstrdup(w, "");
	if (getifaddrs(&ifap) == 0) {
		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name,
			    ifname) != 0 || (ifa->ifa_addr->sa_family !=
			    AF_INET && ifa->ifa_addr->sa_family != AF_INET6) ||
			    ifa->ifa_netmask == NULL || getnameinfo(
			    ifa->ifa_addr, ifa->ifa_addr->sa_len, buf,
			    sizeof(buf), NULL, 0, NI_NUMERICHOST) != 0 ||
			    strchr(buf, '%') != NULL)
				continue;
			m = ifa->ifa_addr->sa_family == AF_INET ?
			    (const unsigned char *)&((struct sockaddr_in *)
			    (void *)ifa->ifa_netmask)->sin_addr :
			    (const unsigned char *)&((struct sockaddr_in6 *)
			    (void *)ifa->ifa_netmask)->sin6_addr;
			len = ifa->ifa_addr->sa_family == AF_INET ? 4 : 16;
			plen = 0;
			for (i = 0; i < len; i++)
				plen += __builtin_popcount(m[i]);
			extra = wfmt(w, "%sAddress = %s/%d\n", extra, buf, plen);
		}
		freeifaddrs(ifap);
	}
	if_current(ifname, &mtu, buf, sizeof(buf));
	if (mtu != 0)
		extra = wfmt(w, "%sMTU = %u\n", extra, mtu);

	path = conf_path(w, ifname);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", path);
	tmp = wfmt(w, "%s/.%s.conf.XXXXXX", opts.wg_dir, ifname);
	if ((fd = mkstemp(tmp)) == -1 || (fp = fdopen(fd, "w")) == NULL) {
		if (fd != -1) {
			close(fd);
			(void)unlink(tmp);
		}
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", opts.wg_dir, strerror(errno));
		return (-1);
	}
	fwrite(res.out, 1, (size_t)(nl + 1 - res.out), fp);
	fputs(extra, fp);
	fputs(nl + 1, fp);
	if (fclose(fp) != 0 || rename(tmp, path) == -1) {
		(void)unlink(tmp);
		step_end(w, step, false, "%s", strerror(errno));
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		return (-1);
	}
	step_end(w, step, true, "for wg-quick(8), mode 0600");
	/* wg-quick makes the interface itself: rc.conf must not as well. */
	e = NULL;
	(void)rc_set(w, "cloned_interfaces", "-=", ifname, &e);
	rc_forget_if(w, ifname);
	if (rc_set(w, "wireguard_interfaces", "+=", ifname, errp) != 0 ||
	    rc_set(w, "wireguard_enable", "=", "YES", errp) != 0)
		return (-1);
	return (0);
}

/* The interface is gone: so is what would bring it up at boot. */
void
wg_forget(struct work *w, const char *ifname)
{
	const char	*e;
	int		 step;

	if (!wg_ifname(ifname))
		return;
	step = step_begin(w, ARC_STEP_KIND_FILE, "remove", "%s", conf_path(w,
	    ifname));
	step_end(w, step, unlink(conf_path(w, ifname)) == 0 || errno == ENOENT,
	    NULL);
	e = NULL;
	(void)rc_set(w, "wireguard_interfaces", "-=", ifname, &e);
}

int
do_wg(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres	 res;
	char		*argv[14];
	int		 n, k;

	if ((*errp = wg_check(w, sp)) != NULL)
		return (-1);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.wg_bin;
	argv[n++] = (char *)(uintptr_t)"set";
	argv[n++] = (char *)(uintptr_t)sp->interface;
	if (strcmp(sp->verb, "init") == 0) {
		/* A key it has is kept: its peers know it by that one. */
		if ((k = has_key(w, sp->interface)) == -1) {
			*errp = wfmt(w, "wg cannot show %s", sp->interface);
			return (-1);
		}
		if (k == 0 && new_key(w, sp->interface, errp) != 0)
			return (-1);
		if (sp->has_listen_port) {
			argv[n++] = (char *)(uintptr_t)"listen-port";
			argv[n++] = wfmt(w, "%u", sp->listen_port);
		}
	} else {
		argv[n++] = (char *)(uintptr_t)"peer";
		argv[n++] = (char *)(uintptr_t)sp->peer;
		if (strcmp(sp->verb, "unpeer") == 0)
			argv[n++] = (char *)(uintptr_t)"remove";
		else {
			if (sp->endpoint != NULL && sp->endpoint[0] != '\0') {
				argv[n++] = (char *)(uintptr_t)"endpoint";
				argv[n++] = (char *)(uintptr_t)sp->endpoint;
			}
			if (sp->allowed_ips != NULL) {
				argv[n++] = (char *)(uintptr_t)"allowed-ips";
				argv[n++] = (char *)(uintptr_t)sp->allowed_ips;
			}
			if (sp->has_keepalive) {
				argv[n++] = (char *)(uintptr_t)
				    "persistent-keepalive";
				argv[n++] = wfmt(w, "%u", sp->keepalive);
			}
		}
	}
	argv[n] = NULL;
	if (n > 3 && run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "wg"));
		return (-1);
	}
	if (sp->persist)
		return (wg_save(w, sp->interface, errp));
	return (0);
}
