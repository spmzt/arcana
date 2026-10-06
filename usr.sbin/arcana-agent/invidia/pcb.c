/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the connections and sockets of a network stack, read from
 * the kernel itself, as netstat(1) and sockstat(1) read them: the
 * protocol control blocks (net.inet.tcp.pcblist, net.inet.udp.pcblist)
 * and, for whose a socket is, the open files (kern.file).  A row is
 * written as it is read, a JSON object a line, in the shape those
 * programs give with --libxo json; the last line is "#total n".  It
 * runs in the helper, which attaches to a jail first when the stack is
 * the jail's own.
 *
 *	pcb-conns family	what netstat -n lists: the connections, not
 *				the listening sockets
 *	pcb-socks family	what sockstat -w lists: every socket with
 *				its owner, command and descriptor
 *
 * family is 0 for both, 4 or 6.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"

static const char *const tcp_states[TCP_NSTATES] = {
	"CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
	"CLOSE_WAIT", "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2",
	"TIME_WAIT",
};

struct owner {
	kvaddr_t	 so;		/* the socket */
	pid_t		 pid;
	uid_t		 uid;
	int		 fd;
};

struct proc_name {
	pid_t		 pid;
	char		 comm[MAXCOMLEN + 1];
};

/* One listing: where its rows go, and what it found to go by. */
struct pc {
	FILE		*out;
	struct owner	*owners;
	size_t		 nowners;
	struct proc_name *procs;
	size_t		 nprocs;
	uint64_t	 total;
};

/* A sysctl's whole value, grown until it fits; free(3) it. */
static void *
whole(const char *name, size_t *lenp)
{
	void	*buf;
	size_t	 len;
	int	 try;

	for (try = 0; try < 5; try++) {
		len = 0;
		if (sysctlbyname(name, NULL, &len, NULL, 0) == -1)
			return (NULL);
		len += len / 4 + 4096;
		if ((buf = malloc(len)) == NULL)
			return (NULL);
		if (sysctlbyname(name, buf, &len, NULL, 0) == 0) {
			*lenp = len;
			return (buf);
		}
		free(buf);
		if (errno != ENOMEM)
			return (NULL);
	}
	return (NULL);
}

static int
owner_cmp(const void *a, const void *b)
{
	const struct owner	*x = a, *y = b;

	return (x->so < y->so ? -1 : x->so > y->so);
}

static int
proc_cmp(const void *a, const void *b)
{
	const struct proc_name	*x = a, *y = b;

	return (x->pid < y->pid ? -1 : x->pid > y->pid);
}

/* Who has which socket open, and what the processes are called. */
static void
owners_read(struct pc *c)
{
	struct xfile		*xf;
	struct kinfo_proc	*kp;
	size_t			 len, n, i;
	int			 mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC };

	if ((xf = whole("kern.file", &len)) != NULL) {
		n = len / sizeof(*xf);
		if ((c->owners = calloc(n > 0 ? n : 1,
		    sizeof(*c->owners))) != NULL)
			for (i = 0; i < n; i++) {
				if (xf[i].xf_size != sizeof(*xf) ||
				    xf[i].xf_type != DTYPE_SOCKET)
					continue;
				c->owners[c->nowners].so = xf[i].xf_data;
				c->owners[c->nowners].pid = xf[i].xf_pid;
				c->owners[c->nowners].uid = xf[i].xf_uid;
				c->owners[c->nowners++].fd = xf[i].xf_fd;
			}
		free(xf);
		qsort(c->owners, c->nowners, sizeof(*c->owners), owner_cmp);
	}
	len = 0;
	if (sysctl(mib, 3, NULL, &len, NULL, 0) == -1 || (kp = malloc(len +
	    len / 4)) == NULL)
		return;
	len += len / 4;
	if (sysctl(mib, 3, kp, &len, NULL, 0) == -1) {
		free(kp);
		return;
	}
	n = len / sizeof(*kp);
	if ((c->procs = calloc(n > 0 ? n : 1, sizeof(*c->procs))) != NULL) {
		for (i = 0; i < n; i++) {
			c->procs[c->nprocs].pid = kp[i].ki_pid;
			strlcpy(c->procs[c->nprocs++].comm, kp[i].ki_comm,
			    sizeof(c->procs[0].comm));
		}
		qsort(c->procs, c->nprocs, sizeof(*c->procs), proc_cmp);
	}
	free(kp);
}

static const char *
comm_of(struct pc *c, pid_t pid)
{
	struct proc_name	 key, *p;

	key.pid = pid;
	p = c->procs != NULL ? bsearch(&key, c->procs, c->nprocs,
	    sizeof(*c->procs), proc_cmp) : NULL;
	return (p != NULL ? p->comm : "?");
}

/* An address as the programs write it: "*" for none. */
static void
addr_of(const struct xinpcb *xi, bool local, bool six, char *buf, size_t len)
{
	const struct in_endpoints	*ie = &xi->inp_inc.inc_ie;

	if (six) {
		const struct in6_addr *a = local ? &ie->ie6_laddr :
		    &ie->ie6_faddr;

		if (IN6_IS_ADDR_UNSPECIFIED(a))
			strlcpy(buf, "*", len);
		else
			inet_ntop(AF_INET6, a, buf, (socklen_t)len);
	} else {
		struct in_addr a = local ? ie->ie_laddr : ie->ie_faddr;

		if (a.s_addr == INADDR_ANY)
			strlcpy(buf, "*", len);
		else
			inet_ntop(AF_INET, &a, buf, (socklen_t)len);
	}
}

/*
 * One control block as a row, or none: conns leaves out what listens
 * and what is connected to nothing, as netstat -n does.
 */
static void
row(struct pc *c, const struct xinpcb *xi, const char *proto, int state,
    bool socks, int fam)
{
	const struct in_endpoints	*ie = &xi->inp_inc.inc_ie;
	struct owner			 key, *o;
	struct passwd			 pwd, *pw;
	char				 pwbuf[1024];
	const char			*ch;
	char				 la[INET6_ADDRSTRLEN], fa[INET6_ADDRSTRLEN],
					 name[16];
	size_t				 i;
	bool				 v4, v6, six;

	v4 = (xi->inp_vflag & INP_IPV4) != 0;
	v6 = (xi->inp_vflag & INP_IPV6) != 0;
	if ((fam == 4 && !v4) || (fam == 6 && !v6))
		return;
	six = v6 && !(v4 && fam == 4);
	snprintf(name, sizeof(name), "%s%s", proto, v4 && v6 ? "46" : v6 ?
	    "6" : "4");
	addr_of(xi, true, six, la, sizeof(la));
	addr_of(xi, false, six, fa, sizeof(fa));
	if (!socks) {
		if (state == TCPS_LISTEN || (state < 0 && strcmp(fa, "*") ==
		    0))
			return;
		c->total++;
		fprintf(c->out, "{\"protocol\":\"%s\",\"receive-bytes-waiting\":%u,"
		    "\"send-bytes-waiting\":%u,\"local\":{\"address\":\"%s\","
		    "\"port\":\"%u\"},\"remote\":{\"address\":\"%s\","
		    "\"port\":\"%u\"}", name, xi->xi_socket.so_rcv.sb_cc,
		    xi->xi_socket.so_snd.sb_cc, la, ntohs(ie->ie_lport), fa,
		    ntohs(ie->ie_fport));
		if (state >= 0 && state < TCP_NSTATES)
			fprintf(c->out, ",\"tcp-state\":\"%s\"", tcp_states[state]);
		fprintf(c->out, "}\n");
		return;
	}
	/* A socket nobody holds any more (closing) is "?", as sockstat
	 * has it "??". */
	key.so = xi->xi_socket.xso_so;
	o = c->owners != NULL ? bsearch(&key, c->owners, c->nowners,
	    sizeof(*c->owners), owner_cmp) : NULL;
	if (o == NULL) {
		c->total++;
		fprintf(c->out, "{\"user\":\"?\",\"command\":\"?\",\"proto\":"
		    "\"%s\",\"local\":{\"address\":\"%s\",\"port\":%u},"
		    "\"foreign\":{\"address\":\"%s\",\"port\":%u}}\n", name,
		    la, ntohs(ie->ie_lport), fa, ntohs(ie->ie_fport));
		return;
	}
	while (o > c->owners && o[-1].so == key.so)
		o--;
	for (i = (size_t)(o - c->owners); i < c->nowners &&
	    c->owners[i].so == key.so; i++) {
		c->total++;
		/* getpwuid(3) is not for two threads: the daemon has many. */
		if (getpwuid_r(c->owners[i].uid, &pwd, pwbuf, sizeof(pwbuf),
		    &pw) != 0)
			pw = NULL;
		fprintf(c->out, "{\"user\":\"%s\",\"command\":\"", pw != NULL ?
		    pw->pw_name : "?");
		/* A command is the process's own: only what JSON allows. */
		for (ch = comm_of(c, c->owners[i].pid); *ch != '\0'; ch++)
			if (*ch != '"' && *ch != '\\' &&
			    (unsigned char)*ch >= 0x20)
				fputc(*ch, c->out);
		fprintf(c->out, "\",\"pid\":%d,\"fd\":%d,\"proto\":\"%s\",\"local\":"
		    "{\"address\":\"%s\",\"port\":%u},\"foreign\":{\"address\":"
		    "\"%s\",\"port\":%u}}\n", (int)c->owners[i].pid,
		    c->owners[i].fd, name, la, ntohs(ie->ie_lport), fa,
		    ntohs(ie->ie_fport));
	}
}

/* The control blocks of one protocol, each its row. */
static void
pcbs(struct pc *c, const char *proto, bool socks, int fam)
{
	struct xinpgen	*xig, *end;
	char		*buf, name[48];
	size_t		 len;
	char		*p;

	snprintf(name, sizeof(name), "net.inet.%s.pcblist", proto);
	if ((buf = whole(name, &len)) == NULL || len < sizeof(*xig))
		return;
	xig = (struct xinpgen *)(void *)buf;
	end = (struct xinpgen *)(void *)(buf + len);
	for (p = buf + xig->xig_len; p + sizeof(struct xinpgen) <= (char *)end;
	    p += ((struct xinpgen *)(void *)p)->xig_len) {
		if (((struct xinpgen *)(void *)p)->xig_len <= sizeof(struct
		    xinpgen))
			break;	/* the trailing generation record */
		if (strcmp(proto, "tcp") == 0) {
			const struct xtcpcb *xt = (const void *)p;

			row(c, &xt->xt_inp, proto, xt->t_state, socks, fam);
		} else
			row(c, (const struct xinpcb *)(const void *)p, proto, -1,
			    socks, fam);
	}
	free(buf);
}

/*
 * The connections (socks false) or the sockets, a row a line into out,
 * and "#total n" last; of family 4, 6 or 0 for both.
 */
int
pcb_list(FILE *out, bool socks, int fam)
{
	struct pc	c;

	memset(&c, 0, sizeof(c));
	c.out = out;
	if (socks)
		owners_read(&c);
	pcbs(&c, "tcp", socks, fam);
	pcbs(&c, "udp", socks, fam);
	fprintf(out, "#total %ju\n", (uintmax_t)c.total);
	free(c.owners);
	free(c.procs);
	return (0);
}

/* The helper's verbs that begin with "pcb-"; argv[0] is the verb. */
int
pcb_helper(int argc, char **argv)
{

	if (argc != 2 || (strcmp(argv[0], "pcb-socks") != 0 && strcmp(argv[0],
	    "pcb-conns") != 0))
		return (2);
	return (pcb_list(stdout, strcmp(argv[0], "pcb-socks") == 0,
	    atoi(argv[1])));
}
