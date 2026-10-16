/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: the connections and sockets of a network stack, read from
 * the kernel itself, as netstat(1) and sockstat(1) read them: the
 * protocol control blocks (net.inet.tcp.pcblist, net.inet.udp.pcblist),
 * SCTP's endpoints and associations (net.inet.sctp.assoclist, as
 * sockstat(1) and netstat(1) read it) and, for whose a socket is, the
 * open files (kern.file).  A row is
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
#include <netinet/sctp.h>
#include <netinet/sctp_constants.h>
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
 * A socket's row in sockstat's shape, one for each who holds it: name
 * the protocol as written (tcp4, sctp46), la and fa its addresses.
 */
static void
sock_rows(struct pc *c, kvaddr_t so, const char *name, const char *la,
    unsigned int lport, const char *fa, unsigned int fport)
{
	struct owner			 key, *o;
	struct passwd			 pwd, *pw;
	char				 pwbuf[1024];
	const char			*ch;
	size_t				 i;

	/* A socket nobody holds any more (closing) is "?", as sockstat
	 * has it "??". */
	key.so = so;
	o = c->owners != NULL ? bsearch(&key, c->owners, c->nowners,
	    sizeof(*c->owners), owner_cmp) : NULL;
	if (o == NULL) {
		c->total++;
		fprintf(c->out, "{\"user\":\"?\",\"command\":\"?\",\"proto\":"
		    "\"%s\",\"local\":{\"address\":\"%s\",\"port\":%u},"
		    "\"foreign\":{\"address\":\"%s\",\"port\":%u}}\n", name,
		    la, lport, fa, fport);
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
		    c->owners[i].fd, name, la, lport, fa, fport);
	}
}

/* A connection's row in netstat's shape. */
static void
conn_row(struct pc *c, const char *name, unsigned int rq, unsigned int sq,
    const char *la, unsigned int lport, const char *fa, unsigned int fport,
    const char *state)
{

	c->total++;
	fprintf(c->out, "{\"protocol\":\"%s\",\"receive-bytes-waiting\":%u,"
	    "\"send-bytes-waiting\":%u,\"local\":{\"address\":\"%s\","
	    "\"port\":\"%u\"},\"remote\":{\"address\":\"%s\","
	    "\"port\":\"%u\"}", name, rq, sq, la, lport, fa, fport);
	if (state != NULL)
		fprintf(c->out, ",\"tcp-state\":\"%s\"", state);
	fprintf(c->out, "}\n");
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
	char				 la[INET6_ADDRSTRLEN], fa[INET6_ADDRSTRLEN],
					 name[16];
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
		conn_row(c, name, xi->xi_socket.so_rcv.sb_cc,
		    xi->xi_socket.so_snd.sb_cc, la, ntohs(ie->ie_lport), fa,
		    ntohs(ie->ie_fport), state >= 0 && state < TCP_NSTATES ?
		    tcp_states[state] : NULL);
		return;
	}
	sock_rows(c, xi->xi_socket.xso_so, name, la, ntohs(ie->ie_lport), fa,
	    ntohs(ie->ie_fport));
}

/* An SCTP address as the programs write it: "*" for none. */
static void
sctp_addr(const union sctp_sockstore *a, char *buf, size_t len)
{

	if (a->sa.sa_family == AF_INET && a->sin.sin_addr.s_addr !=
	    INADDR_ANY)
		inet_ntop(AF_INET, &a->sin.sin_addr, buf, (socklen_t)len);
	else if (a->sa.sa_family == AF_INET6 &&
	    !IN6_IS_ADDR_UNSPECIFIED(&a->sin6.sin6_addr))
		inet_ntop(AF_INET6, &a->sin6.sin6_addr, buf, (socklen_t)len);
	else
		strlcpy(buf, "*", len);
}

static const char *
sctp_state(uint32_t st)
{

	switch (st & SCTP_STATE_MASK) {
	case SCTP_STATE_COOKIE_WAIT:
		return ("COOKIE_WAIT");
	case SCTP_STATE_COOKIE_ECHOED:
		return ("COOKIE_ECHOED");
	case SCTP_STATE_OPEN:
		return ("ESTABLISHED");
	case SCTP_STATE_SHUTDOWN_SENT:
		return ("SHUTDOWN_SENT");
	case SCTP_STATE_SHUTDOWN_RECEIVED:
		return ("SHUTDOWN_RECEIVED");
	case SCTP_STATE_SHUTDOWN_ACK_SENT:
		return ("SHUTDOWN_ACK_SENT");
	case SCTP_STATE_SHUTDOWN_PENDING:
		return ("SHUTDOWN_PENDING");
	case SCTP_STATE_EMPTY:
		return ("CLOSED");
	default:
		return ("UNKNOWN");
	}
}

/*
 * SCTP's endpoints, each with its local addresses (none: bound to all),
 * then its associations, each with its local and its remote addresses;
 * every list ends with a record whose last is 1.  A socket is a row for
 * each address it listens on, and one for each association, by the
 * first address of either end (the primary is the first the kernel
 * lists); a connection, an association's.
 */
static void
sctp(struct pc *c, bool socks, int fam)
{
	const struct xsctp_inpcb	*xi;
	const struct xsctp_tcb		*xt;
	const struct xsctp_laddr	*xl;
	const struct xsctp_raddr	*xr;
	char				*buf, name[16], la[INET6_ADDRSTRLEN],
					 fa[INET6_ADDRSTRLEN];
	size_t				 len, off;
	bool				 six, listens, any, first;

	if ((buf = whole("net.inet.sctp.assoclist", &len)) == NULL)
		return;
	off = 0;
	while (off + sizeof(*xi) <= len) {
		xi = (const void *)(buf + off);
		off += sizeof(*xi);
		if (xi->last)
			break;
		/* Bound to IPv6, it takes IPv4 too: sockstat says so. */
		six = (xi->flags & SCTP_PCB_FLAGS_BOUND_V6) != 0;
		snprintf(name, sizeof(name), "sctp%s", six ? "46" : "4");
		listens = xi->maxqlen > 0 || (xi->flags &
		    SCTP_PCB_FLAGS_UDPTYPE) != 0;
		/* Its local addresses. */
		any = false;
		while (off + sizeof(*xl) <= len) {
			xl = (const void *)(buf + off);
			off += sizeof(*xl);
			if (xl->last)
				break;
			if (fam == 6 && !six)
				continue;
			any = true;
			if (socks && listens) {
				sctp_addr(&xl->address, la, sizeof(la));
				sock_rows(c, xi->socket, name, la,
				    xi->local_port, "*", 0);
			}
		}
		if (!any && socks && listens && !(fam == 6 && !six))
			sock_rows(c, xi->socket, name, "*", xi->local_port, "*",
			    0);
		/* Its associations. */
		while (off + sizeof(*xt) <= len) {
			xt = (const void *)(buf + off);
			off += sizeof(*xt);
			if (xt->last)
				break;
			la[0] = fa[0] = '\0';
			for (first = true; off + sizeof(*xl) <= len; first =
			    false) {
				xl = (const void *)(buf + off);
				off += sizeof(*xl);
				if (xl->last)
					break;
				if (first)
					sctp_addr(&xl->address, la, sizeof(la));
			}
			for (first = true; off + sizeof(*xr) <= len; first =
			    false) {
				xr = (const void *)(buf + off);
				off += sizeof(*xr);
				if (xr->last)
					break;
				if (first)
					sctp_addr(&xr->address, fa, sizeof(fa));
			}
			/* The remote address in use: the primary. */
			if (xt->primary_addr.sa.sa_family == AF_INET ||
			    xt->primary_addr.sa.sa_family == AF_INET6)
				sctp_addr(&xt->primary_addr, fa, sizeof(fa));
			if (fam == 6 && !six)
				continue;
			if (socks)
				sock_rows(c, xi->socket, name, la[0] != '\0' ? la :
				    "*", xt->local_port, fa[0] != '\0' ? fa : "*",
				    xt->remote_port);
			else
				conn_row(c, name, 0, 0, la[0] != '\0' ? la : "*",
				    xt->local_port, fa[0] != '\0' ? fa : "*",
				    xt->remote_port, sctp_state(xt->state));
		}
	}
	free(buf);
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
	sctp(&c, socks, fam);
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
