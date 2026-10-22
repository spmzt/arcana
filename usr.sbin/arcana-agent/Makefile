PROG=		arcana-agent
# The Agent itself, then what it does by Archive (docs/NAMING.md).
SRCS=		main.c handlers.c work.c
# Superbia: identity, configuration, what is true of the host.
SRCS+=		admit.c certs.c ssh.c tlsfiles.c confedit.c confread.c host.c kernel.c ntp.c rtadvd.c sysctl.c transport.c bundle.c l2.c ipfw.c netstore.c sysfiles.c geomjob.c
# Invidia: the network.
SRCS+=		sa.c address.c interfaces.c netgraph.c network.c netdump.c nlroute.c fwmatch.c pathcheck.c neigh.c carp.c capture.c parts.c pcb.c rcconf.c \
		routes.c rtimes.c scope.c sdwan.c vnet.c wireguard.c
# Luxuria: what is not FreeBSD's own, the plugins.
SRCS+=		bird.c birdwatch.c ipsec.c plugins.c sdbird.c sddhcp.c sddns.c sdproxy.c sdids.c idsconf.c surules.c smtpd.c telegram.c poudriere.c clamav.c
# Ira: action and execution.
SRCS+=		build.c exec.c jail.c jails.c jailwatch.c jobs.c lifecycle.c jailmake.c packages.c pkgbase.c \
		services.c update.c
# Acedia: storage.  Avaritia: resources.  Gula: observation.
SRCS+=		record.c \
		pools.c storage.c zfskey.c xfer.c health.c resources.c stats.c trace.c procs.c log.c \
		history.c events.c faults.c kmsg.c probe.c hostwatch.c crashes.c
.PATH:		${.CURDIR}/superbia ${.CURDIR}/invidia ${.CURDIR}/ira \
		${.CURDIR}/acedia ${.CURDIR}/avaritia ${.CURDIR}/gula \
		${.CURDIR}/luxuria
CFLAGS+=	-I${.CURDIR}
MAN=		arcana-agent.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

CBLINK_SPECS=	${ARC_SPEC}
CBLINK_PARTS=	h,c,server

CFLAGS+=	${JAILCONF_CFLAGS} ${UCL_CFLAGS}
LDADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		${.OBJDIR}/../../lib/libvarconf/libvarconf_pie.a
DPADD+=		${.OBJDIR}/../../lib/libvarconf/libvarconf_pie.a
CFLAGS+=	-I${.CURDIR}/../../lib/libvarconf
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		-lfetch -ljail -lgeom -lmemstat -lprocstat -ldevstat -lnv -lutil -lpthread -lcrypto ${UCL_LIBS}
# Every symbol bound when the agent starts (ld(1) -z now): with a
# libcblink older than the agent, it stops there, rtld(1) saying what
# is missing, not at the first call to it, detached, its stderr closed.
LDFLAGS+=	-Wl,-z,now

# The agent's rc.d(8) script.
FILESGROUPS+=	RC
RC=		arcana_agent.sh
RCDIR=		${PREFIX}/etc/rc.d
RCNAME_arcana_agent.sh=	arcana_agent
RCMODE=		0555
CLEANFILES+=	arcana_agent.sh
arcana_agent.sh: arcana_agent.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' ${.ALLSRC} > ${.TARGET}


HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "${CBLINK_MK}"
.include <bsd.prog.mk>
