PROG=		arcana-agent
# The Agent itself, then what it does by Archive (docs/NAMING.md).
SRCS=		main.c handlers.c work.c
# Superbia: identity, configuration, what is true of the host.
SRCS+=		confedit.c confread.c host.c kernel.c sysctl.c transport.c l2.c ipfw.c
# Invidia: the network.
SRCS+=		address.c interfaces.c netgraph.c network.c netdump.c nlroute.c pcb.c rcconf.c \
		routes.c scope.c vnet.c
# Luxuria: what is not FreeBSD's own, the plugins.
SRCS+=		bird.c ipsec.c plugins.c wireguard.c
# Ira: action and execution.
SRCS+=		build.c exec.c jail.c jails.c jobs.c lifecycle.c packages.c \
		services.c update.c
# Acedia: storage.  Avaritia: resources.  Gula: observation.
SRCS+=		pools.c storage.c health.c resources.c stats.c trace.c procs.c log.c \
		history.c events.c kmsg.c
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
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		-ljail -lgeom -lmemstat -lprocstat -ldevstat -lutil -lpthread -lcrypto ${UCL_LIBS}

# The rc.d(8) script.
FILESGROUPS+=	RC
RC=		arcana_agent.sh
RCDIR=		${PREFIX}/etc/rc.d
RCNAME=		arcana_agent
RCMODE=		0555
CLEANFILES+=	arcana_agent.sh
arcana_agent.sh: arcana_agent.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' ${.ALLSRC} > ${.TARGET}

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "${CBLINK_MK}"
.include <bsd.prog.mk>
