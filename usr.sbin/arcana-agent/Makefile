PROG=		arcana-agent
SRCS=		main.c handlers.c actions.c work.c exec.c jails.c confread.c \
		host.c jail.c services.c network.c stats.c packages.c jobs.c
MAN=		arcana-agent.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

CBLINK_SPECS=	${ARC_SPEC}
CBLINK_PARTS=	h,c,server

CFLAGS+=	${JAILCONF_CFLAGS} ${UCL_CFLAGS}
LDADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		-ljail -lprocstat -lutil -lpthread -lcrypto ${UCL_LIBS}

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
