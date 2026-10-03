PROG=		jailgridd
SRCS=		main.c handlers.c actions.c work.c exec.c jails.c confread.c \
		host.c jail.c services.c network.c stats.c packages.c jobs.c
MAN=		jailgridd.8

.include "${.CURDIR}/../../share/mk/jailgrid.mk"

CBLINK_SPECS=	${JG_SPEC}
CBLINK_PARTS=	h,c,server

CFLAGS+=	${JAILCONF_CFLAGS} ${UCL_CFLAGS}
LDADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		-ljail -lprocstat -lutil -lpthread ${UCL_LIBS}

# The rc.d(8) script.
FILESGROUPS+=	RC
RC=		jailgridd.sh
RCDIR=		${PREFIX}/etc/rc.d
RCNAME=		jailgridd
RCMODE=		0555
CLEANFILES+=	jailgridd.sh
jailgridd.sh: jailgridd.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' ${.ALLSRC} > ${.TARGET}

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "${CBLINK_MK}"
.include <bsd.prog.mk>
