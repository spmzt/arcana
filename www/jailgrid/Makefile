# jailgrid.so: the Kore module serving the console and its API.

SHLIB_NAME=	jailgrid.so
SRCS=		api.c auth.c config.c hosts.c pki.c servers.c store.c update.c
LIBDIR?=	${PREFIX}/lib/jailgrid
MAN=

.include "${.CURDIR}/../../share/mk/jailgrid.mk"

CBLINK_SPECS=	${JG_SPEC}
CBLINK_PARTS=	h,c,client

.if empty(KORE_FEATURES:M-DKORE_USE_TASKS)
.error Kore must be built with tasks (TASKS=1): KORE_FEATURES is "${KORE_FEATURES}"
.endif
CFLAGS+=	-I${KORE_INCLUDE} ${KORE_FEATURES} ${UCL_CFLAGS} ${SSL_CFLAGS}
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lcrypto -lfetch

# Configuration samples, the routes, and the rc.d(8) script.
FILESGROUPS+=	CONF RC
CONF=		conf/routes.conf conf/kore.conf.sample conf/web.conf.sample
CONFDIR=	${PREFIX}/etc/jailgrid
RC=		jailgrid.sh
RCDIR=		${PREFIX}/etc/rc.d
RCNAME=		jailgrid
RCMODE=		0555
CLEANFILES+=	jailgrid.sh
jailgrid.sh: conf/jailgrid.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' -e 's|%%LOCALBASE%%|${LOCALBASE}|g' \
	    ${.ALLSRC} > ${.TARGET}
beforeinstall: .PHONY
	${INSTALL} -d ${DESTDIR}${LIBDIR} ${DESTDIR}${CONFDIR}

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "${CBLINK_MK}"
.include <bsd.lib.mk>
