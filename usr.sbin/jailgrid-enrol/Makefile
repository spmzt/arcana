PROG=		jailgrid-enrol
SRCS=		jailgrid-enrol.c
MAN=		jailgrid-enrol.8

.include "${.CURDIR}/../../share/mk/jailgrid.mk"

CFLAGS+=	${UCL_CFLAGS} ${SSL_CFLAGS} -DPREFIX='"${PREFIX}"'
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lcrypto -lfetch

.include <bsd.prog.mk>
