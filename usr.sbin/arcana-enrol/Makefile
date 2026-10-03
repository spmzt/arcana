PROG=		arcana-enrol
SRCS=		arcana-enrol.c
MAN=		arcana-enrol.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

CFLAGS+=	${UCL_CFLAGS} ${SSL_CFLAGS} -DPREFIX='"${PREFIX}"'
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lcrypto -lfetch

.include <bsd.prog.mk>
