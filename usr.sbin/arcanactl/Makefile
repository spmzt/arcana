PROG=		arcanactl
SRCS=		arcanactl.c yjsonin.c
# RFC 7951's JSON in, the console's.
.PATH:		${.CURDIR}/../../www/arcana-console
MAN=		arcanactl.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

ARC_WIRE=	client
.include "${.CURDIR}/../../share/mk/arcana.wire.mk"
.include "${.CURDIR}/../../share/mk/arcana.yang.mk"

CFLAGS+=	-I${.CURDIR}/../../www/arcana-console ${UCL_CFLAGS}
LDADD+=		-lxo -lmd -lcasper -lcap_fileargs -lnv ${UCL_LIBS}

.include <bsd.prog.mk>
