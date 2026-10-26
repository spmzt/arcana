PROG=		arcanactl
SRCS=		arcanactl.c
MAN=		arcanactl.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

ARC_WIRE=	client
.include "${.CURDIR}/../../share/mk/arcana.wire.mk"
.include "${.CURDIR}/../../share/mk/arcana.yang.mk"

LDADD+=		-lxo -lmd -lcasper -lcap_fileargs -lnv

.include <bsd.prog.mk>
