PROG=		arcanactl
SRCS=		arcanactl.c
MAN=		arcanactl.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

CBLINK_SPECS=	${ARC_SPEC}
CBLINK_PARTS=	h,c,client

LDADD+=		-lxo -lmd

.include "${CBLINK_MK}"
.include <bsd.prog.mk>
