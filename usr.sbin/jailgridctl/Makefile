PROG=		jailgridctl
SRCS=		jailgridctl.c
MAN=		jailgridctl.8

.include "${.CURDIR}/../../share/mk/jailgrid.mk"

CBLINK_SPECS=	${JG_SPEC}
CBLINK_PARTS=	h,c,client

LDADD+=		-lxo

.include "${CBLINK_MK}"
.include <bsd.prog.mk>
