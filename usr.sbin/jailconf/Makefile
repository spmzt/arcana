PROG=		jailconf
MAN=		jailconf.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

CFLAGS+=	${JAILCONF_CFLAGS}
LDADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
