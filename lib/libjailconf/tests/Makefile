.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/libjailconf
ATF_TESTS_C=	jailconf_test

CFLAGS+=	-I${.CURDIR}/..
LDADD+=		${.OBJDIR:H}/libjailconf_pie.a
DPADD+=		${.OBJDIR:H}/libjailconf_pie.a

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
