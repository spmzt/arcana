.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/jailconf
ATF_TESTS_SH=	jailconf_test

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
