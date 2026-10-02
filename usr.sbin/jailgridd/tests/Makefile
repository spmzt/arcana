.include "${.CURDIR}/../../../share/mk/jailgrid.mk"

TESTSDIR=	${TESTSBASE}/jailgrid/jailgridd
ATF_TESTS_SH=	jailgridd_test \
		jailgridd_tls_test \
		jailgridd_root_test

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
