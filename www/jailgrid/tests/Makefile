.include "${.CURDIR}/../../../share/mk/jailgrid.mk"

TESTSDIR=	${TESTSBASE}/jailgrid/console
ATF_TESTS_C=	console_test \
		pwa_test

SRCS.console_test=	console_test.c harness.c
SRCS.pwa_test=		pwa_test.c harness.c

CFLAGS+=	${UCL_CFLAGS} ${SSL_CFLAGS} -DTESTSRC='"${.CURDIR}"'
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lcrypto

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
