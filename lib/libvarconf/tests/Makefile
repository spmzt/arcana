.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/libvarconf
ATF_TESTS_C=	varconf_test

# The fixtures, compiled in: the suite runs from the object directory.
FIXTURES=	defaults.conf edge.conf host.conf
SRCS.varconf_test=	varconf_test.c fixtures.c
CLEANFILES+=	fixtures.c
fixtures.c: ${FIXTURES:S,^,${.CURDIR}/fixtures/,}
	@(echo '#include <stddef.h>'; \
	echo '#include "fixtures.h"'; \
	for f in ${FIXTURES}; do \
	    n=$$(basename $$f .conf); \
	    file2c "static const char fx_$$n[] = {" ',0};' \
	        < ${.CURDIR}/fixtures/$$f; \
	done; \
	echo 'const struct fixture fixtures[] = {'; \
	for f in ${FIXTURES}; do \
	    n=$$(basename $$f .conf); \
	    echo "	{ \"$$f\", fx_$$n, sizeof(fx_$$n) - 1 },"; \
	done; \
	echo '	{ NULL, NULL, 0 }'; \
	echo '};') > ${.TARGET}

CFLAGS+=	-I${.CURDIR}/.. -I${.CURDIR}
LDADD+=		${.OBJDIR:H}/libvarconf_pie.a
DPADD+=		${.OBJDIR:H}/libvarconf_pie.a

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
