# libfakejail.so: libjail's jail_getv(3) answered from a file of the
# test's, preloaded into the agent the tests start (fakejail.c).  For
# the tests alone: installed beside them, never where rtld(1) looks.

SHLIB_NAME=	libfakejail.so
SRCS=		fakejail.c
MAN=

.include "${.CURDIR}/../../../../share/mk/arcana.mk"

SHLIBDIR=	${TESTSBASE}/arcana/arcana-agent

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${SHLIBDIR}

.include <bsd.lib.mk>
