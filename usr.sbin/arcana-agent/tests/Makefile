.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/arcana-agent
ATF_TESTS_SH=	agent_test \
		agent_tls_test \
		agent_root_test

# ycollect: what the YANG collectors find, for agent_test.sh.
PROGS=		ycollect
SRCS.ycollect=	ycollect.c yif.c yip.c yrt.c ymodel_schema.c
.PATH:		${.CURDIR}/../invidia ${.CURDIR}/../yang
CFLAGS+=	-I${.CURDIR}/../yang ${CBLINK_CFLAGS}
LDADD.ycollect+=	${CBLINK_LIBS} -lnv
MAN=

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
