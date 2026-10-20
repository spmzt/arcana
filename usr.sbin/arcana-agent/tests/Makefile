.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/arcana-agent
ATF_TESTS_SH=	agent_test \
		agent_tls_test \
		agent_root_test

# kmsg: the kernel's line for a crash, as the event and fault of it.
PROGS=		kmsg
SRCS.kmsg=	kmsg_test.c kmsg.c
CFLAGS.kmsg_test.c+=	-I${.CURDIR}/.. -I${.OBJDIR}/.. -I${.CURDIR}/../../../lib/libvarconf ${UCL_CFLAGS}
CFLAGS.kmsg.c+=	-I${.CURDIR}/.. -I${.OBJDIR}/.. -I${.CURDIR}/../../../lib/libvarconf ${UCL_CFLAGS}
LDADD.kmsg+=	${CBLINK_LIBS} -ljail -lpthread
# fwmatch: a packet walked through an ipfw ruleset.
PROGS+=		fwmatch
SRCS.fwmatch=	fwmatch_test.c fwmatch.c
CFLAGS.fwmatch_test.c+=	-I${.CURDIR}/../invidia
.PATH:		${.CURDIR}/../invidia ${.CURDIR}/../ira ${.CURDIR}/../acedia \
		${.CURDIR}/../luxuria \
		${.CURDIR}/../superbia ${.CURDIR}/../gula
CFLAGS+=	-I${.CURDIR}/../invidia ${CBLINK_CFLAGS}
MAN=

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
