.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/arcana-agent
ATF_TESTS_SH=	agent_test \
		agent_tls_test \
		agent_root_test

# ycollect: what the YANG collectors find, for agent_test.sh.
PROGS=		ycollect
SRCS.ycollect=	ycollect.c yif.c yip.c ylne.c yrt.c rtimes.c ymodel_schema.c
# yni: FIBs as network instances, names in fibs.conf.
PROGS+=		yni
SRCS.yni=	yni_test.c yni.c yif.c yip.c ymodel_schema.c
LDADD.yni+=	${CBLINK_LIBS} -lnv \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
# yjails: the list operation's reply as arcana-jails has it.
PROGS+=		yjails
SRCS.yjails=	yjails_test.c yjails.c ymodel_schema.c
CFLAGS.yjails_test.c+=	-I${.OBJDIR}/..
CFLAGS.yjails.c+=	-I${.OBJDIR}/..
LDADD.yjails+=	${CBLINK_LIBS}
# yservices: the services operations' replies as arcana-services has
# them.
PROGS+=		yservices
SRCS.yservices=	yservices_test.c yservices.c ymodel_schema.c
CFLAGS.yservices_test.c+=	-I${.OBJDIR}/..
CFLAGS.yservices.c+=	-I${.OBJDIR}/..
LDADD.yservices+=	${CBLINK_LIBS}
# yrtadv: rtadvd.conf as the router advertisement submodule has it.
PROGS+=		yrtadv
SRCS.yrtadv=	yrtadv.c rtadv.c ymodel_schema.c
LDADD.yrtadv+=	${CBLINK_LIBS} \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
# yrcroutes: rc.conf's static routes as ietf-routing has them.
PROGS+=		yrcroutes
SRCS.yrcroutes=	yrcroutes.c rcroutes.c ymodel_schema.c
CFLAGS+=	-I${.CURDIR}/../../../lib/libvarconf
LDADD.yrcroutes+=	${CBLINK_LIBS} \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
.PATH:		${.CURDIR}/../invidia ${.CURDIR}/../ira ${.CURDIR}/../yang
CFLAGS+=	-I${.CURDIR}/../yang -I${.CURDIR}/../invidia ${CBLINK_CFLAGS}
LDADD.ycollect+=	${CBLINK_LIBS} -ljail -lnv
MAN=

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
