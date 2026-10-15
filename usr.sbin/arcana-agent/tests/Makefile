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
# ysystem: the sysctl and kernel operations' replies as arcana-sysctl
# and arcana-kernel have them, their configuration written.
PROGS+=		ysystem
SRCS.ysystem=	ysystem_test.c ysystem.c yjson.c ymodel_schema.c
CFLAGS.ysystem_test.c+=	-I${.OBJDIR}/..
CFLAGS.ysystem.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.ysystem+=	${CBLINK_LIBS} ${UCL_LIBS} \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
# fwmatch: a packet walked through an ipfw ruleset.
PROGS+=		fwmatch
SRCS.fwmatch=	fwmatch_test.c fwmatch.c
CFLAGS.fwmatch_test.c+=	-I${.CURDIR}/../invidia
# ylog: the log operation's replies as arcana-log has them, and
# syslog.conf as ietf-syslog.
PROGS+=		ylog
SRCS.ylog=	ylog_test.c ylog.c yjson.c ymodel_schema.c
CFLAGS.ylog_test.c+=	-I${.OBJDIR}/..
CFLAGS.ylog.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.ylog+=	${CBLINK_LIBS} ${UCL_LIBS}
# yfw: the firewall as arcana-firewall has it: the ipfw read, the kept
# file, a kernel trace.
PROGS+=		yfw
SRCS.yfw=	yfw_test.c yfw.c yjson.c ymodel_schema.c
CFLAGS.yfw_test.c+=	-I${.OBJDIR}/..
CFLAGS.yfw.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.yfw+=	${CBLINK_LIBS} ${UCL_LIBS}
# yprocs: the processes operation's replies as arcana-processes has them.
PROGS+=		yprocs
SRCS.yprocs=	yprocs_test.c yprocs.c yjson.c ymodel_schema.c
CFLAGS.yprocs_test.c+=	-I${.OBJDIR}/..
CFLAGS.yprocs.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.yprocs+=	${CBLINK_LIBS} ${UCL_LIBS}
# ystorage: the storage operation's replies as arcana-storage has them.
PROGS+=		ystorage
SRCS.ystorage=	ystorage_test.c ystorage.c yjson.c ymodel_schema.c
CFLAGS.yjson.c+=	${UCL_CFLAGS}
CFLAGS.ystorage_test.c+=	-I${.OBJDIR}/..
CFLAGS.ystorage.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.ystorage+=	${CBLINK_LIBS} ${UCL_LIBS}
# yjobs: the jobs as arcana-jobs has them, a submit's changes as specs.
PROGS+=		yjobs
SRCS.yjobs=	yjobs_test.c yjobs.c yjobs_spec.c ymodel_schema.c
CFLAGS.yjobs_test.c+=	-I${.OBJDIR}/..
CFLAGS.yjobs.c+=	-I${.OBJDIR}/..
CFLAGS.yjobs_spec.c+=	-I${.OBJDIR}/..
LDADD.yjobs+=	${CBLINK_LIBS}
# ypackages: the packages operations' replies as arcana-packages has
# them.
PROGS+=		ypackages
SRCS.ypackages=	ypackages_test.c ypackages.c ymodel_schema.c
CFLAGS.ypackages_test.c+=	-I${.OBJDIR}/..
CFLAGS.ypackages.c+=	-I${.OBJDIR}/..
LDADD.ypackages+=	${CBLINK_LIBS}
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
.PATH:		${.CURDIR}/../invidia ${.CURDIR}/../ira ${.CURDIR}/../acedia \
		${.CURDIR}/../superbia ${.CURDIR}/../gula ${.CURDIR}/../yang
CFLAGS+=	-I${.CURDIR}/../yang -I${.CURDIR}/../invidia ${CBLINK_CFLAGS}
LDADD.ycollect+=	${CBLINK_LIBS} -ljail -lnv
MAN=

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
