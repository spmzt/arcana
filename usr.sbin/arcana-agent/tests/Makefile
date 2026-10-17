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
# kmsg: the kernel's line for a crash, as the event and fault of it.
PROGS+=		kmsg
SRCS.kmsg=	kmsg_test.c kmsg.c
CFLAGS.kmsg_test.c+=	-I${.CURDIR}/.. -I${.OBJDIR}/.. -I${.CURDIR}/../../../lib/libvarconf ${UCL_CFLAGS}
CFLAGS.kmsg.c+=	-I${.CURDIR}/.. -I${.OBJDIR}/.. -I${.CURDIR}/../../../lib/libvarconf ${UCL_CFLAGS}
LDADD.kmsg+=	${CBLINK_LIBS} -ljail -lpthread
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
# yts: path-check, traceroute and capture as arcana-troubleshoot has them.
PROGS+=		yts
SRCS.yts=	yts_test.c yts.c yjson.c ymodel_schema.c
CFLAGS.yts_test.c+=	-I${.OBJDIR}/..
CFLAGS.yts.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.yts+=	${CBLINK_LIBS} ${UCL_LIBS}
# yhist: the history operation's reply as arcana-history has it.
PROGS+=		yhist
SRCS.yhist=	yhist_test.c yhist.c yjson.c ymodel_schema.c
CFLAGS.yhist_test.c+=	-I${.OBJDIR}/..
CFLAGS.yhist.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.yhist+=	${CBLINK_LIBS} ${UCL_LIBS}
# yev: the events operation's reply, and one event, as arcana-events has them.
PROGS+=		yev
SRCS.yev=	yev_test.c yev.c yjson.c ymodel_schema.c
CFLAGS.yev_test.c+=	-I${.OBJDIR}/..
CFLAGS.yev.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.yev+=	${CBLINK_LIBS} ${UCL_LIBS}
# yplug: BIRD, WireGuard and netgraph as their modules have them.
PROGS+=		yplug
SRCS.yplug=	yplug_test.c ybird.c ywg.c yng.c yjson.c ymodel_schema.c
CFLAGS.yplug_test.c+=	-I${.OBJDIR}/..
CFLAGS.ybird.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
CFLAGS.ywg.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
CFLAGS.yng.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.yplug+=	${CBLINK_LIBS} ${UCL_LIBS}
# ymisc: the host, the agent and the jails' files as their modules have them.
PROGS+=		ymisc
SRCS.ymisc=	ymisc_test.c yhost.c yagent.c yjf.c ysshd.c ybuilder.c yjson.c \
		ymodel_schema.c
CFLAGS.ysshd.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
CFLAGS.ybuilder.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
CFLAGS.ymisc_test.c+=	-I${.OBJDIR}/..
CFLAGS.yhost.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
CFLAGS.yagent.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
CFLAGS.yjf.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.ymisc+=	${CBLINK_LIBS} ${UCL_LIBS}
# ysd: the probes and the SD-WAN edge as arcana-probe and arcana-sdwan have them.
PROGS+=		ysd
SRCS.ysd=	ysd_test.c yprobe.c ysd.c yjson.c ymodel_schema.c
CFLAGS.ysd_test.c+=	-I${.OBJDIR}/..
CFLAGS.yprobe.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
CFLAGS.ysd.c+=	-I${.OBJDIR}/.. ${UCL_CFLAGS}
LDADD.ysd+=	${CBLINK_LIBS} ${UCL_LIBS}
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
		${.CURDIR}/../luxuria \
		${.CURDIR}/../superbia ${.CURDIR}/../gula ${.CURDIR}/../yang
CFLAGS+=	-I${.CURDIR}/../yang -I${.CURDIR}/../invidia ${CBLINK_CFLAGS}
LDADD.ycollect+=	${CBLINK_LIBS} -ljail -lnv
MAN=

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
