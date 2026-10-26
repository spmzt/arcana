.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/arcana-agent
ATF_TESTS_SH=	agent_test \
		agent_tls_test \
		agent_root_test

# The collectors of the standard models (invidia/y*.c), run alone over
# the structs and tables the agent's build made (its ymodel.h and
# ymodel_schema.c), for agent_root_test.sh's yang_* cases.
YOBJ=		${.OBJDIR}/..
# ycollect: what the collectors find: interfaces, routes, vnet jails.
PROGS=		ycollect
SRCS.ycollect=	ycollect.c yif.c yip.c yni.c ylne.c yrt.c rtimes.c \
		ymodel_schema.c
LDADD.ycollect+=	${CBLINK_LIBS} -ljail -lnv \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
# yni: FIBs as network instances, names in fibs.conf.
PROGS+=		yni
SRCS.yni=	yni_test.c yni.c yif.c yip.c ymodel_schema.c
LDADD.yni+=	${CBLINK_LIBS} -lnv \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
# yrtadv: rtadvd.conf as the router advertisement submodule has it.
PROGS+=		yrtadv
SRCS.yrtadv=	yrtadv.c rtadv.c ymodel_schema.c
LDADD.yrtadv+=	${CBLINK_LIBS} \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
# yrcroutes: rc.conf's static routes as ietf-routing has them.
PROGS+=		yrcroutes
SRCS.yrcroutes=	yrcroutes.c rcroutes.c ymodel_schema.c
LDADD.yrcroutes+=	${CBLINK_LIBS} \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
CFLAGS+=	-I${.CURDIR}/.. -I${YOBJ} -I${.CURDIR}/../../../lib/libvarconf
# Arcana's own modules: each operation's reply as its module has it
# (the collectors of yarcana.c's reads), from JSON a case gives.
CFLAGS+=	${UCL_CFLAGS}
# yjails: the list operation's reply as arcana-jails has it.
PROGS+=		yjails
SRCS.yjails=	yjails_test.c yjails.c ymodel_schema.c
LDADD.yjails+=	${CBLINK_LIBS}
# ysystem: the sysctl and kernel operations' replies as arcana-sysctl
# and arcana-kernel have them, their configuration written.
PROGS+=		ysystem
SRCS.ysystem=	ysystem_test.c ysystem.c yjson.c ymodel_schema.c
LDADD.ysystem+=	${CBLINK_LIBS} ${UCL_LIBS} \
		${.OBJDIR}/../../../lib/libvarconf/libvarconf_pie.a
# ylog: the log operation's replies as arcana-log has them, and
# syslog.conf as ietf-syslog.
PROGS+=		ylog
SRCS.ylog=	ylog_test.c ylog.c yjson.c ymodel_schema.c
LDADD.ylog+=	${CBLINK_LIBS} ${UCL_LIBS}
# yfw: the firewall as arcana-firewall has it: the ipfw read, the kept
# file, a kernel trace.
PROGS+=		yfw
SRCS.yfw=	yfw_test.c yfw.c yjson.c ymodel_schema.c
LDADD.yfw+=	${CBLINK_LIBS} ${UCL_LIBS}
# yts: path-check, traceroute and capture as arcana-troubleshoot has them.
PROGS+=		yts
SRCS.yts=	yts_test.c yts.c yjson.c ymodel_schema.c
LDADD.yts+=	${CBLINK_LIBS} ${UCL_LIBS}
# yhist: the history operation's reply as arcana-history has it.
PROGS+=		yhist
SRCS.yhist=	yhist_test.c yhist.c yjson.c ymodel_schema.c
LDADD.yhist+=	${CBLINK_LIBS} ${UCL_LIBS}
# yev: the events operation's reply, and one event, as arcana-events
# has them.
PROGS+=		yev
SRCS.yev=	yev_test.c yev.c yjson.c ymodel_schema.c
LDADD.yev+=	${CBLINK_LIBS} ${UCL_LIBS}
# yplug: BIRD, WireGuard and netgraph as their modules have them.
PROGS+=		yplug
SRCS.yplug=	yplug_test.c ybird.c ywg.c yng.c yjson.c ymodel_schema.c
LDADD.yplug+=	${CBLINK_LIBS} ${UCL_LIBS}
# ymisc: the host, the agent and the jails' files as their modules
# have them.
PROGS+=		ymisc
SRCS.ymisc=	ymisc_test.c yhost.c yagent.c yjf.c ysshd.c ybuilder.c yjson.c \
		ymodel_schema.c
LDADD.ymisc+=	${CBLINK_LIBS} ${UCL_LIBS}
# ysd: the probes and the SD-WAN edge as arcana-probe and arcana-sdwan
# have them.
PROGS+=		ysd
SRCS.ysd=	ysd_test.c yprobe.c ysd.c yjson.c ymodel_schema.c
LDADD.ysd+=	${CBLINK_LIBS} ${UCL_LIBS}
# yprocs: the processes operation's replies as arcana-processes has them.
PROGS+=		yprocs
SRCS.yprocs=	yprocs_test.c yprocs.c yjson.c ymodel_schema.c
LDADD.yprocs+=	${CBLINK_LIBS} ${UCL_LIBS}
# ystorage: the storage operation's replies as arcana-storage has them.
PROGS+=		ystorage
SRCS.ystorage=	ystorage_test.c ystorage.c yjson.c ymodel_schema.c
LDADD.ystorage+=	${CBLINK_LIBS} ${UCL_LIBS}
# ypackages: the packages operations' replies as arcana-packages has
# them.
PROGS+=		ypackages
SRCS.ypackages=	ypackages_test.c ypackages.c ymodel_schema.c
LDADD.ypackages+=	${CBLINK_LIBS}
# yservices: the services operations' replies as arcana-services has
# them.
PROGS+=		yservices
SRCS.yservices=	yservices_test.c yservices.c ymodel_schema.c
LDADD.yservices+=	${CBLINK_LIBS}
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
.PATH:		${.CURDIR}/../invidia ${.CURDIR}/../ira ${.CURDIR}/../acedia \
		${.CURDIR}/../luxuria \
		${.CURDIR}/../superbia ${.CURDIR}/../gula ${.CURDIR}/.. ${YOBJ}
CFLAGS+=	-I${.CURDIR}/../invidia ${CBLINK_CFLAGS}
MAN=

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
