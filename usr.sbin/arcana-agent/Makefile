PROG=		arcana-agent
# The Agent itself, then what it does by Archive (docs/NAMING.md).
SRCS=		main.c handlers.c work.c
# The standard models and Arcana's, served by cblink's YANG family:
# what the collectors (y*.c) read into their structs.
SRCS+=		yjson.c
# Superbia: identity, configuration, what is true of the host.
SRCS+=		admit.c ynacm.c certs.c ssh.c tlsfiles.c confedit.c confread.c host.c kernel.c ntp.c rtadvd.c sysctl.c transport.c bundle.c l2.c ipfw.c netstore.c sysfiles.c geomjob.c \
		yagent.c yhost.c yhw.c ysshd.c ysystem.c ysysedit.c
# Invidia: the network.
SRCS+=		sa.c address.c interfaces.c netgraph.c network.c netdump.c nlroute.c fwmatch.c pathcheck.c neigh.c carp.c capture.c parts.c pcb.c rcconf.c \
		routes.c rtimes.c scope.c sdwan.c vnet.c wireguard.c \
		yif.c yip.c yni.c yrt.c rcroutes.c rcarcana.c ynetconf.c yifedit.c rtadv.c ylne.c lneroot.c yfw.c yng.c ysd.c \
		yts.c ywg.c yserve.c yarcana.c ynotif.c
# Luxuria: what is not FreeBSD's own, the plugins.
SRCS+=		bird.c birdwatch.c ipsec.c plugins.c sdbird.c sddhcp.c sddns.c sdproxy.c sdconf.c sdids.c idsconf.c idsfiles.c surules.c smtpd.c speeder.c telegram.c poudriere.c clamav.c \
		ybird.c ybuilder.c
# Ira: action and execution.
SRCS+=		build.c exec.c jail.c jails.c jailwatch.c jobs.c lifecycle.c jailmake.c jailallow.c packages.c pkgbase.c \
		services.c update.c yjails.c yjf.c yjobs.c ypackages.c yservices.c ysvcedit.c
# Acedia: storage.  Avaritia: resources.  Gula: observation.
SRCS+=		record.c \
		pools.c storage.c zfskey.c xfer.c health.c resources.c stats.c trace.c procs.c log.c \
		history.c events.c faults.c kmsg.c probe.c hostwatch.c crashes.c \
		ystorage.c yev.c yhist.c ylog.c ysyslog.c yprobe.c yprocs.c yalarms.c
.PATH:		${.CURDIR}/superbia ${.CURDIR}/invidia ${.CURDIR}/ira \
		${.CURDIR}/acedia ${.CURDIR}/avaritia ${.CURDIR}/gula \
		${.CURDIR}/luxuria
CFLAGS+=	-I${.CURDIR}
MAN=		arcana-agent.8

# Shipped to the hosts by agent-update: libcblink linked in (arcana.mk).
CBLINK_STATIC=	yes
.include "${.CURDIR}/../../share/mk/arcana.mk"

ARC_WIRE=	server
.include "${.CURDIR}/../../share/mk/arcana.wire.mk"
ARC_YANG_SERVER= yes
.include "${.CURDIR}/../../share/mk/arcana.yang.mk"
# arcana-jobs' submit: a change made a job-spec as jobs.yaml says, by
# jobs.awk over the wire's header (which members have a has_).
SRCS+=		yjobs_spec.c
CLEANFILES+=	yjobs_spec.c yjobs_spec.c.tmp
yjobs_spec.c: ${ARC_TOP}/share/arcana/jobs.awk ${ARC_TOP}/share/arcana/jobs.yaml \
    ${ARC_TOP}/share/arcana/arcana.yaml arcana_v2.h ymodel.h
	awk -v out=yspec -f ${ARC_TOP}/share/arcana/jobs.awk \
	    ${ARC_TOP}/share/arcana/arcana.yaml \
	    ${ARC_TOP}/share/arcana/jobs.yaml ${.OBJDIR}/arcana_v2.h \
	    > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

CFLAGS+=	${JAILCONF_CFLAGS} ${UCL_CFLAGS}
LDADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		${.OBJDIR}/../../lib/libvarconf/libvarconf_pie.a
DPADD+=		${.OBJDIR}/../../lib/libvarconf/libvarconf_pie.a
CFLAGS+=	-I${.CURDIR}/../../lib/libvarconf
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		-lfetch -ljail -lgeom -lmemstat -lprocstat -ldevstat -lnv -lutil -lpthread -lcrypto ${UCL_LIBS}
# Every symbol bound when the agent starts (ld(1) -z now): with a
# libcblink older than the agent, it stops there, rtld(1) saying what
# is missing, not at the first call to it, detached, its stderr closed.
LDFLAGS+=	-Wl,-z,now

# The agent's rc.d(8) script.
FILESGROUPS+=	RC
RC=		arcana_agent.sh
RCDIR=		${PREFIX}/etc/rc.d
RCNAME_arcana_agent.sh=	arcana_agent
RCMODE=		0555
CLEANFILES+=	arcana_agent.sh
arcana_agent.sh: arcana_agent.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' ${.ALLSRC} > ${.TARGET}


HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
