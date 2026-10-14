PROG=		arcana-agent
# The Agent itself, then what it does by Archive (docs/NAMING.md).
SRCS=		main.c handlers.c work.c
# Superbia: identity, configuration, what is true of the host.
SRCS+=		admit.c certs.c ssh.c tlsfiles.c confedit.c confread.c host.c kernel.c ntp.c rtadvd.c sysctl.c transport.c ysystem.c l2.c ipfw.c
# Invidia: the network.
SRCS+=		sa.c address.c interfaces.c netgraph.c network.c netdump.c nlroute.c neigh.c carp.c capture.c parts.c pcb.c rcconf.c \
		rcroutes.c routes.c rtadv.c rtimes.c scope.c sdwan.c vnet.c \
		yif.c yip.c yjobs_spec.c yjson.c ylne.c yni.c yrt.c
# The IETF modules the collectors fill (PLAN-SDN-YANG 1.9): cblink-gen's
# structs and tables of share/yang's modules, committed, so that building
# needs no libyang; "make regen-yang" refreshes them.
SRCS+=		ymodel_schema.c
# Luxuria: what is not FreeBSD's own, the plugins.
SRCS+=		bird.c ipsec.c plugins.c sdbird.c sddhcp.c sddns.c sdproxy.c sdids.c wireguard.c
# Ira: action and execution.
SRCS+=		build.c exec.c jail.c jails.c jailwatch.c jobs.c lifecycle.c jailmake.c packages.c \
		services.c update.c yjails.c yjobs.c ypackages.c yservices.c
# Acedia: storage.  Avaritia: resources.  Gula: observation.
SRCS+=		record.c \
		pools.c storage.c ystorage.c zfskey.c xfer.c health.c resources.c stats.c trace.c procs.c yprocs.c log.c \
		history.c events.c faults.c kmsg.c probe.c
.PATH:		${.CURDIR}/superbia ${.CURDIR}/invidia ${.CURDIR}/ira \
		${.CURDIR}/acedia ${.CURDIR}/avaritia ${.CURDIR}/gula \
		${.CURDIR}/luxuria ${.CURDIR}/yang
CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/yang
MAN=		arcana-agent.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

CBLINK_SPECS=	${ARC_SPEC}
CBLINK_PARTS=	h,c,server

CFLAGS+=	${JAILCONF_CFLAGS} ${UCL_CFLAGS}
LDADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		${.OBJDIR}/../../lib/libvarconf/libvarconf_pie.a
DPADD+=		${.OBJDIR}/../../lib/libvarconf/libvarconf_pie.a
CFLAGS+=	-I${.CURDIR}/../../lib/libvarconf
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		-ljail -lgeom -lmemstat -lprocstat -ldevstat -lnv -lutil -lpthread -lcrypto ${UCL_LIBS}
# Every symbol bound when the agent starts (ld(1) -z now): with a
# libcblink older than the agent, it stops there, rtld(1) saying what
# is missing, not at the first call to it, detached, its stderr closed.
LDFLAGS+=	-Wl,-z,now

# The rc.d(8) script.
FILESGROUPS+=	RC
RC=		arcana_agent.sh
RCDIR=		${PREFIX}/etc/rc.d
RCNAME=		arcana_agent
RCMODE=		0555
CLEANFILES+=	arcana_agent.sh
arcana_agent.sh: arcana_agent.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' ${.ALLSRC} > ${.TARGET}

# The modules, their features, their .sid files: what ymodel.h and
# ymodel_schema.c are made of.
YANG_DIR=	${.CURDIR}/../../share/yang
YANG_MODS=	ietf-interfaces@2018-02-20 arcana-interfaces@2026-10-14 \
		ietf-if-extensions@2025-08-07 ietf-if-ethernet-like@2026-06-19 \
		ietf-if-vlan-encapsulation@2026-07-06 \
		ieee802-ethernet-interface@2025-09-10 \
		ieee802-dot1ax-linkagg@2025-09-30 \
		arcana-ieee802-deviations@2026-10-14 \
		ietf-ip@2018-02-22 arcana-ip-deviations@2026-10-14 \
		iana-if-type@2026-03-17 ietf-yang-types@2025-12-22 \
		ietf-inet-types@2025-12-22 ietf-routing@2018-03-13 \
		ietf-ipv4-unicast-routing@2018-03-13 \
		ietf-ipv6-unicast-routing@2018-03-13 arcana-routing@2026-10-14 \
		ietf-network-instance@2019-01-21 \
		arcana-network-instance@2026-10-14 \
		ietf-logical-network-element@2019-01-25 arcana-jails@2026-10-14 \
		arcana-services@2026-10-14 arcana-packages@2026-10-14 \
		arcana-jobs@2026-10-14 arcana-storage@2026-10-14 \
		arcana-sysctl@2026-10-14 arcana-kernel@2026-10-14 \
		arcana-processes@2026-10-14
# Modules only imported whose identities are used, their .sid files'
# alone: the routing protocols', whose identities name a route's origin;
# IEEE 802.1Q's types, a VLAN tag's; IEEE 802.3's PHY and PMD types;
# IEEE 802.1AX's, its port algorithms'.
YANG_IMPORTS=	ietf-ospf@2022-10-19 ietf-rip@2020-02-20 ietf-isis@2022-10-19 \
		ietf-babel@2024-10-10 ietf-bgp@2026-08-14 ietf-bfd-types@2022-09-22 \
		ieee802-dot1q-types@2023-10-26 ieee802-ethernet-phy-type@2025-09-10 \
		ieee802-dot1ax-types@2025-09-30
# ietf-routing's multiple-ribs: a FIB each (setfib(1)).
YANG_FEATS=	-F ietf-interfaces:if-mib,arbitrary-names -F arcana-interfaces: \
		-F ietf-if-extensions:max-frame-size,peer-interface,sub-interfaces \
		-F ietf-if-ethernet-like:configurable-mac-address \
		-F ietf-if-vlan-encapsulation: -F ieee802-ethernet-interface: \
		-F ieee802-dot1ax-linkagg: -F arcana-ieee802-deviations: \
		-F ietf-ip:ipv6-privacy-autoconf -F arcana-ip-deviations: \
		-F iana-if-type: -F ietf-yang-types: -F ietf-inet-types: \
		-F ietf-routing:multiple-ribs -F ietf-ipv4-unicast-routing: \
		-F ietf-ipv6-unicast-routing: -F arcana-routing: \
		-F ietf-network-instance: -F arcana-network-instance: \
		-F ietf-logical-network-element: -F arcana-jails: \
		-F arcana-services: -F arcana-packages: -F arcana-jobs: \
		-F arcana-storage: -F arcana-sysctl: -F arcana-kernel: \
		-F arcana-processes:
YANG_OUT?=	${.CURDIR}/yang
# The kinds of job, made from share/arcana/jobs.yaml as the console's
# forms are: arcana-jobs's submodule, and yjobs_spec(), a change of it
# made the job-spec the queue takes (by arcana.h, the family's header).
JOBS_AWK=	awk -f ${.CURDIR}/../../share/arcana/jobs.awk \
		${.CURDIR}/../../share/arcana/arcana.yaml \
		${.CURDIR}/../../share/arcana/jobs.yaml
YANG_KINDS_OUT?=	${YANG_DIR}
regen-yang: .PHONY
	${JOBS_AWK:S/^awk/awk -v out=yang/} > \
	    ${YANG_KINDS_OUT}/arcana-jobs-kinds@2026-10-14.yang
	${JOBS_AWK:S/^awk/awk -v out=yspec/} ${.OBJDIR}/arcana.h > \
	    ${YANG_OUT}/yjobs_spec.c
	cd ${YANG_DIR} && ${CBLINK_GEN} -m h,schema -b ymodel \
	    -o ${YANG_OUT} ${YANG_FEATS} ${YANG_MODS:@m@-s ${m}.sid@} \
	    ${YANG_IMPORTS:@m@-s ${m}.sid@} \
	    ${YANG_MODS:S/$/.yang/}

# make check's: the committed files are what the modules make now, by
# the generator of the cblink submodule (another may write them
# otherwise).
check-yang: .PHONY
	@t=$$(mktemp -d) && trap 'rm -rf "$$t"' EXIT && \
	    ${MAKE} -C ${.CURDIR} regen-yang YANG_OUT="$$t" \
	    YANG_KINDS_OUT="$$t" >/dev/null && \
	    for f in ymodel.h ymodel_schema.c yjobs_spec.c; do \
		cmp -s "$$t/$$f" ${.CURDIR}/yang/$$f || { echo \
		    "usr.sbin/arcana-agent: yang/$$f is not what make regen-yang makes" >&2; \
		    exit 1; }; \
	    done; \
	    f=arcana-jobs-kinds@2026-10-14.yang; \
	    cmp -s "$$t/$$f" ${YANG_DIR}/$$f || { echo \
		"share/yang/$$f is not what make regen-yang makes" >&2; \
		exit 1; }; \
	    echo "usr.sbin/arcana-agent: yang/ is what make regen-yang makes"

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "${CBLINK_MK}"
.include <bsd.prog.mk>
