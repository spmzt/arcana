PROG=		arcana-agent
# The Agent itself, then what it does by Archive (docs/NAMING.md).
SRCS=		main.c handlers.c work.c
# Superbia: identity, configuration, what is true of the host.
SRCS+=		admit.c certs.c ssh.c tlsfiles.c confedit.c confread.c host.c kernel.c ntp.c rtadvd.c sysctl.c transport.c l2.c ipfw.c
# Invidia: the network.
SRCS+=		sa.c address.c interfaces.c netgraph.c network.c netdump.c nlroute.c neigh.c carp.c capture.c parts.c pcb.c rcconf.c \
		routes.c scope.c sdwan.c vnet.c yif.c yip.c
# The IETF modules the collectors fill (PLAN-SDN-YANG 1.9): cblink-gen's
# structs and tables of share/yang's modules, committed, so that building
# needs no libyang; "make regen-yang" refreshes them.
SRCS+=		ymodel_schema.c
# Luxuria: what is not FreeBSD's own, the plugins.
SRCS+=		bird.c ipsec.c plugins.c sdbird.c sddhcp.c sddns.c sdproxy.c sdids.c wireguard.c
# Ira: action and execution.
SRCS+=		build.c exec.c jail.c jails.c jailwatch.c jobs.c lifecycle.c jailmake.c packages.c \
		services.c update.c
# Acedia: storage.  Avaritia: resources.  Gula: observation.
SRCS+=		record.c \
		pools.c storage.c zfskey.c xfer.c health.c resources.c stats.c trace.c procs.c log.c \
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
DPADD+=		${.OBJDIR}/../../lib/libjailconf/libjailconf_pie.a
LDADD+=		-ljail -lgeom -lmemstat -lprocstat -ldevstat -lnv -lutil -lpthread -lcrypto ${UCL_LIBS}

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
		ietf-ip@2018-02-22 iana-if-type@2026-03-17 \
		ietf-yang-types@2025-12-22 ietf-inet-types@2025-12-22
YANG_FEATS=	-F ietf-interfaces:if-mib,arbitrary-names -F arcana-interfaces: \
		-F ietf-ip:ipv6-privacy-autoconf -F iana-if-type: \
		-F ietf-yang-types: -F ietf-inet-types:
YANG_OUT?=	${.CURDIR}/yang
regen-yang: .PHONY
	cd ${YANG_DIR} && ${CBLINK_GEN} -m h,schema -b ymodel \
	    -o ${YANG_OUT} ${YANG_FEATS} ${YANG_MODS:@m@-s ${m}.sid@} \
	    ${YANG_MODS:S/$/.yang/}

# make check's: the committed files are what the modules make now, by
# the generator of the cblink submodule (another may write them
# otherwise).
check-yang: .PHONY
	@t=$$(mktemp -d) && trap 'rm -rf "$$t"' EXIT && \
	    ${MAKE} -C ${.CURDIR} regen-yang YANG_OUT="$$t" >/dev/null && \
	    for f in ymodel.h ymodel_schema.c; do \
		cmp -s "$$t/$$f" ${.CURDIR}/yang/$$f || { echo \
		    "usr.sbin/arcana-agent: yang/$$f is not what make regen-yang makes" >&2; \
		    exit 1; }; \
	    done; \
	    echo "usr.sbin/arcana-agent: yang/ is what make regen-yang makes"

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "${CBLINK_MK}"
.include <bsd.prog.mk>
