# The standard models a program speaks over cblink's YANG family, family
# 1: ietf-interfaces and ietf-ip, with the IETF and IEEE modules that
# augment them and Arcana's augments and deviations, the FIBs as RFC
# 8529's network instances, the routes (RFC 8349) and the vnet jails as
# RFC 8530's logical network elements, their structs and schema tables
# written by cblink-gen at the build (ymodel.h, ymodel_schema.c); with
# ARC_YANG_SERVER=yes the server's handler table too (ymodel_server.c),
# whose handlers the program defines.
#
#	ARC_YANG_SERVER=	yes	(the agent)
#	.include "${.CURDIR}/../../share/mk/arcana.yang.mk"
#
# After arcana.wire.mk (cblink-gen, the YANG directories).

.if !target(__<arcana.yang.mk>__)
__<arcana.yang.mk>__:

# The modules, each with its .sid file in share/yang.
ARC_YMODS=	ietf-interfaces@2018-02-20 arcana-interfaces@2026-10-14 \
		ietf-if-extensions@2025-08-07 ietf-if-ethernet-like@2026-06-19 \
		ietf-if-vlan-encapsulation@2026-07-06 \
		ieee802-ethernet-interface@2025-09-10 \
		ieee802-dot1ax-linkagg@2025-09-30 ieee802-dot1q-bridge@2023-10-26 \
		ieee802-dot1q-rstp-bridge@2025-02-04 \
		arcana-ieee802-deviations@2026-10-14 \
		ietf-ip@2018-02-22 arcana-ip-deviations@2026-10-14 \
		iana-if-type@2026-03-17 ietf-yang-types@2025-12-22 \
		ietf-inet-types@2025-12-22 \
		ietf-network-instance@2019-01-21 \
		arcana-network-instance@2026-10-14 \
		ietf-routing@2018-03-13 ietf-ipv4-unicast-routing@2018-03-13 \
		ietf-ipv6-unicast-routing@2018-03-13 arcana-routing@2026-10-14 \
		ietf-logical-network-element@2019-01-25 \
		arcana-jails@2026-10-14 arcana-services@2026-10-14 \
		arcana-packages@2026-10-14 arcana-jobs@2026-10-14 \
		arcana-storage@2026-10-14 arcana-sysctl@2026-10-14 \
		arcana-kernel@2026-10-14 arcana-processes@2026-10-14 \
		arcana-log@2026-10-14 ietf-syslog@2025-04-30 \
		arcana-firewall@2026-10-15 arcana-troubleshoot@2026-10-15 \
		arcana-history@2026-10-15 arcana-events@2026-10-15 \
		arcana-bird@2026-10-15 arcana-wireguard@2026-10-15 \
		arcana-netgraph@2026-10-15 arcana-host@2026-10-15 \
		arcana-agent@2026-10-15 arcana-jail-files@2026-10-15 \
		arcana-probe@2026-10-15 arcana-sdwan@2026-10-15 \
		arcana-sshd@2026-10-15 arcana-builder@2026-10-17 \
		arcana-notify@2026-10-17 \
		ietf-yang-library@2019-01-04 ietf-datastores@2018-02-14 \
		ietf-alarms@2019-09-11 arcana-alarms@2026-10-27 \
		iana-hardware@2018-03-13 ietf-hardware@2018-03-13 \
		ietf-subscribed-notifications@2019-09-09 \
		ietf-yang-push@2019-09-09 ietf-netconf-acm@2018-02-14 \
		ietf-netconf@2011-06-01 ietf-origin@2018-02-14 \
		ietf-defaults@2024-04-03 ietf-yang-schema-mount@2019-01-14 \
		ietf-subscribed-notif-receivers@2026-06-30 \
		ietf-https-notif-transport@2026-06-30 arcana-notif@2026-10-28 \
		arcana-ra@2026-10-28 arcana-crashes@2026-10-29 \
		arcana-system@2026-10-29 arcana-netstore@2026-10-29 \
		arcana-suricata@2026-10-29 arcana-smtpd@2026-10-29 \
		arcana-speeder@2026-10-29 arcana-stream@2026-10-29 \
		arcana-network@2026-10-29
# Modules only imported whose identities are used: their .sid files
# alone (a VLAN tag's types, the PHY types, the port algorithms; the
# routing protocols', whose identities name a route's origin).
ARC_YIMPORTS=	ietf-ospf@2022-10-19 ietf-rip@2020-02-20 ietf-isis@2022-10-19 \
		ietf-babel@2024-10-10 ietf-bgp@2026-08-14 \
		ietf-bfd-types@2022-09-22 \
		ieee802-dot1q-types@2023-10-26 \
		ieee802-ethernet-phy-type@2025-09-10 \
		ieee802-dot1ax-types@2025-09-30 ietf-http-client@2024-08-15
ARC_YFEATS=	-F ietf-interfaces:if-mib,arbitrary-names -F arcana-interfaces: \
		-F ietf-if-extensions:max-frame-size,peer-interface,sub-interfaces \
		-F ietf-if-ethernet-like:configurable-mac-address \
		-F ietf-if-vlan-encapsulation: -F ieee802-ethernet-interface: \
		-F ieee802-dot1ax-linkagg: -F arcana-ieee802-deviations: \
		-F ieee802-dot1q-bridge: -F ieee802-dot1q-rstp-bridge: \
		-F ietf-ip:ipv6-privacy-autoconf -F arcana-ip-deviations: \
		-F iana-if-type: -F ietf-yang-types: -F ietf-inet-types: \
		-F ietf-network-instance: -F arcana-network-instance: \
		-F ietf-routing:multiple-ribs -F ietf-ipv4-unicast-routing: \
		-F ietf-ipv6-unicast-routing: -F arcana-routing: \
		-F ietf-logical-network-element: -F arcana-jails: \
		-F arcana-services: -F arcana-packages: -F arcana-jobs: \
		-F arcana-storage: -F arcana-sysctl: -F arcana-kernel: \
		-F arcana-processes: -F arcana-log: \
		-F ietf-syslog:console-action,file-action,file-limit-size,file-limit-duration,remote-action,select-adv-compare \
		-F arcana-firewall: -F arcana-troubleshoot: -F arcana-history: \
		-F arcana-events: -F arcana-bird: -F arcana-wireguard: \
		-F arcana-netgraph: -F arcana-host: -F arcana-agent: \
		-F arcana-jail-files: -F arcana-probe: -F arcana-sdwan: \
		-F arcana-sshd: -F arcana-builder: -F arcana-notify: \
		-F ietf-yang-library: -F ietf-datastores: \
		-F ietf-alarms:alarm-summary,alarm-history -F arcana-alarms: \
		-F iana-hardware: -F ietf-hardware:hardware-sensor \
		-F ietf-subscribed-notifications:configured,xpath,replay,subtree \
		-F ietf-yang-push:on-change \
		-F ietf-netconf-acm: -F ietf-netconf:candidate,confirmed-commit \
		-F ietf-origin: -F ietf-defaults: -F ietf-yang-schema-mount: \
		-F ietf-subscribed-notif-receivers: -F ietf-https-notif-transport: \
		-F arcana-notif: -F arcana-ra:

.if ${ARC_YANG_SERVER:Uno} == "yes"
_arc_yparts=	h,schema,server
# The modules imported only, name@revision by commas: ietf-yang-library's
# import-only-module list (the tables have the implemented ones alone).
CFLAGS+=	-DARC_YIMPORT_LIST=\"${ARC_YIMPORTS:ts,}\"
SRCS+=		ymodel_server.c
CLEANFILES+=	ymodel_server.c
ymodel_server.c: ymodel.h
.else
_arc_yparts=	h,schema
.endif
SRCS+=		ymodel.h ymodel_schema.c
CLEANFILES+=	ymodel.h ymodel_schema.c
ymodel_schema.c: ymodel.h
ymodel.h: ${ARC_YMODS:@m@${ARC_YANG_DIR}/${m}.yang ${ARC_YANG_DIR}/${m}.sid@} \
    ${ARC_YIMPORTS:@m@${ARC_YANG_DIR}/${m}.sid@} ${CBLINK_GEN} \
    ${.PARSEDIR}/arcana.yang.mk
	cd ${ARC_YANG_DIR} && ${CBLINK_GEN} -m ${_arc_yparts} -b ymodel \
	    -o ${.OBJDIR} ${ARC_YFEATS} \
	    ${ARC_YMODS:@m@-s ${m}.sid@} ${ARC_YIMPORTS:@m@-s ${m}.sid@} \
	    -p ${CBLINK_YANG_DIR} ${ARC_YMODS:S/$/.yang/} > /dev/null

.endif	# !target(__<arcana.yang.mk>__)
