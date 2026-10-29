# What the programs keep for their own use (a jail, a service, a job
# and its change): the YANG module written from share/arcana/arcana.yaml
# (share/yang/arcana@<rev>.yang, its SIDs beside it), the structs and
# schema tables cblink-gen writes from it (arcana_v2.h,
# arcana_v2_schema.c) and the programs' names for them and the
# definitions (arcana.h, written by share/arcana/wire.awk).  No family
# of it is spoken: the agent's are YANG's and its own streams'.
#
#	ARC_CLUSTER=	yes	the console's own family (cluster.h,
#				cluster_wire.c, from cluster.yaml)
#	.include "${.CURDIR}/../../share/mk/arcana.wire.mk"
#
# After arcana.mk.  Includes cblink.mk for the library's flags.

.if !target(__<arcana.wire.mk>__)
__<arcana.wire.mk>__:

ARC_WIRE_AWK=	${ARC_TOP}/share/arcana/wire.awk
ARC_CLUSTER_SPEC= ${ARC_TOP}/share/arcana/cluster.yaml
ARC_YANG_REV?=	2026-10-22
ARC_YANG_DIR=	${ARC_TOP}/share/yang
ARC_YANG=	${ARC_YANG_DIR}/arcana@${ARC_YANG_REV}.yang
ARC_SIDS=	${ARC_YANG_DIR}/arcana@${ARC_YANG_REV}.sid
ARC_CLUSTER_YANG= ${ARC_YANG_DIR}/arcana-cluster@${ARC_YANG_REV}.yang
ARC_CLUSTER_SIDS= ${ARC_YANG_DIR}/arcana-cluster@${ARC_YANG_REV}.sid
# cblink's own modules (cblink-gen.yang, cg:struct): the submodule's, or
# the installed cblink's.
.if ${CBLINK_SUBMODULE} == "yes"
CBLINK_YANG_DIR?= ${ARC_TOP}/cblink/share/yang
.else
CBLINK_YANG_DIR?= ${CBLINK_PREFIX}/share/cblink/yang
.endif

_arc_mods=	${ARC_YANG}
_arc_sids=	-s ${ARC_SIDS}
.if ${ARC_CLUSTER:Uno} == "yes"
_arc_mods+=	${ARC_CLUSTER_YANG}
_arc_sids+=	-s ${ARC_CLUSTER_SIDS}
.endif

SRCS+=		arcana_v2.h arcana_v2_schema.c arcana.h
CLEANFILES+=	arcana_v2.h arcana_v2_schema.c arcana.h arcana.h.tmp
# One generator run makes the header and the tables: the header stands
# for both.
arcana_v2_schema.c: arcana_v2.h
arcana_v2.h: ${_arc_mods} ${ARC_SIDS} ${CBLINK_GEN}
	${CBLINK_GEN} -m h,schema -b arcana_v2 -o ${.OBJDIR} ${_arc_sids} \
	    -p ${ARC_YANG_DIR} -p ${CBLINK_YANG_DIR} ${_arc_mods} > /dev/null
arcana.h: ${ARC_SPEC} ${ARC_WIRE_AWK} arcana_v2.h
	awk -v out=h -v base=arcana_v2 -f ${ARC_WIRE_AWK} ${ARC_SPEC} \
	    > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

.if ${ARC_CLUSTER:Uno} == "yes"
SRCS+=		cluster.h cluster_wire.c
CLEANFILES+=	cluster.h cluster.h.tmp cluster_wire.c cluster_wire.c.tmp
cluster.h: ${ARC_CLUSTER_SPEC} ${ARC_WIRE_AWK} arcana_v2.h
	awk -v out=h -v base=arcana_v2 -f ${ARC_WIRE_AWK} ${ARC_CLUSTER_SPEC} \
	    > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
cluster_wire.c: ${ARC_CLUSTER_SPEC} ${ARC_WIRE_AWK} cluster.h
	awk -v out=c -v side=both -v hdrname=cluster -f ${ARC_WIRE_AWK} \
	    ${ARC_CLUSTER_SPEC} > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
.endif

.include "${CBLINK_MK}"

.endif	# !target(__<arcana.wire.mk>__)
