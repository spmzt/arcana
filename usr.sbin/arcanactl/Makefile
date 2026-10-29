PROG=		arcanactl
SRCS=		arcanactl.c yjsonin.c yqueue.c ychange.c ystore.c ygula.c \
		yevjson.c ytshoot.c ytsjson.c yprobes.c yhostjson.c ysdwan.c \
		zprog.c
# RFC 7951's JSON in, arcana-jobs, arcana-storage, what runs and was
# written down, packets and paths followed, arcana-probe, the host and
# its agent, arcana-sdwan: the console's; a program compressed for
# agent-update: the agent's.
.PATH:		${.CURDIR}/../../www/arcana-console \
		${.CURDIR}/../arcana-agent/ira
MAN=		arcanactl.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

ARC_WIRE=	client
.include "${.CURDIR}/../../share/mk/arcana.wire.mk"
.include "${.CURDIR}/../../share/mk/arcana.yang.mk"

# A job-spec made the change arcana-jobs' submit takes, as the console's.
CLEANFILES+=	ychange.c ychange.c.tmp
ychange.c: ${ARC_TOP}/share/arcana/jobs.awk ${ARC_TOP}/share/arcana/jobs.yaml \
    ${ARC_TOP}/share/arcana/arcana.yaml arcana_v2.h ymodel.h
	awk -v out=ychange -f ${ARC_TOP}/share/arcana/jobs.awk \
	    ${ARC_TOP}/share/arcana/arcana.yaml \
	    ${ARC_TOP}/share/arcana/jobs.yaml ${.OBJDIR}/arcana_v2.h \
	    > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

CFLAGS+=	-I${.CURDIR}/../../www/arcana-console \
		-I${.CURDIR}/../arcana-agent/ira ${UCL_CFLAGS}
LDADD+=		-lxo -lmd -lcasper -lcap_fileargs -lnv -lz ${UCL_LIBS}

.include <bsd.prog.mk>
