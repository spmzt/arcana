# arcana-console.so: the Kore module serving the console and its API.

SHLIB_NAME=	arcana-console.so
SRCS=		api.c auth.c config.c hosts.c pki.c push.c servers.c settings.c security.c troubleshoot.c \
		stream.c follow.c tokens.c transfers.c workflows.c sdwan.c sdwan_edge.c \
		store.c update.c webpush.c audit.c mail.c smtp.c templates.c
LIBDIR?=	${PREFIX}/lib/arcana
MAN=		arcana-console.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

CBLINK_SPECS=	${ARC_SPEC}
CBLINK_PARTS=	h,c,client

.if empty(KORE_FEATURES:M-DKORE_USE_TASKS)
.error Kore must be built with tasks (TASKS=1): KORE_FEATURES is "${KORE_FEATURES}"
.endif
CFLAGS+=	-I${KORE_INCLUDE} ${KORE_FEATURES} ${UCL_CFLAGS} ${SSL_CFLAGS}
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lssl -lcrypto -lfetch

# Configuration samples, the routes, and the rc.d(8) script.
FILESGROUPS+=	CONF RC
CONF=		conf/routes.conf conf/kore.conf.sample conf/web.conf.sample
CONFDIR=	${PREFIX}/etc/arcana
RC=		arcana_console.sh
RCDIR=		${PREFIX}/etc/rc.d
RCNAME=		arcana_console
RCMODE=		0555
CLEANFILES+=	arcana_console.sh
arcana_console.sh: conf/arcana_console.in
	sed -e 's|%%PREFIX%%|${PREFIX}|g' -e 's|%%LOCALBASE%%|${LOCALBASE}|g' \
	    ${.ALLSRC} > ${.TARGET}
beforeinstall: .PHONY
	${INSTALL} -d ${DESTDIR}${LIBDIR} ${DESTDIR}${CONFDIR}

# The kinds of job, as share/arcana/jobs.yaml says: a workflow's steps
# are checked against it, and it against arcana.yaml's job-kind and
# job-spec, which stops the build where they differ.
DPSRCS+=	jobs_table.h
CLEANFILES+=	jobs_table.h jobs_table.h.tmp
jobs_table.h: ${ARC_TOP}/share/arcana/jobs.yaml ${ARC_TOP}/share/arcana/jobs.awk \
    ${ARC_TOP}/share/arcana/arcana.yaml
	awk -v out=c -f ${ARC_TOP}/share/arcana/jobs.awk \
	    ${ARC_TOP}/share/arcana/arcana.yaml \
	    ${ARC_TOP}/share/arcana/jobs.yaml > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
workflows.pico workflows.o: jobs_table.h

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include "${CBLINK_MK}"
.include <bsd.lib.mk>
