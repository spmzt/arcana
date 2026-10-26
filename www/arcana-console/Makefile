# arcana-console: the console, its API and its pages, served on
# libwebsockets(3) (web.c).

PROG=		arcana-console
SRCS=		web.c keymgr.c routes.c api.c auth.c config.c hosts.c pki.c push.c servers.c settings.c security.c troubleshoot.c \
		stream.c follow.c tokens.c transfers.c workflows.c sdwan.c sdwan_edge.c \
		store.c update.c webpush.c audit.c mail.c templates.c ldap.c labels.c prefixlists.c users.c \
		craft.c nodes.c ytrans.c
BINDIR?=	${PREFIX}/sbin
MAN=		arcana-console.8

.include "${.CURDIR}/../../share/mk/arcana.mk"

# The consoles of a cluster to each other: a family served and asked
# both, apart from arcana.yaml's, of which the console is a client.
ARC_WIRE=	client
ARC_CLUSTER=	yes
.include "${.CURDIR}/../../share/mk/arcana.wire.mk"
# The standard models, asked of the agents by cblink's YANG family: the
# Network tab's interfaces (ytrans.c).
.include "${.CURDIR}/../../share/mk/arcana.yang.mk"

CFLAGS+=	${LWS_CFLAGS} ${UCL_CFLAGS} ${SSL_CFLAGS} \
		-DARCW_WEBROOT=\"${PREFIX}/www/arcana-console\" \
		-DARCW_CONF=\"${PREFIX}/etc/arcana/web.conf\"
LDADD+=		${LWS_LIBS} ${UCL_LIBS} ${SSL_LDFLAGS} -lssl -lcrypto -lfetch \
		-lcrypt -lutil -lm -lpthread

# The configuration's sample and the rc.d(8) script.
FILESGROUPS+=	CONF RC
CONF=		conf/web.conf.sample
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
	${INSTALL} -d ${DESTDIR}${BINDIR} ${DESTDIR}${CONFDIR}

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
workflows.o: jobs_table.h
# The parser of a job as the API takes it: the kinds' names and each
# field's member, from the same files.
DPSRCS+=	jobs_spec.h
CLEANFILES+=	jobs_spec.h jobs_spec.h.tmp
jobs_spec.h: ${ARC_TOP}/share/arcana/jobs.yaml ${ARC_TOP}/share/arcana/jobs.awk \
    ${ARC_TOP}/share/arcana/arcana.yaml
	awk -v out=spec -f ${ARC_TOP}/share/arcana/jobs.awk \
	    ${ARC_TOP}/share/arcana/arcana.yaml \
	    ${ARC_TOP}/share/arcana/jobs.yaml > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
hosts.o: jobs_spec.h

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
