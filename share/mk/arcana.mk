# Common settings, included by every Makefile in the tree:
#
#	.include "${.CURDIR}/<path to top>/share/mk/arcana.mk"

.if !target(__<arcana.mk>__)
__<arcana.mk>__:

ARC_TOP:=	${.PARSEDIR:tA:H:H}

# Build products go to ${ARC_TOP}/obj, mirroring the tree, unless
# MAKEOBJDIRPREFIX or MAKEOBJDIR in the environment says where else.
.if !defined(MAKEOBJDIRPREFIX) && !defined(MAKEOBJDIR)
.if ${.CURDIR:tA} == ${ARC_TOP}
ARC_OBJDIR=	${ARC_TOP}/obj
.else
ARC_OBJDIR=	${ARC_TOP}/obj/${.CURDIR:tA:S,^${ARC_TOP}/,,}
.endif
.if ${.OBJDIR:tA} != ${ARC_OBJDIR}
__objdir!=	mkdir -p ${ARC_OBJDIR} && echo ${ARC_OBJDIR}
.OBJDIR:	${ARC_OBJDIR}
.endif
.endif

.include <bsd.opts.mk>

# WITHOUT_CONSOLE builds only what a jail host runs (arcana-agent, jailconf,
# arcanactl), with no need for Kore or emcc.
__DEFAULT_YES_OPTIONS=	CONSOLE
.include <bsd.mkopt.mk>

# Per-machine overrides (linker, where cblink lives); see config.mk.sample.
.sinclude "${ARC_TOP}/config.mk"

PREFIX?=	/usr/local
LOCALBASE?=	/usr/local
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/share/man/man
TESTSBASE?=	${PREFIX}/tests

CSTD?=		c17
WARNS?=		6

# cblink: the transport between arcana-agent and its clients.
CBLINK_PREFIX?=	${LOCALBASE}
CBLINK_MK?=	${CBLINK_PREFIX}/share/cblink/cblink.mk
.if !exists(${CBLINK_MK})
.error cblink is not at CBLINK_PREFIX=${CBLINK_PREFIX} (no ${CBLINK_MK}): \
install devel/cblink, or set CBLINK_PREFIX in ${ARC_TOP}/config.mk, \
where the top of the tree is $${ARC_TOP}
.endif
CBLINK_GEN?=	${CBLINK_PREFIX}/bin/cblink-gen
CBLINK_CFLAGS?=	-I${CBLINK_PREFIX}/include
CBLINK_LIBS?=	-L${CBLINK_PREFIX}/lib -lcblink

# Kore, for the web console module: its headers and the feature flags it
# was built with, which change struct layouts; an installed Kore records
# them in share/kore/features.
KORE_INCLUDE?=	${LOCALBASE}/include
KORE_SHARE?=	${LOCALBASE}/share/kore
.if !defined(KORE_FEATURES) && exists(${KORE_SHARE}/features)
KORE_FEATURES!=	cat ${KORE_SHARE}/features
.endif
KORE_FEATURES?=	-DTLS_BACKEND_OPENSSL -DKORE_USE_TASKS
KORE_BIN?=	${LOCALBASE}/bin/kore
KORE_DHPARAM?=	${KORE_SHARE}/ffdhe4096.pem

# OpenSSL's libcrypto, for WebAuthn signatures: base's unless these name
# another one, which must be the one Kore uses.
SSL_CFLAGS?=
SSL_LDFLAGS?=

# libucl from base, private but installed with its header.
UCL_CFLAGS=	-I/usr/include/private/ucl
UCL_LIBS=	-lprivateucl

# The family spec shared by arcana-agent, arcanactl and the web backend.
ARC_SPEC=	${ARC_TOP}/share/arcana/arcana.yaml

# libjailconf, built in lib/libjailconf.
JAILCONF_CFLAGS=	-I${ARC_TOP}/lib/libjailconf

# No mtree(8) hierarchy outside the source tree: make the directories
# before installing.
jg-dirs: .PHONY
	${INSTALL} -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}8 \
	    ${DESTDIR}${PREFIX}/etc/rc.d
beforeinstall: jg-dirs

# The files and directories FILESGROUPS install belong to root unless
# told otherwise; follow SHAREOWN, which an unprivileged staging sets.
.for _d in CONFDIR RCDIR
${_d}_OWN?=	${SHAREOWN}
${_d}_GRP?=	${SHAREGRP}
.endfor
.for _g in CONF RC
${_g}OWN?=	${SHAREOWN}
${_g}GRP?=	${SHAREGRP}
.endfor

# atf.test.mk only knows LDADD_atf_c inside the source tree; base ships
# atf-c as a private library with its header in /usr/include.
LDADD_atf_c=	-lprivateatf-c

.endif
