# Common settings, included by every Makefile in the tree:
#
#	.include "${.CURDIR}/<path to top>/share/mk/jailgrid.mk"

.if !target(__<jailgrid.mk>__)
__<jailgrid.mk>__:

JG_TOP:=	${.PARSEDIR:tA:H:H}

# Build products go to ${JG_TOP}/obj, mirroring the tree, unless
# MAKEOBJDIRPREFIX or MAKEOBJDIR in the environment says where else.
.if !defined(MAKEOBJDIRPREFIX) && !defined(MAKEOBJDIR)
.if ${.CURDIR:tA} == ${JG_TOP}
JG_OBJDIR=	${JG_TOP}/obj
.else
JG_OBJDIR=	${JG_TOP}/obj/${.CURDIR:tA:S,^${JG_TOP}/,,}
.endif
.if ${.OBJDIR:tA} != ${JG_OBJDIR}
__objdir!=	mkdir -p ${JG_OBJDIR} && echo ${JG_OBJDIR}
.OBJDIR:	${JG_OBJDIR}
.endif
.endif

.include <bsd.opts.mk>

# WITHOUT_CONSOLE builds only what a jail host runs (jailgridd, jailconf,
# jailgridctl), with no need for Kore or emcc.
__DEFAULT_YES_OPTIONS=	CONSOLE
.include <bsd.mkopt.mk>

# Per-machine overrides (linker, where cblink lives); see config.mk.sample.
.sinclude "${JG_TOP}/config.mk"

PREFIX?=	/usr/local
LOCALBASE?=	/usr/local
BINDIR?=	${PREFIX}/sbin
MANDIR?=	${PREFIX}/share/man/man
TESTSBASE?=	${PREFIX}/tests

CSTD?=		c17
WARNS?=		6

# cblink: the transport between jailgridd and its clients.
CBLINK_PREFIX?=	${LOCALBASE}
CBLINK_MK?=	${CBLINK_PREFIX}/share/cblink/cblink.mk
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

# The family spec shared by jailgridd, jailgridctl and the web backend.
JG_SPEC=	${JG_TOP}/share/jailgrid/jailgrid.yaml

# libjailconf, built in lib/libjailconf.
JAILCONF_CFLAGS=	-I${JG_TOP}/lib/libjailconf

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
