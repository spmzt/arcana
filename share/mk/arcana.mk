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
# arcanactl), with no need for libwebsockets or emcc.
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

# cblink: the transport between arcana-agent and its clients.  It comes
# with the tree as the submodule cblink/ (git submodule update --init):
# the top-level make builds it first, in its own object directory, and
# the programs use it from there, finding libcblink.so by an rpath, so
# nothing of it need be installed to build or to test; make install
# installs it with the rest.  Without the submodule (a release tarball,
# the port) an installed cblink is used, devel/cblink's at CBLINK_PREFIX.
.if !defined(CBLINK_PREFIX) && exists(${ARC_TOP}/cblink/share/cblink/cblink.mk)
CBLINK_SUBMODULE=	yes
.if defined(MAKEOBJDIRPREFIX)
CBLINK_OBJ?=	${MAKEOBJDIRPREFIX}${ARC_TOP}/cblink
.else
CBLINK_OBJ?=	${ARC_TOP}/cblink/obj
.endif
CBLINK_MK?=	${ARC_TOP}/cblink/share/cblink/cblink.mk
CBLINK_GEN?=	${CBLINK_OBJ}/usr.bin/cblink-gen/cblink-gen
CBLINK_CFLAGS?=	-I${ARC_TOP}/cblink/lib/libcblink
.if defined(CBLINK_STATIC)
# A program shipped to other hosts (the agent, by agent-update) carries
# its own libcblink, the submodule's: a host's may be older, and the
# program would not run there.  libcbor and OpenSSL stay shared.
CBLINK_LIBS?=	${CBLINK_OBJ}/lib/libcblink/libcblink_pic.a \
		${LOCALBASE}/lib/libcbor.so -lssl -lcrypto -lm
DPADD+=		${CBLINK_OBJ}/lib/libcblink/libcblink_pic.a
.else
CBLINK_LIBS?=	-L${CBLINK_OBJ}/lib/libcblink -lcblink
LDFLAGS+=	-Wl,-rpath,${CBLINK_OBJ}/lib/libcblink
.endif
.else
CBLINK_SUBMODULE=	no
CBLINK_PREFIX?=	${LOCALBASE}
CBLINK_MK?=	${CBLINK_PREFIX}/share/cblink/cblink.mk
.if !exists(${CBLINK_MK})
.error cblink is not at CBLINK_PREFIX=${CBLINK_PREFIX} (no ${CBLINK_MK}): \
check out the submodule (git submodule update --init), install \
devel/cblink, or set CBLINK_PREFIX in ${ARC_TOP}/config.mk, where \
the top of the tree is $${ARC_TOP}
.endif
CBLINK_GEN?=	${CBLINK_PREFIX}/bin/cblink-gen
CBLINK_CFLAGS?=	-I${CBLINK_PREFIX}/include
CBLINK_LIBS?=	-L${CBLINK_PREFIX}/lib -lcblink
.endif

# libwebsockets(3), the console's HTTP server (net/libwebsockets).
LWS_CFLAGS?=	-I${LOCALBASE}/include
LWS_LIBS?=	-L${LOCALBASE}/lib -lwebsockets

# The C libraries the console's page compiles to WebAssembly: their
# sources, not a built library, the system's (pkgbase's FreeBSD-src
# installs them); LIBUCL_SRC and LIBYAML_SRC name other trees.
LIBUCL_SRC?=	/usr/src/contrib/libucl
LIBYAML_SRC?=	/usr/src/contrib/libyaml

# The map's WebGPU, emscripten's emdawnwebgpu port: Dawn's package, the
# release emscripten pins, which "make depends" fetches into
# ${EMDAWN_DIR} (or takes from the zip put there by hand), so that the
# build itself fetches nothing.  EMDAWN names its port file;
# EMDAWN=emdawnwebgpu has emcc fetch it instead, at build time.
EMDAWN_V=	v20260423.175430
EMDAWN_SHA512=	42784f70b67197c614322f9fabb0f1dc64228a0de10e88f99941fa9d29bee9ad6683f4651d4eefd5a7a9fbd1f976eb522b190b683219ed1793e9b531c602ffa6
EMDAWN_ZIP=	emdawnwebgpu_pkg-${EMDAWN_V}.zip
EMDAWN_URL=	https://github.com/google/dawn/releases/download/${EMDAWN_V}/${EMDAWN_ZIP}
EMDAWN_DIR?=	${ARC_TOP}/build/emdawnwebgpu
EMDAWN?=	${EMDAWN_DIR}/emdawnwebgpu_pkg/emdawnwebgpu.port.py

# OpenSSL's libcrypto, for WebAuthn signatures: base's unless these name
# another one, which must be the one libwebsockets uses.
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
