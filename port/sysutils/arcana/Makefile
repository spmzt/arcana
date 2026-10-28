PORTNAME=	arcana
DISTVERSIONPREFIX=	v
DISTVERSION=	0.95.0
CATEGORIES=	sysutils www

MAINTAINER=	pouria@FreeBSD.org
COMMENT=	Agent and web console for a fleet of FreeBSD hosts
WWW=		https://github.com/spmzt/arcana

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

BUILD_DEPENDS=	cblink-gen:devel/cblink
LIB_DEPENDS=	libcblink.so:devel/cblink

USES=		uidfix

USE_GITHUB=	yes
GH_ACCOUNT=	spmzt
GH_PROJECT=	arcana

MAKE_ARGS=	LOCALBASE=${LOCALBASE} \
		PREFIX=${PREFIX} \
		WWWDIR=${WWWDIR}
# The test suite is built only by "make test".
MAKE_ENV=	WITHOUT_DEBUG_FILES=yes \
		WITHOUT_TESTS=yes

OPTIONS_DEFINE=		CONSOLE
OPTIONS_DEFAULT=	CONSOLE
OPTIONS_SUB=		yes

CONSOLE_DESC=	Web console: its server and the PWA (else only the jail host's programs)
# The console's HTTP server is on libwebsockets; the PWA compiles libucl
# and libyaml, the releases base imports, to wasm: their sources, as
# /usr/src has them, fetched here (a package build has no /usr/src).
CONSOLE_BUILD_DEPENDS=	emcc:devel/emscripten
# The map's WebGPU is emscripten's emdawnwebgpu port, its package taken
# here so that the build fetches nothing.
EMDAWN_V=		v20260423.175430
CONSOLE_MASTER_SITES=	https://github.com/google/dawn/releases/download/${EMDAWN_V}/:dawn
CONSOLE_DISTFILES=	emdawnwebgpu_pkg-${EMDAWN_V}.zip:dawn
CONSOLE_LIB_DEPENDS=	libwebsockets.so:net/libwebsockets
CONSOLE_USES=		ssl
CONSOLE_GH_TUPLE=	vstakhov:libucl:0.9.4:libucl/libucl \
			yaml:libyaml:0.2.5:libyaml/libyaml
# arcana-console's libcrypto must be the one libwebsockets uses.
CONSOLE_MAKE_ARGS=	LIBUCL_SRC=${WRKSRC_libucl} \
			LIBYAML_SRC=${WRKSRC_libyaml} \
			SSL_CFLAGS="-I${OPENSSLINC}" \
			SSL_LDFLAGS="-L${OPENSSLLIB}" \
			EMDAWN=${WRKDIR}/emdawnwebgpu_pkg/emdawnwebgpu.port.py
CONSOLE_MAKE_ENV_OFF=	WITHOUT_CONSOLE=yes

SUB_FILES=	pkg-message

# Build everything with the tests and run them with kyua(1) in the build
# tree, as "make check" does.  Cases needing root, or Chromium for the
# PWA, are skipped without them.
do-test:
	cd ${WRKSRC} && ${SETENV} ${MAKE_ENV:NWITHOUT_TESTS=*} ${MAKE_CMD} \
	    ${MAKE_ARGS} check

.include <bsd.port.pre.mk>

# FreeBSD 16.0 and later alone (16-CURRENT among them).
.if ${OSVERSION} < 1600000
IGNORE=		needs FreeBSD 16.0 or later
.endif

.include <bsd.port.post.mk>
