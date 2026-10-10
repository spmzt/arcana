PORTNAME=	arcana
DISTVERSIONPREFIX=	v
DISTVERSION=	0.86.0
CATEGORIES=	sysutils www

MAINTAINER=	pouria@FreeBSD.org
COMMENT=	Agent and web console for a fleet of FreeBSD hosts
WWW=		https://github.com/spmzt/arcana

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

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

CONSOLE_DESC=	Web console: Kore module and PWA (else only the jail host's programs)
# Kore's headers and its record of the features it was built with; the
# PWA compiles libucl, the release base imports, to wasm.
CONSOLE_BUILD_DEPENDS=	${LOCALBASE}/share/kore/features:www/kore \
			emcc:devel/emscripten
CONSOLE_RUN_DEPENDS=	kore:www/kore
CONSOLE_TEST_DEPENDS=	kore:www/kore
CONSOLE_USES=		ssl
CONSOLE_GH_TUPLE=	vstakhov:libucl:0.9.4:libucl/libucl
# arcana-console.so's libcrypto must be the one Kore uses.
CONSOLE_MAKE_ARGS=	LIBUCL_SRC=${WRKSRC_libucl} \
			SSL_CFLAGS="-I${OPENSSLINC}" \
			SSL_LDFLAGS="-L${OPENSSLLIB}"
CONSOLE_MAKE_ENV_OFF=	WITHOUT_CONSOLE=yes

SUB_FILES=	pkg-message

# Build everything with the tests and run them with kyua(1) in the build
# tree, as "make check" does.  Cases needing root, or Chromium for the
# PWA, are skipped without them.
do-test:
	cd ${WRKSRC} && ${SETENV} ${MAKE_ENV:NWITHOUT_TESTS=*} ${MAKE_CMD} \
	    ${MAKE_ARGS} check

.include <bsd.port.mk>
