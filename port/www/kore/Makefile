PORTNAME=	kore
DISTVERSION=	4.3.0
CATEGORIES=	www devel
MASTER_SITES=	https://kore.io/releases/

MAINTAINER=	pouria@FreeBSD.org
COMMENT=	Web application platform for writing scalable web APIs in C
WWW=		https://kore.io/

LICENSE=	ISCL
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		gmake ssl

# The kore binary bakes PREFIX in to find its share/kore; it builds as
# C99 with -Werror, and base's basename(3) is a C11 _Generic macro.
MAKE_ARGS=	OPENSSL_PATH=${OPENSSLBASE} \
		PREFIX=${PREFIX}
CFLAGS+=	-Wno-c11-extensions

OPTIONS_DEFINE=		ACME CURL DEBUG JSONRPC PGSQL TASKS
OPTIONS_DEFAULT=	TASKS

ACME_DESC=	Let's Encrypt certificates through ACME (implies CURL)
ACME_IMPLIES=	CURL
ACME_MAKE_ARGS=	ACME=1
CURL_DESC=	Asynchronous HTTP client through libcurl
CURL_LIB_DEPENDS=	libcurl.so:ftp/curl
CURL_MAKE_ARGS=	CURL=1
DEBUG_MAKE_ARGS=	DEBUG=1
JSONRPC_DESC=	JSON-RPC support through yajl
JSONRPC_LIB_DEPENDS=	libyajl.so:devel/yajl
JSONRPC_MAKE_ARGS=	JSONRPC=1
PGSQL_USES=	pgsql
PGSQL_MAKE_ARGS=	PGSQL=1
TASKS_DESC=	Background tasks on threads (needed by sysutils/jailgrid)
TASKS_MAKE_ARGS=	TASKS=1

post-install:
	${STRIP_CMD} ${STAGEDIR}${PREFIX}/bin/kore ${STAGEDIR}${PREFIX}/bin/kodev

.include <bsd.port.mk>
