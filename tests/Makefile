# The top of the installed test suite.

.include "${.CURDIR}/../share/mk/jailgrid.mk"

FILES=		Kyuafile
FILESDIR=	${TESTSBASE}/jailgrid

beforeinstall: .PHONY
	${INSTALL} -d ${DESTDIR}${FILESDIR}

.include <bsd.prog.mk>
