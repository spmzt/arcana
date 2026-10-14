.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/console
ATF_TESTS_C=	console_test \
		pwa_test \
		webpush_test \
		yaml_test

SRCS.console_test=	console_test.c harness.c
SRCS.pwa_test=		pwa_test.c harness.c
SRCS.webpush_test=	webpush_test.c webpush.c
# The panel's YAML, natively: base's libucl and libyaml.
SRCS.yaml_test=		yaml_test.c yaml.c
CFLAGS.yaml_test.c+=	-DDISTDIR='"${.OBJDIR}/../../arcana-ui/dist"'
CFLAGS.yaml.c+=		-I/usr/include/private/yaml
LDADD.yaml_test+=	-lprivateyaml
.PATH:			${.CURDIR}/.. ${.CURDIR}/../../arcana-ui/src

CFLAGS+=	${UCL_CFLAGS} ${SSL_CFLAGS} -DTESTSRC='"${.CURDIR}"'
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lcrypto -lm

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
