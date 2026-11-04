.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/console
ATF_TESTS_C=	console_test \
		pwa_test \
		raft_test \
		webpush_test \
		yaml_test \
		yxlate_test

# The page's YANG-CBOR reader, for the pass-through's case.
SRCS.console_test=	console_test.c harness.c ycbor.c
SRCS.pwa_test=		pwa_test.c harness.c
SRCS.webpush_test=	webpush_test.c webpush.c
SRCS.raft_test=		raft_test.c craft.c
# The panel's YAML, natively: base's libucl and libyaml.
SRCS.yaml_test=		yaml_test.c yaml.c
CFLAGS.yaml_test.c+=	-DDISTDIR='"${.OBJDIR}/../../arcana-ui/dist"'
CFLAGS.yaml_test.c+=	-DOPENAPI='"${.CURDIR}/../../../docs/openapi.yaml"'
CFLAGS.yaml.c+=		-I/usr/include/private/yaml
LDADD.yaml_test+=	-lprivateyaml
.PATH:			${.CURDIR}/.. ${.CURDIR}/../../arcana-ui/src

# The translator (yxlate.c, ysid.c) over RFC 7951's and RFC 7952's
# example modules (yang/), their tables written by cblink-gen here.
SRCS.yxlate_test=	yxlate_test.c ysid.c yxlate.c yxtest_schema.c
_yx_mods=	example-foomod@2026-11-05 example-barmod@2026-11-05 \
		example-last-modified@2026-11-05
DPSRCS+=	yxtest.h
CLEANFILES+=	yxtest.h yxtest_schema.c
yxtest_schema.c: yxtest.h
yxtest.h: ${_yx_mods:@m@${.CURDIR}/yang/${m}.yang ${.CURDIR}/yang/${m}.sid@} \
    ${CBLINK_GEN}
	cd ${.CURDIR}/yang && ${CBLINK_GEN} -m h,schema -b yxtest \
	    -o ${.OBJDIR} ${_yx_mods:@m@-s ${m}.sid@} \
	    -s ${ARC_TOP}/share/yang/ietf-yang-types@2025-12-22.sid \
	    -p ${ARC_TOP}/share/yang -p ${ARC_TOP}/cblink/share/yang \
	    ${_yx_mods:S/$/.yang/} > /dev/null
yxlate_test.o ysid.o yxlate.o: yxtest.h
CFLAGS.yxlate_test.c+=	-I${.OBJDIR} -I${.CURDIR}/.. -DYXDIR='"${.CURDIR}/yang"'
LDADD.yxlate_test+=	${CBLINK_LIBS}

CFLAGS+=	${UCL_CFLAGS} ${SSL_CFLAGS} ${CBLINK_CFLAGS} -DTESTSRC='"${.CURDIR}"'
# pwa_mapgpu: the page's WebGPU backend, built only WITH_WEBGPU.
.if ${MK_WEBGPU} != "no"
CFLAGS.pwa_test.c+=	-DARC_WEBGPU
.endif
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lcrypto -lm

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
