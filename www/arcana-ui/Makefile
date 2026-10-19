# The console's web application: C compiled to WebAssembly with emcc(1),
# plus its static files, written to ${.OBJDIR}/dist.
#
#	make && make install [DESTDIR=dir] [WWWDIR=/usr/local/www/arcana-console]

.include "${.CURDIR}/../../share/mk/arcana.mk"

EMCC?=		emcc
# JSON: base's libucl, compiled to wasm from the source tree.
LIBUCL_SRC?=	/usr/src/contrib/libucl
# YAML: base's libyaml (its private library's source), the same way.
LIBYAML_SRC?=	/usr/src/contrib/libyaml
# emcc links at -O2 and above only with its JS optimizer's npm modules
# (acorn); the FreeBSD package lacks them.  The C is -O2 either way.
EMLDOPT?=	-O1
WWWDIR?=	${PREFIX}/www/arcana-console

DIST=		${.OBJDIR}/dist

APP_SRCS=	cluster.c users.c pfxlists.c iflabels.c templates.c main.c actions.c ca.c carp.c api.c apidoc.c bird.c ecmp.c mtr.c fleet.c ipfw.c l2.c kernel.c storage.c sysctl.c procs.c logs.c usage.c tbl.c topo.c vpn.c jailmk.c certs.c sshd.c span.c ipsec.c workflow.c sdwan.c graph.c html.c json.c netview.c \
		schema.c view.c live.c yaml.c export.c hostconf.c trouble.c routing.c birdform.c help.c secpage.c surules.c idsown.c idsstats.c builder.c
UCL_SRCS=	ucl_emitter_streamline.c ucl_emitter_utils.c ucl_emitter.c \
		ucl_hash.c ucl_msgpack.c ucl_parser.c ucl_schema.c ucl_sexp.c \
		ucl_util.c
YAML_SRCS=	api.c dumper.c emitter.c loader.c parser.c reader.c scanner.c \
		writer.c

# -Werror covers emcc's own warnings too: the emscripten package can
# expect another LLVM major than the llvm-devel it depends on, and only
# a clean cache (a port build, a container) runs that check.
EMCFLAGS=	-O2 -std=gnu17 -Wall -Wextra -Wno-unused-parameter \
		-Werror -Wno-version-check -I${LIBUCL_SRC}/include \
		-I${LIBYAML_SRC}/include \
		-I${.CURDIR}/vendor/qrcodegen
UCLFLAGS=	-O2 -w -I${LIBUCL_SRC}/include -I${LIBUCL_SRC}/src \
		-I${LIBUCL_SRC}/uthash -I${LIBUCL_SRC}/klib
EMLDFLAGS=	-sENVIRONMENT=web \
		-sDYNAMIC_EXECUTION=0 \
		-sALLOW_MEMORY_GROWTH=1 \
		-sSTACK_SIZE=524288 \
		-sEXPORTED_FUNCTIONS=_main,_malloc,_free,_arc_on_action,_arc_on_http,_arc_on_webauthn,_arc_on_net,_arc_on_visible \
		--js-library ${.CURDIR}/js/bridge.js

FONTS=		jetbrains-mono-latin-400-normal.woff2 \
		jetbrains-mono-latin-500-normal.woff2 \
		jetbrains-mono-latin-700-normal.woff2 \
		orbitron-latin-700-normal.woff2
ICONS=		icon.svg icon-192.png icon-512.png icon-maskable-512.png
STATIC=		index.html style.css manifest.webmanifest fx.js

# Objects by their full path, so none is picked up from the source
# directory through .PATH.
OBJS=
.for _s in ${APP_SRCS}
OBJS+=		${.OBJDIR}/${_s:R}.wo
${.OBJDIR}/${_s:R}.wo: ${.CURDIR}/src/${_s} ${.CURDIR}/src/app.h
	${EMCC} ${EMCFLAGS} -c ${.CURDIR}/src/${_s} -o ${.TARGET}
.endfor
.for _s in ${UCL_SRCS}
OBJS+=		${.OBJDIR}/${_s:R}.wo
${.OBJDIR}/${_s:R}.wo: ${LIBUCL_SRC}/src/${_s}
	${EMCC} ${UCLFLAGS} -c ${LIBUCL_SRC}/src/${_s} -o ${.TARGET}
.endfor
# libyaml's api.c and the panel's would have one object: its are
# yaml-*.wo.  The defines are lib/libyaml's.
YAMLFLAGS=	-O2 -w -I${LIBYAML_SRC}/include -I${LIBYAML_SRC}/src \
		-DYAML_VERSION_STRING=\"0.2.5\" -DYAML_VERSION_MAJOR=0 \
		-DYAML_VERSION_MINOR=2 -DYAML_VERSION_PATCH=5
.for _s in ${YAML_SRCS}
OBJS+=		${.OBJDIR}/yaml-${_s:R}.wo
${.OBJDIR}/yaml-${_s:R}.wo: ${LIBYAML_SRC}/src/${_s}
	${EMCC} ${YAMLFLAGS} -c ${LIBYAML_SRC}/src/${_s} -o ${.TARGET}
.endfor

# Project Nayuki's QR code generator, unmodified (vendor/README).
OBJS+=		${.OBJDIR}/qrcodegen.wo
${.OBJDIR}/qrcodegen.wo: ${.CURDIR}/vendor/qrcodegen/qrcodegen.c
	${EMCC} -O2 -std=gnu17 -w -c ${.CURDIR}/vendor/qrcodegen/qrcodegen.c \
	    -o ${.TARGET}

all: ${DIST}/sw.js

${DIST}/arcana.js: ${OBJS} ${.CURDIR}/js/bridge.js
	mkdir -p ${DIST}
	${EMCC} ${EMLDOPT} ${EMLDFLAGS} ${OBJS} -o ${.TARGET}

# The icon, drawn by a small native program.
MKICON=		${.OBJDIR}/mkicon
${MKICON}: ${.CURDIR}/tools/mkicon.c
	${CC} -O2 ${LDFLAGS} -o ${.TARGET} ${.CURDIR}/tools/mkicon.c -lz -lm

${DIST}/icons/icon-192.png: ${MKICON}
	mkdir -p ${DIST}/icons
	${MKICON} 192 ${.TARGET}
${DIST}/icons/icon-512.png: ${MKICON}
	mkdir -p ${DIST}/icons
	${MKICON} 512 ${.TARGET}
${DIST}/icons/icon-maskable-512.png: ${MKICON}
	mkdir -p ${DIST}/icons
	${MKICON} -m 512 ${.TARGET}

# The family's schema, shown beside an operation: cblink-gen's reference
# for share/arcana/arcana.yaml, as JSON.
# The kinds of job, for the workflows' forms: share/arcana/jobs.yaml.
${DIST}/jobs.json: ${ARC_TOP}/share/arcana/jobs.yaml \
    ${ARC_TOP}/share/arcana/jobs.awk ${ARC_TOP}/share/arcana/arcana.yaml
	mkdir -p ${DIST}
	awk -v out=json -f ${ARC_TOP}/share/arcana/jobs.awk \
	    ${ARC_TOP}/share/arcana/arcana.yaml \
	    ${ARC_TOP}/share/arcana/jobs.yaml > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}

${DIST}/schema.json: ${ARC_TOP}/share/arcana/arcana.yaml \
    ${.CURDIR}/tools/schema.awk
	mkdir -p ${DIST}
	${CBLINK_GEN} -m md -o ${.OBJDIR} ${ARC_TOP}/share/arcana/arcana.yaml
	awk -f ${.CURDIR}/tools/schema.awk ${.OBJDIR}/arcana.md > ${.TARGET}

# The YANG model of each operation converted to YANG (share/arcana/
# yang-ops), shown beside its CBOR schema: the module's RFC 8340 tree.
# The trees are committed in yang/, as the agent's tables are: building
# needs no libyang, only "make regen-yang" does, and make check fails
# when they are not what it makes.
YANG_TREES!=	ls ${.CURDIR}/yang/*.tree 2>/dev/null || true
${DIST}/yang.json: ${ARC_TOP}/share/arcana/yang-ops ${.CURDIR}/tools/yang.sh \
    ${YANG_TREES}
	mkdir -p ${DIST}
	sh ${.CURDIR}/tools/yang.sh json ${ARC_TOP}/share/arcana/yang-ops \
	    ${.CURDIR}/yang > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
YANG_OUT?=	${.CURDIR}/yang
regen-yang: .PHONY
	sh ${.CURDIR}/tools/yang.sh trees ${CBLINK_GEN} ${ARC_TOP}/share/yang \
	    ${ARC_TOP}/share/arcana/yang-ops ${YANG_OUT}
check-yang: .PHONY
	@t=$$(mktemp -d) && trap 'rm -rf "$$t"' EXIT && \
	    ${MAKE} -C ${.CURDIR} regen-yang YANG_OUT="$$t" >/dev/null && \
	    for f in $$(cd "$$t" && ls); do \
		cmp -s "$$t/$$f" ${.CURDIR}/yang/$$f || { echo \
		    "www/arcana-ui: yang/$$f is not what make regen-yang makes" >&2; \
		    exit 1; }; \
	    done; \
	    echo "www/arcana-ui: yang/ is what make regen-yang makes"

# The console's API as it is documented, for the API page: the document
# itself, and what the page shows of it.
${DIST}/openapi.yaml: ${ARC_TOP}/docs/openapi.yaml
	mkdir -p ${DIST}
	cp ${ARC_TOP}/docs/openapi.yaml ${.TARGET}
${DIST}/openapi.json: ${ARC_TOP}/docs/openapi.yaml \
    ${.CURDIR}/tools/openapi.awk
	mkdir -p ${DIST}
	awk -f ${.CURDIR}/tools/openapi.awk ${ARC_TOP}/docs/openapi.yaml > \
	    ${.TARGET}

SHELL_FILES=	${STATIC:S,^,${DIST}/,} ${DIST}/arcana.js ${DIST}/schema.json \
		${DIST}/yang.json ${DIST}/jobs.json \
		${DIST}/openapi.json ${DIST}/openapi.yaml \
		${DIST}/morphdom-umd.min.js ${FONTS:S,^,${DIST}/fonts/,} \
		${ICONS:S,^,${DIST}/icons/,}

${STATIC:S,^,${DIST}/,}: ${STATIC:S,^,${.CURDIR}/web/,}
	mkdir -p ${DIST}
	cp ${.CURDIR}/web/${.TARGET:T} ${.TARGET}
${DIST}/morphdom-umd.min.js: ${.CURDIR}/vendor/morphdom/morphdom-umd.min.js
	cp ${.ALLSRC} ${.TARGET}
${FONTS:S,^,${DIST}/fonts/,}:
	mkdir -p ${DIST}/fonts
	cp ${.CURDIR}/vendor/fonts/${.TARGET:T} ${.TARGET}
${DIST}/icons/icon.svg: ${.CURDIR}/web/icon.svg
	mkdir -p ${DIST}/icons
	cp ${.ALLSRC} ${.TARGET}

# The service worker caches the shell under a name that changes with it.
${DIST}/sw.js: ${.CURDIR}/web/sw.js ${SHELL_FILES}
	cd ${DIST} && id=`cat ${SHELL_FILES:S,^${DIST}/,,} arcana.wasm | \
	    cksum | cut -d' ' -f1` && \
	files="[\"./\"`for f in ${SHELL_FILES:S,^${DIST}/,,} arcana.wasm; \
	    do printf ',"%s"' $$f; done`]" && \
	sed -e "s/__BUILD__/$$id/" -e "s|__FILES__|$$files|" \
	    ${.CURDIR}/web/sw.js > ${.TARGET}

install: .PHONY
	${INSTALL} -d ${DESTDIR}${WWWDIR}/icons ${DESTDIR}${WWWDIR}/fonts
	cd ${DIST} && for f in ${SHELL_FILES:S,^${DIST}/,,} arcana.wasm \
	    sw.js; do ${INSTALL} -m 0444 $$f ${DESTDIR}${WWWDIR}/$$f; done

clean: .PHONY
	rm -rf ${OBJS} ${MKICON} ${DIST} ${.OBJDIR}/arcana.md

.include <bsd.obj.mk>
