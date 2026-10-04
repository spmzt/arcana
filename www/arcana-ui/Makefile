# The console's web application: C compiled to WebAssembly with emcc(1),
# plus its static files, written to ${.OBJDIR}/dist.
#
#	make && make install [DESTDIR=dir] [WWWDIR=/usr/local/www/arcana-console]

.include "${.CURDIR}/../../share/mk/arcana.mk"

EMCC?=		emcc
# JSON: base's libucl, compiled to wasm from the source tree.
LIBUCL_SRC?=	/usr/src/contrib/libucl
# emcc links at -O2 and above only with its JS optimizer's npm modules
# (acorn); the FreeBSD package lacks them.  The C is -O2 either way.
EMLDOPT?=	-O1
WWWDIR?=	${PREFIX}/www/arcana-console

DIST=		${.OBJDIR}/dist

APP_SRCS=	main.c actions.c api.c bird.c fleet.c kernel.c topo.c vpn.c graph.c html.c json.c netview.c \
		schema.c view.c
UCL_SRCS=	ucl_emitter_streamline.c ucl_emitter_utils.c ucl_emitter.c \
		ucl_hash.c ucl_msgpack.c ucl_parser.c ucl_schema.c ucl_sexp.c \
		ucl_util.c

# -Werror covers emcc's own warnings too: the emscripten package can
# expect another LLVM major than the llvm-devel it depends on, and only
# a clean cache (a port build, a container) runs that check.
EMCFLAGS=	-O2 -std=gnu17 -Wall -Wextra -Wno-unused-parameter \
		-Werror -Wno-version-check -I${LIBUCL_SRC}/include
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
${DIST}/schema.json: ${ARC_TOP}/share/arcana/arcana.yaml \
    ${.CURDIR}/tools/schema.awk
	mkdir -p ${DIST}
	${CBLINK_GEN} -m md -o ${.OBJDIR} ${ARC_TOP}/share/arcana/arcana.yaml
	awk -f ${.CURDIR}/tools/schema.awk ${.OBJDIR}/arcana.md > ${.TARGET}

SHELL_FILES=	${STATIC:S,^,${DIST}/,} ${DIST}/arcana.js ${DIST}/schema.json \
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
