# arcana, built with base make(1) and bsd.*.mk:
#
#	make && make check
#	make install [DESTDIR=dir] [PREFIX=/usr/local]
#
# Build products go to obj/, mirroring the tree (share/mk/arcana.mk).
# cblink (libcblink, cblink-gen, cblink.mk) is the submodule cblink/,
# checked out with git submodule update --init and built first, in its
# own obj/; devel/libcbor is what it needs.  The console needs Kore's
# headers and emcc(1); see config.mk.sample to point at copies not
# installed in ${LOCALBASE}.  WITHOUT_CONSOLE=yes builds only the jail
# host's programs.  "make check" runs the tests in the build tree: those
# that need root are skipped unless it runs as root, the browser test
# unless Chromium and chromedriver are installed.

.include "share/mk/arcana.mk"

# cblink from the submodule, built before anything made from its spec,
# without its tests; installed with the rest, since the programs need
# libcblink.so.2 at run time and a host that builds the agent cblink-gen
# (which needs net/libyang3 there).
.if ${CBLINK_SUBMODULE} == "yes"
_CBLINK_MAKE=	${MAKE} -C ${.CURDIR}/cblink WITH_AUTO_OBJ=yes WITHOUT_TESTS=yes
cblink-build: .PHONY
	@${_CBLINK_MAKE} all
beforeinstall: .PHONY
	@${_CBLINK_MAKE} install DESTDIR=${DESTDIR} PREFIX=${PREFIX}
.endif

SUBDIR=		lib/libjailconf \
		lib/libvarconf \
		usr.sbin/jailconf \
		usr.sbin/arcana-enrol \
		usr.sbin/arcana-agent \
		usr.sbin/arcanactl
SUBDIR.${MK_CONSOLE}+= www/arcana-ui \
		www/arcana-console
SUBDIR.${MK_TESTS}+= tests
SUBDIR_DEPEND_usr.sbin/jailconf=	lib/libjailconf
SUBDIR_DEPEND_usr.sbin/arcana-agent=	lib/libjailconf lib/libvarconf

.if ${CBLINK_SUBMODULE} == "yes"
.for _d in ${SUBDIR} ${SUBDIR.yes}
all_subdir_${_d}: cblink-build
.endfor
.endif

TESTDIRS=	lib/libjailconf/tests \
		lib/libvarconf/tests \
		usr.sbin/jailconf/tests \
		usr.sbin/arcana-agent/tests
.if ${MK_CONSOLE} != "no"
TESTDIRS+=	www/arcana-console/tests
.endif

# A failed or broken test fails the target, with kyua's report on it
# (less the environment, which can hold secrets).  The suites run at
# the same time, and the cases of each side by side, CHECK_JOBS of them
# at once: each has a directory and sockets of its own.  Each suite's
# lines carry its name, as they come interleaved; the build before it
# is made with as many jobs.  kyua's directories under $HOME are made
# first: four kyua starting at once on a fresh home race for them.
CHECK_JOBS?=	12
# The wire: the YANG modules share/arcana/wire.awk writes from the specs
# and their .sid files, committed in share/yang; regen-wire remakes them
# (a new item gets the next SID, nothing is renumbered) and check-wire
# fails when they are not what the specs make.
ARC_WIRE_REV=	2026-10-22
_wire_dir=	${.CURDIR}/share/yang
_wire_gen=	${CBLINK_GEN} -p ${_wire_dir} -p ${.CURDIR}/cblink/share/yang
regen-wire: .PHONY
	@for s in arcana cluster; do \
	    m=$$s; [ $$s = cluster ] && m=arcana-cluster; \
	    awk -v out=yang -v rev=${ARC_WIRE_REV} -f ${.CURDIR}/share/arcana/wire.awk \
	        ${.CURDIR}/share/arcana/$$s.yaml > ${_wire_dir}/$$m@${ARC_WIRE_REV}.yang.tmp && \
	    mv ${_wire_dir}/$$m@${ARC_WIRE_REV}.yang.tmp ${_wire_dir}/$$m@${ARC_WIRE_REV}.yang && \
	    ${_wire_gen} -n -a -s ${_wire_dir}/$$m@${ARC_WIRE_REV}.sid \
	        ${_wire_dir}/$$m@${ARC_WIRE_REV}.yang > /dev/null || exit 1; \
	done
check-wire: .PHONY
	@t=$$(mktemp -d) && trap 'rm -rf "$$t"' EXIT && \
	for s in arcana cluster; do \
	    m=$$s; [ $$s = cluster ] && m=arcana-cluster; \
	    awk -v out=yang -v rev=${ARC_WIRE_REV} -f ${.CURDIR}/share/arcana/wire.awk \
	        ${.CURDIR}/share/arcana/$$s.yaml > "$$t/$$m@${ARC_WIRE_REV}.yang" && \
	    cp ${_wire_dir}/$$m@${ARC_WIRE_REV}.sid "$$t/" && chmod 644 "$$t/$$m@${ARC_WIRE_REV}.sid" && \
	    ${_wire_gen} -n -a -s "$$t/$$m@${ARC_WIRE_REV}.sid" "$$t/$$m@${ARC_WIRE_REV}.yang" > /dev/null && \
	    cmp -s "$$t/$$m@${ARC_WIRE_REV}.yang" ${_wire_dir}/$$m@${ARC_WIRE_REV}.yang && \
	    cmp -s "$$t/$$m@${ARC_WIRE_REV}.sid" ${_wire_dir}/$$m@${ARC_WIRE_REV}.sid || \
	    { echo "share/yang/$$m@${ARC_WIRE_REV}: not what share/arcana/$$s.yaml makes: make regen-wire" >&2; exit 1; }; \
	done
# "all" as a dependency would not recurse: bsd.subdir.mk only descends
# for targets named on the command line.
check: .PHONY
	@${MAKE} -j${CHECK_JOBS} -C ${.CURDIR} all
.if ${CBLINK_SUBMODULE} == "yes"
	@${MAKE} -C ${.CURDIR}/www/arcana-ui check-yang
.endif
	@${MAKE} -C ${.CURDIR} check-wire
	@mkdir -p "$${HOME}/.kyua/logs" "$${HOME}/.kyua/store"
	@rc=0; pids=""; \
	for d in ${TESTDIRS}; do \
	    ( set -o pipefail; cd ${.OBJDIR}/$$d && kyua \
	        -v parallelism=${CHECK_JOBS} \
	        -v test_suites.FreeBSD.kore=${KORE_BIN} \
	        -v test_suites.FreeBSD.dhparam=${KORE_DHPARAM} \
	        test -k Kyuafile 2>&1 | sed -n '/->/p;$$p' | \
	        sed "s|^|$$d: |" || { kyua report --verbose \
	        --results-filter broken,failed | awk '/^===> /{ \
	        ctx = $$0 == "===> Execution context" } !ctx'; \
	        exit 1; } ) & pids="$$pids $$!"; \
	done; \
	for p in $$pids; do wait $$p || rc=1; done; \
	exit $$rc

# Everything built is under obj/, cblink's under its own.
clean cleandir: .PHONY
	rm -rf ${ARC_TOP}/obj ${ARC_TOP}/cblink/obj

.include <bsd.subdir.mk>
