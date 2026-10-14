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
# libcblink.so.1 at run time and a host that builds the agent cblink-gen.
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
# "all" as a dependency would not recurse: bsd.subdir.mk only descends
# for targets named on the command line.
check: .PHONY
	@${MAKE} -j${CHECK_JOBS} -C ${.CURDIR} all
.if ${CBLINK_SUBMODULE} == "yes"
	@${MAKE} -C ${.CURDIR}/usr.sbin/arcana-agent check-yang
.endif
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
