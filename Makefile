# arcana, built with base make(1) and bsd.*.mk:
#
#	make && make check
#	make install [DESTDIR=dir] [PREFIX=/usr/local]
#
# Build products go to obj/, mirroring the tree (share/mk/arcana.mk).
# Needs cblink (libcblink, cblink-gen, cblink.mk), and for the console
# Kore's headers and emcc(1); see config.mk.sample to point at copies not
# installed in ${LOCALBASE}.  WITHOUT_CONSOLE=yes builds only the jail
# host's programs.  "make check" runs the tests in the build tree: those
# that need root are skipped unless it runs as root, the browser test
# unless Chromium and chromedriver are installed.

.include "share/mk/arcana.mk"

SUBDIR=		lib/libjailconf \
		usr.sbin/jailconf \
		usr.sbin/arcana-enrol \
		usr.sbin/arcana-agent \
		usr.sbin/arcanactl
SUBDIR.${MK_CONSOLE}+= www/arcana-ui \
		www/arcana-console
SUBDIR.${MK_TESTS}+= tests
SUBDIR_DEPEND_usr.sbin/jailconf=	lib/libjailconf
SUBDIR_DEPEND_usr.sbin/arcana-agent=	lib/libjailconf

TESTDIRS=	lib/libjailconf/tests \
		usr.sbin/jailconf/tests \
		usr.sbin/arcana-agent/tests
.if ${MK_CONSOLE} != "no"
TESTDIRS+=	www/arcana-console/tests
.endif

# A failed or broken test fails the target, with kyua's report on it
# (less the environment, which can hold secrets).  The cases of a suite
# run side by side, CHECK_JOBS of them at once: each has a directory and
# sockets of its own.
CHECK_JOBS?=	8
# "all" as a dependency would not recurse: bsd.subdir.mk only descends
# for targets named on the command line.
check: .PHONY
	@${MAKE} -C ${.CURDIR} all
.for _d in ${TESTDIRS}
	@echo "===> ${_d} (check)"
	@set -o pipefail; cd ${.OBJDIR}/${_d} && kyua \
	    -v parallelism=${CHECK_JOBS} \
	    -v test_suites.FreeBSD.kore=${KORE_BIN} \
	    -v test_suites.FreeBSD.dhparam=${KORE_DHPARAM} \
	    test -k Kyuafile | sed -n '/->/p;$$p' || { kyua report \
	    --verbose --results-filter broken,failed | awk '/^===> /{ \
	    ctx = $$0 == "===> Execution context" } !ctx'; exit 1; }
.endfor

# Everything built is under obj/.
clean cleandir: .PHONY
	rm -rf ${ARC_TOP}/obj

.include <bsd.subdir.mk>
