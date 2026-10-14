# libvarconf: files of variable assignments (rc.conf, rc.conf.d) read
# and changed in place.  Internal: linked statically, not installed.

LIB=		varconf
INTERNALLIB=
SRCS=		varconf.c capconf.c

.include "${.CURDIR}/../../share/mk/arcana.mk"

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.lib.mk>

# The tests link the library: under make -j, build it first.
all_subdir_${DIRPRFX}tests: ${_LIBS}
