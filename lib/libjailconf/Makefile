# libjailconf: change values in jail.conf(5) in place.  Internal: linked
# statically into jailconf(8) and arcana-agent(8), not installed.

LIB=		jailconf
INTERNALLIB=
SRCS=		jailconf.c

.include "${.CURDIR}/../../share/mk/arcana.mk"

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.lib.mk>

# The tests link the library: under make -j, build it first.
all_subdir_${DIRPRFX}tests: ${_LIBS}
