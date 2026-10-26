#!/bin/sh
#
# In the Containerfile's build stage (ARCANA_CODEQL=yes): the tree built
# from nothing with every compile written down, and what replay.py needs
# to compile it again for CodeQL on a Linux runner, in /tmp/codeql.tar.zst:
#
#	compiles.log	the compiles, one JSON line each (ccwrap.py)
#	emcc-sysroot	where emcc's sysroot is, below root/
#	obj/, cblink/obj/	the generated sources and headers of the build
#	root/		the headers outside the tree: base's, the packages',
#			libucl's and libyaml's sources, emcc's sysroot
#
# CodeQL runs on Linux alone: this is how it sees the FreeBSD build, its
# headers and its generated code, rather than guessing at them.

set -eu

SRC=/usr/src/arcana
OUT=/tmp/codeql
rm -rf "${OUT}"
mkdir -p "${OUT}/bin" "${OUT}/root"
install -m 0555 "${SRC}/tools/codeql/ccwrap.py" "${OUT}/bin/cc"
ln -s cc "${OUT}/bin/emcc"
export CODEQL_LOG="${OUT}/compiles.log"
export CODEQL_CC="$(command -v cc)"
export CODEQL_EMCC="$(command -v emcc)"
: > "${CODEQL_LOG}"

cd "${SRC}"
rm -rf obj
make obj
make -j "$(sysctl -n hw.ncpu)" CC="${OUT}/bin/cc" EMCC="${OUT}/bin/emcc" \
    LIBUCL_SRC=/usr/src/libucl LIBYAML_SRC=/usr/src/libyaml

sysroot="$(em-config CACHE)/sysroot"
echo "${sysroot}" > "${OUT}/emcc-sysroot"
# What the compiles include from outside the tree, under root/.
for d in /usr/include /usr/local/include /usr/src/libucl /usr/src/libyaml \
    "${sysroot}/include"; do
	mkdir -p "${OUT}/root${d}"
	tar -C "${d}" -cf - --exclude '*.o' . | tar -C "${OUT}/root${d}" -xf -
done
# The build's own generated files; its objects are of no use.
tar -C "${SRC}" -cf - --exclude '*.o' --exclude '*.pico' \
    --exclude '*.pieo' --exclude '*.po' --exclude '*.a' --exclude '*.so*' \
    --exclude '*.full' --exclude '*.debug' --exclude '*.wasm' \
    --exclude '*.core' obj cblink/obj | tar -C "${OUT}" -xf -
rm -rf "${OUT}/bin"
tar -C "${OUT}" --zstd -cf /tmp/codeql.tar.zst .
echo "capture: $(wc -l < "${CODEQL_LOG}") compiles," \
    "$(($(stat -f %z /tmp/codeql.tar.zst) / 1048576)) MB"
