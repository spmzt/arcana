# arcana: the arcana console on FreeBSD, kore(1) with arcana-console.so and
# the PWA, unprivileged, on the cblink image.
#
#	buildah build -f Containerfile --network=host -t arcana .
#	podman run -d --name arcana -p 8443:8443 \
#	    -e ARCANA_RP_ID=console.example -v arcana:/var/db/arcana \
#	    arcana
#
# It serves HTTPS on 8443 with a mounted RSA certificate, or plain HTTP
# for a reverse proxy that terminates TLS; container/arcana-container.sh
# lists its settings.
#
# The first stage builds Kore and the tree on the emscripten image (base
# toolchain and emcc, from spmzt/images) with cblink taken from its
# image, runs the test suite as an unprivileged user (a failing test
# fails the build; set ARCANA_TESTS=no to skip it) and installs the
# runtime files; the second has only those, on the cblink image.
# arcana-agent(8) runs on each host itself: it manages that host's jails.

ARG CBLINK_IMAGE=ghcr.io/spmzt/cblink:latest
ARG EMSCRIPTEN_IMAGE=ghcr.io/spmzt/freebsd-emscripten:latest

FROM ${CBLINK_IMAGE} AS cblink

FROM ${EMSCRIPTEN_IMAGE} AS build
ARG ARCANA_TESTS=yes
ARG KORE_VERSION=4.3.0
ARG KORE_SHA256=94f767eb113f2c97a133b9609c78c4e3795c420dc8726154edce49965df6b8ed
# The libucl release base imports; the PWA compiles it to wasm.
ARG LIBUCL_VERSION=0.9.4
ARG LIBUCL_SHA256=319d8ff13441f55d91cd7f3708a54bd03779733e26958c2346c5109014520aaf
# jail(8) for the tests, gmake for Kore, libcbor for libcblink.
RUN pkg install -y FreeBSD-jail gmake libcbor && \
    pkg-cleanup
COPY --from=cblink /usr/local/bin/cblink-gen /usr/local/bin/
COPY --from=cblink /usr/local/include/cblink.h /usr/local/include/
COPY --from=cblink /usr/local/lib/libcblink.so.1 /usr/local/lib/
COPY --from=cblink /usr/local/share/cblink/ /usr/local/share/cblink/
RUN ln -s libcblink.so.1 /usr/local/lib/libcblink.so && \
    ldconfig -m /usr/local/lib

# Kore, with tasks, as arcana-console.so needs it.  It builds as C99 with
# -Werror, and base's basename(3) is a C11 _Generic macro.  The port's
# patch has it share memory between its processes with mmap(2): SysV
# shared memory is not there in a jail without sysvshm, as a container is.
WORKDIR /usr/src/kore
COPY port/www/kore/files/ /usr/src/kore-patches/
RUN fetch -o kore.tar.gz \
        https://kore.io/releases/kore-${KORE_VERSION}.tar.gz && \
    [ "$(openssl dgst -sha256 -r kore.tar.gz | cut -d' ' -f1)" = \
        "${KORE_SHA256}" ] && \
    tar -xzf kore.tar.gz --strip-components 1 && rm kore.tar.gz && \
    for p in /usr/src/kore-patches/patch-*; do patch -p0 < "$p"; done && \
    mkdir obj && env CFLAGS=-Wno-c11-extensions gmake TASKS=1 kore && \
    install -d /usr/local/include/kore /usr/local/share/kore && \
    install -m 0555 kore /usr/local/bin/kore && \
    install -m 0444 include/kore/*.h /usr/local/include/kore && \
    install -m 0444 kore.features /usr/local/share/kore/features && \
    install -m 0444 misc/ffdhe4096.pem /usr/local/share/kore

WORKDIR /usr/src/libucl
RUN fetch -o libucl.tar.gz \
        https://github.com/vstakhov/libucl/archive/refs/tags/${LIBUCL_VERSION}.tar.gz && \
    [ "$(openssl dgst -sha256 -r libucl.tar.gz | cut -d' ' -f1)" = \
        "${LIBUCL_SHA256}" ] && \
    tar -xzf libucl.tar.gz --strip-components 1 && rm libucl.tar.gz

COPY . /usr/src/arcana
WORKDIR /usr/src/arcana
RUN make -j "$(sysctl -n hw.ncpu)" LIBUCL_SRC=/usr/src/libucl
# The tests that need root drive real jails; as another user they are
# skipped, as is the browser test without Chromium.
RUN if [ "${ARCANA_TESTS}" = yes ]; then \
        pw useradd -n arctest -m -s /bin/sh && \
        chown -R arctest /usr/src/arcana && \
        su arctest -c 'make -C /usr/src/arcana check \
            LIBUCL_SRC=/usr/src/libucl'; \
    fi
RUN make install WITHOUT_TESTS=yes WITHOUT_DEBUG_FILES=yes DESTDIR=/dist && \
    install -d /dist/usr/local/libexec && \
    install -m 0555 container/arcana-container.sh \
        /dist/usr/local/libexec/arcana-container

FROM cblink
LABEL org.opencontainers.image.source="https://github.com/spmzt/arcana" \
    org.opencontainers.image.title="arcana" \
    org.opencontainers.image.description="Arcana, The Seven Archives of FreeBSD: the fleet console, a PWA with WebAuthn login, served by Kore" \
    org.opencontainers.image.licenses="BSD-2-Clause" \
    org.opencontainers.image.authors="spmzt" \
    io.containers.autoupdate=registry
# The build stage's base can be newer than the cblink image's.
RUN env IGNORE_OSVERSION=yes pkg upgrade -y && \
    pkg clean -ay && \
    pw groupadd arcana -g 4310 && \
    pw useradd arcana -u 4310 -g arcana -c "arcana console" \
        -d /var/db/arcana -s /usr/sbin/nologin && \
    install -d -o arcana -g arcana -m 0700 /var/db/arcana && \
    install -d -o arcana -g arcana -m 0755 /var/run/arcana
COPY --from=build /usr/local/bin/kore /usr/local/bin/kore
COPY --from=build /usr/local/share/kore/ffdhe4096.pem /usr/local/share/kore/
COPY --from=build /dist/usr/local/ /usr/local/
USER arcana
WORKDIR /var/db/arcana
VOLUME /var/db/arcana
EXPOSE 8443
CMD ["/usr/local/libexec/arcana-container"]
