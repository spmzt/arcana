# arcana: the arcana console on FreeBSD, arcana-console(8) and the PWA,
# unprivileged, on the cblink image.
#
#	buildah build -f Containerfile --network=host -t arcana .
#	podman run -d --name arcana -p 8443:8443 \
#	    -e ARCANA_RP_ID=console.example -v arcana:/var/db/arcana \
#	    arcana
#
# It serves HTTPS on 8443 with a mounted certificate, or plain HTTP
# for a reverse proxy that terminates TLS; container/arcana-container.sh
# lists its settings.
#
# The first stage builds the tree on the emscripten image (base
# toolchain and emcc, from spmzt/images), cblink from the submodule with
# it, runs the test suite as an unprivileged user (a failing test fails
# the build; set ARCANA_TESTS=no to skip it) and installs the runtime
# files; the second has only those, on the cblink image, whose libcblink
# the one built here replaces.
# arcana-agent(8) runs on each host itself: it manages that host's jails.

ARG CBLINK_IMAGE=ghcr.io/spmzt/cblink:latest
ARG EMSCRIPTEN_IMAGE=ghcr.io/spmzt/freebsd-emscripten:latest

FROM ${CBLINK_IMAGE} AS cblink

FROM ${EMSCRIPTEN_IMAGE} AS build
ARG ARCANA_TESTS=yes
# yes: the build written down for CodeQL as well, in /tmp/codeql.tar.zst
# (tools/codeql/capture.sh; .github/workflows/codeql.yaml takes it).
ARG ARCANA_CODEQL=no
# The libucl and libyaml releases base imports; the PWA compiles them to
# wasm (the image has no /usr/src).
ARG LIBUCL_VERSION=0.9.4
ARG LIBUCL_SHA256=319d8ff13441f55d91cd7f3708a54bd03779733e26958c2346c5109014520aaf
ARG LIBYAML_VERSION=0.2.5
ARG LIBYAML_SHA256=fa240dbf262be053f3898006d502d514936c818e422afdcf33921c63bed9bf2e
# jail(8), git, curl and python3 for the tests, libcbor for libcblink,
# libyang for cblink-gen, libwebsockets for the console's server.
RUN pkg install -y FreeBSD-jail git curl python3 libcbor libyang3 \
        libwebsockets && \
    pkg-cleanup

WORKDIR /usr/src/libucl
RUN fetch -o libucl.tar.gz \
        https://github.com/vstakhov/libucl/archive/refs/tags/${LIBUCL_VERSION}.tar.gz && \
    [ "$(openssl dgst -sha256 -r libucl.tar.gz | cut -d' ' -f1)" = \
        "${LIBUCL_SHA256}" ] && \
    tar -xzf libucl.tar.gz --strip-components 1 && rm libucl.tar.gz

WORKDIR /usr/src/libyaml
RUN fetch -o libyaml.tar.gz \
        https://github.com/yaml/libyaml/archive/refs/tags/${LIBYAML_VERSION}.tar.gz && \
    [ "$(openssl dgst -sha256 -r libyaml.tar.gz | cut -d' ' -f1)" = \
        "${LIBYAML_SHA256}" ] && \
    tar -xzf libyaml.tar.gz --strip-components 1 && rm libyaml.tar.gz

# The submodule cblink/ must be checked out in what is copied.
# ARCANA_WEBGPU=yes builds the map's WebGPU too (WITH_WEBGPU), with
# Dawn's emdawnwebgpu package, which make depends fetches.
ARG ARCANA_WEBGPU=no
COPY . /usr/src/arcana
WORKDIR /usr/src/arcana
RUN test -f cblink/Makefile || { echo "cblink/ is empty: git submodule update --init" >&2; exit 1; } && \
    if [ "${ARCANA_WEBGPU}" = yes ]; then echo "WITH_WEBGPU=yes" >> config.mk; fi && \
    make depends && \
    if [ "${ARCANA_CODEQL}" = yes ]; then \
        sh tools/codeql/capture.sh; \
    else \
        make -j "$(sysctl -n hw.ncpu)" LIBUCL_SRC=/usr/src/libucl LIBYAML_SRC=/usr/src/libyaml; \
    fi
# The tests that need root drive real jails; as another user they are
# skipped, as is the browser test without Chromium.
RUN if [ "${ARCANA_TESTS}" = yes ]; then \
        pw useradd -n arctest -m -s /bin/sh && \
        chown -R arctest /usr/src/arcana && \
        su arctest -c 'make -C /usr/src/arcana check \
            LIBUCL_SRC=/usr/src/libucl LIBYAML_SRC=/usr/src/libyaml'; \
    fi
RUN make install WITHOUT_TESTS=yes WITHOUT_DEBUG_FILES=yes DESTDIR=/dist && \
    install -d /dist/usr/local/libexec && \
    install -m 0555 container/arcana-container.sh \
        /dist/usr/local/libexec/arcana-container

FROM cblink
LABEL org.opencontainers.image.source="https://github.com/spmzt/arcana" \
    org.opencontainers.image.title="arcana" \
    org.opencontainers.image.description="Arcana, The Seven Archives of FreeBSD: the fleet console, a PWA with WebAuthn login, served on libwebsockets" \
    org.opencontainers.image.licenses="BSD-2-Clause" \
    org.opencontainers.image.authors="spmzt" \
    io.containers.autoupdate=registry
# The build stage's base can be newer than the cblink image's.
RUN env IGNORE_OSVERSION=yes pkg upgrade -y && \
    pkg install -y libwebsockets && \
    pkg clean -ay && \
    pw groupadd arcana -g 4310 && \
    pw useradd arcana -u 4310 -g arcana -c "arcana console" \
        -d /var/db/arcana -s /usr/sbin/nologin && \
    install -d -o arcana -g arcana -m 0700 /var/db/arcana && \
    install -d -o arcana -g arcana -m 0755 /var/run/arcana
COPY --from=build /dist/usr/local/ /usr/local/
USER arcana
WORKDIR /var/db/arcana
VOLUME /var/db/arcana
EXPOSE 8443
CMD ["/usr/local/libexec/arcana-container"]
