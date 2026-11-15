# HR-23 option (i): the project's Zeek 9.0.1 build, C1p and C2 of
# docs/phase4/D4-hr23-design.md, section 4.1. build.sh is the only caller:
# it checks every input against build.env first and passes the unpacked,
# signature-checked tarball as the context, with the patch beside it.
#
# One build tree gives both images, so they differ only by the patch: the
# tree is configured and built once and installed as C1p, then the patch is
# applied with `patch --fuzz=0` and the same tree is rebuilt and installed
# as C2. Both use the binpac inside the tarball (tools/binpac); the record
# shows which binpac CMake found, and the SHA-256 of each generated
# dnp3_pac.cc and dnp3_pac.h (the design's check on paper). build.sh fails
# unless the two images differ in exactly the four files the patch changes,
# and unless CMake's binpac is the in-tree one (D6's N4 on #715).
#
# The configure line is Zeek's own docker/Makefile line (Ninja, Release, no
# test builds) with the six options of the design's section 4.5 (D7). Spicy
# stays on (D7's C6). Every step after the package install runs with no
# network (D3's N1 on #715), so a fetcher the options did not leave out
# fails the build instead of fetching. In Zeek 9.0.1, `--disable-af-packet`
# sets a CMake cache entry that no CMake file reads: AF_Packet is built in on
# Linux whatever the option says (src/iosource/af_packet/CMakeLists.txt), so
# the images carry it. It captures from an interface and fetches nothing;
# the sensor reads the frame stage's pipe (C13 0.3). build.sh checks that
# what the other five leave out is absent (D6's N5 on #715).
ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS build
RUN apt-get -q update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -q -y --no-install-recommends \
      bison cmake flex g++ gcc git libfl-dev libfl2 libmaxminddb-dev libpcap-dev libssl-dev \
      libuv1-dev libz-dev make ninja-build patch python3-minimal \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f '${Package} ${Version}\n' > /build-packages.txt
COPY zeek-9.0.1 /src/zeek
COPY hr23-fc-dispatch.patch /src/hr23-fc-dispatch.patch
WORKDIR /src/zeek
# The notices of the tree's third-party code (D7's N1 on #715): Zeek's
# COPYING-3rdparty and every COPYING* and LICENSE* file outside test
# folders, from the signature-checked tree before it is built, with their
# paths kept.
RUN --network=none mkdir -p /stage/notices/zeek-9.0.1 \
 && find . -type d \( -name test -o -name tests -o -name testing \) -prune \
      -o -type f \( -name 'COPYING*' -o -name 'LICENSE*' \) -print | sort > /stage/notices.list \
 && tar -cf - -T /stage/notices.list | tar -xf - -C /stage/notices/zeek-9.0.1 \
 && test -f /stage/notices/zeek-9.0.1/COPYING-3rdparty
RUN --network=none ./configure --build-dir=build --generator=Ninja --build-type=Release \
      --disable-btest-pcaps --disable-broker-tests --disable-cpp-tests \
      --disable-zkg --disable-zeekctl --disable-javascript --disable-python \
      --disable-cluster-backend-zeromq --disable-af-packet
RUN --network=none ninja -C build \
 && DESTDIR=/stage/c1p ninja -C build install \
 && mkdir -p /stage/c1p/record \
 && (cd build && sha256sum $(find . -name 'dnp3_pac.cc' -o -name 'dnp3_pac.h' | sort)) > /stage/c1p/record/generated.sha256
RUN --network=none patch -p1 --fuzz=0 --no-backup-if-mismatch < /src/hr23-fc-dispatch.patch \
 && ninja -C build \
 && DESTDIR=/stage/c2 ninja -C build install \
 && mkdir -p /stage/c2/record \
 && (cd build && sha256sum $(find . -name 'dnp3_pac.cc' -o -name 'dnp3_pac.h' | sort)) > /stage/c2/record/generated.sha256
RUN grep -i binpac build/CMakeCache.txt | grep -iE 'exe|path|dir' > /stage/binpac.txt || true

FROM ${BASE_IMAGE} AS runtime
RUN apt-get -q update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -q -y --no-install-recommends \
      libmaxminddb0 libpcap0.8 libssl3 libuv1 libz1 \
 && rm -rf /var/lib/apt/lists/*
ENV PATH="/usr/local/zeek/bin:${PATH}"

# The notices travel with the binary (D7's C5 and N1; R-4): Zeek's COPYING,
# the patch, which names it, and the tree's third-party notices. C1p carries
# them too, though it never ships.
FROM runtime AS c1p
COPY --from=build /stage/c1p/usr/local/zeek /usr/local/zeek
COPY --from=build /stage/c1p/record /usr/local/zeek/share/otsec-build
COPY --from=build /stage/binpac.txt /build-packages.txt /usr/local/zeek/share/otsec-build/
COPY --from=build /stage/notices/zeek-9.0.1 /usr/local/zeek/share/otsec-build/notices/zeek-9.0.1
COPY COPYING hr23-fc-dispatch.patch /usr/local/zeek/share/otsec-build/notices/
RUN dpkg-query -W -f '${Package} ${Version}\n' > /usr/local/zeek/share/otsec-build/runtime-packages.txt

FROM runtime AS c2
COPY --from=build /stage/c2/usr/local/zeek /usr/local/zeek
COPY --from=build /stage/c2/record /usr/local/zeek/share/otsec-build
COPY --from=build /stage/binpac.txt /build-packages.txt /usr/local/zeek/share/otsec-build/
COPY --from=build /stage/notices/zeek-9.0.1 /usr/local/zeek/share/otsec-build/notices/zeek-9.0.1
COPY COPYING hr23-fc-dispatch.patch /usr/local/zeek/share/otsec-build/notices/
RUN dpkg-query -W -f '${Package} ${Version}\n' > /usr/local/zeek/share/otsec-build/runtime-packages.txt
