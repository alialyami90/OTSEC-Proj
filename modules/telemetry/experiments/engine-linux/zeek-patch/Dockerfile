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

# (B')'s three controls (D1's ruling on #715, condition 4.5), never shipped:
# the patched tree, with one control patch from controls/ applied at a time,
# rebuilt (DNP3.cc only, then the link) and installed apart. Each control
# image is C2 with only bin/zeek replaced. No target ships them.
FROM build AS controls
COPY controls /src/controls
RUN --network=none for m in stock-catch raise-rethrow no-violation; do \
      patch -p1 --fuzz=0 --no-backup-if-mismatch < /src/controls/$m.patch \
      && ninja -C build \
      && DESTDIR=/stage/m-$m ninja -C build install \
      && patch -R -p1 --fuzz=0 --no-backup-if-mismatch < /src/controls/$m.patch \
      || exit 1; \
    done

FROM runtime AS c2
COPY --from=build /stage/c2/usr/local/zeek /usr/local/zeek
COPY --from=build /stage/c2/record /usr/local/zeek/share/otsec-build
COPY --from=build /stage/binpac.txt /build-packages.txt /usr/local/zeek/share/otsec-build/
COPY --from=build /stage/notices/zeek-9.0.1 /usr/local/zeek/share/otsec-build/notices/zeek-9.0.1
COPY COPYING hr23-fc-dispatch.patch /usr/local/zeek/share/otsec-build/notices/
RUN dpkg-query -W -f '${Package} ${Version}\n' > /usr/local/zeek/share/otsec-build/runtime-packages.txt

FROM c2 AS m-stock-catch
COPY --from=controls /stage/m-stock-catch/usr/local/zeek/bin/zeek /usr/local/zeek/bin/zeek

FROM c2 AS m-raise-rethrow
COPY --from=controls /stage/m-raise-rethrow/usr/local/zeek/bin/zeek /usr/local/zeek/bin/zeek

FROM c2 AS m-no-violation
COPY --from=controls /stage/m-no-violation/usr/local/zeek/bin/zeek /usr/local/zeek/bin/zeek

# HR-25's option A with option (a), part HR25-B1 (D4-124; the design's
# section 4, C1): the same tree, after C2, with hr25-resync.patch applied
# after hr23-fc-dispatch.patch in that fixed order with no fuzz, rebuilt and
# installed as C2A. build.sh checks that C2 and C2A differ only in files
# that A's patch can change.
FROM build AS build-a
COPY hr25-resync.patch /src/hr25-resync.patch
RUN --network=none patch -p1 --fuzz=0 --no-backup-if-mismatch < /src/hr25-resync.patch \
 && ninja -C build \
 && DESTDIR=/stage/c2a ninja -C build install \
 && mkdir -p /stage/c2a/record \
 && (cd build && sha256sum $(find . -name 'dnp3_pac.cc' -o -name 'dnp3_pac.h' | sort)) > /stage/c2a/record/generated.sha256

# A's mutant controls, never shipped: the (i)+A tree with one control patch
# from controls/ applied at a time, rebuilt and installed apart; only each
# control's bin/zeek is kept. The list is build.env's HR25_CONTROLS.
FROM build-a AS controls-a
ARG HR25_CONTROLS
COPY controls /src/controls
RUN --network=none test -n "$HR25_CONTROLS" && mkdir -p /stage/m25 && for m in $HR25_CONTROLS; do \
      patch -p1 --fuzz=0 --no-backup-if-mismatch < /src/controls/hr25-$m.patch \
      && ninja -C build \
      && DESTDIR=/stage/tmp ninja -C build install \
      && cp /stage/tmp/usr/local/zeek/bin/zeek /stage/m25/$m \
      && rm -rf /stage/tmp \
      && patch -R -p1 --fuzz=0 --no-backup-if-mismatch < /src/controls/hr25-$m.patch \
      || exit 1; \
    done

# C2A carries both patch files in its notices (the design's section 4, C2
# and C5).
FROM runtime AS c2a
COPY --from=build-a /stage/c2a/usr/local/zeek /usr/local/zeek
COPY --from=build-a /stage/c2a/record /usr/local/zeek/share/otsec-build
COPY --from=build /stage/binpac.txt /build-packages.txt /usr/local/zeek/share/otsec-build/
COPY --from=build /stage/notices/zeek-9.0.1 /usr/local/zeek/share/otsec-build/notices/zeek-9.0.1
COPY COPYING hr23-fc-dispatch.patch hr25-resync.patch /usr/local/zeek/share/otsec-build/notices/
RUN dpkg-query -W -f '${Package} ${Version}\n' > /usr/local/zeek/share/otsec-build/runtime-packages.txt

# One control image: C2A with control MUTANT's bin/zeek.
FROM c2a AS m25
ARG MUTANT
COPY --from=controls-a /stage/m25/${MUTANT} /usr/local/zeek/bin/zeek
