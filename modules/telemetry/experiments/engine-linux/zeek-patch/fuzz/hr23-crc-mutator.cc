// HR-23's sanitizer fuzz run (brief P4-4-HR23-FUZZ; docs/phase4/
// D4-hr23-design.md, section 4.6, "The CRC fix-up"). The project's own file,
// linked into the three fuzz targets of both builds, C1p and C2, alike; it
// is no part of the code under test, which stays Zeek 9.0.1's source, with
// option (i)'s patch in C2 only.
//
// DNP3_Base::CheckCRC checks every link header and every 16-octet block of
// user data before binpac sees a byte, so a plain mutator would almost
// never reach the parsers. After libFuzzer's own mutation, this recomputes
// every CRC it can find, in every FuzzBuffer chunk:
// - stream framing (dnp3_tcp, dnp3_udp): the chunk is the DNP3 octets;
// - IP framing (packet, built with HR23_FRAMING_IP=1): the chunk is a raw
//   IPv4 packet (DLT_RAW); the fix-up runs on a UDP datagram's payload
//   only, and leaves any other packet as it is.
// In the octets, a frame starts wherever 05 64 is followed by at least the
// rest of a 10-octet header. Its header CRC is recomputed, then each block
// its length octet announces that the chunk holds whole, with its CRC.
// A block cut short by the chunk's end is left as it is.
//
// Two limits on what the mutated inputs reach (D2's N2 and N3 on #731):
// - The fix-up works per chunk, but DNP3_Base buffers per endpoint across
//   chunks (TCP segments, UDP datagrams). So a frame that runs on into the
//   next chunk keeps its later blocks' CRCs unfixed, and the next chunk is
//   scanned for 05 64 from its first octet, where a match in user data has
//   two octets rewritten as a CRC. Such inputs mostly stop at CheckCRC.
// - Every mutated input gets valid CRCs, so the CRC-failure paths
//   (broken_checksum, dnp3_corrupt_app_chunk_checksum, HR-25's skip) are
//   reached only by the unmutated seeds that carry a bad CRC, not by the
//   campaign's mutations. The coverage of the run does not cover them.
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

const unsigned char kMagic[4] = {0x01, 'P', 'K', 'T'};  // FuzzBuffer::PKT_MAGIC

// CRC-16/DNP: polynomial 0x3D65, reflected (0xA6BC), initial 0, complemented,
// written low octet first (IEEE 1815's link layer).
uint16_t dnp3_crc(const uint8_t* p, size_t n) {
    uint16_t c = 0;
    for ( size_t i = 0; i < n; i++ ) {
        c ^= p[i];
        for ( int b = 0; b < 8; b++ )
            c = (c & 1) ? (c >> 1) ^ 0xA6BC : c >> 1;
    }
    return ~c;
}

void put_crc(uint8_t* p, size_t n) {
    uint16_t c = dnp3_crc(p, n);
    p[n] = c & 0xFF;
    p[n + 1] = c >> 8;
}

// The DNP3 octets of one chunk; returns the number of frames whose header
// CRC was written.
size_t fix_octets(uint8_t* d, size_t n) {
    size_t frames = 0;
    size_t i = 0;
    while ( i + 10 <= n ) {
        if ( d[i] != 0x05 || d[i + 1] != 0x64 ) {
            i++;
            continue;
        }
        put_crc(d + i, 8);
        frames++;
        size_t user = d[i + 2] >= 5 ? d[i + 2] - 5 : 0;
        size_t j = i + 10;
        while ( user > 0 ) {
            size_t b = user < 16 ? user : 16;
            if ( j + b + 2 > n )
                break;
            put_crc(d + j, b);
            j += b + 2;
            user -= b;
        }
        i = j;
    }
    return frames;
}

// One raw IPv4 packet: the UDP payload's octets, or nothing.
size_t fix_ip(uint8_t* d, size_t n) {
    if ( n < 20 || (d[0] >> 4) != 4 || d[9] != 17 )
        return 0;
    size_t ihl = (size_t)(d[0] & 0x0F) * 4;
    if ( ihl < 20 || ihl + 8 > n )
        return 0;
    return fix_octets(d + ihl + 8, n - ihl - 8);
}

const uint8_t* find_magic(const uint8_t* p, const uint8_t* end) {
    for ( ; p + 4 <= end; p++ )
        if ( memcmp(p, kMagic, 4) == 0 )
            return p;
    return nullptr;
}

} // namespace

// Every chunk of a FuzzBuffer input, cut as FuzzBuffer::Next cuts it: from
// one PKT_MAGIC, past its flag octet, to the next PKT_MAGIC or the end.
// Returns the number of frames whose header CRC was written. Exported for
// the unit tests (test_hr23_fuzz.py).
extern "C" size_t hr23_fix_buffer(uint8_t* data, size_t size, int ip_framing) {
    const uint8_t* end = data + size;
    const uint8_t* m = find_magic(data, end);
    size_t frames = 0;
    while ( m && m + 5 < end ) {
        uint8_t* chunk = const_cast<uint8_t*>(m) + 5;
        const uint8_t* next = find_magic(chunk, end);
        size_t n = (next ? next : end) - chunk;
        frames += ip_framing ? fix_ip(chunk, n) : fix_octets(chunk, n);
        m = next;
    }
    return frames;
}

#ifndef HR23_NO_LIBFUZZER
#ifndef HR23_FRAMING_IP
#define HR23_FRAMING_IP 0
#endif

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t max_size, unsigned int seed) {
    (void)seed;
    size = LLVMFuzzerMutate(data, size, max_size);
    hr23_fix_buffer(data, size, HR23_FRAMING_IP);
    return size;
}
#endif
