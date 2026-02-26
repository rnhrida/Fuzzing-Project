#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Simulates a vulnerable kernel network packet parser
static void parse_packet(const uint8_t *data, size_t size) {
    uint32_t packet_len = *(uint32_t*)data;
    char *buf = (char*)malloc(64);
    // BUG: if packet_len > 64, this overflows = HEAP-BUFFER-OVERFLOW
    memcpy(buf, data + 4, packet_len);
    free(buf);
}

// AFL++ calls this for every fuzz input
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) return 0;
    parse_packet(data, size);
    return 0;
}
