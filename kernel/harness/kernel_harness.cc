#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Vulnerable buffer - only 64 bytes
char global_buf[64];

// Vulnerable function - no bounds check
void parse_packet(const uint8_t *data, size_t size) {
    if (size < 4) return;
    uint32_t len = *(uint32_t*)data;
    // BUG: len can be > 64 = OVERFLOW!
    memcpy(global_buf, data + 4, len);
}

// Correct AFL++ entry point - NO main()
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5 || size > 200) return 0;
    parse_packet(data, size);
    return 0;
}
