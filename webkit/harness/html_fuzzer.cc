#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Simulates WebKit HTML parser with a vulnerability
static void parse_html(const uint8_t *data, size_t size) {
    char *buf = (char*)malloc(128);
    char tag[32];
    // BUG: if size > 32, this overflows = HEAP-BUFFER-OVERFLOW
    memcpy(tag, data, size);
    memcpy(buf, tag, sizeof(tag));
    free(buf);
}

// LibFuzzer calls this for every fuzz input
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    parse_html(data, size);
    return 0;
}
