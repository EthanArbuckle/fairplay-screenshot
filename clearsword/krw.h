#ifndef krw_h
#define krw_h

#include "common.h"

#define CHAIN_WRITE_ZONE_ELEMENT_MIN_SIZE 0x20
#define EARLY_KRW_LENGTH 0x20  // 32

uint64_t early_kread64(uint64_t where);
void early_kwrite64(uint64_t where, uint64_t what);

int clearsword_kreadbuf(uint64_t kaddr, void* output, size_t size);
int clearsword_kwritebuf(uint64_t kaddr, const void* input, size_t size);

// Research helper: bounded 32-byte operations that always park the exploit
// socket's redirected filter on its own retained PCB before returning.
bool park_krw_socket(void);
bool krw_read_32_bytes(uint64_t where, uint8_t out[32]);
bool krw_write_32_bytes(uint64_t where, const uint8_t input[32]);


#endif /* krw_h */
