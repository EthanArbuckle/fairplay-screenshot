#ifndef RESEARCH_INFO_H
#define RESEARCH_INFO_H
#include <stdint.h>

typedef struct {
    struct {
        uint64_t staticBase;
    } kernelConstant;
    struct {
        struct { uint64_t list_next, pcbinfo, socket, icmp6filt; } inpcb;
        struct { uint64_t ipi_zone; } inpcbinfo;
        struct { uint64_t kt_zv_zv_name; } kalloc_type_view;
        struct { uint64_t proto, usecount; } socket;
        struct { uint64_t input; } protosw;
    } kernelStruct;
} KernelOffsetInfo;

extern KernelOffsetInfo gSystemInfo;
#define koffsetof(type, field) (gSystemInfo.kernelStruct.type.field)
#define kconstant(field) (gSystemInfo.kernelConstant.field)
#endif
