// Metal through the system's own Metal.framework: the system default device
// (the accelerator's MetalPluginClassName, from the bundle its
// MetalPluginName names), a compute dispatch of a precompiled kernel, blit
// copies and fills, a texture's upload and read back, and a texture over an
// IOSurface that the CPU and the GPU both write, each through the WebMetal
// plugin, the accelerator's WebMetal connection and the host executor. Every output is checked against what Metal defines for it,
// computed here; the line printed ends with a digest (FNV-1a, 64 bits) of
// all of them, which the same program prints on the macOS test shim's
// device (phase 4 of the WebMetal plan) over the same WebGPU
// implementation.
//
// The kernel is linked in as a metallib (section __DATA,__metallib). On
// macOS the shim's device comes from its provider, named by the first
// argument (WMRefProvideDevice in a dylib); with none, the Mac's own.
#import <Foundation/Foundation.h>
#import <IOSurface/IOSurfaceRef.h>
#import <Metal/Metal.h>
#include <dlfcn.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <stdio.h>
#include <string.h>

static uint64_t digest = 0xcbf29ce484222325ull;

static void hash(const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        digest ^= b[i];
        digest *= 0x100000001b3ull;
    }
}

static int bad(const char *what, unsigned long long got, unsigned long long want) {
    printf("metal: %s: %#llx (want %#llx)\n", what, got, want);
    return 1;
}

static id<MTLDevice> device_for(int argc, char **argv) {
#if TARGET_OS_OSX
    if (argc < 2) return MTLCreateSystemDefaultDevice();
    void *h = dlopen(argv[1], RTLD_NOW);
    id<MTLDevice> (*provide)(void) = h ? (id<MTLDevice> (*)(void))dlsym(h, "WMRefProvideDevice") : NULL;
    return provide ? provide() : nil;
#else
    (void)argc;
    (void)argv;
    return MTLCreateSystemDefaultDevice();
#endif
}

// A completed command buffer, or the reason it is not.
static int run(id<MTLCommandBuffer> cb, const char *what) {
    [cb commit];
    [cb waitUntilCompleted];
    if (cb.status != MTLCommandBufferStatusCompleted) {
        printf("metal: %s: status %ld, error %s\n", what, (long)cb.status, cb.error.description.UTF8String);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        id<MTLDevice> device = device_for(argc, argv);
        if (!device) return bad("the system default device", 0, 1);
        id<MTLCommandQueue> queue = [device newCommandQueue];
        if (!queue) return bad("a command queue", 0, 1);

        // Compute: out[i] = a[i] * 2654435761 + (b[i] ^ (i << 3)), in
        // 32-bit unsigned arithmetic (wrapping, MSL 2.4 section 2.1).
        unsigned long size = 0;
        const uint8_t *lib = getsectiondata(&_mh_execute_header, "__DATA", "__metallib", &size);
        if (!lib) return bad("the linked metallib", 0, 1);
        dispatch_data_t data = dispatch_data_create(lib, size, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithData:data error:&error];
        if (!library) {
            printf("metal: the library: %s\n", error.description.UTF8String);
            return 1;
        }
        id<MTLFunction> fn = [library newFunctionWithName:@"metal_mad"];
        if (!fn) return bad("the kernel function", 0, 1);
        id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:fn error:&error];
        if (!pipeline) {
            printf("metal: the compute pipeline: %s\n", error.description.UTF8String);
            return 1;
        }
        enum { N = 256 };
        uint32_t a[N], b[N];
        for (uint32_t i = 0; i < N; i++) {
            a[i] = i * 7 + 1;
            b[i] = i * i;
        }
        id<MTLBuffer> ba = [device newBufferWithBytes:a length:sizeof a options:MTLResourceStorageModeShared];
        id<MTLBuffer> bb = [device newBufferWithBytes:b length:sizeof b options:MTLResourceStorageModeShared];
        id<MTLBuffer> bo = [device newBufferWithLength:sizeof a options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cb = [queue commandBuffer];
        id<MTLComputeCommandEncoder> ce = [cb computeCommandEncoder];
        [ce setComputePipelineState:pipeline];
        [ce setBuffer:ba offset:0 atIndex:0];
        [ce setBuffer:bb offset:0 atIndex:1];
        [ce setBuffer:bo offset:0 atIndex:2];
        [ce dispatchThreadgroups:MTLSizeMake(N / 64, 1, 1) threadsPerThreadgroup:MTLSizeMake(64, 1, 1)];
        [ce endEncoding];
        if (run(cb, "the compute dispatch")) return 1;
        const uint32_t *out = bo.contents;
        for (uint32_t i = 0; i < N; i++) {
            uint32_t want = a[i] * 2654435761u + (b[i] ^ (i << 3));
            if (out[i] != want) return bad("a computed value", ((uint64_t)i << 32) | out[i], ((uint64_t)i << 32) | want);
        }
        hash(out, sizeof a);

        // Blit: a fill and a copy between buffers (MTLBlitCommandEncoder.h:
        // the bytes copied and filled, exactly).
        id<MTLBuffer> src = [device newBufferWithLength:1024 options:MTLResourceStorageModeShared];
        id<MTLBuffer> dst = [device newBufferWithLength:1024 options:MTLResourceStorageModeShared];
        uint8_t *s = src.contents, *d = dst.contents;
        for (int i = 0; i < 1024; i++) {
            s[i] = (uint8_t)(i * 13 + 5);
            d[i] = 0x5a;
        }
        cb = [queue commandBuffer];
        id<MTLBlitCommandEncoder> be = [cb blitCommandEncoder];
        [be fillBuffer:dst range:NSMakeRange(0, 128) value:0xc3];
        [be copyFromBuffer:src sourceOffset:256 toBuffer:dst destinationOffset:512 size:384];
        [be endEncoding];
        if (run(cb, "the blit")) return 1;
        for (int i = 0; i < 1024; i++) {
            uint8_t want = i < 128 ? 0xc3 : (i >= 512 && i < 896) ? (uint8_t)((i - 256) * 13 + 5) : 0x5a;
            if (d[i] != want) return bad("a blitted byte", ((uint64_t)i << 8) | d[i], ((uint64_t)i << 8) | want);
        }
        hash(d, 1024);

        // A texture: its upload (replaceRegion), a blit from a buffer into
        // part of it, its read back (getBytes), and a blit of it into a
        // buffer. RGBA8Unorm texels are their bytes.
        enum { W = 32, H = 16 };
        MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:W height:H mipmapped:NO];
        td.storageMode = MTLStorageModeShared;
        td.usage = MTLTextureUsageShaderRead;
        id<MTLTexture> tex = [device newTextureWithDescriptor:td];
        if (!tex) return bad("a texture", 0, 1);
        static uint8_t up[H][W][4], back[H][W][4], want[H][W][4];
        for (int y = 0; y < H; y++)
            for (int x = 0; x < W; x++)
                for (int c = 0; c < 4; c++)
                    up[y][x][c] = want[y][x][c] = (uint8_t)(x * 8 + y * 3 + c * 61);
        [tex replaceRegion:MTLRegionMake2D(0, 0, W, H) mipmapLevel:0 withBytes:up bytesPerRow:W * 4];
        id<MTLBuffer> patch = [device newBufferWithLength:8 * 4 * 4 options:MTLResourceStorageModeShared];
        uint8_t *p = patch.contents;
        for (int i = 0; i < 8 * 4 * 4; i++) p[i] = (uint8_t)(0xf0 ^ i);
        for (int y = 0; y < 4; y++)
            for (int x = 0; x < 8; x++)
                memcpy(want[5 + y][10 + x], p + (y * 8 + x) * 4, 4);
        id<MTLBuffer> readback = [device newBufferWithLength:W * H * 4 options:MTLResourceStorageModeShared];
        cb = [queue commandBuffer];
        be = [cb blitCommandEncoder];
        [be copyFromBuffer:patch sourceOffset:0 sourceBytesPerRow:8 * 4 sourceBytesPerImage:8 * 4 * 4 sourceSize:MTLSizeMake(8, 4, 1)
                 toTexture:tex destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(10, 5, 0)];
        [be copyFromTexture:tex sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(W, H, 1)
                   toBuffer:readback destinationOffset:0 destinationBytesPerRow:W * 4 destinationBytesPerImage:W * H * 4];
        [be endEncoding];
        if (run(cb, "the texture blits")) return 1;
        // (The slice form, with no image stride for a 2D texture: the
        // plugin's short form passes one, as IOGPU's does, which the
        // executor refuses as Metal leaves it undefined.)
        [tex getBytes:back bytesPerRow:W * 4 bytesPerImage:0 fromRegion:MTLRegionMake2D(0, 0, W, H) mipmapLevel:0 slice:0];
        if (memcmp(back, want, sizeof want) != 0) return bad("the texture read back", 0, 1);
        if (memcmp(readback.contents, want, sizeof want) != 0) return bad("the texture blitted into a buffer", 0, 1);
        hash(back, sizeof back);
        hash(readback.contents, sizeof want);

        // An IOSurface's texture (IOSurfaceRef.h: the CPU's accesses are
        // between IOSurfaceLock and IOSurfaceUnlock). The GPU reads what
        // the CPU wrote under its lock, the CPU sees the GPU's writes at its
        // next lock, and the GPU sees the CPU's next writes.
        enum { SW = 16, SH = 8 };
        NSDictionary *props = @{
            (id)kIOSurfaceWidth: @(SW),
            (id)kIOSurfaceHeight: @(SH),
            (id)kIOSurfaceBytesPerElement: @4,
            (id)kIOSurfacePixelFormat: @((uint32_t)'BGRA'),
        };
        IOSurfaceRef surface = IOSurfaceCreate((__bridge CFDictionaryRef)props);
        if (!surface) return bad("an IOSurface", 0, 1);
        size_t bpr = IOSurfaceGetBytesPerRow(surface);
        uint8_t *base = IOSurfaceGetBaseAddress(surface);
        static uint8_t cpu[SH][SW][4], seen[SH][SW][4];
        for (int y = 0; y < SH; y++)
            for (int x = 0; x < SW; x++)
                for (int c = 0; c < 4; c++)
                    cpu[y][x][c] = (uint8_t)(y * 29 + x * 5 + c * 77);
        IOSurfaceLock(surface, 0, NULL);
        for (int y = 0; y < SH; y++) memcpy(base + y * bpr, cpu[y], SW * 4);
        IOSurfaceUnlock(surface, 0, NULL);
        MTLTextureDescriptor *sd = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:SW height:SH mipmapped:NO];
        sd.storageMode = MTLStorageModeShared;
        sd.usage = MTLTextureUsageShaderRead;
        id<MTLTexture> stex = [device newTextureWithDescriptor:sd iosurface:surface plane:0];
        if (!stex) return bad("a texture over the IOSurface", 0, 1);
        id<MTLBuffer> first = [device newBufferWithLength:SW * SH * 4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> spatch = [device newBufferWithLength:4 * 2 * 4 options:MTLResourceStorageModeShared];
        uint8_t *sp = spatch.contents;
        for (int i = 0; i < 4 * 2 * 4; i++) sp[i] = (uint8_t)(0x3c + i * 9);
        cb = [queue commandBuffer];
        be = [cb blitCommandEncoder];
        [be copyFromTexture:stex sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(SW, SH, 1)
                   toBuffer:first destinationOffset:0 destinationBytesPerRow:SW * 4 destinationBytesPerImage:SW * SH * 4];
        [be copyFromBuffer:spatch sourceOffset:0 sourceBytesPerRow:4 * 4 sourceBytesPerImage:4 * 2 * 4 sourceSize:MTLSizeMake(4, 2, 1)
                 toTexture:stex destinationSlice:0 destinationLevel:0 destinationOrigin:MTLOriginMake(6, 3, 0)];
        [be endEncoding];
        if (run(cb, "the IOSurface texture's blits")) return 1;
        if (memcmp(first.contents, cpu, sizeof cpu) != 0) return bad("the CPU's IOSurface bytes as the GPU read them", 0, 1);
        for (int y = 0; y < 2; y++)
            for (int x = 0; x < 4; x++)
                memcpy(cpu[3 + y][6 + x], sp + (y * 4 + x) * 4, 4);
        IOSurfaceLock(surface, kIOSurfaceLockReadOnly, NULL);
        for (int y = 0; y < SH; y++) memcpy(seen[y], base + y * bpr, SW * 4);
        IOSurfaceUnlock(surface, kIOSurfaceLockReadOnly, NULL);
        if (memcmp(seen, cpu, sizeof cpu) != 0) return bad("the GPU's IOSurface writes as the CPU locked them", 0, 1);
        hash(first.contents, sizeof cpu);
        hash(seen, sizeof seen);
        IOSurfaceLock(surface, 0, NULL);
        for (int y = 0; y < SH; y++)
            for (int x = 0; x < SW; x++) {
                cpu[y][x][0] ^= 0xff;
                memcpy(base + y * bpr + x * 4, cpu[y][x], 4);
            }
        IOSurfaceUnlock(surface, 0, NULL);
        id<MTLBuffer> second = [device newBufferWithLength:SW * SH * 4 options:MTLResourceStorageModeShared];
        cb = [queue commandBuffer];
        be = [cb blitCommandEncoder];
        [be copyFromTexture:stex sourceSlice:0 sourceLevel:0 sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(SW, SH, 1)
                   toBuffer:second destinationOffset:0 destinationBytesPerRow:SW * 4 destinationBytesPerImage:SW * SH * 4];
        [be endEncoding];
        if (run(cb, "the IOSurface texture's second read")) return 1;
        if (memcmp(second.contents, cpu, sizeof cpu) != 0) return bad("the CPU's second IOSurface writes as the GPU read them", 0, 1);
        hash(second.contents, sizeof cpu);
        CFRelease(surface);

        printf("metal %s %016llx\n", NSStringFromClass([(id)device class]).UTF8String, (unsigned long long)digest);
    }
    return 0;
}
