// The kernel tests/darwin/src/metal.m dispatches.
#include <metal_stdlib>
using namespace metal;

kernel void metal_mad(device const uint *a [[buffer(0)]],
                      device const uint *b [[buffer(1)]],
                      device uint *out [[buffer(2)]],
                      uint i [[thread_position_in_grid]])
{
    out[i] = a[i] * 2654435761u + (b[i] ^ (i << 3));
}
