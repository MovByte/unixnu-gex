#!/bin/sh
# Build the Darwin test programs with Xcode's iOS toolchain into bin/.
#
# The static programs make raw system calls and need neither dyld nor a
# shared cache. They are linked where gex places a position-independent
# Darwin program (gex_ld::macho::PIE_BASE), above its dispatch tables and
# the shared region, because a static image has no fixups to slide it with.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
OUT=$HERE/bin
TARGET=${GEX_DARWIN_TARGET:-arm64-apple-ios17.0}
STATIC_BASE=0x280000000
mkdir -p "$OUT"

cc() {
    xcrun -sdk iphoneos clang -target "$TARGET" "$@"
}

for p in hello-static bsd-carry commpage exclusive-pair; do
    cc -O2 -ffreestanding -fno-stack-protector -nostdlib -static \
        -Wl,-e,_start -Wl,-image_base,$STATIC_BASE \
        -o "$OUT/$p" "$HERE/src/$p.c"
done

cc -O2 -o "$OUT/hello" "$HERE/src/hello.c"

echo "built: $(cd "$OUT" && ls | tr '\n' ' ')"
