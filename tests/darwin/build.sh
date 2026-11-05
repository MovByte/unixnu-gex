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

for p in hello-static bsd-carry commpage exclusive-pair aes; do
    cc -O2 -ffreestanding -fno-stack-protector -nostdlib -static \
        -Wl,-e,_start -Wl,-image_base,$STATIC_BASE \
        -o "$OUT/$p" "$HERE/src/$p.c"
done

for p in hello pthread dispatch dispatch-signal sighandler kq-pipe pipe ioctl lockf fsops sigthread sigio vnode codesig rlimit apple exec spawn wait sigchld procknote fork jobctl setexec taskpolicy priority threadpolicy poll itimer threadsuspend threadstate xpc-anon; do
    cc -O2 -o "$OUT/$p" "$HERE/src/$p.c"
done
cc -O2 -framework CoreFoundation -o "$OUT/cfrunloop" "$HERE/src/cfrunloop.c"
# codesig reads its own signature: signed ad hoc, as the linker leaves an
# iOS program unsigned.
codesign -s - -f "$OUT/codesig" 2>/dev/null
# apple checks the cdhash exec hands it: signed as every iOS program is.
codesign -s - -f "$OUT/apple" 2>/dev/null
# exec's images: an arm64e slice (no pointer authentication on this CPU),
# and a fat file of it and the arm64 one exec picks.
xcrun -sdk iphoneos clang -target arm64e-apple-ios17.0 -O2 -o "$OUT/hello-arm64e" "$HERE/src/hello.c"
lipo -create "$OUT/hello" "$OUT/hello-arm64e" -output "$OUT/hello-fat"

echo "built: $(cd "$OUT" && ls | tr '\n' ' ')"
