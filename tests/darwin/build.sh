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

for p in hello pthread dispatch dispatch-signal sighandler kq-pipe pipe ioctl lockf fsops sigthread sigio vnode codesig rlimit apple exec spawn wait sigchld procknote fork jobctl setexec taskpolicy priority threadpolicy poll itimer threadsuspend threadstate tasksuspend portrefs crosstask spawnports taskname excports pages mmapflags madvise memlimit excdeliver startsusp readports taskthreads amfi policy creds uniqueid procinfo persona killperm exitreason sigwait pagezero cputime vtimer protect efault procpolicy cpumon nocldwait boottime timebase jit xpc-anon; do
    cc -O2 -o "$OUT/$p" "$HERE/src/$p.c"
done
cc -O2 -framework CoreFoundation -o "$OUT/cfrunloop" "$HERE/src/cfrunloop.c"
# amfi's: a program in no trust cache, and one holding get-task-allow.
cc -O2 -o "$OUT/untrusted" "$HERE/src/hello.c"
cc -O2 -o "$OUT/gta" "$HERE/src/hello.c"
# exec's images: an arm64e slice (no pointer authentication on this CPU).
xcrun -sdk iphoneos clang -target arm64e-apple-ios17.0 -O2 -o "$OUT/hello-arm64e" "$HERE/src/hello.c"
# Every iOS program is signed (the linker leaves one unsigned): ad hoc,
# for the run's trust cache to hold. memlimit sets its own memory limit,
# which memorystatus allows an entitled task.
for f in "$OUT"/*; do
    if [ -f "$f" ]; then
        codesign -s - -f "$f" 2>/dev/null
    fi
done
codesign -s - -f --entitlements "$HERE/src/memlimit.entitlements" "$OUT/memlimit" 2>/dev/null
codesign -s - -f --entitlements "$HERE/src/gta.entitlements" "$OUT/gta" 2>/dev/null
# persona manages personas, which takes the persona manager's entitlement.
codesign -s - -f --entitlements "$HERE/src/persona.entitlements" "$OUT/persona" 2>/dev/null
# killperm spawns into a persona to have another user's process.
codesign -s - -f --entitlements "$HERE/src/persona.entitlements" "$OUT/killperm" 2>/dev/null
# jit maps a JIT region: dynamic-codesigning for AMFI, and for the platform
# profile one of the signing identifiers it lets generate code (XNU's jitbox).
codesign -s - -f -i com.apple.test.xnu.jitbox --entitlements "$HERE/src/jit.entitlements" "$OUT/jit" 2>/dev/null
# The exception tests set handlers of every behavior: a platform program
# (a hardened one) may only with the entitlement that allows it.
for p in excports excdeliver readports; do
    codesign -s - -f --entitlements "$HERE/src/exc.entitlements" "$OUT/$p" 2>/dev/null
done
# A fat file of the arm64e slice and the arm64 one exec picks.
lipo -create "$OUT/hello" "$OUT/hello-arm64e" -output "$OUT/hello-fat"

echo "built: $(cd "$OUT" && ls | tr '\n' ' ')"
