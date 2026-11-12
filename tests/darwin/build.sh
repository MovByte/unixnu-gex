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

for p in hello pthread dispatch dispatch-signal sighandler kq-pipe pipe ioctl lockf fsops sigthread sigio vnode codesig rlimit apple exec spawn wait sigchld procknote fork jobctl setexec taskpolicy priority threadpolicy poll itimer threadsuspend threadstate tasksuspend portrefs crosstask spawnports taskname excports pages mmapflags madvise memlimit excdeliver startsusp readports taskthreads amfi policy creds uniqueid procinfo persona killperm exitreason sigwait pagezero cputime vtimer protect efault procpolicy cpumon nocldwait boottime timebase sysctlnodes kernproc vmregion msync rlimitctl xattr fileport guarded vectored pathconf mlock fdinfo setattr vmcopy sockevent thcwd clone renameswap pidhold fixedcalls sockerr select filesec psem aio statino statfsino dirino workinterval eventlink voucherx circular importance lockimp coalition spawnfa watchport ipcfd fpinfo openmode pshared lastclose setexecbad sockname machclock atmflag timeouts wlqos halfclose vnextend procmask guardesc rcvlarge extractright sonce vmwx sockopts pathrules pty ptyjob ptyclose bsdpty devfs devattr loadavg ttyinfo hoststat ttydead fcntltty nosigpipe realdev ttydrain revoke dgrambuf streambuf jit xpc-anon sbxinit sbxexec sbxkill hostspecial sbxmask sbxnet; do
    cc -O2 -o "$OUT/$p" "$HERE/src/$p.c"
done
cc -O2 -framework CoreFoundation -o "$OUT/cfrunloop" "$HERE/src/cfrunloop.c"
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/iokit" "$HERE/src/iokit.c"
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/ioreg" "$HERE/src/ioreg.c"
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/accel" "$HERE/src/accel.c"
# accelr: accel in a task entitled to be a restricted GPU client.
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/accelr" "$HERE/src/accel.c"
# amfi's: a program in no trust cache, and one holding get-task-allow.
cc -O2 -o "$OUT/untrusted" "$HERE/src/hello.c"
cc -O2 -o "$OUT/gta" "$HERE/src/hello.c"
# sbxkill's children, which their entitlements have Sandbox kill.
for p in sbxstacked sbxnotstr sbxunknown; do
    cc -O2 -o "$OUT/$p" "$HERE/src/sbxchild.c"
done
# exec's images: an arm64e slice (no pointer authentication on this CPU).
xcrun -sdk iphoneos clang -target arm64e-apple-ios17.0 -O2 -o "$OUT/hello-arm64e" "$HERE/src/hello.c"
# Every iOS program is signed (the linker leaves one unsigned): ad hoc,
# for the run's trust cache to hold. Those the suite runs from /private/var
# hold com.apple.private.security.no-container (default.entitlements, and
# every other entitlements file here but the sbx ones): the platform
# profile's process-exec* refuses a caller without it (or no-sandbox) the
# exec of a file under /private/var, as on a device, and these programs
# exec copies of themselves and files they write there. The static programs
# run from this directory and exec nothing. sbxexec's entitlements and
# sbxkill's children's are what those tests are about, so they hold only
# theirs.
for f in "$OUT"/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
    hello-static | bsd-carry | commpage | exclusive-pair | aes) codesign -s - -f "$f" 2>/dev/null ;;
    *) codesign -s - -f --entitlements "$HERE/src/default.entitlements" "$f" 2>/dev/null ;;
    esac
done
# memlimit sets its own memory limit, which memorystatus allows an entitled
# task.
codesign -s - -f --entitlements "$HERE/src/memlimit.entitlements" "$OUT/memlimit" 2>/dev/null
codesign -s - -f --entitlements "$HERE/src/gta.entitlements" "$OUT/gta" 2>/dev/null
# persona manages personas, which takes the persona manager's entitlement.
codesign -s - -f --entitlements "$HERE/src/persona.entitlements" "$OUT/persona" 2>/dev/null
# killperm spawns into a persona to have another user's process.
codesign -s - -f --entitlements "$HERE/src/persona.entitlements" "$OUT/killperm" 2>/dev/null
# jit maps a JIT region: dynamic-codesigning for AMFI, and for the platform
# profile one of the signing identifiers it lets generate code (XNU's jitbox).
codesign -s - -f -i com.apple.test.xnu.jitbox --entitlements "$HERE/src/jit.entitlements" "$OUT/jit" 2>/dev/null
# workinterval creates work intervals, which PRIV_WORK_INTERVAL grants by
# its entitlement.
codesign -s - -f --entitlements "$HERE/src/workinterval.entitlements" "$OUT/workinterval" 2>/dev/null
# accelr's IOGPU device client is restricted by its entitlement.
codesign -s - -f --entitlements "$HERE/src/gpurestricted.entitlements" "$OUT/accelr" 2>/dev/null
# atmflag sets the ATM diagnostic flag, which its entitlement allows.
codesign -s - -f --entitlements "$HERE/src/atmflag.entitlements" "$OUT/atmflag" 2>/dev/null
# hostspecial sets the telemetry port, which launchd's event monitor may.
codesign -s - -f --entitlements "$HERE/src/hostspecial.entitlements" "$OUT/hostspecial" 2>/dev/null
# sbxexec's seatbelt-profiles entitlement names the builtin profile its exec
# gives it; sbxkill's children name two, a number, and an unknown name.
for p in sbxexec sbxstacked sbxnotstr sbxunknown; do
    codesign -s - -f --entitlements "$HERE/src/$p.entitlements" "$OUT/$p" 2>/dev/null
done
# The exception tests set handlers of every behavior: a platform program
# (a hardened one) may only with the entitlement that allows it.
for p in excports excdeliver readports; do
    codesign -s - -f --entitlements "$HERE/src/exc.entitlements" "$OUT/$p" 2>/dev/null
done
# A fat file of the arm64e slice and the arm64 one exec picks.
lipo -create "$OUT/hello" "$OUT/hello-arm64e" -output "$OUT/hello-fat"

echo "built: $(cd "$OUT" && ls | tr '\n' ' ')"
