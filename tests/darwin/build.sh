#!/bin/sh
# Build the Darwin test programs with Xcode's iOS toolchain into bin/.
#
# The static programs make raw system calls and need neither dyld nor a
# shared cache. A static image has no fixups to slide it with, so exec
# loads it where it was linked: the linker's default, after a 4 GiB
# __PAGEZERO.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
OUT=$HERE/bin
TARGET=${GEX_DARWIN_TARGET:-arm64-apple-ios17.0}
mkdir -p "$OUT"

cc() {
    xcrun -sdk iphoneos clang -target "$TARGET" "$@"
}

for p in hello-static bsd-carry commpage exclusive-pair aes; do
    cc -O2 -ffreestanding -fno-stack-protector -nostdlib -static \
        -Wl,-e,_start -o "$OUT/$p" "$HERE/src/$p.c"
done

for p in hello pthread dispatch dispatch-signal sighandler kq-pipe pipe ioctl lockf fsops sigthread sigio vnode codesig rlimit apple exec spawn wait sigchld procknote fork jobctl setexec taskpolicy priority threadpolicy poll itimer threadsuspend threadstate tasksuspend portrefs crosstask spawnports taskname excports pages mmapflags madvise memlimit excdeliver startsusp readports taskthreads amfi policy creds uniqueid procinfo persona killperm exitreason sigwait pagezero cputime vtimer protect efault procpolicy cpumon nocldwait boottime timebase sysctlnodes kernproc vmregion msync rlimitctl xattr fileport guarded vectored pathconf mlock fdinfo setattr vmcopy sockevent thcwd clone renameswap pidhold fixedcalls sockerr select filesec psem aio statino statfsino dirino workinterval eventlink voucherx circular importance lockimp coalition spawnfa watchport ipcfd fpinfo openmode pshared lastclose setexecbad sockname machclock atmflag timeouts wlqos halfclose vnextend procmask guardesc rcvlarge extractright sonce vmwx sockopts pathrules pty ptyjob ptyclose bsdpty devfs devattr loadavg ttyinfo hoststat ttydead fcntltty nosigpipe realdev ttydrain revoke dgrambuf streambuf jit xpc-anon sbxinit sbxexec sbxkill hostspecial sbxmask sbxnet sbxpriv sbxfile layout; do
    cc -O2 -o "$OUT/$p" "$HERE/src/$p.c"
done
cc -O2 -framework CoreFoundation -o "$OUT/cfrunloop" "$HERE/src/cfrunloop.c"
# stackfb: an LC_MAIN stack of 1.75 GiB, which ld will not write (it caps
# arm64 at 512 MB) but exec takes, written into the command.
cc -O2 -o "$OUT/stackfb" "$HERE/src/stackfb.c"
python3 -I - "$OUT/stackfb" <<'EOF2'
import struct, sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
ncmds = struct.unpack_from('<I', b, 16)[0]
o = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', b, o)
    if cmd == 0x80000028:
        struct.pack_into('<Q', b, o + 16, 0x70000000)
        break
    o += size
else:
    sys.exit('no LC_MAIN in ' + p)
open(p, 'wb').write(b)
EOF2
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/iokit" "$HERE/src/iokit.c"
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/ioreg" "$HERE/src/ioreg.c"
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/accel" "$HERE/src/accel.c"
cc -O2 -framework IOKit -framework IOSurface -framework CoreFoundation -o "$OUT/iosurface" "$HERE/src/iosurface.c"
cc -O2 -framework IOSurface -framework CoreFoundation -o "$OUT/iosurfacex" "$HERE/src/iosurfacex.c"
cc -O2 -framework IOKit -framework IOSurface -framework CoreFoundation -o "$OUT/iogpudev" "$HERE/src/iogpudev.c"
# metalwire: WebMetal's wire records, from its generated header (the pinned
# submodule's).
xcrun -sdk iphoneos clang++ -target "$TARGET" -std=c++17 -O2 -I "$HERE/../../third_party/WebMetal/wire/generated" \
    -framework IOKit -framework CoreFoundation -o "$OUT/metalwire" "$HERE/src/metalwire.cpp"
# metal: Metal through the root's Metal.framework, with its kernel compiled
# by Xcode's Metal toolchain into a metallib linked in as a section (made
# in a directory of its own: the runner trusts every file of bin/).
mkdir -p "$OUT/metallib"
xcrun -sdk iphoneos metal -std=ios-metal2.4 -c -o "$OUT/metallib/metal.air" "$HERE/src/metal.metal"
xcrun -sdk iphoneos metallib -o "$OUT/metallib/metal.metallib" "$OUT/metallib/metal.air"
cc -O2 -fobjc-arc -framework Foundation -framework IOSurface -framework Metal -Wl,-sectcreate,__DATA,__metallib,"$OUT/metallib/metal.metallib" \
    -o "$OUT/metal" "$HERE/src/metal.m"
# iosurfacesplash and iosurfacexpreboard: iosurface as splashboardd and
# iosurfacex as PreBoard, outside the container.
cc -O2 -framework IOKit -framework IOSurface -framework CoreFoundation -o "$OUT/iosurfacesplash" "$HERE/src/iosurface.c"
cc -O2 -framework IOSurface -framework CoreFoundation -o "$OUT/iosurfacexpreboard" "$HERE/src/iosurfacex.c"
cc -O2 -framework IOKit -framework CoreFoundation -o "$OUT/sbxiokit" "$HERE/src/sbxiokit.c"
# sbxscrub: sbxfile's directory times, in a task that may run any cdhash.
cc -O2 -o "$OUT/sbxscrub" "$HERE/src/sbxfile.c"
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
# theirs, and those signed as a system program hold only its.
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
codesign -s - -f --entitlements "$HERE/src/sbxscrub.entitlements" "$OUT/sbxscrub" 2>/dev/null
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
# The IOSurface programs outside the container are signed as system
# programs whose iokit-user-client-class entitlement names
# IOSurfaceRootUserClient are, with their identifiers and entitlements:
# /usr/libexec/splashboardd's, and for iosurfacex, which spawns a copy of
# itself from /private/var, /Applications/PreBoard.app's, which hold
# no-sandbox.
codesign -s - -f -i com.apple.splashboardd --entitlements "$HERE/src/splashboardd.entitlements" "$OUT/iosurfacesplash" 2>/dev/null
codesign -s - -f -i com.apple.PreBoard --entitlements "$HERE/src/preboard.entitlements" "$OUT/iosurfacexpreboard" 2>/dev/null
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
