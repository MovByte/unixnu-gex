#!/bin/sh
# Run the Darwin programs under gexc and check what each prints and how it
# exits. Builds them first when bin/ is missing; GEXC picks the runner.
# With program names, only those run; without, all of them.
#
# A dynamic program needs a Darwin root (GEX_DARWIN_ROOT: dyld and the
# shared cache, as UniXNU's webroot lays them out) and runs from inside it.
# Without one it is skipped, or fails when it was asked for by name.
#
# The system boots with the device's payload (GEX_DARWIN_BOOT: its trust
# cache bundle and the Sandbox's platform profile and profile collections)
# with these programs' cdhashes added to its static trust cache, as an
# owner adds their own code: AMFI runs only trusted code.
set -u

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/../.." && pwd)
GEXC=${GEXC:-$ROOT/target/release/gexc}
[ -d "$HERE/bin" ] || "$HERE/build.sh" >/dev/null

BOOT=$HERE/bin/boot
mkdir -p "$BOOT"
# (untrusted is the one left out. bin may be a link to where the build
# keeps them, which find follows with -H.)
progs=$(find -H "$HERE/bin" -maxdepth 1 -type f ! -name untrusted | sort)
if [ -n "${GEX_DARWIN_BOOT:-}" ]; then
    # shellcheck disable=SC2086
    python3 -I "$ROOT/tools/darwin-trust-cache.py" -o "$BOOT/TrustCache" --bundle "$GEX_DARWIN_BOOT/TrustCache" $progs || exit 1
else
    # shellcheck disable=SC2086
    python3 -I "$ROOT/tools/darwin-trust-cache.py" -o "$BOOT/TrustCache" $progs || exit 1
fi
if [ -n "${GEX_DARWIN_BOOT:-}" ] && [ -f "$GEX_DARWIN_BOOT/DeviceTree" ]; then
    cp "$GEX_DARWIN_BOOT/DeviceTree" "$BOOT/"
fi
for f in sandbox_profile.bin sandbox_builtin.bin sandbox_protobox.bin; do
    if [ -n "${GEX_DARWIN_BOOT:-}" ] && [ -f "$GEX_DARWIN_BOOT/$f" ]; then
        cp "$GEX_DARWIN_BOOT/$f" "$BOOT/"
    fi
done
export GEX_DARWIN_BOOT="$BOOT"

fail=0
named=$#

report() {
    name=$1 out=$2 status=$3 want_out=$4 want_status=$5
    if [ "$out" = "$want_out" ] && [ "$status" -eq "$want_status" ]; then
        echo "PASS $name"
    else
        echo "FAIL $name: status $status (want $want_status), output: $out"
        fail=1
    fi
}

check() {
    name=$1 want_out=$2 want_status=$3
    out=$("$GEXC" run "$HERE/bin/$name" 2>/dev/null)
    report "$name" "$out" $? "$want_out" "$want_status"
}

# check_root NAME WANT_OUT WANT_STATUS [ARGS...]: a dynamic program, run
# from the root's /var/tmp.
check_root() {
    name=$1 want_out=$2 want_status=$3
    shift 3
    if [ -z "${GEX_DARWIN_ROOT:-}" ]; then
        if [ "$named" -gt 0 ]; then
            echo "FAIL $name: no Darwin root (set GEX_DARWIN_ROOT)"
            fail=1
        else
            echo "SKIP $name (set GEX_DARWIN_ROOT)"
        fi
        return
    fi
    mkdir -p "$GEX_DARWIN_ROOT/var/tmp"
    cp "$HERE/bin/$name" "$GEX_DARWIN_ROOT/var/tmp/gex-darwin-$name"
    out=$("$GEXC" run --sysroot "$GEX_DARWIN_ROOT" "$GEX_DARWIN_ROOT/var/tmp/gex-darwin-$name" "$@" 2>/dev/null)
    report "$name" "$out" $? "$want_out" "$want_status"
}

run() {
    case $1 in
    hello-static) check hello-static "hello from darwin" 0 ;;
    bsd-carry) check bsd-carry "carry ok" 0 ;;
    commpage) check commpage "" 0 ;;
    exclusive-pair) check exclusive-pair "" 0 ;;
    aes) check aes "" 0 ;;
    hello) check_root hello "hello from /var/tmp/gex-darwin-hello with 2 arguments" 0 a b ;;
    pthread) check_root pthread "pthread 4000" 0 ;;
    dispatch) check_root dispatch "dispatch 55 140" 0 ;;
    dispatch-signal) check_root dispatch-signal "dispatch-signal 2" 0 ;;
    sighandler) check_root sighandler "sighandler 3" 0 ;;
    kq-pipe) check_root kq-pipe "kq-pipe 7" 0 ;;
    pipe) check_root pipe "pipe ok" 0 ;;
    ioctl) check_root ioctl "ioctl ok" 0 ;;
    lockf) check_root lockf "lockf ok" 0 ;;
    fsops) check_root fsops "fsops ok" 0 ;;
    sigthread) check_root sigthread "sigthread ok" 0 ;;
    sigio) check_root sigio "sigio ok" 0 ;;
    vnode) check_root vnode "vnode ok" 0 ;;
    codesig) check_root codesig "codesig ok" 0 ;;
    rlimit) check_root rlimit "rlimit ok" 0 ;;
    apple) check_root apple "apple ok" 0 ;;
    exec)
        if [ -n "${GEX_DARWIN_ROOT:-}" ]; then
            mkdir -p "$GEX_DARWIN_ROOT/var/tmp"
            cp "$HERE/bin/hello-fat" "$GEX_DARWIN_ROOT/var/tmp/gex-exec-fat"
            cp "$HERE/bin/hello-arm64e" "$GEX_DARWIN_ROOT/var/tmp/gex-exec-arm64e"
        fi
        check_root exec "exec ok
hello from /var/tmp/gex-exec-fat with 1 argument" 0
        ;;
    spawn)
        if [ -n "${GEX_DARWIN_ROOT:-}" ]; then
            mkdir -p "$GEX_DARWIN_ROOT/var/tmp"
            cp "$HERE/bin/hello-fat" "$GEX_DARWIN_ROOT/var/tmp/gex-spawn-fat"
        fi
        check_root spawn "spawn ok" 0
        ;;
    wait) check_root wait "wait ok" 0 ;;
    sigchld) check_root sigchld "sigchld ok" 0 ;;
    procknote) check_root procknote "procknote ok" 0 ;;
    fork) check_root fork "fork ok" 0 ;;
    jobctl) check_root jobctl "jobctl ok" 0 ;;
    setexec) check_root setexec "setexec ok" 0 ;;
    taskpolicy) check_root taskpolicy "taskpolicy ok" 0 ;;
    priority) check_root priority "priority ok" 0 ;;
    threadpolicy) check_root threadpolicy "threadpolicy ok" 0 ;;
    poll) check_root poll "poll ok" 0 ;;
    itimer) check_root itimer "itimer ok" 0 ;;
    threadsuspend) check_root threadsuspend "threadsuspend ok" 0 ;;
    threadstate) check_root threadstate "threadstate ok" 0 ;;
    tasksuspend) check_root tasksuspend "tasksuspend ok" 0 ;;
    portrefs) check_root portrefs "portrefs ok" 0 ;;
    crosstask) check_root crosstask "crosstask ok" 0 ;;
    spawnports) check_root spawnports "spawnports ok" 0 ;;
    taskname) check_root taskname "taskname ok" 0 ;;
    excports) check_root excports "excports ok" 0 ;;
    pages) check_root pages "pages ok" 0 ;;
    mmapflags) check_root mmapflags "mmapflags ok" 0 ;;
    madvise) check_root madvise "madvise ok" 0 ;;
    memlimit) check_root memlimit "memlimit ok" 0 ;;
    excdeliver) check_root excdeliver "excdeliver ok" 0 ;;
    startsusp) check_root startsusp "startsusp ok" 0 ;;
    readports) check_root readports "readports ok" 0 ;;
    taskthreads) check_root taskthreads "taskthreads ok" 0 ;;
    policy) check_root policy "policy ok" 0 ;;
    creds) check_root creds "creds ok" 0 ;;
    uniqueid) check_root uniqueid "uniqueid ok" 0 ;;
    procinfo) check_root procinfo "procinfo ok" 0 ;;
    persona) check_root persona "persona ok" 0 ;;
    killperm) check_root killperm "killperm ok" 0 ;;
    exitreason) check_root exitreason "exitreason ok" 0 ;;
    sigwait) check_root sigwait "sigwait ok" 0 ;;
    pagezero) check_root pagezero "pagezero ok" 0 ;;
    cputime) check_root cputime "cputime ok" 0 ;;
    vtimer) check_root vtimer "vtimer ok" 0 ;;
    protect) check_root protect "protect ok" 0 ;;
    efault) check_root efault "efault ok" 0 ;;
    procpolicy) check_root procpolicy "procpolicy ok" 0 ;;
    cpumon) check_root cpumon "cpumon ok" 0 ;;
    nocldwait) check_root nocldwait "nocldwait ok" 0 ;;
    boottime) check_root boottime "boottime ok" 0 ;;
    timebase) check_root timebase "timebase ok" 0 ;;
    sysctlnodes) check_root sysctlnodes "sysctlnodes ok" 0 ;;
    kernproc) check_root kernproc "kernproc ok" 0 ;;
    vmregion) check_root vmregion "vmregion ok" 0 ;;
    msync) check_root msync "msync ok" 0 ;;
    rlimitctl) check_root rlimitctl "rlimitctl ok" 0 ;;
    iokit) check_root iokit "iokit ok" 0 ;;
    machclock) check_root machclock "machclock ok" 0 ;;
    atmflag) check_root atmflag "atmflag ok" 0 entitled ;;
    timeouts) check_root timeouts "timeouts ok" 0 ;;
    wlqos) check_root wlqos "wlqos ok" 0 ;;
    halfclose) check_root halfclose "halfclose ok" 0 ;;
    vnextend) check_root vnextend "vnextend ok" 0 ;;
    procmask) check_root procmask "procmask ok" 0 ;;
    guardesc) check_root guardesc "guardesc ok" 0 ;;
    rcvlarge) check_root rcvlarge "rcvlarge ok" 0 ;;
    extractright) check_root extractright "extractright ok" 0 ;;
    sonce) check_root sonce "sonce ok" 0 ;;
    vmwx) check_root vmwx "vmwx ok" 0 ;;
    sockopts) check_root sockopts "sockopts ok" 0 ;;
    pathrules) check_root pathrules "pathrules ok" 0 ;;
    pty) check_root pty "pty ok" 0 ;;
    ptyjob) check_root ptyjob "ptyjob ok" 0 ;;
    ptyclose) check_root ptyclose "ptyclose ok" 0 ;;
    bsdpty) check_root bsdpty "bsdpty ok" 0 ;;
    devfs) check_root devfs "devfs ok" 0 ;;
    devattr) check_root devattr "devattr ok" 0 ;;
    loadavg) check_root loadavg "loadavg ok" 0 ;;
    ttyinfo) check_root ttyinfo "ttyinfo ok" 0 ;;
    hoststat) check_root hoststat "hoststat ok" 0 ;;
    ttydead) check_root ttydead "ttydead ok" 0 ;;
    fcntltty) check_root fcntltty "fcntltty ok" 0 ;;
    nosigpipe) check_root nosigpipe "nosigpipe ok" 0 ;;
    realdev) check_root realdev "realdev ok" 0 ;;
    ttydrain) check_root ttydrain "ttydrain ok" 0 ;;
    revoke) check_root revoke "revoke ok" 0 ;;
    dgrambuf) check_root dgrambuf "dgrambuf ok" 0 ;;
    streambuf) check_root streambuf "streambuf ok" 0 ;;
    ioreg) check_root ioreg "ioreg ok" 0 ;;
    accel) check_root accel "accel ok" 0 ;;
    accelr) check_root accelr "accel ok" 0 restricted ;;
    iosurface) check_root iosurface "iosurface ok" 0 ;;
    iosurfacex) check_root iosurfacex "iosurfacex ok" 0 ;;
    iogpudev) check_root iogpudev "iogpudev ok" 0 ;;
    xattr) check_root xattr "xattr ok" 0 ;;
    fileport) check_root fileport "fileport ok" 0 ;;
    guarded) check_root guarded "guarded ok" 0 ;;
    vectored) check_root vectored "vectored ok" 0 ;;
    pathconf) check_root pathconf "pathconf ok" 0 ;;
    mlock) check_root mlock "mlock ok" 0 ;;
    fdinfo) check_root fdinfo "fdinfo ok" 0 ;;
    setattr) check_root setattr "setattr ok" 0 ;;
    vmcopy) check_root vmcopy "vmcopy ok" 0 ;;
    sockevent) check_root sockevent "sockevent ok" 0 ;;
    thcwd) check_root thcwd "thcwd ok" 0 ;;
    clone) check_root clone "clone ok" 0 ;;
    renameswap) check_root renameswap "renameswap ok" 0 ;;
    pidhold) check_root pidhold "pidhold ok" 0 ;;
    fixedcalls) check_root fixedcalls "fixedcalls ok" 0 ;;
    sockerr) check_root sockerr "sockerr ok" 0 ;;
    select) check_root select "select ok" 0 ;;
    filesec) check_root filesec "filesec ok" 0 ;;
    psem) check_root psem "psem ok" 0 ;;
    aio) check_root aio "aio ok" 0 ;;
    statino) check_root statino "statino ok" 0 ;;
    statfsino) check_root statfsino "statfsino ok" 0 ;;
    dirino) check_root dirino "dirino ok" 0 ;;
    workinterval) check_root workinterval "workinterval ok" 0 ;;
    eventlink) check_root eventlink "eventlink ok" 0 ;;
    voucherx) check_root voucherx "voucherx ok" 0 ;;
    circular) check_root circular "circular ok" 0 ;;
    importance) check_root importance "importance ok" 0 ;;
    lockimp) check_root lockimp "lockimp ok" 0 ;;
    coalition) check_root coalition "coalition ok" 0 ;;
    spawnfa) check_root spawnfa "spawnfa ok" 0 ;;
    watchport) check_root watchport "watchport ok" 0 ;;
    ipcfd) check_root ipcfd "ipcfd ok" 0 ;;
    fpinfo) check_root fpinfo "fpinfo ok" 0 ;;
    openmode) check_root openmode "openmode ok" 0 ;;
    pshared) check_root pshared "pshared ok" 0 ;;
    lastclose) check_root lastclose "lastclose ok" 0 ;;
    setexecbad) check_root setexecbad "setexecbad ok" 0 ;;
    sockname) check_root sockname "sockname ok" 0 ;;
    jit) check_root jit "jit ok" 0 ;;
    amfi)
        if [ -n "${GEX_DARWIN_ROOT:-}" ]; then
            mkdir -p "$GEX_DARWIN_ROOT/var/tmp"
            cp "$HERE/bin/untrusted" "$GEX_DARWIN_ROOT/var/tmp/gex-darwin-untrusted"
            cp "$HERE/bin/gta" "$GEX_DARWIN_ROOT/var/tmp/gex-darwin-gta"
        fi
        check_root amfi "amfi ok" 0
        ;;
    sbxinit) check_root sbxinit "sbxinit ok" 0 ;;
    sbxexec) check_root sbxexec "sbxexec ok" 0 ;;
    sbxkill)
        if [ -n "${GEX_DARWIN_ROOT:-}" ]; then
            mkdir -p "$GEX_DARWIN_ROOT/var/tmp"
            for c in sbxstacked sbxnotstr sbxunknown sbxexec; do
                cp "$HERE/bin/$c" "$GEX_DARWIN_ROOT/var/tmp/gex-darwin-$c"
            done
        fi
        check_root sbxkill "sbxkill ok" 0
        ;;
    cfrunloop) check_root cfrunloop "cfrunloop 3 1" 0 ;;
    xpc-anon) check_root xpc-anon "xpc-anon 42" 0 ;;
    *)
        echo "FAIL $1: no such program"
        fail=1
        ;;
    esac
}

if [ "$named" -gt 0 ]; then
    for p in "$@"; do
        run "$p"
    done
else
    for p in hello-static bsd-carry commpage exclusive-pair aes hello pthread dispatch dispatch-signal sighandler kq-pipe pipe ioctl lockf fsops sigthread sigio vnode codesig rlimit apple exec spawn wait sigchld procknote fork jobctl setexec taskpolicy priority threadpolicy poll itimer threadsuspend threadstate tasksuspend portrefs crosstask spawnports taskname excports pages mmapflags madvise memlimit excdeliver startsusp readports taskthreads amfi policy creds uniqueid procinfo persona killperm exitreason sigwait pagezero cputime vtimer protect efault procpolicy cpumon nocldwait boottime timebase sysctlnodes kernproc vmregion msync rlimitctl iokit ioreg accel accelr iosurface iosurfacex iogpudev xattr fileport guarded vectored pathconf mlock fdinfo setattr vmcopy sockevent thcwd clone renameswap pidhold fixedcalls sockerr select filesec psem aio statino statfsino dirino workinterval eventlink voucherx circular importance lockimp coalition spawnfa watchport ipcfd fpinfo openmode pshared lastclose setexecbad sockname machclock atmflag timeouts wlqos halfclose vnextend procmask guardesc rcvlarge extractright sonce vmwx sockopts pathrules pty ptyjob ptyclose bsdpty devfs devattr loadavg ttyinfo hoststat ttydead fcntltty nosigpipe realdev ttydrain revoke dgrambuf streambuf jit sbxinit sbxexec sbxkill cfrunloop xpc-anon; do
        run "$p"
    done
fi
exit $fail
