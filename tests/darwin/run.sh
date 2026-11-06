#!/bin/sh
# Run the Darwin programs under gexc and check what each prints and how it
# exits. Builds them first when bin/ is missing; GEXC picks the runner.
# With program names, only those run; without, all of them.
#
# A dynamic program needs a Darwin root (GEX_DARWIN_ROOT: dyld and the
# shared cache, as UniXNU's webroot lays them out) and runs from inside it.
# Without one it is skipped, or fails when it was asked for by name.
set -u

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/../.." && pwd)
GEXC=${GEXC:-$ROOT/target/release/gexc}
[ -d "$HERE/bin" ] || "$HERE/build.sh" >/dev/null

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
# from the root's /var/tmp (its /tmp is the guest's own, in memory, so a
# program there could not see its own file).
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
    for p in hello-static bsd-carry commpage exclusive-pair aes hello pthread dispatch dispatch-signal sighandler kq-pipe pipe ioctl lockf fsops sigthread sigio vnode codesig rlimit apple exec spawn wait sigchld procknote fork jobctl setexec taskpolicy priority threadpolicy poll itimer threadsuspend threadstate tasksuspend portrefs crosstask spawnports taskname excports pages cfrunloop xpc-anon; do
        run "$p"
    done
fi
exit $fail
