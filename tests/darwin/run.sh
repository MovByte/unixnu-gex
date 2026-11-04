#!/bin/sh
# Run the Darwin programs under gexc and check what each prints and how it
# exits. Builds them first when bin/ is missing; GEXC picks the runner.
set -u

HERE=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/../.." && pwd)
GEXC=${GEXC:-$ROOT/target/release/gexc}
[ -d "$HERE/bin" ] || "$HERE/build.sh" >/dev/null

fail=0
check() {
    name=$1 want_out=$2 want_status=$3
    out=$("$GEXC" run "$HERE/bin/$name" 2>/dev/null)
    status=$?
    if [ "$out" = "$want_out" ] && [ "$status" -eq "$want_status" ]; then
        echo "PASS $name"
    else
        echo "FAIL $name: status $status (want $want_status), output: $out"
        fail=1
    fi
}

check hello-static "hello from darwin" 0
check bsd-carry "carry ok" 0
check commpage "" 0
check exclusive-pair "" 0
check aes "" 0

# A dynamic program needs a Darwin root (GEX_DARWIN_ROOT: dyld and the
# shared cache, as UniXNU's webroot lays them out); it runs from inside it.
if [ -n "${GEX_DARWIN_ROOT:-}" ]; then
    mkdir -p "$GEX_DARWIN_ROOT/tmp"
    cp "$HERE/bin/hello" "$GEX_DARWIN_ROOT/tmp/gex-darwin-hello"
    out=$("$GEXC" run --sysroot "$GEX_DARWIN_ROOT" "$GEX_DARWIN_ROOT/tmp/gex-darwin-hello" a b 2>/dev/null)
    status=$?
    if [ "$out" = "hello from /tmp/gex-darwin-hello with 2 arguments" ] && [ "$status" -eq 0 ]; then
        echo "PASS hello (dyld, shared cache)"
    else
        echo "FAIL hello: status $status, output: $out"
        fail=1
    fi
else
    echo "SKIP hello (set GEX_DARWIN_ROOT)"
fi
exit $fail
