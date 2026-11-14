#!/usr/bin/env python3
"""Check the page's GPU Worker (hosts/metal) in a browser, on its WebGPU and the machine's GPU.

Builds hosts/metal for wasm32 (the GPU Worker's module and examples/check_task.rs), runs wasm-bindgen on both,
serves tests/page cross-origin isolated (SharedArrayBuffer) from 127.0.0.1 with the ring's script
(hosts/browser/js), WebMetal's reference outputs and the reference shader library, and opens it in a browser. The
page starts the GPU Worker with the display's canvas and a process memory, and runs the checks from a Worker that
stands where that process's kernel stands. Each check's result is printed; the exit status is 0 when every check
passed, 1 when one did not, 2 when the run could not complete.

Usage: check_page.py [--browser chrome|firefox|safari|PATH] [--build DIR] [--no-build] [--reference-build DIR]
                     [--out RESULTS] [--timeout SECONDS]

Browsers: chrome (headless); firefox, in a window of a fresh profile (Firefox gives a headless page no WebGPU
adapter); safari, through `open -a Safari`. --reference-build names a build of WebMetal's
`tests/reference/build.py --platform ios`; without it the script makes one (Xcode's Metal toolchain).
"""

import argparse
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(CRATE))
WEBMETAL = os.path.join(ROOT, "third_party", "WebMetal")
JS = os.path.join(ROOT, "hosts", "browser", "js")
PAGE = os.path.join(HERE, "page")
BROWSERS = {
    "chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "firefox": "/Applications/Firefox.app/Contents/MacOS/firefox",
    "safari": "/Applications/Safari.app",
}


def build(args, out):
    env = dict(os.environ)
    base = [args.cargo, "build", "-p", "gex-metal-page", "--target", "wasm32-unknown-unknown", "--release"]
    subprocess.run(base, cwd=CRATE, env=env, check=True)
    subprocess.run(base + ["--example", "check_task"], cwd=CRATE, env=env, check=True)
    target = env.get("CARGO_TARGET_DIR") or os.path.join(CRATE, "target")
    rel = os.path.join(target, "wasm32-unknown-unknown", "release")
    for wasm, dest in [(os.path.join(rel, "gex_metal_page.wasm"), "pkg"),
                       (os.path.join(rel, "examples", "check_task.wasm"), "pkg-task")]:
        d = os.path.join(out, dest)
        shutil.rmtree(d, ignore_errors=True)
        subprocess.run([args.wasm_bindgen, "--target", "web", "--no-typescript", "--out-dir", d, wasm], check=True)


def reference(args, out):
    if args.reference_build:
        return os.path.abspath(args.reference_build)
    dest = os.path.join(out, "reference-ios")
    if not os.path.isfile(os.path.join(dest, "wmref.metallib")):
        script = os.path.join(WEBMETAL, "tests", "reference", "build.py")
        subprocess.run([sys.executable, "-B", "-I", script, "--platform", "ios", "--out", dest], check=True)
    return dest


def serve(out, reference_dir, state):
    roots = {"js": JS, "pkg": os.path.join(out, "pkg"), "pkg-task": os.path.join(out, "pkg-task"),
             "__webmetal": WEBMETAL, "__reference": reference_dir}

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=PAGE, **kw)

        def translate_path(self, path):
            p = urllib.parse.unquote(urllib.parse.urlsplit(path).path)
            parts = [x for x in p.split("/") if x and x not in (".", "..")]
            if parts and parts[0] in roots:
                return os.path.join(roots[parts[0]], *parts[1:])
            return os.path.join(PAGE, *parts)

        def end_headers(self):
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def guess_type(self, path):
            if path.endswith((".mjs", ".js")):
                return "text/javascript"
            return super().guess_type(path)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n).decode("utf-8", "replace") or "{}")
            if self.path == "/__environment":
                state["environment"] = body
            elif self.path == "/__result":
                state["results"].append(body)
                print("%-12s %s  %s" % (body.get("name"), "pass" if body.get("ok") else "FAIL", body.get("detail")),
                      flush=True)
            elif self.path == "/__done":
                state["done"] = body
                state["event"].set()
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def launch(browser, url, profile):
    path = BROWSERS.get(browser, browser)
    name = os.path.basename(path).lower()
    if browser == "safari" or name.startswith("safari"):
        subprocess.run(["open", "-g", "-a", path, url], check=True)
        return None
    if "firefox" in name:
        cmd = [path, "--no-remote", "--new-instance", "--profile", profile, url]
    else:
        cmd = [path, "--headless=new", "--no-first-run", "--no-default-browser-check", "--user-data-dir=" + profile,
               url]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def close_safari_tabs(prefix):
    """Close the Safari tabs the run opened (`open -a` leaves them open)."""
    script = [
        'tell application "Safari"',
        "repeat with w in windows",
        'set ts to (every tab of w whose URL starts with "%s")' % prefix,
        "repeat with i from (count of ts) to 1 by -1",
        "close (item i of ts)",
        "end repeat",
        "end repeat",
        "end tell",
    ]
    args = ["osascript"]
    for line in script:
        args += ["-e", line]
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--browser", default="chrome")
    ap.add_argument("--cargo", default="cargo")
    ap.add_argument("--wasm-bindgen", default="wasm-bindgen")
    ap.add_argument("--build", help="build into this directory and keep it")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--reference-build")
    ap.add_argument("--out", help="write the results here (JSON)")
    ap.add_argument("--timeout", type=float, default=600)
    args = ap.parse_args()
    out = args.build or tempfile.mkdtemp(prefix="gex-metal-page-")
    os.makedirs(out, exist_ok=True)
    if not args.no_build:
        build(args, out)
    reference_dir = reference(args, out)
    state = {"results": [], "environment": None, "done": None, "event": threading.Event()}
    httpd = serve(out, reference_dir, state)
    url = "http://127.0.0.1:%d/index.html" % httpd.server_address[1]
    profile = tempfile.mkdtemp(prefix="gex-metal-page-profile-")
    print("%s: %s" % (args.browser, url), flush=True)
    proc = launch(args.browser, url, profile)
    try:
        finished = state["event"].wait(args.timeout)
    finally:
        if proc is None:
            close_safari_tabs("http://127.0.0.1:%d/" % httpd.server_address[1])
        else:
            proc.terminate()
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                proc.kill()
        httpd.shutdown()
        shutil.rmtree(profile, ignore_errors=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"browser": args.browser, "environment": state["environment"], "results": state["results"],
                       "done": state["done"]}, f, indent=1)
    if not finished:
        print("the page did not finish within %.0f s" % args.timeout, file=sys.stderr)
        return 2
    if state["done"].get("failure"):
        print("the page failed:\n" + state["done"]["failure"], file=sys.stderr)
        return 2
    for line in state["done"].get("log", []):
        print("log: " + line)
    ok = all(r.get("ok") for r in state["results"])
    print("%s: %s (%s)" % (args.browser, "every check passed" if ok else "a check failed",
                           (state["environment"] or {}).get("userAgent")))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
