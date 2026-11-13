# unixnu-gex

unixnu-gex is a fork of [gex](https://github.com/HeyPuter/gex) that adds a
Darwin personality: XNU's system call interface, ported into gex's kernel,
so that the userland of iPadOS 17.7.11 (build 21H461), as it ships for the
iPad7,1 (iPad Pro 12.9-inch, 2nd generation, A10X), runs on gex. It is the
engine for [UniXNU](https://github.com/MovByte/UniXNU), to run that userland
in a web browser.

The Darwin work is on this repository's default branch, `darwin`. The rest
of the tree is upstream gex.

**Where it stands.** Darwin programs run today under gex's native host,
`gexc`, which runs the translated program on wasmtime. The browser host
(`hosts/browser`) does not start Darwin processes yet. See [Status](#status).

## gex, upstream

gex, by Puter Technologies, runs unmodified Linux and Windows programs in a
web browser. It translates their machine code to WebAssembly and runs it
against its own implementation of the Linux kernel ABI, which is written in
Rust and compiled to WebAssembly as well. `gexc` also runs programs natively
on wasmtime, for debugging and for building what a page loads ahead of time.

The Linux and Windows support is upstream's, and this README does not
document it again. Upstream's README is the reference for the base engine:
[the revision this branch last merged](https://github.com/HeyPuter/gex/blob/8d55896e61824a0bc534d3c9c2de1b175f1b4a8f/README.md)
matches this tree's layout (`hosts/`, `page/`, `toolchain/`, `scripts/`,
`wine/`); a later upstream revision may describe a newer one.
`page/README.md` covers the page's builds.

## The Darwin personality

A Darwin process enters the kernel with `svc #0x80` and the call number in
x16. The number says which part of the kernel answers: a positive number is
a BSD system call, a negative one a Mach trap, and `0x80000000` the
machine-dependent calls (the thread's TSD pointer). A BSD call with a Linux
counterpart is renumbered onto gex's own dispatch, its flags and structures
translated; the rest are answered by Darwin code. Results go back as XNU
returns them: the value in x0 with the carry flag clear, or a Darwin errno in
x0 with the carry flag set. A Mach trap returns its `kern_return_t` in x0.

A process sees iOS's machine: 16 KiB pages, the address space exec lays
out, the commpage, and the iPad7,1's identity in `sysctl`, the host
routines and the device tree.

The address space is XNU's for this device (`load_machfile`,
`create_unix_stack`, `vm_shared_region_enter`). The map runs from the main
image to `0x4_5800_0000` (`ARM64_MAX_OFFSET_DEVICE_LARGE`: the device has
more than 3 GB). The main image is slid by a random 1 to 1023 16 KiB pages
and 0, 1 or 2 32 MiB sections, its 4 GiB `__PAGEZERO` extended to it; dyld
goes right after the main image's end, by 1 to 255 pages of its own (and
moves itself into its copy in the shared cache); the main stack's top is
`USRSTACK64` (`0x1_6fe0_0000`) less the main image's slide. A release
kernel slides every image: `_POSIX_SPAWN_DISABLE_ASLR` is ignored. The
shared region, `0x1_8000_0000` for `0x1_8000_0000`, is one read-only
entry, the system's: the first dyld to find it empty (launchd's, at boot)
maps the dyld shared cache into it with `shared_region_map_and_slide_2_np`,
passing the cache's `maxSlide`, and the kernel slides the cache once a
boot below it, on a 16 KiB boundary, relocating the slid mappings by their
slide info; every task after enters it as it is. A run's region is made as
launchd's dyld makes it, before the run's first program. libmalloc's nano
allocator, in a process exec engages it for (a spawn with
`_POSIX_SPAWN_NANO_ALLOCATOR`, as an app's is), takes the 512 MiB after
the shared region.

The kernel side is in `crates/gex-kernel/src/darwin/`, one module per
subsystem, most naming in their header the XNU source they port:

- **System calls.** The BSD call table, generated from XNU's
  `syscalls.master` (`sysno.rs`); renumbering onto the canonical dispatch
  (`bsd.rs`); the calls with no Linux counterpart (`kern.rs`); errno numbers
  (`errno.rs`); and the calls a release kernel settles before doing any
  work (`fixedcalls.rs`).
- **Mach traps and IPC.** The traps (`mach.rs`); ports, port sets, rights,
  name spaces and notifications (`ipc/`); `mach_msg` and `mach_msg2`, with
  port rights and out-of-line data (`mach_msg.rs`); kernel object ports and
  the MIG server for the host, task, thread, `mach_port`, `vm_map` and
  `mach_vm`, clock, voucher and IOKit routines (`kobject.rs`, `mig.rs`);
  exception ports and delivery to handlers (`exception.rs`, `triage.rs`);
  semaphores (`sema.rs`), Mach timers (`mk_timer.rs`), eventlinks
  (`eventlink.rs`), vouchers with the bank and importance attribute managers
  (`voucher.rs`), IPC importance (`importance.rs`), and thread state
  (`threadstate.rs`).
- **Processes and threads.** `execve` with the Mach-O, fat and interpreter
  activators, and the new image's stack with its `apple[]` strings
  (`execve.rs`, `exec.rs`); `posix_spawn` with file actions, port actions
  and attributes (`spawn.rs`); `wait4` and `waitid` (`exit.rs`);
  libpthread's kernel side: `bsdthread_*` and `ulock` (`thread.rs`), psynch,
  ported from libpthread's `kern_synch.c` (`psynch.rs`), and the workqueue
  that runs libdispatch's threads (`workq.rs`); kernel waits (`wait.rs`);
  credentials (`cred.rs`), personas (`persona.rs`), coalitions
  (`coalition.rs`), resource limits (`rlimit.rs`), exit reasons
  (`reason.rs`), `proc_info` (`procinfo.rs`) and `kern.proc` (`kinfo.rs`).
- **Signals.** Dispositions, XNU's arm64 signal frame and `sigreturn`
  (`signal.rs`), job control (`jobctl.rs`) and interval timers
  (`itimer.rs`).
- **Scheduling state.** Task and thread policy: app type, role, QoS and
  priority (`taskpolicy.rs`, `threadpolicy.rs`, `priority.rs`,
  `procpolicy.rs`); the CPU usage monitor (`cpumon.rs`); work intervals
  (`workinterval.rs`); the scheduler's load averages and Mach factor
  (`sched.rs`); and the kernel's thread calls, which fire timers
  (`timer.rs`). Priorities and QoS are computed as XNU computes them;
  running the threads is the host's job.
- **Memory.** The task's VM map entries (`vm.rs`); `mmap`, `madvise` and
  `mach_vm_behavior_set` (`mman.rs`); `map_with_linking_np` and the dyld
  pager's fixups (`mwl.rs`); the commpage (`commpage.rs`); the
  `phys_footprint` ledger and `TASK_VM_INFO` (`footprint.rs`);
  memorystatus and the jetsam bands (`memorystatus.rs`); POSIX shared
  memory (`shm.rs`).
- **Files.** Name, mode and time changes and `getdirentries64`
  (`fsops.rs`); the `getattrlist` family (`attrlist.rs`, `attrcall.rs`);
  `clonefile` and `exchangedata` (`clonefile.rs`); extended attributes
  (`xattr.rs`); `pathconf` (`pathconf.rs`); the file security calls
  (`filesec.rs`); advisory locks (`lockf.rs`); guarded descriptors
  (`guarded.rs`); file ports (`fileport.rs`); asynchronous I/O (`aio.rs`);
  pipes (`pipe.rs`); `select` (`select.rs`); `ioctl` (`ioctl.rs`); POSIX
  semaphores (`psem.rs`); and `/dev` as an iOS kernel makes it
  (`devfs.rs`).
- **kqueue.** File kqueues, the workqueue's kqueue and workloops
  (`kevent.rs`), and their filters (`kfilt.rs`): `EVFILT_READ`, `WRITE`,
  `VNODE`, `PROC`, `SIGNAL`, `TIMER`, `USER`, `MACHPORT`, `MEMORYSTATUS` and
  `WORKLOOP`.
- **Terminals.** `struct tty`, its character lists and the termios line
  discipline (`tty.rs`, `clist.rs`); `/dev/ptmx` and its replicas, the BSD
  ptys and `/dev/tty` (`ptmx.rs`, `ttydev.rs`); sessions and controlling
  terminals (`ctty.rs`).
- **Sockets.** Darwin's address structures, flags and option numbers
  (`sockaddr.rs`); socket-level options (`sockopt.rs`); the socket layer's
  refusals (`sockerr.rs`); Unix-domain stream sockets' sends and receives
  with the descriptors they carry, over XNU's socket buffer accounting
  (`unixsock.rs`, `sockbuf.rs`). As in upstream gex, an internet socket's
  connection is carried by the host.
- **Security.** The MAC framework's checks, with AMFI and Sandbox as its
  policies (`mac.rs`); AMFI's decisions on code signatures, task ports, JIT
  and executable mappings (`amfi.rs`); embedded code signatures and
  entitlements (`codesign.rs`); trust caches (`trustcache.rs`); Sandbox's
  compiled profiles and their evaluation (`sandbox.rs`), the sandboxes a
  process gets from its exec or `sandbox_init` (`sandboxes.rs`), and
  AppleMatch, the regular expression engine those profiles use
  (`applematch.rs`).
- **IOKit.** The registry's `IODeviceTree` plane, built from the device's
  own device tree, with the APFS volumes its file system table names
  published as services, reached through IOKit's MIG routines (`iokit.rs`).
- **IOSurface.** `IOSurfaceRoot` and its user client as the device's
  IOSurface kext has them (`iosurface/`): surfaces created, looked up by id
  and by send right, locked with their seeds, their values, use counts and
  purgeability, and the records and graphics comm page the root shares with
  every client. A surface's memory is the kernel's, and each task that maps
  it has a view of it, brought up to date when the task locks the surface
  and sent back when it unlocks; a store outside a lock is caught by the
  page's protection and kept. libkern's binary serialization, which its
  methods carry, is `osserialize.rs`.
- **sysctl.** The kernel's own nodes, read from the device's kernelcache
  (`sysctl_nodes.rs`), and the values this kernel has for them
  (`sysctl.rs`).

Outside the kernel crate:

- `crates/gex-ld/src/macho.rs` loads Mach-O images as `parse_machfile`
  places them: a position-independent image, and dyld, moved by its slide,
  dyld after the main image. A Darwin process's own tables (its dispatch
  directory and page protections) are kept inside its `__PAGEZERO`
  (`gex_abi::DARWIN_DISPATCH_DIR64`), so that its address space is XNU's.
- `crates/gex-ld/src/dsc.rs` reads the dyld shared cache, its subcaches and
  their slide info.
- `crates/gex-abi/src/crypto.rs` computes the A64 cryptographic extension
  (AES, SHA-1, SHA-256 and the polynomial multiplies), which translated code
  calls; corecrypto uses these instructions without asking.
- `crates/gexc/src/darwin_run.rs` is `gexc run` for a Mach-O file, and
  `crates/gexc/src/dsc_info.rs` is `gexc dsc-info`.
- `hosts/native/src/darwin_image.rs` loads a program and its dyld, for the
  first program and for `execve`.

## Principles

- **Ported from the source.** The modules port XNU at the tag the profile
  pins, `xnu-10063.141.1`, name the files they follow, and keep XNU's
  structures, limits, error paths and ordering. The BSD call table is generated from
  that tag's `syscalls.master` under the iPhoneOS RELEASE configuration
  (`tools/darwin-gen-sysno.py`), and the sysctl nodes from the device's
  kernelcache (`tools/darwin-sysctl-nodes.py`). psynch and the workqueue
  follow libpthread's kernel side. AMFI, Sandbox, AppleMatch and
  libTrustCache, which have no published source, follow the kexts in the
  device's iOS 17.7.11 kernelcache.
- **Measured where the source is silent.** Where behaviour belongs to the
  filesystem rather than to XNU, the values come from a real APFS volume:
  what a clone keeps, `pathconf`'s answers, `select` on vnodes, and the
  attributes `getattrlist` reports.
- **Gaps fail loudly.** Whatever a program asks for that is not implemented
  is reported on stderr, once per kind per process:

  ```
  [gex:<pid>] Darwin: not implemented: <what>
  ```

  The call then fails with the error its path chooses: an unknown BSD call
  is ENOSYS, a Mach trap that is not implemented is `KERN_FAILURE`, and a
  Sandbox question the evaluator cannot answer is EPERM. A few paths go on
  where XNU would and name in the report what they could not supply (a
  signal frame's fault syndrome, for one). A trap number that does not
  exist raises `EXC_SYSCALL`, as on XNU, and becomes SIGSYS. Under
  `--strace` every occurrence is reported, not only the first.
- **Strict mode.** With `GEX_DARWIN_STRICT=1`, the first report stops the
  process: when the call returns, it is killed with SIGSYS, and gexc prints

  ```
  [gex:<pid>] GEX_DARWIN_STRICT: stopping at pc <pc>: <what>
  ```

## Building

You need the Rust toolchain that `rust-toolchain.toml` names (it installs
the `wasm32-unknown-unknown` target) and a C++17 compiler. The native host
links the host's EGL and GLES (`crates/gex-gl`): on macOS that is Mesa's,
found under Homebrew's prefix (`brew install mesa`), or under the prefix
`GEX_MESA_PREFIX` names, which must hold `include/EGL/egl.h` and `lib/`.

```sh
cargo build --release -p gexc
```

That builds `target/release/gexc`, for AArch64 guests, which is what Darwin
programs are. The page, Wine and the other upstream builds are documented
upstream (see [gex, upstream](#gex-upstream)).

### The Darwin test programs

The test programs are C, built with Xcode's iOS toolchain: you need macOS
with Xcode and its iOS SDK (`xcrun -sdk iphoneos clang`), plus `codesign`,
`lipo` and `python3`.

```sh
tests/darwin/build.sh
```

They are written to `tests/darwin/bin/` (not tracked).
`GEX_DARWIN_TARGET` sets the clang target (default `arm64-apple-ios17.0`).
The static ones make raw system calls and need neither dyld nor the shared
cache; they are linked at the linker's default base, after a 4 GiB
`__PAGEZERO`, where exec loads them, since a static image has no fixups to
slide it with. Every program is signed ad hoc, and some carry the
entitlements in `tests/darwin/src/*.entitlements`.

## What you supply

This repository ships no iPadOS files. You supply your own, extracted from
the IPSW for the iPad7,1, iPadOS 17.7.11 (21H461): a root filesystem and a
boot payload. The paths below are placeholders.

### The root filesystem, `<ipados-root>`

A directory holding the root filesystem, given to gexc with `--sysroot`;
the guest sees its files through host passthrough. gexc reads from it:

- dyld, at the path the program's `LC_LOAD_DYLINKER` names
  (`<ipados-root>/usr/lib/dyld`);
- the shared cache, at
  `<ipados-root>/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`,
  with its subcaches beside it. iOS 17 keeps the shared cache in the
  SystemOS cryptex, so the cryptex's contents go under
  `System/Cryptexes/OS`. `GEX_DARWIN_CACHE` names another location for the
  cache's main file.

The test runner copies its programs into `<ipados-root>/var/tmp/`, so the
directory must be writable.

### The boot payload, `<ipados-boot>`

A directory named by `GEX_DARWIN_BOOT`, holding what the boot loader and
the kernelcache would give the kernel. Each file is optional, but what is
missing has effects:

| file | what it is | without it |
|------|------------|------------|
| `TrustCache` | the trust cache bundle the boot loader hands the kernel at `/chosen/memory-map/TrustCache`: a module count, each module's offset, then the modules, the first being the static trust cache | there are no trust caches, and AMFI runs no code |
| `sandbox_profile.bin` | the Sandbox kext's platform profile, a compiled profile blob from the kernelcache | every Sandbox check is reported and refused (EPERM) |
| `sandbox_builtin.bin` | the Sandbox kext's builtin profile collection (its named profiles), a compiled collection blob from the kernelcache | a process that would get a builtin profile is reported and its exec killed (or its `sandbox_init` refused, EPERM) |
| `sandbox_protobox.bin` | the Sandbox kext's protobox profile collection (profiles named by executable path), a compiled collection blob from the kernelcache | every exec is reported and killed, since its protobox profile cannot be looked up |
| `DeviceTree` | the flattened device tree: the payload of the IPSW's device tree image (an IM4P) for this device | the IOKit registry has no device tree, which is reported |

A `TrustCache` that does not load stops the boot. `tools/darwin-trust-cache.py`
makes the bundle from the IPSW's static trust cache (its IM4P-wrapped
`.trustcache`, or a raw module), adding the cdhashes of any signed Mach-O
files you name:

```sh
python3 tools/darwin-trust-cache.py -o <ipados-boot>/TrustCache \
    --static <static-trust-cache> [your-programs...]
```

`--bundle <file>` takes an existing bundle's first module instead of
`--static`. `tools/darwin-sandbox-blobs.py` writes the three Sandbox blobs
from a decompressed kernelcache (a prelinked one or a fileset), finding them
where the Sandbox kext's `policy_init` loads them and checking each as the
kext's loader does, with each file's SHA-256:

```sh
python3 tools/darwin-sandbox-blobs.py <kernelcache> <ipados-boot>
```

In 21H461's iPad7,1 kernelcache the platform profile is 0x22111 bytes at
0xfffffff0056ca320, the builtin collection 0xd6d7b bytes at
0xfffffff0056ecab0 and the protobox collection 0x75bd1 bytes at
0xfffffff0057c3840. The repository has no tool to unwrap the device tree's
IM4P.

AMFI treats code as platform code when its cdhash is in the static trust
cache, and requires dyld to be platform code. The other path, a CMS
signature checked by CoreTrust and amfid, is not implemented, and an ad hoc
signature outside the trust cache is refused, as on iOS. So a program of
your own runs only once it is signed (ad hoc is enough) and its cdhash is
in the bundle, as the test runner does for its programs.

## Running a program

`gexc run` recognises a thin 64-bit Mach-O file and runs it on the Darwin
personality. (A fat file is taken apart by `execve` inside the guest, not
by `gexc run`.) A dynamic program starts in dyld, read from the root, and
needs `--sysroot`; place the program inside the root so that its own path
resolves in the guest.

```sh
codesign -s - -f my-tool
python3 tools/darwin-trust-cache.py -o <ipados-boot>/TrustCache \
    --static <static-trust-cache> my-tool
cp my-tool <ipados-root>/var/tmp/

GEX_DARWIN_BOOT=<ipados-boot> target/release/gexc run \
    --sysroot <ipados-root> <ipados-root>/var/tmp/my-tool arg1 arg2

# Stop at the first thing the kernel does not implement.
GEX_DARWIN_BOOT=<ipados-boot> GEX_DARWIN_STRICT=1 target/release/gexc run \
    --sysroot <ipados-root> <ipados-root>/var/tmp/my-tool
```

A static program (no `LC_LOAD_DYLINKER`) needs no root:
`gexc run <program>`, with `GEX_DARWIN_BOOT` set as above.

What gexc sets up:

| setting | effect |
|---|---|
| `GEX_DARWIN_BOOT` | the boot payload (above); the system boots from it once, and an `execve` runs on the same system |
| `GEX_DARWIN_STRICT=1` | strict mode (above) |
| `GEX_DARWIN_CACHE` | the shared cache's main file, when it is not at the root's cryptex path |
| environment | without `--env` or `--host-env`, `PATH=/usr/bin:/bin` and `HOME=/var/mobile` |
| identity | the host user's ids, or `--uid`; `/sbin/launchd` runs as root and pid 1, and any other program as a child of a pid 1 that is the kernel's own |
| memory | always a 64-bit guest memory (`--mem32` is refused): Darwin images live above 4 GiB |

The other `gexc run` options (`--strace`, `--env`, `--cwd`, `--argv0`, and
the rest in `gexc help`) apply as they do to Linux programs. `gexc dsc-info
<dyld_shared_cache> [--images] [--check-slide]` prints what gex reads from
a shared cache.

## Running the tests

```sh
cargo build --release -p gexc
tests/darwin/build.sh

# Every program:
GEX_DARWIN_ROOT=<ipados-root> GEX_DARWIN_BOOT=<ipados-boot> tests/darwin/run.sh

# Some, by name:
GEX_DARWIN_ROOT=<ipados-root> GEX_DARWIN_BOOT=<ipados-boot> \
    tests/darwin/run.sh hello dispatch xpc-anon
```

`run.sh` runs each program under gexc and compares its output and exit
status with what it expects, printing `PASS`, `FAIL` or `SKIP` for each; it
exits 1 when any fails. It builds the programs first when
`tests/darwin/bin/` is missing, and needs `python3` for the trust cache.

| variable | effect |
|---|---|
| `GEXC` | the gexc to run (default `target/release/gexc`) |
| `GEX_DARWIN_ROOT` | the root for the dynamic programs, which run from its `/var/tmp`. Without it they are skipped, or fail when named |
| `GEX_DARWIN_BOOT` | the device's boot payload. Its trust cache, with the test programs' cdhashes added, goes to `tests/darwin/bin/boot/TrustCache`, with its `DeviceTree` and Sandbox blobs beside it, and gexc boots from there. Without it, the trust cache holds the test programs only |

`GEX_DARWIN_STRICT=1` reaches gexc from the environment as well. The
runner discards each program's stderr, so run a failing program directly
under gexc to see its reports.

The kernel's and loader's unit tests run with `cargo test -p gex-kernel`
and `cargo test -p gex-ld`.

## Repository layout

The Darwin work, beside upstream's tree:

| path | what it is |
|------|------------|
| `crates/gex-kernel/src/darwin/` | the Darwin personality, one module per subsystem; `ipc/` is Mach IPC |
| `crates/gex-kernel/src/darwin/sysno.rs` | the BSD call numbers, generated by `tools/darwin-gen-sysno.py` |
| `crates/gex-kernel/src/darwin/sysctl_nodes.rs` | the kernel's sysctl nodes, generated by `tools/darwin-sysctl-nodes.py` |
| `crates/gex-kernel/src/` (the rest) | the shared kernel: the dispatch, processes, signals, pipes, sockets and VFS, extended for Darwin's needs |
| `crates/gex-ld/src/macho.rs`, `dsc.rs` | Mach-O loading; the dyld shared cache |
| `crates/gex-abi/src/crypto.rs` | the A64 cryptographic extension |
| `crates/gexc/src/darwin_run.rs`, `dsc_info.rs` | `gexc run` for Mach-O; `gexc dsc-info` |
| `hosts/native/src/darwin_image.rs` | a Darwin program's image, as exec loads it |
| `tests/darwin/src/` | the test programs, and the entitlements some are signed with |
| `tests/darwin/build.sh`, `run.sh` | building and running them |
| `tools/darwin-trust-cache.py` | making a trust cache bundle |
| `tools/darwin-gen-sysno.py` | `sysno.rs` from XNU's `syscalls.master` at a tag (fetched from Apple's open source) |
| `tools/darwin-sysctl-nodes.py` | `sysctl_nodes.rs` from a kernelcache (a 64-bit Mach-O) |

## Status

### What the suite covers

Each program in `tests/darwin/src/` checks one area against XNU's rules and
prints a line `run.sh` expects. Five are static (`hello-static`,
`bsd-carry`, `commpage`, `exclusive-pair`, `aes`); the rest run through
dyld and libSystem from the device's shared cache.

| area | programs |
|------|----------|
| entry, the commpage and the CPU | `hello-static`, `bsd-carry`, `commpage`, `exclusive-pair`, `aes`, `hello`, `apple`, `pages`, `pagezero` |
| clocks and the host | `timebase`, `boottime`, `machclock`, `hoststat`, `loadavg`, `atmflag`, `sysctlnodes` |
| threads and synchronization | `pthread`, `pshared`, `psem`, `thcwd`, `threadsuspend`, `threadstate`, `threadpolicy`, `taskthreads`, `workinterval`, `eventlink` |
| libdispatch, CoreFoundation, XPC | `dispatch`, `dispatch-signal`, `wlqos`, `cfrunloop`, `xpc-anon` |
| processes | `fork`, `exec`, `spawn`, `spawnfa`, `spawnports`, `setexec`, `setexecbad`, `startsusp`, `wait`, `sigchld`, `nocldwait`, `exitreason`, `procknote`, `jobctl`, `pidhold`, `tasksuspend` |
| identity and process information | `creds`, `persona`, `killperm`, `uniqueid`, `procinfo`, `kernproc`, `fdinfo`, `fpinfo`, `ipcfd`, `coalition` |
| policy and resources | `taskpolicy`, `priority`, `procpolicy`, `cpumon`, `rlimit`, `rlimitctl`, `cputime`, `vtimer`, `itimer`, `memlimit` |
| signals and exceptions | `sighandler`, `sigthread`, `sigwait`, `sigio`, `procmask`, `excports`, `excdeliver`, `efault`, `protect` |
| Mach IPC | `portrefs`, `crosstask`, `taskname`, `readports`, `extractright`, `sonce`, `rcvlarge`, `guardesc`, `circular`, `voucherx`, `importance`, `lockimp`, `watchport` |
| memory | `layout`, `stackfb`, `mmapflags`, `madvise`, `msync`, `mlock`, `vmregion`, `vmcopy`, `vmwx`, `jit` |
| files | `fsops`, `pathrules`, `pathconf`, `statino`, `statfsino`, `dirino`, `setattr`, `xattr`, `clone`, `renameswap`, `lockf`, `lastclose`, `guarded`, `fileport`, `filesec`, `openmode`, `vectored`, `aio`, `fixedcalls`, `ioctl`, `realdev` |
| kqueue, poll and pipes | `kq-pipe`, `vnode`, `vnextend`, `select`, `poll`, `pipe`, `timeouts` |
| terminals and `/dev` | `pty`, `ptyjob`, `ptyclose`, `bsdpty`, `ttyinfo`, `ttydead`, `ttydrain`, `fcntltty`, `revoke`, `devfs`, `devattr` |
| sockets | `sockerr`, `sockevent`, `sockname`, `sockopts`, `halfclose`, `nosigpipe`, `dgrambuf`, `streambuf` |
| code signing and IOKit | `codesig`, `amfi`, `policy`, `iokit`, `ioreg`, `iosurface`, `iosurfacex`, `iogpudev` |

The suite runs single programs and the processes they create. None of it
boots launchd or runs an app.

### Known gaps

What follows is grouped from the kernel's own "not implemented" reports and
the limits its comments state. It is a summary, not the full list: the code
is the reference (search `crates/gex-kernel/src/` for
`darwin_unimplemented`, `note_unimplemented` and `Unported`).

- **The browser.** The page runs no Darwin process yet.
- **Code signing.** Only the static trust cache is consulted; trust caches
  loaded at run time (by AMFI's user client, after a cryptex's manifest is
  checked) are not. CMS signatures (CoreTrust and amfid) are not
  implemented. AMFI's launch constraints are not implemented: an image
  whose trust cache entry has a constraint category, or that carries its
  own constraints, is refused (EPERM). AMFI's `__mac_syscall` calls for
  local signing, trust cache loading and launch constraints are reported.
- **Sandbox.** A process gets its sandbox as the kext gives it: at exec
  from its `seatbelt-profiles` entitlement, its spawn's Sandbox attributes,
  the platform profile's choice for apps, or its executable's protobox
  profile; or by `sandbox_init` with a builtin profile. The platform
  profile, then the process's, decide the checks that are wired, an exec's
  process-exec* and process-exec-interpreter among them; Sandbox's other
  hooks (the other vnode checks among them) are not called. Not ported,
  and reported where the kext would act: the
  profiles of the `com.apple.private.sandbox.profile` entitlements,
  containers and containermanagerd's upcall, the extensions of the
  `com.apple.security.exception.*` entitlements, matching an extension
  filter against an object, Mach message filtering, a profile's own system
  call masks (nor are the platform profile's masks applied), filters whose
  facts the kernel does not have, some `sandbox_check` filter types,
  `sandbox_check` of another process's operation, and Sandbox's other
  `__mac_syscall` calls.
- **IOKit.** The registry holds the device tree and the APFS services
  only; no `IOService` driver is present. `IOConnectCallMethod` on a
  driver, `iokit_user_client_trap`, and matching dictionaries of kinds not
  handled are reported.
- **Mach.** The traps `clock_sleep`, `debug_control_port_for_pid` and
  `iokit_user_client_trap`; MIG routines not in `mig.rs`, and some
  `task_info`, `thread_info`, `host_statistics` and `task_policy_get`
  flavors; `task_for_pid` and its read and inspect forms on another
  process; a fault's exception (`EXC_BAD_ACCESS` and the like) sent to a
  handler the program set, which is reported and taken as a signal instead;
  telling an `EXC_CRASH` handler of a death outside a system call; corpses
  (`EXC_CORPSE_NOTIFY`, and the corpse an `EXC_RESOURCE` or simulated
  `EXC_GUARD` would make); handlers of `EXCEPTION_IDENTITY_PROTECTED`
  behavior; hardware breakpoints, watchpoints and single step.
- **Address space.** gex's 64-bit memory is 16 GiB (V8's memory64 cap),
  so a task's map is held only to `0x3_ffff_4000`, not XNU's
  `0x4_5800_0000` (`0xf_c000_0000` for a jumbo map): above it are the
  commpage's alias, to `0x4_0000_0000` (where a program reads the commpage
  and the device has unmapped space), and the memory's end. A fixed
  mapping that reaches past `0x3_ffff_4000`, and an anywhere one with no
  room below it, is reported and fails; a random address (`MAP_JIT`,
  `VM_FLAGS_RANDOM_ADDR`) is drawn below it. `shared_region_map_and_slide_2_np`
  itself is not implemented: a run's shared region is made before its first
  program, so `/sbin/launchd` as the first program finds it made, which is
  reported.
- **Memory.** Purgeable memory, 4 GB chunks and other `mach_vm_allocate`
  and `mach_vm_map` flags not handled, `MAP_TPRO`, reuse advice on a
  region a fork left copy-on-write, the freezer, and the
  `memorystatus_control` commands that need a memory model. A POSIX shared
  memory object is copied into each mapping, so its mappings agree only at
  `msync` and `munmap`, and a second mapping is reported. Memory pressure is
  never posted: the level stays normal.
- **Files and devices.** The filesystems keep no file owners and no access
  control lists, so the `chown` family and ACLs are refused and reported.
  Also reported: `mount`, `mkfifo` and `mknod`, `fsctl`, `F_PREALLOCATE`,
  data protection classes, `fsgetpath` by object id, resource fork offsets,
  `RENAME_SECLUDE`, and opening a device whose driver is not modelled.
- **Sockets.** Interface `ioctl`s know only `lo0`. Out-of-band data,
  `SO_LINGER`, `SO_DONTROUTE`, `SO_OOBINLINE`, address sharing
  (`SO_REUSEADDR`, `SO_REUSEPORT`) when a bind is refused, keepalive probes
  on a connection the host carries, broadcast datagrams, a socket's owner
  (`so_pgid`), descriptors in a Unix datagram socket's control messages,
  `EVFILT_SOCK`, `EVFILT_EXCEPT` on a socket, and socket `ioctl`s not
  handled are reported.
- **Processes and signals.** Darwin signals with no Linux number, `ptrace`
  requests not handled, `wait4`'s resource usage, `settid`, cancelling a
  thread blocked in a BSD call, process-shared psynch objects and ulocks in
  memory another process maps, `__mac_execve` with a label, and
  `posix_spawn` with a subsystem root path or an audit session port action.
- **Accounting.** What needs ledgers the kernel does not keep: a
  coalition's resource usage, the CPU monitor's actions on a violation, the
  task-wide CPU limit, the wakeups monitor, workloop CPU limits, and the
  pmap's and compressor's ledgers in `TASK_VM_INFO` (resident, internal,
  external, reusable and compressed sizes and their peaks, the footprint's
  peak, decompressions, swap-ins). On a host without per-thread clocks,
  the virtual timers, `RLIMIT_CPU`, the CPU monitor, the workqueue's
  quantum and `getrusage`'s times are reported; on one that cannot say
  which pages are a task's, `phys_footprint` is.
- **Terminals.** Terminal `ioctl`s not handled, an `fcntl` that would sleep
  in the driver, calls that would wait for a revoke to finish, and parts of
  `revoke` itself.
- **Other.** `EVFILT_FS`, `NOTE_WL_SYNC_IPC` on a workloop, writes to the
  `sysctl` nodes that only have a fixed value here, the nodes this kernel
  has no value for, and some `proc_info` flavors and `iopolicysys` types.

## Licence

The fork keeps upstream's licence. gex is free software under the GNU
Affero General Public License, version 3 only (`LICENSE`), Copyright (C)
2026 Puter Technologies Inc. Third-party code keeps its own licence;
`NOTICE` lists it. The Darwin work is part of this repository and carries
no other licence.

iPadOS and its files are Apple's and are not part of this repository.
