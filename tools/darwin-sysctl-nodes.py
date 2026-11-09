#!/usr/bin/env python3
"""Generate crates/gex-kernel/src/darwin/sysctl_nodes.rs from a kernelcache.

The kernel registers its sysctl nodes through STARTUP entries
(`sysctl_register_oid_early`), so its `__init_entry_set` section lists every
built-in `struct sysctl_oid`. Nodes a kext registers later are not there.

usage: darwin-sysctl-nodes.py KERNELCACHE OUT.rs
"""
import collections
import struct
import sys

STARTUP_ENTRY = 24  # subsystem, rank, func, arg
OID_AUTO = -1
OID_AUTO_START = 100
OID_ANCHOR_NAME = "__anchor__"
CTLTYPE_NODE = 1


def main(path, out):
    data = open(path, "rb").read()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<8I", data, 0)
    if magic != 0xfeedfacf:
        sys.exit("not a 64-bit Mach-O")
    segs, sects, at = [], [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<2I", data, at)
        if cmd == 0x19:  # LC_SEGMENT_64
            vmaddr, _vmsize, fileoff, filesize = struct.unpack_from("<4Q", data, at + 24)
            segs.append((vmaddr, fileoff, filesize))
            s = at + 72
            for _ in range(struct.unpack_from("<I", data, at + 64)[0]):
                name = data[s:s + 16].rstrip(b"\0").decode()
                addr, sz = struct.unpack_from("<2Q", data, s + 32)
                off = struct.unpack_from("<I", data, s + 48)[0]
                sects.append((name, addr, sz, off))
                s += 80
        at += size

    def to_off(va):
        for vmaddr, fileoff, filesize in segs:
            if vmaddr <= va < vmaddr + filesize:
                return fileoff + va - vmaddr
        return None

    def ptr(v):
        return (v & 0xffffffffffff) | 0xffff000000000000 if v >> 48 not in (0, 0xffff) else v

    def cstr(va):
        o = to_off(ptr(va))
        if o is None:
            return None
        return data[o:data.index(b"\0", o)].decode("utf8", "replace")

    def name_of(oidva):
        o = to_off(oidva)
        if o is None:
            return None
        try:
            name = cstr(struct.unpack_from("<Q", data, o + 40)[0])
            fmt = cstr(struct.unpack_from("<Q", data, o + 56)[0])
        except (struct.error, ValueError):
            return None
        return name if name and name.isprintable() and len(name) <= 64 and fmt is not None and len(fmt) <= 32 else None

    entries = []
    for name, addr, sz, off in sects:
        if name == "__init_entry_set":
            for i in range(sz // STARTUP_ENTRY):
                sub, rank = struct.unpack_from("<2I", data, off + STARTUP_ENTRY * i)
                func, arg = struct.unpack_from("<2Q", data, off + STARTUP_ENTRY * i + 8)
                entries.append((sub, rank, ptr(func), ptr(arg)))
    # sysctl_register_oid_early is the one function every entry that names
    # a sysctl_oid has in common.
    reg = collections.Counter(e[2] for e in entries if name_of(e[3])).most_common(1)[0][0]

    nodes = []
    for _sub, rank, func, oidva in entries:
        if func != reg:
            continue
        o = to_off(oidva)
        if o is None:
            continue
        parent = ptr(struct.unpack_from("<Q", data, o)[0])
        number, kind = struct.unpack_from("<iI", data, o + 16)
        arg1 = ptr(struct.unpack_from("<Q", data, o + 24)[0])
        name = cstr(struct.unpack_from("<Q", data, o + 40)[0])
        handler = struct.unpack_from("<Q", data, o + 48)[0]
        fmt = cstr(struct.unpack_from("<Q", data, o + 56)[0]) or ""
        nodes.append(dict(rank=rank, parent=parent, number=number, kind=kind, arg1=arg1, name=name, handler=handler != 0, fmt=fmt))

    nodes = [n for n in nodes if n["name"] and not n["name"].startswith(OID_ANCHOR_NAME)]
    children_of = {n["arg1"]: n for n in nodes if n["kind"] & 0xf == CTLTYPE_NODE and not n["handler"]}

    def path(n):
        p = children_of.get(n["parent"])
        return f"{path(p)}.{n['name']}" if p else n["name"]

    # sysctl_register_oid: an OID_AUTO node takes the next number after the
    # highest registered in its parent, at least OID_AUTO_START. Nodes
    # register before leaves (STARTUP_RANK_FIRST), in link order.
    taken = collections.defaultdict(lambda: OID_AUTO_START - 1)
    resolved = []
    for n in sorted(nodes, key=lambda n: n["rank"]):
        if n["number"] != OID_AUTO:
            taken[n["parent"]] = max(taken[n["parent"]], n["number"])
    for n in sorted(nodes, key=lambda n: n["rank"]):
        number = n["number"]
        if number == OID_AUTO:
            taken[n["parent"]] += 1
            number = taken[n["parent"]]
        resolved.append((path(n), number, n["kind"], n["fmt"], n["handler"]))

    with open(out, "w") as f:
        f.write("//! The kernel's sysctl nodes, from its `__init_entry_set` section\n")
        f.write("//! (`tools/darwin-sysctl-nodes.py`, iPad7,1 21H461). Generated: do not edit.\n\n")
        f.write("use super::sysctl::Node;\n\n")
        f.write("#[rustfmt::skip]\n")
        f.write("pub static NODES: &[Node] = &[\n")
        for p, number, kind, fmt, handler in sorted(resolved):
            esc = fmt.replace("\\", "\\\\").replace('"', '\\"')
            f.write(f'    Node {{ path: "{p}", number: {number}, kind: {kind:#x}, fmt: "{esc}", handler: {"true" if handler else "false"} }},\n')
        f.write("];\n")
    print(len(resolved), "nodes", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
