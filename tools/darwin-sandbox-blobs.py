#!/usr/bin/env python3
"""Write the Sandbox kext's profile blobs from a kernelcache, for a Darwin boot payload.

The kext (com.apple.security.sandbox) carries three compiled blobs in its
__TEXT,__const, which its policy_init hands to the profile loaders:

  sandbox_profile.bin   the platform profile, a single profile whose address
                        and size policy_init stores into the platform
                        profile's object (`stp blob, size, [object]`) after
                        the builtin collection is loaded
  sandbox_builtin.bin   the builtin collection (its named profiles), loaded
                        as "builtin collection"
  sandbox_protobox.bin  the protobox collection (profiles named by executable
                        path), loaded as "protobox collection"

Each blob is found as policy_init finds it: the collection loader's calls
take the collection's name (x1), the blob (x2) and its size (w3), and the
platform profile's address and size are the pair stored right after the
builtin collection's call. The kext's code is followed with the registers
those instructions set (adrp, add, movz, movk, mov). Each blob is then
checked as the kext's loader checks it (191 operations, a collection's flag
bit 15 and none for the platform profile, its tables, nodes, regexes,
pattern variables and profile names inside its size) and written with its
SHA-256.

The kernelcache is the decompressed Mach-O: a prelinked one (its kexts in
__PRELINK_TEXT, named by __PRELINK_INFO), or a fileset (LC_FILESET_ENTRY).

usage: darwin-sandbox-blobs.py KERNELCACHE OUTDIR
"""
import hashlib
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET

MH_MAGIC_64 = 0xFEEDFACF
MH_FILESET = 12
LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
BUNDLE = 'com.apple.security.sandbox'
OPERATIONS = 191
ENTRY = 4 + 2 * OPERATIONS
NODE = 8


def die(msg):
    sys.exit('darwin-sandbox-blobs: ' + msg)


def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


class Image:
    """A Mach-O in the kernelcache: its segments and sections by address."""

    def __init__(self, kc, off):
        self.kc = kc
        magic, _, _, self.filetype, ncmds, _, _, _ = struct.unpack_from('<IiiIIIII', kc, off)
        if magic != MH_MAGIC_64:
            die('no 64-bit Mach-O header at file offset %#x' % off)
        self.segments = []
        self.sections = {}
        self.commands = []
        at = off + 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', kc, at)
            self.commands.append((cmd, at))
            if cmd == LC_SEGMENT_64:
                name = kc[at + 8:at + 24].rstrip(b'\0').decode()
                vm, vsize, foff, fsize, _, _, nsects, _ = struct.unpack_from('<QQQQIIII', kc, at + 24)
                self.segments.append((name, vm, vsize, foff, fsize))
                for k in range(nsects):
                    s = at + 72 + 80 * k
                    sect = kc[s:s + 16].rstrip(b'\0').decode()
                    seg = kc[s + 16:s + 32].rstrip(b'\0').decode()
                    addr, ssize = struct.unpack_from('<QQ', kc, s + 32)
                    self.sections[(seg, sect)] = (addr, ssize)
            at += size


class Kernelcache:
    def __init__(self, data):
        self.b = data
        self.top = Image(data, 0)

    def fo(self, vm):
        """The file offset of address `vm`, by the kernelcache's own segments."""
        for _, v, _, f, fs in self.top.segments:
            if v <= vm < v + fs:
                return f + vm - v
        die('address %#x is in no segment of the kernelcache' % vm)

    def read(self, vm, n):
        o = self.fo(vm)
        return self.b[o:o + n]

    def kext(self):
        """The Sandbox kext's Mach-O."""
        if self.top.filetype == MH_FILESET:
            for cmd, at in self.top.commands:
                if cmd == LC_FILESET_ENTRY:
                    vm, foff, name_off = struct.unpack_from('<QQI', self.b, at + 8)
                    name = self.b[at + name_off:self.b.index(b'\0', at + name_off)].decode()
                    if name == BUNDLE:
                        return Image(self.b, foff)
            die('no fileset entry ' + BUNDLE)
        info = [s for s in self.top.segments if s[0] == '__PRELINK_INFO']
        if not info:
            die('neither a fileset nor a prelinked kernelcache (no __PRELINK_INFO)')
        _, vm, _, foff, fsize = info[0]
        xml = self.b[foff:foff + fsize].split(b'\0', 1)[0]
        root = ET.fromstring(xml)
        ids = {}
        for e in root.iter():
            if 'ID' in e.attrib:
                ids[e.attrib['ID']] = e.text
        for d in root.iter('dict'):
            kids = list(d)
            fields = {}
            for k, v in zip(kids[0::2], kids[1::2]):
                if k.tag == 'key':
                    fields[k.text] = ids.get(v.attrib['IDREF']) if 'IDREF' in v.attrib else v.text
            if fields.get('CFBundleIdentifier') == BUNDLE:
                load = int(fields['_PrelinkExecutableLoadAddr'], 0)
                return Image(self.b, self.fo(load))
        die('no prelinked kext ' + BUNDLE)


def sign_extend(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def calls_and_stores(kc, kext):
    """Follow the kext's __text: each `bl` with the x1, x2 and w3 it is made
    with, and each 64-bit `stp` with the values of its two registers, from
    the registers adrp, add, movz, movk and mov set. A branch or a return
    forgets them; a call forgets the ones it may change (x0 to x18)."""
    addr, size = kext.sections[('__TEXT_EXEC', '__text')]
    code = kc.read(addr, size)
    regs = {}
    events = []
    for i in range(0, size - 3, 4):
        w = u32(code, i)
        pc = addr + i
        rd = w & 31
        if w & 0x9F000000 == 0x90000000:  # adrp
            imm = ((w >> 29) & 3) | (((w >> 5) & 0x7FFFF) << 2)
            regs[rd] = (pc & ~0xFFF) + (sign_extend(imm, 21) << 12)
        elif w & 0xFF800000 == 0x91000000:  # add (immediate), 64-bit
            rn = (w >> 5) & 31
            imm = ((w >> 10) & 0xFFF) << (12 if w & (1 << 22) else 0)
            if rn in regs:
                regs[rd] = regs[rn] + imm
            else:
                regs.pop(rd, None)
        elif w & 0x7F800000 == 0x52800000:  # movz
            regs[rd] = ((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3))
        elif w & 0x7F800000 == 0x72800000:  # movk
            hw = 16 * ((w >> 21) & 3)
            if rd in regs:
                regs[rd] = (regs[rd] & ~(0xFFFF << hw)) | (((w >> 5) & 0xFFFF) << hw)
        elif w & 0x7FE0FFE0 == 0x2A0003E0:  # mov (orr from the zero register)
            rm = (w >> 16) & 31
            if rm in regs:
                regs[rd] = regs[rm] & (0xFFFFFFFF if not w & 0x80000000 else (1 << 64) - 1)
            else:
                regs.pop(rd, None)
        elif w & 0xFC000000 == 0x94000000:  # bl
            events.append(('bl', pc, regs.get(1), regs.get(2), regs.get(3)))
            for r in range(19):
                regs.pop(r, None)
        elif w & 0xFFC00000 in (0xA9000000, 0xA9800000, 0xA8800000):  # stp (64-bit)
            events.append(('stp', pc, regs.get(rd), regs.get((w >> 10) & 31), None))
        elif w & 0xFC000000 == 0x14000000 or w & 0xFFFFFC1F in (0xD65F0000, 0xD61F0000):
            regs = {}  # b, ret, br
        elif w & 0x0A000000 == 0x08000000:
            # A load forgets what it loads (a pair, both); a store writes
            # no register.
            if w & (1 << 22):
                regs.pop(rd, None)
                if w & 0x3A000000 == 0x28000000:
                    regs.pop((w >> 10) & 31, None)
        else:
            # Any other instruction writing Rd forgets it.
            regs.pop(rd, None)
    return events


def header(b):
    if len(b) < 0xE:
        return None, 'truncated'
    if b[4] != OPERATIONS:
        return None, 'operation count mismatch (%u vs %u)' % (b[4], OPERATIONS)
    h = {
        'flags': u16(b, 0), 'nodes': u16(b, 2), 'vars': b[5], 'd': b[6],
        'profiles': u16(b, 8), 'regexes': u16(b, 0xA), 'f': u16(b, 0xC),
    }
    h['tables_end'] = 0xE + 2 * (h['regexes'] + h['vars'] + h['d'] + h['f'])
    return h, None


def check(b, collection):
    """The loader's checks of a blob: none, or what is wrong."""
    h, why = header(b)
    if why:
        return why
    if bool(h['flags'] & 0x8000) != collection:
        return 'wrong flags'
    first = h['tables_end']
    ops_end = first + (h['profiles'] * ENTRY if collection else 2 * OPERATIONS)
    nodes = (ops_end + NODE - 1) & ~(NODE - 1)
    nodes_end = nodes + NODE * h['nodes']
    if nodes_end > len(b):
        return 'truncated'

    def obj(index, what):
        at = nodes_end + index * NODE
        if at + 2 > len(b):
            return None, 'bad %s offset' % what
        n = u16(b, at)
        if at + 2 + n > len(b):
            return None, 'bad %s size' % what
        return b[at + 2:at + 2 + n], None

    for i in range(h['regexes']):
        _, why = obj(u16(b, 0xE + 2 * i), 'regex')
        if why:
            return why
    for i in range(h['vars']):
        name, why = obj(u16(b, 0xE + 2 * h['regexes'] + 2 * i), 'variable name')
        if why:
            return why
        if not name or name[-1] != 0:
            return 'variable name not terminated'
    for i in range(h['profiles'] if collection else 0):
        name, why = obj(u16(b, first + i * ENTRY), 'profile name')
        if why:
            return why
        if not name or name[-1] != 0:
            return 'profile name not terminated'
    # Each operation starts at a node.
    for p in range(h['profiles'] if collection else 1):
        table = first + (p * ENTRY + 4 if collection else 0)
        for op in range(OPERATIONS):
            if u16(b, table + 2 * op) >= h['nodes']:
                return 'operation %d of profile %d starts past the nodes' % (op, p)
    return None


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip().splitlines()[-1])
    path, out = sys.argv[1:]
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != struct.pack('<I', MH_MAGIC_64):
        die('%s is not a decompressed 64-bit kernelcache' % path)
    kc = Kernelcache(data)
    kext = kc.kext()
    const = kext.sections.get(('__TEXT', '__const'))
    cstring = kext.sections.get(('__TEXT', '__cstring'))
    if not const or not cstring:
        die("the Sandbox kext has no __TEXT,__const or __TEXT,__cstring")
    strings = kc.read(*cstring)

    def string_at(name):
        m = re.search(re.escape(name.encode()) + b'\0', strings)
        if not m or (m.start() and strings[m.start() - 1] != 0):
            die('the Sandbox kext has no string "%s"' % name)
        return cstring[0] + m.start()

    def in_const(a, n):
        return a is not None and n is not None and const[0] <= a and a + n <= const[0] + const[1]

    names = {'builtin collection': 'sandbox_builtin.bin', 'protobox collection': 'sandbox_protobox.bin'}
    want = {string_at(n): n for n in names}
    events = calls_and_stores(kc, kext)
    found = {}
    builtin_call = None
    for k, (kind, pc, x1, x2, x3) in enumerate(events):
        if kind == 'bl' and x1 in want:
            name = want[x1]
            size = x3 & 0xFFFFFFFF if x3 is not None else None
            if not in_const(x2, size):
                die('the %s call at %#x does not name a blob in __TEXT,__const' % (name, pc))
            if name in found:
                die('two calls load the %s' % name)
            found[name] = (x2, size)
            if name == 'builtin collection':
                builtin_call = k
    for n in names:
        if n not in found:
            die('no call loads the ' + n)
    # The platform profile: a pair stored after the builtin collection's
    # call, before the next call, that is a single profile in
    # __TEXT,__const.
    for kind, pc, a, n, _ in events[builtin_call + 1:]:
        if kind == 'bl':
            break
        if kind == 'stp' and n is not None and n < 1 << 32 and in_const(a, n):
            h, _ = header(kc.read(a, min(n, 0xE)))
            if h and not h['flags'] & 0x8000:
                found['platform profile'] = (a, n)
                break
    if 'platform profile' not in found:
        die('no platform profile stored after the builtin collection is loaded')
    os.makedirs(out, exist_ok=True)
    files = dict(names, **{'platform profile': 'sandbox_profile.bin'})
    for name in ('platform profile', 'builtin collection', 'protobox collection'):
        a, n = found[name]
        blob = kc.read(a, n)
        why = check(blob, name != 'platform profile')
        if why:
            die('the %s at %#x (%#x bytes) is invalid: %s' % (name, a, n, why))
        dest = os.path.join(out, files[name])
        with open(dest, 'wb') as f:
            f.write(blob)
        print('%s  %s  (%s, %#x bytes at %#x)' % (hashlib.sha256(blob).hexdigest(), dest, name, n, a))


if __name__ == '__main__':
    main()
