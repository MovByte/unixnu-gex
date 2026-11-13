#!/usr/bin/env python3
"""Make a Darwin boot payload's trust cache bundle.

The bundle is what the boot loader hands the kernel at
/chosen/memory-map/TrustCache: a module count, each module's offset from
the bundle's start, and the modules. Its first module is the static trust
cache. This one has a single module: the given static trust cache (an
IPSW's IM4P-wrapped `.trustcache`, a raw module, or another bundle's first
module), with the cdhashes of the given Mach-O files added (each slice's
best CodeDirectory), as an owner adds their own code to it. The entries
are version 2 (cdhash, hash type, flags, constraint category), sorted by
cdhash; added code has flags 0 and launch constraint category 0, or the
category a --category CAT:MACHO names for that file.

usage: darwin-trust-cache.py -o BUNDLE [--static FILE | --bundle FILE]
                             [--category CAT:MACHO]... [MACHO...]
"""
import argparse
import hashlib
import struct
import sys

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSSLOT_CODEDIRECTORY = 0
CSSLOT_ALTERNATE = range(0x1000, 0x1005)
LC_CODE_SIGNATURE = 0x1D
# hash_rank: SHA-1 < SHA-256 truncated < SHA-256 < SHA-384.
RANK = {1: 1, 3: 2, 2: 3, 4: 4}


def der_len(b, i):
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], 'big')
        i += k
    return n, i


def im4p_payload(b):
    """An IM4P's payload: SEQUENCE { "IM4P", type, description, OCTET STRING }."""
    _, i = der_len(b, 1)
    items = []
    while i < len(b) and len(items) < 4:
        n, j = der_len(b, i + 1)
        items.append(b[j:j + n])
        i = j + n
    if len(items) < 4 or items[0] != b'IM4P':
        sys.exit('not an IM4P')
    return items[3]


def module_entries(m):
    version, = struct.unpack_from('<I', m, 0)
    size = {0: 20, 1: 22, 2: 24}.get(version)
    if size is None:
        sys.exit('trust cache module version %d' % version)
    count, = struct.unpack_from('<I', m, 0x14)
    if 0x18 + count * size > len(m):
        sys.exit('trust cache module truncated')
    out = {}
    for k in range(count):
        e = m[0x18 + k * size:0x18 + (k + 1) * size]
        hash_type = e[20] if version else 0
        flags = e[21] if version else 0
        category = e[22] if version == 2 else 0
        out[bytes(e[:20])] = (hash_type, flags, category)
    return m[4:20], out


def slices(b):
    """A file's Mach-O slices: a fat file's, or the file."""
    magic, = struct.unpack_from('>I', b, 0)
    if magic == 0xCAFEBABE:
        n, = struct.unpack_from('>I', b, 4)
        return [b[off:off + size] for _, _, off, size, _ in (struct.unpack_from('>IIIII', b, 8 + 20 * i) for i in range(n))]
    return [b]


def cdhash(macho):
    """The best CodeDirectory's cdhash and hash type, or None unsigned."""
    if struct.unpack_from('<I', macho, 0)[0] != 0xFEEDFACF:
        return None
    ncmds, = struct.unpack_from('<I', macho, 16)
    o = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', macho, o)
        if cmd == LC_CODE_SIGNATURE:
            off, n = struct.unpack_from('<II', macho, o + 8)
            sb = macho[off:off + n]
            if struct.unpack_from('>I', sb, 0)[0] != CSMAGIC_EMBEDDED_SIGNATURE:
                return None
            count, = struct.unpack_from('>I', sb, 8)
            best = None
            for i in range(count):
                ty, at = struct.unpack_from('>II', sb, 12 + 8 * i)
                if ty != CSSLOT_CODEDIRECTORY and ty not in CSSLOT_ALTERNATE:
                    continue
                magic, length = struct.unpack_from('>II', sb, at)
                if magic != CSMAGIC_CODEDIRECTORY:
                    continue
                cd = sb[at:at + length]
                if best is None or RANK.get(cd[37], 0) > RANK.get(best[37], 0):
                    best = cd
            if best is None:
                return None
            digest = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha256, 4: hashlib.sha384}[best[37]](best).digest()
            return digest[:20], best[37]
        o += size
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('-o', required=True, help='the bundle to write')
    ap.add_argument('--static', help='an IM4P trust cache or a raw module')
    ap.add_argument('--bundle', help="another bundle, whose first module is taken")
    ap.add_argument('--category', action='append', default=[], metavar='CAT:MACHO', help='a Mach-O file whose entries have launch constraint category CAT')
    ap.add_argument('files', nargs='*')
    a = ap.parse_args()
    uuid, entries = bytes(16), {}
    if a.static:
        b = open(a.static, 'rb').read()
        uuid, entries = module_entries(im4p_payload(b) if b[0] == 0x30 else b)
    elif a.bundle:
        b = open(a.bundle, 'rb').read()
        first, = struct.unpack_from('<I', b, 4)
        uuid, entries = module_entries(b[first:])
    for f in a.files:
        for s in slices(open(f, 'rb').read()):
            h = cdhash(s)
            if h is None:
                sys.exit('%s has no code signature' % f)
            entries.setdefault(h[0], (h[1], 0, 0))
    for spec in a.category:
        cat, _, f = spec.partition(':')
        if not f or not cat.isdigit() or int(cat) > 255:
            sys.exit('--category takes CAT:MACHO, CAT 0 to 255: %s' % spec)
        for s in slices(open(f, 'rb').read()):
            h = cdhash(s)
            if h is None:
                sys.exit('%s has no code signature' % f)
            entries[h[0]] = (h[1], 0, int(cat))
    module = struct.pack('<I', 2) + uuid + struct.pack('<I', len(entries))
    for h in sorted(entries):
        hash_type, flags, category = entries[h]
        module += h + bytes([hash_type, flags, category, 0])
    with open(a.o, 'wb') as out:
        out.write(struct.pack('<II', 1, 8) + module)


if __name__ == '__main__':
    main()
