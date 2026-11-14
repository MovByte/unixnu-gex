#!/usr/bin/env python3
"""Write the owners, modes and file flags of a Darwin volume's files.

A Darwin root extracted onto a host keeps its files' contents but not their
owners (the host's user owns them all), nor always their modes and flags.
The device's system volume has them: mount the IPSW's root filesystem image
read-only with its owners honoured (`hdiutil attach -readonly -nobrowse
-owners on -mountpoint MNT IMAGE.dmg`) and point this at the mount point.

The output is a specification in mtree(5)'s layout: `/set` lines give the
defaults of the entries after them; each entry is its name (vis(3)-encoded:
each byte outside the printable ASCII, and space and backslash, as \\ooo)
and the keywords where it differs from the defaults: `type` (dir, file,
link, char, block, fifo, socket), `uid`, `gid`, `mode` (the permission bits
and the set-id and sticky bits, in octal) and `flags` (`st_flags`, in
hexadecimal: this file's own spelling, where mtree(5) uses chflags(1)'s
names). A directory's entry is followed by its own entries and then `..`.
The root is `.`.

A directory the caller cannot read is reported and its entries are left
out: run as root to read every one.

usage: darwin-volume-attrs.py MOUNTPOINT -o SPEC
"""
import argparse
import collections
import os
import stat
import sys

TYPES = {
    stat.S_IFDIR: 'dir',
    stat.S_IFREG: 'file',
    stat.S_IFLNK: 'link',
    stat.S_IFCHR: 'char',
    stat.S_IFBLK: 'block',
    stat.S_IFIFO: 'fifo',
    stat.S_IFSOCK: 'socket',
}


def vis(name):
    out = []
    for b in os.fsencode(name):
        if 0x21 <= b <= 0x7E and b != 0x5C:
            out.append(chr(b))
        else:
            out.append('\\%03o' % b)
    return ''.join(out)


def keys(st):
    return {
        'type': TYPES[stat.S_IFMT(st.st_mode)],
        'uid': str(st.st_uid),
        'gid': str(st.st_gid),
        'mode': '%04o' % stat.S_IMODE(st.st_mode),
        'flags': '%x' % st.st_flags,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('root')
    ap.add_argument('-o', required=True)
    a = ap.parse_args()
    out = open(a.o, 'w', encoding='ascii')
    unread = []
    current = {}

    def line(name, k):
        # The keywords that differ from the defaults; a directory always
        # says its type.
        diff = [f'{n}={v}' for n, v in k.items() if current.get(n) != v or (n == 'type' and v == 'dir')]
        out.write(' '.join([vis(name)] + diff) + '\n')

    def walk(path, name):
        line(name, keys(os.lstat(path)))
        try:
            names = sorted(os.listdir(path), key=os.fsencode)
        except PermissionError:
            unread.append(path)
            names = []
        entries = [(n, keys(os.lstat(os.path.join(path, n)))) for n in names]
        files = [k for _, k in entries if k['type'] != 'dir']
        if files:
            # The commonest keywords of the directory's other entries.
            common = collections.Counter(tuple(sorted(k.items())) for k in files).most_common(1)[0][0]
            want = dict(common)
            if want != current:
                current.clear()
                current.update(want)
                out.write('/set ' + ' '.join(f'{n}={v}' for n, v in sorted(want.items())) + '\n')
        for n, k in entries:
            if k['type'] != 'dir':
                line(n, k)
        for n, k in entries:
            if k['type'] == 'dir':
                walk(os.path.join(path, n), n)
        out.write('..\n')

    out.write('# darwin-volume-attrs: type, uid, gid, mode, flags (hexadecimal)\n')
    walk(a.root, '.')
    out.close()
    for p in unread:
        print(f'not readable, its entries left out: {os.path.relpath(p, a.root)}', file=sys.stderr)


if __name__ == '__main__':
    main()
