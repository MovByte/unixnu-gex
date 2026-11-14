# Check the frame the iomfb program swapped, as the test embedder recorded
# it (hosts/native/src/darwin_frames.rs): one frame, of swap 1, one layer
# (layer 0) of a BGRA surface the panel's size, its source and destination
# the whole panel, untransformed, one plane, and every pixel the pattern
# the program wrote (iomfb.c's fill), the rows' padding zero.
import struct
import sys
from pathlib import Path


def fail(why):
    print(f"frame-check: {why}")
    sys.exit(1)


frames = sorted(Path(sys.argv[1]).glob("frame-*.bin"))
if len(frames) != 1:
    fail(f"{len(frames)} frames recorded, want 1")
b = frames[0].read_bytes()
at = 0


def take(fmt):
    global at
    v = struct.unpack_from("<" + fmt, b, at)
    at += struct.calcsize("<" + fmt)
    return v


magic, version, swap_id, vbl, time, pw, ph, layers = take("4sIIQQIII")
if magic != b"GEXF" or version != 1:
    fail("not a recorded frame")
if swap_id != 1 or layers != 1 or vbl == 0 or time == 0:
    fail(f"swap {swap_id}, {layers} layers, blank {vbl} at {time}")
index, surface, fmt, w, h = take("IIIQQ")
src = take("4i")
dst = take("4i")
transform, planes = take("II")
if index != 0 or fmt != int.from_bytes(b"BGRA", "big") or (w, h) != (pw, ph):
    fail(f"layer {index}, format {fmt:#x}, {w}x{h} on a {pw}x{ph} panel")
if src != (0, 0, pw, ph) or dst != (0, 0, pw, ph) or transform != 0 or planes != 1:
    fail(f"source {src}, destination {dst}, transform {transform}, {planes} planes")
offset, pwidth, pheight, bpr, bpe, ew, eh, size = take("QQQQIIIQ")
if (offset, pwidth, pheight, bpe, ew, eh) != (0, w, h, 4, 1, 1) or bpr < 4 * w or size < bpr * h:
    fail(f"plane at {offset}: {pwidth}x{pheight}, {bpr} bytes a row, {bpe} an element, {ew}x{eh}, {size} bytes")
(n,) = take("Q")
data = b[at:at + n]
if len(data) != n or n < bpr * h:
    fail(f"{len(data)} bytes of {n}")
for y in range(h):
    row = data[y * bpr:(y + 1) * bpr]
    want = bytearray(bpr)
    for x in range(w):
        want[4 * x:4 * x + 4] = bytes(((x * 7 + y) & 0xFF, (y * 3) & 0xFF, (x ^ y) & 0xFF, 0xFF))
    if row != want:
        x = next(i for i in range(bpr) if row[i] != want[i]) // 4
        fail(f"row {y} differs from pixel {x}")
