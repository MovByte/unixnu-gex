# Check the frames the iomfb program swapped, as the test embedder recorded
# them (hosts/native/src/darwin_frames.rs): the first, of swap 1, one layer
# (layer 0) of a BGRA surface the panel's size, its source and destination
# the whole panel, untransformed, one plane, and every pixel the pattern
# the program wrote (iomfb.c's fill), the rows' padding zero; the second,
# its layer 1 swap (its no-op swap makes none). Then the panel going dark,
# the glass blanked (no layers) by the kernel's request the controller made
# for its last frame as it went off, the panel lighting again (the swap made
# while off is never shown), and the glass blanked by the kernel's swap of
# kind 7 as the last swap client closed.
import struct
import sys
from pathlib import Path


def fail(why):
    print(f"frame-check: {why}")
    sys.exit(1)


frames = sorted(Path(sys.argv[1]).glob("frame-*.bin"), key=lambda p: int(p.name[len("frame-"):-len(".bin")]))
if len(frames) != 4:
    fail(f"{len(frames)} frames recorded, want 4")
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

# The second frame: a later swap that set only layer 1 (a 64x64 BGRA surface
# of 0x40 bytes on the panel's corner), layer 0 still the first swap's.
b = frames[1].read_bytes()
at = 0
magic, version, swap2, vbl2, time2, pw2, ph2, layers2 = take("4sIIQQIII")
if magic != b"GEXF" or swap2 <= swap_id or vbl2 <= vbl or layers2 != 2:
    fail(f"second frame: swap {swap2}, blank {vbl2}, {layers2} layers")
index0, surface0, fmt0, w0, h0 = take("IIIQQ")
src0, dst0 = take("4i"), take("4i")
transform0, planes0 = take("II")
if (index0, surface0, w0, h0, src0, dst0) != (0, surface, w, h, src, dst):
    fail(f"second frame's layer 0: {index0}, surface {surface0}, {w0}x{h0}, {src0} to {dst0}")
at += planes0 * struct.calcsize("<QQQQIIIQ")
(n0,) = take("Q")
at += n0
index1, surface1, fmt1, w1, h1 = take("IIIQQ")
src1, dst1 = take("4i"), take("4i")
transform1, planes1 = take("II")
if (index1, fmt1, w1, h1, src1, dst1, transform1, planes1) != (1, fmt, 64, 64, (0, 0, 64, 64), (0, 0, 64, 64), 0, 1) or surface1 == surface:
    fail(f"second frame's layer 1: {index1}, format {fmt1:#x}, {w1}x{h1}, {src1} to {dst1}")
offset1, pw1, ph1, bpr1, bpe1, ew1, eh1, size1 = take("QQQQIIIQ")
(n1,) = take("Q")
if any(b[at + y * bpr1 + x] != 0x40 for y in range(64) for x in range(256)):
    fail("second frame's layer 1 is not its surface's bytes")

# The panel's power, numbered with the frames: dark between the second
# frame and the third, lit between the third and the fourth.
num = lambda p, pre, suf: int(p.name[len(pre):-len(suf)])
at_ = [num(f, "frame-", ".bin") for f in frames]
panel = sorted(Path(sys.argv[1]).glob("panel-*.txt"), key=lambda p: num(p, "panel-", ".txt"))
states = [(num(p, "panel-", ".txt"), p.read_text().strip()) for p in panel]
if [s for _, s in states] != ["off", "on"] or not (at_[1] < states[0][0] < at_[2] < states[1][0] < at_[3]):
    fail(f"the panel's power {states} with frames at {at_}, want off after the second and on after the third")

# The blanked glass: no layers, later swaps (each a new swap id), later
# blanks.
last_swap, last_vbl = swap2, vbl2
for f in frames[2:]:
    b = f.read_bytes()
    at = 0
    magic, version, sid_, vbl_, time_, pw_, ph_, layers_ = take("4sIIQQIII")
    if magic != b"GEXF" or layers_ != 0 or sid_ <= last_swap or vbl_ <= last_vbl:
        fail(f"{f.name}: swap {sid_}, blank {vbl_}, {layers_} layers, want an empty glass after swap {last_swap}")
    last_swap, last_vbl = sid_, vbl_
