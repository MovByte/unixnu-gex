//! The display's frames as the canvas shows them: which frames the page
//! shows, the canvas configuration each needs, and the canvas texels of a
//! frame. Pure; the GPU Worker's sink ([`crate::sink`]) configures the canvas
//! and writes the texels.
//!
//! The framebuffer hands over a frame as its surfaces hold it, with no
//! conversion (`iomfb::sink`). The canvas is the panel: its size is the
//! panel's, and it shows one layer that covers the panel at the panel's
//! resolution, untransformed. What the display pipe does beyond that
//! (blending two layers, scaling, rotating, the background behind a partial
//! layer, the swap's color matrix) is not modelled, and a frame that needs it
//! is refused with the reason.
//!
//! Pixel formats (the pipe's RGB formats, `iomfb::swap`'s table):
//!
//! - `BGRA` (`kCVPixelFormatType_32BGRA`): CoreVideo describes its bytes as
//!   blue, green, red, alpha (`CGBitmapInfo` 0x2004, black block
//!   `00 00 00 ff`, measured on macOS 27.0.1 26A434), the order of
//!   `bgra8unorm`: the canvas texel is the pixel's four 8-bit codes,
//!   unchanged, and WebGPU's texel copies keep every bit of a non-packed
//!   unorm format.
//! - `b3a8` (`kCVPixelFormatType_30RGBLE_8A_BiPlanar`, "little-endian RGB
//!   XX-10-10-10 2 MSB zero in first plane (wide-gamut), alpha 8 bits in
//!   second plane (full-range)", `CVPixelBuffer.h` of the iPhoneOS SDK):
//!   shown on an `rgba16float` canvas, as the owner decided for the
//!   display's 10-bit frames. Plane 0 is a 32-bit little-endian word per
//!   pixel with blue in bits 0-9, green in 10-19 and red in 20-29; plane 1 is
//!   one alpha byte per pixel. Measured on macOS 27.0.1 26A434 (Apple M4)
//!   through Metal views of a `b3a8` surface's planes (`BGR10_XR` and
//!   `A8Unorm`): clearing to black writes 384 in each field, white 894, 0.5
//!   639, and alpha 0.5 the byte 0x80; CoreVideo reports its component range
//!   as `WideRange`, the extended range of `BGR10_XR`, where code `c` has the
//!   value `(c - 384) / 510` (WebMetal `tables/formats.toml`,
//!   `6.3-xr-encoding`). Bits 30-31 are padding (Metal wrote 1s there in the
//!   measurement, where the header says zero); they carry no value. Alpha
//!   code `a` has the value `a / 255`.
//!
//!   Each value goes to its binary16, the half float nearest it with ties
//!   to even, computed in exact integer arithmetic ([`half_of_ratio`]). Most
//!   of these values have no exact binary16 representation (the spacing of
//!   the codes is 1/510, of halves near 1 is 2^-11), so a half stands for its
//!   code's value as the nearest one; distinct codes always give distinct
//!   halves, and the code is recovered from the half by rounding
//!   `h * 510 + 384`. Every half produced is zero or normal, which WebGPU's
//!   texel copies keep bit for bit. The canvas is configured with
//!   `toneMapping: "extended"`, so values outside [0, 1] are shown as the
//!   extended range means them, rather than clamped.
//! - Every other format (`ARGB`, `RGBA`, `L565`, `w40a`, `w10p`, `w30r`,
//!   `l10r`, `w18p`, `f3a8`) is refused: no canvas format holds its values
//!   exactly, or CoreVideo publishes no description of its bytes ('ARGB',
//!   'RGBA', 'w10p', 'w18p' and 'L565' have none on the reference system).
//!
//! The canvas's color space is "srgb" for both: `BGRA` frames are sRGB
//! codes, and the XR encoding of `b3a8` extends sRGB's range. The swap's color
//! matrix (`SwapSetColorMatrix`), through which the render server tells the
//! pipe how to map the framebuffer to the panel, is not modelled by the
//! framebuffer (it reports the call), so nothing here confirms a frame's
//! color space beyond that.

use crate::protocol::{Frame, Layer, Plane};

/// A four-character code as `IOSurfaceGetPixelFormat` returns it.
pub const fn fourcc(c: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*c)
}

pub const BGRA: u32 = fourcc(b"BGRA");
pub const B3A8: u32 = fourcc(b"b3a8");

/// The canvas format a frame needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanvasFormat {
    Bgra8unorm,
    Rgba16float,
}

impl CanvasFormat {
    /// Bytes of one canvas texel.
    pub fn texel_bytes(self) -> usize {
        match self {
            CanvasFormat::Bgra8unorm => 4,
            CanvasFormat::Rgba16float => 8,
        }
    }

    /// Whether values outside [0, 1] are shown (`toneMapping: "extended"`).
    pub fn extended(self) -> bool {
        self == CanvasFormat::Rgba16float
    }
}

/// A frame ready for the canvas: its configuration and its texels, row by
/// row with no padding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    pub format: CanvasFormat,
    pub width: u32,
    pub height: u32,
    pub texels: Vec<u8>,
}

impl Shown {
    pub fn bytes_per_row(&self) -> u32 {
        self.width * self.format.texel_bytes() as u32
    }
}

/// The binary16 nearest `num / den` (ties to even), from the exact ratio.
/// `den` is positive; the result is finite for any ratio below 65520 in
/// magnitude.
pub fn half_of_ratio(num: i64, den: u64) -> u16 {
    assert!(den > 0);
    let sign: u16 = if num < 0 { 0x8000 } else { 0 };
    let n = u128::from(num.unsigned_abs());
    let d = u128::from(den);
    if n == 0 {
        return sign;
    }
    // n/d >= 2^e (n < 2^63 and d < 2^64, so |e| <= 64 and no shift overflows).
    let at_least = |e: i32| if e >= 0 { n >= d << e as u32 } else { n << (-e) as u32 >= d };
    // e: 2^e <= n/d < 2^(e+1), from the bit lengths, then exactly.
    let bits = |v: u128| 128 - v.leading_zeros() as i32;
    let mut e = bits(n) - bits(d);
    if !at_least(e) {
        e -= 1;
    }
    debug_assert!(at_least(e) && !at_least(e + 1));
    // n/d * 2^s rounded to an integer, ties to even.
    let round = |s: i32| -> u128 {
        let (num, den) = if s >= 0 { (n << s as u32, d) } else { (n, d << (-s) as u32) };
        let q = num / den;
        let r = num % den;
        match (r * 2).cmp(&den) {
            std::cmp::Ordering::Less => q,
            std::cmp::Ordering::Greater => q + 1,
            std::cmp::Ordering::Equal => q + (q & 1),
        }
    };
    if e < -14 {
        // Subnormal: units of 2^-24.
        let m = round(24) as u16;
        return sign | m; // m == 1024 is the smallest normal's encoding, as it should be.
    }
    let mut m = round(10 - e);
    let mut exp = e;
    if m == 2048 {
        m = 1024;
        exp += 1;
    }
    assert!(exp <= 15, "{num}/{den} is beyond binary16's range");
    sign | (((exp + 15) as u16) << 10) | (m as u16 & 0x3ff)
}

/// The value of a binary16 (for checks).
pub fn half_value(h: u16) -> f64 {
    let s = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let e = i32::from((h >> 10) & 0x1f);
    let m = f64::from(h & 0x3ff);
    match e {
        0 => s * m * 2f64.powi(-24),
        31 => panic!("not finite"),
        _ => s * (1.0 + m / 1024.0) * 2f64.powi(e - 15),
    }
}

/// The halves of the 1024 extended-range codes: `(c - 384) / 510`.
pub fn xr_halves() -> [u16; 1024] {
    std::array::from_fn(|c| half_of_ratio(c as i64 - 384, 510))
}

/// The halves of the 256 alpha codes: `a / 255`.
pub fn unorm8_halves() -> [u16; 256] {
    std::array::from_fn(|a| half_of_ratio(a as i64, 255))
}

/// The plane `p` of `layer`, with its bytes inside the layer's.
fn plane<'a>(layer: &'a Layer, p: usize, element: u32, what: &str) -> Result<(&'a Plane, &'a [u8]), String> {
    let pl = layer.planes.get(p).ok_or_else(|| format!("a {what} layer without plane {p}"))?;
    if pl.bytes_per_element != element || pl.element_width != 1 || pl.element_height != 1 {
        return Err(format!(
            "a {what} layer whose plane {p} has {}-byte elements of {}x{} pixels (expected {element}-byte pixels)",
            pl.bytes_per_element, pl.element_width, pl.element_height
        ));
    }
    if pl.width < layer.width || pl.height < layer.height {
        return Err(format!("a {what} layer whose plane {p} ({}x{}) is smaller than the layer", pl.width, pl.height));
    }
    let row = layer.width * u64::from(element);
    let need = pl.offset + pl.bytes_per_row * (layer.height - 1) + row;
    if pl.bytes_per_row < row || need > layer.bytes.len() as u64 {
        return Err(format!("a {what} layer whose plane {p} lies outside the surface's {} bytes", layer.bytes.len()));
    }
    Ok((pl, &layer.bytes))
}

/// The canvas texels of `frame`, or why the page cannot show it as it is.
pub fn show(frame: &Frame, xr: &[u16; 1024], alpha: &[u16; 256]) -> Result<Shown, String> {
    let (pw, ph) = frame.panel;
    let layer = match frame.layers.as_slice() {
        [] => {
            return Err("a frame with no layer on the glass: what the display pipe shows behind its layers is not modelled"
                .to_string());
        }
        [l] => l,
        ls => {
            return Err(format!(
                "a frame of {} layers: the display pipe's blending of layers is not modelled (layers {:?})",
                ls.len(),
                ls.iter().map(|l| l.index).collect::<Vec<_>>()
            ));
        }
    };
    let full = |r: &crate::protocol::Rect| r.x == 0 && r.y == 0 && r.w == pw as i32 && r.h == ph as i32;
    if layer.transform != 0 {
        return Err(format!("layer {} with transform {:#x}: the display pipe's transforms are not modelled", layer.index, layer.transform));
    }
    if !full(&layer.src) || !full(&layer.dst) || layer.width != u64::from(pw) || layer.height != u64::from(ph) {
        return Err(format!(
            "layer {} of a {}x{} surface from {:?} to {:?} on a {pw}x{ph} panel: only a layer that covers the panel at the panel's resolution is shown (the pipe's scaling and background are not modelled)",
            layer.index, layer.width, layer.height, layer.src, layer.dst
        ));
    }
    let (w, h) = (pw as usize, ph as usize);
    match layer.pixel_format {
        BGRA => {
            let (pl, bytes) = plane(layer, 0, 4, "BGRA")?;
            let mut texels = Vec::with_capacity(w * h * 4);
            for y in 0..h {
                let at = (pl.offset + pl.bytes_per_row * y as u64) as usize;
                texels.extend_from_slice(&bytes[at..at + w * 4]);
            }
            Ok(Shown { format: CanvasFormat::Bgra8unorm, width: pw, height: ph, texels })
        }
        B3A8 => {
            let (rgb, bytes) = plane(layer, 0, 4, "b3a8")?;
            let (a, _) = plane(layer, 1, 1, "b3a8")?;
            let mut texels = vec![0u8; w * h * 8];
            for y in 0..h {
                let r0 = (rgb.offset + rgb.bytes_per_row * y as u64) as usize;
                let a0 = (a.offset + a.bytes_per_row * y as u64) as usize;
                let out = &mut texels[y * w * 8..(y + 1) * w * 8];
                for x in 0..w {
                    let v = u32::from_le_bytes(bytes[r0 + 4 * x..r0 + 4 * x + 4].try_into().unwrap());
                    let t = [
                        xr[((v >> 20) & 0x3ff) as usize],
                        xr[((v >> 10) & 0x3ff) as usize],
                        xr[(v & 0x3ff) as usize],
                        alpha[bytes[a0 + x] as usize],
                    ];
                    for (i, c) in t.iter().enumerate() {
                        out[8 * x + 2 * i..8 * x + 2 * i + 2].copy_from_slice(&c.to_le_bytes());
                    }
                }
            }
            Ok(Shown { format: CanvasFormat::Rgba16float, width: pw, height: ph, texels })
        }
        f => Err(refusal(f)),
    }
}

/// Why a format is not shown.
fn refusal(f: u32) -> String {
    let name = {
        let b = f.to_be_bytes();
        if b.iter().all(|c| (0x20..0x7f).contains(c)) { String::from_utf8_lossy(&b).into_owned() } else { format!("{f:#x}") }
    };
    let why = match &f.to_be_bytes() {
        b"ARGB" | b"RGBA" | b"w10p" | b"w18p" | b"L565" => {
            "CoreVideo publishes no description of its bytes (CVPixelFormatDescriptionCreateWithPixelFormatType returns none on macOS 27.0.1 26A434), so their order is not established"
        }
        b"l10r" | b"f3a8" => "a 10-bit full-range code c has the value c / 1023, which no canvas format holds (binary16 holds it exactly only for 0 and 1023)",
        b"w30r" | b"w40a" => "an extended-range code c has the value (c - 384) / 510, which no canvas format holds exactly (the owner's decision to show 10-bit frames on rgba16float covers the display's b3a8 frames)",
        _ => "not a format the display pipe shows unscaled",
    };
    format!("a layer of pixel format {name}: {why}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Rect;

    /// The halves next to `h` (towards zero and away), for nearest checks.
    fn neighbours(h: u16) -> [u16; 2] {
        let mag = h & 0x7fff;
        let s = h & 0x8000;
        [if mag == 0 { 0x8001 } else { s | (mag - 1) }, s | (mag + 1)]
    }

    fn check_nearest(num: i64, den: u64, h: u16) {
        // Exact: compare |h - q| with the neighbours' distances in rationals scaled by den * 2^24 * 2^15.
        let q = num as f64 / den as f64;
        let d = (half_value(h) - q).abs();
        for n in neighbours(h) {
            if (n & 0x7c00) == 0x7c00 {
                continue;
            }
            let dn = (half_value(n) - q).abs();
            assert!(d <= dn, "{num}/{den}: {h:#06x} is not nearest ({n:#06x} is nearer)");
            if d == dn {
                assert_eq!(h & 1, 0, "{num}/{den}: a tie goes to the even half");
            }
        }
    }

    #[test]
    fn xr_codes_go_to_their_nearest_distinct_halves() {
        let t = xr_halves();
        for (c, &h) in t.iter().enumerate() {
            check_nearest(c as i64 - 384, 510, h);
            // Zero or normal: texel copies keep it.
            let e = (h >> 10) & 0x1f;
            assert!(h & 0x7fff == 0 || (e != 0 && e != 31), "code {c}: {h:#06x}");
            // The code comes back from the half.
            assert_eq!((half_value(h) * 510.0 + 384.0).round() as usize, c);
        }
        let mut s = t.to_vec();
        s.sort();
        s.dedup();
        assert_eq!(s.len(), 1024, "distinct codes give distinct halves");
        assert_eq!(t[384], 0x0000);
        assert_eq!(t[894], 0x3c00, "1.0");
        assert_eq!(t[639], 0x3800, "0.5");
        assert_eq!(t[129], 0xb800, "-0.5");
        assert_eq!(t[0], half_of_ratio(-384, 510));
        // -384/510 = -0.75294...: nearest half is -0.7529296875 (0xba06).
        assert_eq!(t[0], 0xba06);
    }

    #[test]
    fn alpha_codes_go_to_their_nearest_halves() {
        let t = unorm8_halves();
        for (a, &h) in t.iter().enumerate() {
            check_nearest(a as i64, 255, h);
            assert_eq!((half_value(h) * 255.0).round() as usize, a);
        }
        assert_eq!(t[0], 0);
        assert_eq!(t[255], 0x3c00);
    }

    #[test]
    fn halves_of_exact_values_are_exact() {
        assert_eq!(half_of_ratio(1, 1), 0x3c00);
        assert_eq!(half_of_ratio(-2, 1), 0xc000);
        assert_eq!(half_of_ratio(1, 1024), 0x1400);
        assert_eq!(half_of_ratio(1, 1 << 24), 0x0001, "the smallest subnormal");
        assert_eq!(half_of_ratio(1, 1 << 14), 0x0400, "the smallest normal");
        assert_eq!(half_of_ratio(65504, 1), 0x7bff);
        // 1 + 2^-11 lies halfway between 1 and 1 + 2^-10: to even (1).
        assert_eq!(half_of_ratio(2049, 2048), 0x3c00);
        assert_eq!(half_of_ratio(2051, 2048), 0x3c02);
    }

    fn layer(format: u32, w: u32, h: u32, planes: Vec<Plane>, bytes: Vec<u8>) -> Layer {
        let r = Rect { x: 0, y: 0, w: w as i32, h: h as i32 };
        Layer { index: 0, surface: 1, pixel_format: format, width: w.into(), height: h.into(), planes, bytes, src: r, dst: r, transform: 0 }
    }

    fn p(offset: u64, w: u64, h: u64, bpr: u64, bpe: u32) -> Plane {
        Plane { offset, width: w, height: h, bytes_per_row: bpr, bytes_per_element: bpe, element_width: 1, element_height: 1, size: bpr * h }
    }

    #[test]
    fn bgra_frames_are_their_bytes() {
        let bytes: Vec<u8> = (0..64u8).collect();
        let f = Frame { panel: (2, 2), layers: vec![layer(BGRA, 2, 2, vec![p(0, 2, 2, 32, 4)], bytes)], ..Default::default() };
        let s = show(&f, &xr_halves(), &unorm8_halves()).unwrap();
        assert_eq!(s.format, CanvasFormat::Bgra8unorm);
        let want: Vec<u8> = (0..8u8).chain(32..40).collect();
        assert_eq!(s.texels, want);
    }

    #[test]
    fn b3a8_frames_are_their_codes_halves() {
        // One row of two pixels; plane 1 after plane 0.
        let mut bytes = vec![0u8; 32];
        let px = |r: u32, g: u32, b: u32| (3 << 30) | (r << 20) | (g << 10) | b;
        bytes[0..4].copy_from_slice(&px(894, 384, 639).to_le_bytes());
        bytes[4..8].copy_from_slice(&px(0, 1023, 129).to_le_bytes());
        bytes[16] = 255;
        bytes[17] = 0x80;
        let f = Frame { panel: (2, 1), layers: vec![layer(B3A8, 2, 1, vec![p(0, 2, 1, 16, 4), p(16, 2, 1, 16, 1)], bytes)], ..Default::default() };
        let xr = xr_halves();
        let a = unorm8_halves();
        let s = show(&f, &xr, &a).unwrap();
        assert_eq!(s.format, CanvasFormat::Rgba16float);
        let h: Vec<u16> = s.texels.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        assert_eq!(h, vec![0x3c00, 0, 0x3800, 0x3c00, xr[0], xr[1023], 0xb800, a[0x80]]);
    }

    #[test]
    fn frames_the_page_cannot_show_are_refused() {
        let ok = |l: Layer| Frame { panel: (2, 2), layers: vec![l], ..Default::default() };
        let bgra = || layer(BGRA, 2, 2, vec![p(0, 2, 2, 8, 4)], vec![0; 16]);
        assert!(show(&ok(bgra()), &xr_halves(), &unorm8_halves()).is_ok());
        let mut t = bgra();
        t.transform = 1;
        assert!(show(&ok(t), &xr_halves(), &unorm8_halves()).unwrap_err().contains("transform"));
        let mut s = bgra();
        s.dst = Rect { x: 0, y: 0, w: 1, h: 2 };
        assert!(show(&ok(s), &xr_halves(), &unorm8_halves()).unwrap_err().contains("covers the panel"));
        let argb = layer(fourcc(b"ARGB"), 2, 2, vec![p(0, 2, 2, 8, 4)], vec![0; 16]);
        assert!(show(&ok(argb), &xr_halves(), &unorm8_halves()).unwrap_err().contains("no description"));
        let two = Frame { panel: (2, 2), layers: vec![bgra(), bgra()], ..Default::default() };
        assert!(show(&two, &xr_halves(), &unorm8_halves()).unwrap_err().contains("blending"));
        let none = Frame { panel: (2, 2), ..Default::default() };
        assert!(show(&none, &xr_halves(), &unorm8_halves()).is_err());
        let short = layer(BGRA, 2, 2, vec![p(0, 2, 2, 8, 4)], vec![0; 15]);
        assert!(show(&ok(short), &xr_halves(), &unorm8_halves()).unwrap_err().contains("outside"));
    }
}
