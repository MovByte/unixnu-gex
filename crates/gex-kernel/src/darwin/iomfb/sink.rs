//! The presentation sink: the embedder's side of the panel. When a swap
//! reaches the glass (the vertical blank that makes it the displayed swap),
//! the framebuffer hands its layers to the sink as the surfaces hold them:
//! their bytes, pixel format, plane geometry and rectangles, with no
//! conversion. Showing them (on a canvas, or in a recording) is the
//! embedder's; one that cannot show a frame as it is says why, and the
//! kernel reports it. The sink is also told when the panel goes dark and
//! lights again (its power, [`PresentSink::panel`]): a dark panel shows
//! nothing, whatever frame it last showed.
//!
//! The embedder installs the sink ([`install`]); until one does, a swap
//! that reaches the glass is reported.
//!
//! A layer's pixel format is one the pipe shows unscaled (its RGB formats:
//! `BGRA`, `ARGB`, `RGBA`, `L565`, `w40a`, `w10p`, `w30r`, `l10r`, `w18p`,
//! `b3a8` and `f3a8`), its bytes as the surface holds them. The browser's
//! sink presents the 10-bit `b3a8` frames on an `rgba16float` canvas; the
//! test sink records every frame as it is. A sink that converts a frame
//! for its glass converts every value exactly (each 10-bit value to its
//! half float), or says it cannot.

use std::sync::OnceLock;

/// A rectangle as the swap gives it (`x`, `y`, `w`, `h`, in pixels).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// One plane of a layer's surface: where it starts in the surface's bytes,
/// its size in pixels and bytes, and its element geometry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Plane {
    pub offset: u64,
    pub width: u64,
    pub height: u64,
    pub bytes_per_row: u64,
    pub bytes_per_element: u32,
    pub element_width: u32,
    pub element_height: u32,
    pub size: u64,
}

/// One layer of a frame: the layer's index (0 to 3), its surface (id,
/// pixel format, width and height, planes, and its bytes, the surface's
/// whole allocation), the rectangle read from it (`src`), the one it
/// covers on the panel (`dst`), and its transform (the swap's 3 bits).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layer {
    pub index: u32,
    pub surface: u32,
    pub pixel_format: u32,
    pub width: u64,
    pub height: u64,
    pub planes: Vec<Plane>,
    pub bytes: Vec<u8>,
    pub src: Rect,
    pub dst: Rect,
    pub transform: u32,
}

/// A frame on the glass: its swap, the vertical blank that showed it (its
/// count and absolute time), the panel's size, and its layers in index
/// order. A swap with no layer enabled shows nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub swap_id: u32,
    pub vbl: u64,
    pub time: u64,
    pub panel: (u32, u32),
    pub layers: Vec<Layer>,
}

/// What the kernel asks of the embedder's panel.
pub trait PresentSink: Send + Sync {
    /// Show `frame`. `Err` says why the embedder cannot show it as it is
    /// (a pixel format its glass cannot hold, say), which is reported.
    fn present(&self, frame: &Frame) -> Result<(), String>;

    /// The panel lit (`on`) or dark, as the display's power turns it (its
    /// backlight off as it goes dark, and the panel on again). The panel
    /// starts lit. `Err` says why the embedder cannot, which is reported.
    fn panel(&self, on: bool) -> Result<(), String>;
}

static SINK: OnceLock<Box<dyn PresentSink>> = OnceLock::new();

/// The embedder's sink, once.
pub fn install(s: Box<dyn PresentSink>) -> Result<(), Box<dyn PresentSink>> {
    SINK.set(s)
}

/// The embedder's sink, if one is installed.
pub fn sink() -> Option<&'static dyn PresentSink> {
    SINK.get().map(|b| b.as_ref())
}
