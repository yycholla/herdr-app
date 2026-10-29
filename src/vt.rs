//! Herdr's view of a core terminal: libghostty-vt fed with the relayed bytes,
//! read back as frames to draw, and asked to encode keys and mouse input.

use ghostty_sys::*;
use std::collections::HashMap;
use std::ffi::c_void;
use std::rc::Rc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl From<GhosttyColorRgb> for Rgb {
    fn from(c: GhosttyColorRgb) -> Self {
        Rgb(c.r, c.g, c.b)
    }
}

impl Rgb {
    /// WCAG relative luminance.
    fn luminance(self) -> f32 {
        let ch = |v: u8| {
            let v = v as f32 / 255.0;
            if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * ch(self.0) + 0.7152 * ch(self.1) + 0.0722 * ch(self.2)
    }
}

fn contrast(a: Rgb, b: Rgb) -> f32 {
    let (x, y) = (a.luminance(), b.luminance());
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// Ghostty's graphics ranges retain intentional low contrast, as do our sprites.
fn preserves_graphics_color(text: &str) -> bool {
    crate::sprites::is_sprite(text)
        || text.chars().next().is_some_and(|c| matches!(c as u32,
            0x2500..=0x259f | 0xe0b0..=0xe0d7 | 0x1fb00..=0x1fbff | 0x1cc00..=0x1cebf))
}

/// `fg`, or near-white / near-black when it would vanish into `bg`.
fn readable(fg: Rgb, bg: Rgb, minimum: f32) -> Rgb {
    if minimum <= 1.0 || contrast(fg, bg) >= minimum {
        return fg;
    }
    let (light, dark) = (Rgb(0xf2, 0xf2, 0xf4), Rgb(0x1b, 0x1b, 0x1e));
    if contrast(light, bg) >= contrast(dark, bg) { light } else { dark }
}

#[derive(Clone, PartialEq)]
pub struct Theme {
    pub fg: Rgb,
    pub bg: Rgb,
    pub cursor: Rgb,
    pub selection_bg: Rgb,
    pub palette16: [Rgb; 16],
    pub minimum_contrast: f32,
}

/// The terminal colors from settings.json's theme.
pub fn theme() -> Theme {
    use crate::settings::rgb;
    let t = crate::settings::theme();
    let get = |k: &str| rgb(t.get(k).map(String::as_str).unwrap_or("#ff00ff"));
    let mut palette16 = [Rgb::default(); 16];
    for (i, c) in palette16.iter_mut().enumerate() {
        *c = get(&format!("ansi{i}"));
    }
    Theme { fg: get("terminal_foreground"), bg: get("background"), cursor: get("cursor"), selection_bg: get("selection"), palette16, minimum_contrast: crate::settings::get().minimum_contrast }
}

#[derive(Clone, Default, PartialEq)]
pub struct Cell {
    /// Empty for blank cells and for the tail half of a wide character.
    pub text: String,
    pub fg: Rgb,
    pub bg: Option<Rgb>,
    pub bold: bool,
    pub italic: bool,
    pub faint: bool,
    pub underline: bool,
    pub strike: bool,
    pub wide: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CursorShape {
    Block,
    Bar,
    Underline,
    Hollow,
}

#[derive(Clone, Copy)]
pub struct Cursor {
    pub x: u16,
    pub y: u16,
    pub shape: CursorShape,
    pub color: Rgb,
}

pub struct Frame {
    /// A row that didn't change since the last frame is the same `Rc`.
    pub rows: Vec<Rc<Vec<Cell>>>,
    /// Every row changed (output scrolled, a resize, new colors): none is kept.
    pub all: bool,
    pub cursor: Option<Cursor>,
    /// The cursor's cell even when the program hides it (agents draw their
    /// own): where input methods put their candidate window.
    pub cursor_cell: Option<(u16, u16)>,
    pub bg: Rgb,
}

/// Holds what the terminal's callbacks write into; boxed so its address is stable.
struct Shared {
    state: GhosttyRenderState,
    held_since: Option<Instant>,
    title_changed: bool,
    /// Replies the terminal writes back to the program (e.g. kitty graphics acks).
    replies: Vec<u8>,
    clipboard_write: bool,
    clipboard: [Option<String>; 2],
    /// Kitty images may load from local files and shared memory. Off for a
    /// program that runs elsewhere (Rex): it mustn't read this machine's files.
    local_media: bool,
}

/// One kitty graphics image on screen, in cells of the viewport.
#[derive(Clone, Debug, PartialEq)]
pub struct Placement {
    pub image: u32,
    /// Changes whenever the image's pixels do (cache key).
    pub generation: u64,
    pub col: i32,
    pub row: i32,
    pub width: u32,
    pub height: u32,
    pub source: [u32; 4],
    pub z: i32,
}

unsafe extern "C" fn on_write_pty(_t: GhosttyTerminal, userdata: *mut c_void, data: *const u8, len: usize) {
    let shared = unsafe { &mut *(userdata as *mut Shared) };
    if !data.is_null() && len > 0 {
        shared.replies.extend_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
    }
}

const MAX_CLIPBOARD_BYTES: usize = 1 << 20;

unsafe extern "C" fn on_clipboard_write(_t: GhosttyTerminal, userdata: *mut c_void, request: *const GhosttyClipboardWrite) {
    let shared = unsafe { &mut *(userdata as *mut Shared) };
    let request = unsafe { &*request };
    if !shared.clipboard_write || request.size < std::mem::size_of::<GhosttyClipboardWrite>() {
        return;
    }
    let slot = match request.location {
        GHOSTTY_CLIPBOARD_LOCATION_STANDARD => 0,
        GHOSTTY_CLIPBOARD_LOCATION_PRIMARY if cfg!(target_os = "linux") => 1,
        _ => return,
    };
    let text = if request.contents_len == 0 {
        ""
    } else {
        if request.contents_len != 1 || request.contents.is_null() {
            return;
        }
        let content = unsafe { &*request.contents };
        if content.mime.ptr.is_null() || content.data.len > MAX_CLIPBOARD_BYTES {
            return;
        }
        let mime = unsafe { std::slice::from_raw_parts(content.mime.ptr, content.mime.len) };
        if mime != b"text/plain" {
            return;
        }
        let bytes = if content.data.len == 0 {
            &[][..]
        } else if content.data.ptr.is_null() {
            return;
        } else {
            unsafe { std::slice::from_raw_parts(content.data.ptr, content.data.len) }
        };
        let Ok(text) = std::str::from_utf8(bytes) else { return };
        text
    };
    // Keep only the last write per destination, bounding a whole output batch.
    shared.clipboard[slot] = Some(text.to_owned());
    if let Some(reply) = request.reply {
        let result = GhosttyClipboardWriteReply {
            size: std::mem::size_of::<GhosttyClipboardWriteReply>(),
            result: GHOSTTY_CLIPBOARD_WRITE_RESULT_SUCCESS,
            remember: false,
        };
        unsafe { reply(request, &result) };
    }
}

/// PNG decoding for kitty graphics (libghostty-vt leaves it to the embedder).
unsafe extern "C" fn decode_png(_ud: *mut c_void, alloc: *const GhosttyAllocator, data: *const u8, len: usize, out: *mut GhosttySysImage) -> bool {
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    let mut decoder = png::Decoder::new(bytes);
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16 | png::Transformations::ALPHA);
    let Ok(mut reader) = decoder.read_info() else { return false };
    let mut buf = vec![0; reader.output_buffer_size()];
    let Ok(info) = reader.next_frame(&mut buf) else { return false };
    let (w, h) = (info.width, info.height);
    let rgba: Vec<u8> = match info.color_type {
        png::ColorType::Rgba => buf[..info.buffer_size()].to_vec(),
        png::ColorType::GrayscaleAlpha => buf[..info.buffer_size()].chunks(2).flat_map(|p| [p[0], p[0], p[0], p[1]]).collect(),
        png::ColorType::Rgb => buf[..info.buffer_size()].chunks(3).flat_map(|p| [p[0], p[1], p[2], 255]).collect(),
        png::ColorType::Grayscale => buf[..info.buffer_size()].iter().flat_map(|g| [*g, *g, *g, 255]).collect(),
        _ => return false,
    };
    let ptr = unsafe { ghostty_alloc(alloc, rgba.len()) };
    if ptr.is_null() {
        return false;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(rgba.as_ptr(), ptr, rgba.len());
        *out = GhosttySysImage { width: w, height: h, data: ptr, data_len: rgba.len() };
    }
    true
}

fn install_png_decoder() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        let f: GhosttySysDecodePngFn = Some(decode_png);
        ghostty_sys_set(GHOSTTY_SYS_OPT_DECODE_PNG, std::mem::transmute::<GhosttySysDecodePngFn, *const c_void>(f));
    });
}

pub struct Vt {
    term: GhosttyTerminal,
    shared: Box<Shared>,
    rows_it: GhosttyRenderStateRowIterator,
    cells: GhosttyRenderStateRowCells,
    keys: GhosttyKeyEncoder,
    key_event: GhosttyKeyEvent,
    mouse: GhosttyMouseEncoder,
    mouse_event: GhosttyMouseEvent,
    pub cols: u16,
    pub rows: u16,
    theme: Theme,
    /// The built-in 256-color palette, which the theme's 16 colors override.
    base_palette: [GhosttyColorRgb; 256],
    /// Ghostty's own click/double-click/triple-click/drag selection logic.
    gesture: GhosttySelectionGesture,
    press: GhosttySelectionGestureEvent,
    drag: GhosttySelectionGestureEvent,
    release: GhosttySelectionGestureEvent,
    /// The cursor, the kitty images and the colors as last drawn: changes to
    /// them don't mark the render state dirty.
    drawn: (CursorKey, u64, u64),
    /// The rows read last frame by libghostty's row id, with their selection:
    /// one that isn't dirty is the same row and isn't read again.
    seen: HashMap<[u64; 2], (Rc<Vec<Cell>>, Option<(u16, u16)>)>,
    /// The width and colors they were read with: a change reads every row.
    seen_with: (u16, u64),
    /// Whether the program wants win32 key events (Ghostty doesn't track it).
    pub win32: crate::win32_keys::Win32Input,
}

/// What of the cursor a frame shows: (on screen, x, y, visible, style).
type CursorKey = (bool, u16, u16, bool, i32);

/// Where a link shows: (viewport row, first column, last column) per row.
pub type Spans = Vec<(u16, u16, u16)>;

/// A link found in the terminal: what it says, and where it shows.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkHit {
    pub target: String,
    pub spans: Spans,
}

fn hyperlink_uri(r: &GhosttyGridRef) -> Option<String> {
    let mut len = 0usize;
    let mut buf = vec![0u8; 512];
    let mut res = unsafe { ghostty_grid_ref_hyperlink_uri(r, buf.as_mut_ptr(), buf.len(), &mut len) };
    if res == GHOSTTY_OUT_OF_SPACE {
        buf.resize(len, 0);
        res = unsafe { ghostty_grid_ref_hyperlink_uri(r, buf.as_mut_ptr(), buf.len(), &mut len) };
    }
    (res == GHOSTTY_SUCCESS && len > 0).then(|| String::from_utf8_lossy(&buf[..len]).into_owned())
}

#[derive(Clone, Copy)]
pub enum Select {
    Press,
    Drag,
    Release,
}

fn ok(r: GhosttyResult, what: &str) {
    assert!(r == GHOSTTY_SUCCESS, "{what} failed: {r}");
}

unsafe extern "C" fn on_render_hold(_t: GhosttyTerminal, userdata: *mut c_void, held: bool) {
    let shared = unsafe { &mut *(userdata as *mut Shared) };
    if held {
        // Capture the finished frame the program wants on screen before it redraws.
        unsafe { ghostty_render_state_update(shared.state, _t) };
        shared.held_since = Some(Instant::now());
    } else {
        shared.held_since = None;
    }
}

unsafe extern "C" fn on_title(_t: GhosttyTerminal, userdata: *mut c_void) {
    let shared = unsafe { &mut *(userdata as *mut Shared) };
    shared.title_changed = true;
}

const SYNC_OUTPUT: GhosttyMode = 2026;
const BRACKETED_PASTE: GhosttyMode = 2004;
const MAX_HOLD: Duration = Duration::from_millis(1000);
const SCROLLBACK_MAX_LINES: usize = 10_000;
// Bound memory per terminal; wide or heavily styled rows may hit this first.
const SCROLLBACK_MAX_BYTES: usize = 10_000_000;
/// Units per pixel for selection gestures (see `select`).
const SUBPIXEL: f32 = 64.0;

/// Points a terminal's callbacks at `shared` and sets Herdr's limits: what
/// every terminal a `Vt` owns needs (a new one, and one from a snapshot).
unsafe fn configure(term: GhosttyTerminal, shared: &mut Box<Shared>) {
    unsafe {
        let ud = &mut **shared as *mut Shared as *const c_void;
        ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_USERDATA, ud);
        let hold: GhosttyTerminalRenderHoldFn = Some(on_render_hold);
        ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_RENDER_HOLD, std::mem::transmute::<GhosttyTerminalRenderHoldFn, *const c_void>(hold));
        let title: GhosttyTerminalTitleChangedFn = Some(on_title);
        ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_TITLE_CHANGED, std::mem::transmute::<GhosttyTerminalTitleChangedFn, *const c_void>(title));
        let write: GhosttyTerminalWritePtyFn = Some(on_write_pty);
        ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_WRITE_PTY, std::mem::transmute::<GhosttyTerminalWritePtyFn, *const c_void>(write));
        let clipboard: GhosttyTerminalClipboardWriteFn = Some(on_clipboard_write);
        ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_CLIPBOARD_WRITE, std::mem::transmute::<GhosttyTerminalClipboardWriteFn, *const c_void>(clipboard));
        let max_clipboard: usize = MAX_CLIPBOARD_BYTES;
        ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_CLIPBOARD_WRITE_MAX_BYTES, &max_clipboard as *const _ as *const c_void);
        // No read callback: programs can never read the local clipboard.
        let images: u64 = 128 << 20;
        ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_KITTY_IMAGE_STORAGE_LIMIT, &images as *const _ as *const c_void);
        ok(ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_BYTES, &SCROLLBACK_MAX_BYTES as *const _ as *const c_void), "scrollback_max_bytes");
        ok(ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_SCROLLBACK_MAX_LINES, &SCROLLBACK_MAX_LINES as *const _ as *const c_void), "scrollback_max_lines");
        if !shared.local_media {
            let off = false;
            ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_KITTY_IMAGE_MEDIUM_FILE, &off as *const _ as *const c_void);
            ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_KITTY_IMAGE_MEDIUM_TEMP_FILE, std::ptr::null());
            ghostty_terminal_set(term, GHOSTTY_TERMINAL_OPT_KITTY_IMAGE_MEDIUM_SHARED_MEM, &off as *const _ as *const c_void);
        }
    }
}

/// Snapshot records this Ghostty decodes (TERMINAL through CONTINUATION).
/// Newer encoders add optional ones (Kitty graphics: 8 to 10) that newer
/// decoders skip once their checksum holds; this one refuses them instead.
const SNAPSHOT_TAGS: std::ops::RangeInclusive<u16> = 1..=7;
const SNAPSHOT_FINISH: u16 = 6;
/// What a snapshot may take to import (Rex's own bound).
const MAX_SNAPSHOT_BYTES: usize = 64 << 20;
/// What a snapshot's screen may hold.
const MAX_SNAPSHOT_CELLS: usize = 65_536;

/// The snapshot with records of unknown tags left out, as newer Ghostty
/// decoders skip them: each is checked (CRC32C) first, so a damaged one still
/// fails. Known records stay byte for byte, for Ghostty to validate.
fn known_snapshot_records(bytes: &[u8]) -> anyhow::Result<std::borrow::Cow<'_, [u8]>> {
    use anyhow::{Context, ensure};
    ensure!(bytes.len() <= MAX_SNAPSHOT_BYTES, "the snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes");
    ensure!(bytes.len() >= 10 && &bytes[..8] == b"GHOSTSNP", "not a Ghostty snapshot");
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    ensure!(version == 1, "unsupported Ghostty snapshot version {version}");
    let mut known: Option<Vec<u8>> = None;
    let mut at = 10;
    loop {
        ensure!(bytes.len() - at >= 10, "truncated snapshot record");
        let header = &bytes[at..at + 10];
        let tag = u16::from_le_bytes([header[0], header[1]]);
        let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let end = (at + 10).checked_add(len).filter(|end| *end <= bytes.len()).context("truncated snapshot record")?;
        if SNAPSHOT_TAGS.contains(&tag) {
            if let Some(known) = &mut known {
                known.extend_from_slice(&bytes[at..end]);
            }
        } else {
            let crc = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);
            ensure!(crc32c(&[&header[..6], &bytes[at + 10..end]]) == crc, "snapshot record {tag} fails its checksum");
            known.get_or_insert_with(|| bytes[..at].to_vec());
        }
        at = end;
        if tag == SNAPSHOT_FINISH {
            break;
        }
    }
    ensure!(at == bytes.len(), "bytes follow the snapshot's FINISH");
    Ok(known.map_or(std::borrow::Cow::Borrowed(bytes), std::borrow::Cow::Owned))
}

/// CRC32C (Castagnoli), as Ghostty's snapshot records use.
fn crc32c(parts: &[&[u8]]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0; 256];
        let mut i = 0;
        while i < 256 {
            let mut v = i as u32;
            let mut bit = 0;
            while bit < 8 {
                v = if v & 1 == 0 { v >> 1 } else { (v >> 1) ^ 0x82f6_3b78 };
                bit += 1;
            }
            table[i] = v;
            i += 1;
        }
        table
    };
    let mut crc = u32::MAX;
    for b in parts.iter().flat_map(|p| p.iter()) {
        crc = (crc >> 8) ^ TABLE[((crc ^ u32::from(*b)) & 0xff) as usize];
    }
    !crc
}

/// Restores a terminal from a whole snapshot with Ghostty's decoder, which
/// validates every record (checksums, order, counts, contents).
fn decode_snapshot(bytes: &[u8]) -> anyhow::Result<GhosttyTerminal> {
    unsafe {
        let mut decoder: GhosttySnapshotDecoder = std::ptr::null_mut();
        let r = ghostty_snapshot_decoder_new_buf(std::ptr::null(), &mut decoder, bytes.as_ptr(), bytes.len());
        anyhow::ensure!(r == GHOSTTY_SUCCESS && !decoder.is_null(), "cannot start decoding the snapshot ({r})");
        let mut term: GhosttyTerminal = std::ptr::null_mut();
        let r = ghostty_snapshot_decoder_decode(decoder, &mut term);
        let mut used = 0usize;
        let offset = ghostty_snapshot_decoder_get(decoder, GHOSTTY_SNAPSHOT_DECODER_DATA_SOURCE_OFFSET, &mut used as *mut _ as *mut c_void);
        ghostty_snapshot_decoder_free(decoder);
        if r != GHOSTTY_SUCCESS || term.is_null() {
            anyhow::bail!("invalid snapshot ({r})");
        }
        if offset != GHOSTTY_SUCCESS || used != bytes.len() {
            ghostty_terminal_free(term);
            anyhow::bail!("the snapshot decoder stopped at byte {used} of {}", bytes.len());
        }
        Ok(term)
    }
}

impl Vt {
    pub fn new(cols: u16, rows: u16) -> Vt {
        unsafe {
            let mut term = std::ptr::null_mut();
            ok(ghostty_terminal_new(std::ptr::null(), &mut term, cols.max(1), rows.max(1)), "terminal_new");
            let mut state = std::ptr::null_mut();
            ok(ghostty_render_state_new(std::ptr::null(), &mut state), "render_state_new");
            let mut rows_it = std::ptr::null_mut();
            ok(ghostty_render_state_row_iterator_new(std::ptr::null(), &mut rows_it), "row_iterator_new");
            let mut cells = std::ptr::null_mut();
            ok(ghostty_render_state_row_cells_new(std::ptr::null(), &mut cells), "row_cells_new");
            let mut keys = std::ptr::null_mut();
            ok(ghostty_key_encoder_new(std::ptr::null(), &mut keys), "key_encoder_new");
            let mut key_event = std::ptr::null_mut();
            ok(ghostty_key_event_new(std::ptr::null(), &mut key_event), "key_event_new");
            let mut mouse = std::ptr::null_mut();
            ok(ghostty_mouse_encoder_new(std::ptr::null(), &mut mouse), "mouse_encoder_new");
            let mut mouse_event = std::ptr::null_mut();
            ok(ghostty_mouse_event_new(std::ptr::null(), &mut mouse_event), "mouse_event_new");

            install_png_decoder();
            let mut shared = Box::new(Shared { state, held_since: None, title_changed: false, replies: Vec::new(), clipboard_write: true, clipboard: [None, None], local_media: true });
            configure(term, &mut shared);

            ghostty_render_state_update(state, term);
            let mut colors = GhosttyRenderStateColors { size: std::mem::size_of::<GhosttyRenderStateColors>(), ..Default::default() };
            ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_COLORS, &mut colors as *mut _ as *mut c_void);

            let mut gesture = std::ptr::null_mut();
            ok(ghostty_selection_gesture_new(std::ptr::null(), &mut gesture), "selection_gesture_new");
            let ev = |t| {
                let mut e = std::ptr::null_mut();
                ok(ghostty_selection_gesture_event_new(std::ptr::null(), &mut e, t), "gesture_event_new");
                e
            };
            let (press, drag, release) = (
                ev(GHOSTTY_SELECTION_GESTURE_EVENT_TYPE_PRESS),
                ev(GHOSTTY_SELECTION_GESTURE_EVENT_TYPE_DRAG),
                ev(GHOSTTY_SELECTION_GESTURE_EVENT_TYPE_RELEASE),
            );
            let mut vt = Vt {
                term,
                shared,
                rows_it,
                cells,
                keys,
                key_event,
                mouse,
                mouse_event,
                cols,
                rows,
                theme: theme(),
                base_palette: colors.palette,
                gesture,
                press,
                drag,
                release,
                drawn: Default::default(),
                seen: HashMap::new(),
                seen_with: (0, 0),
                win32: Default::default(),
            };
            vt.apply_theme();
            vt
        }
    }

    /// Switches colors live (settings.json changed).
    pub fn set_theme(&mut self, theme: Theme) {
        if self.theme != theme {
            self.theme = theme;
            self.apply_theme();
            // Rows carry the theme's own colors too (the selection's).
            self.seen.clear();
        }
    }

    fn apply_theme(&mut self) {
        let c = |rgb: Rgb| GhosttyColorRgb { r: rgb.0, g: rgb.1, b: rgb.2 };
        let t = &self.theme;
        let (fg, bg, cur) = (c(t.fg), c(t.bg), c(t.cursor));
        let mut palette = self.base_palette;
        for (i, rgb) in t.palette16.iter().enumerate() {
            palette[i] = c(*rgb);
        }
        unsafe {
            ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_COLOR_FOREGROUND, &fg as *const _ as *const c_void);
            ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_COLOR_BACKGROUND, &bg as *const _ as *const c_void);
            ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_COLOR_CURSOR, &cur as *const _ as *const c_void);
            ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_COLOR_PALETTE, &palette as *const _ as *const c_void);
        }
    }


    /// What the terminal wants to say back to the program since the last call.
    pub fn take_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.shared.replies)
    }

    /// Visible kitty graphics placements, bottom layer first.
    pub fn placements(&self) -> Vec<Placement> {
        let mut out = Vec::new();
        unsafe {
            let mut g: GhosttyKittyGraphics = std::ptr::null_mut();
            if ghostty_terminal_get(self.term, GHOSTTY_TERMINAL_DATA_KITTY_GRAPHICS, &mut g as *mut _ as *mut c_void) != GHOSTTY_SUCCESS || g.is_null() {
                return out;
            }
            let mut it: GhosttyKittyGraphicsPlacementIterator = std::ptr::null_mut();
            if ghostty_kitty_graphics_placement_iterator_new(std::ptr::null(), &mut it) != GHOSTTY_SUCCESS {
                return out;
            }
            if ghostty_kitty_graphics_get(g, GHOSTTY_KITTY_GRAPHICS_DATA_PLACEMENT_ITERATOR, &mut it as *mut _ as *mut c_void) == GHOSTTY_SUCCESS {
                while ghostty_kitty_graphics_placement_next(it) {
                    let (mut id, mut z, mut virt) = (0u32, 0i32, false);
                    ghostty_kitty_graphics_placement_get(it, GHOSTTY_KITTY_GRAPHICS_PLACEMENT_DATA_IMAGE_ID, &mut id as *mut _ as *mut c_void);
                    ghostty_kitty_graphics_placement_get(it, GHOSTTY_KITTY_GRAPHICS_PLACEMENT_DATA_Z, &mut z as *mut _ as *mut c_void);
                    ghostty_kitty_graphics_placement_get(it, GHOSTTY_KITTY_GRAPHICS_PLACEMENT_DATA_IS_VIRTUAL, &mut virt as *mut _ as *mut c_void);
                    let img = ghostty_kitty_graphics_image(g, id);
                    if virt || img.is_null() {
                        continue;
                    }
                    let mut info = GhosttyKittyGraphicsPlacementRenderInfo { size: std::mem::size_of::<GhosttyKittyGraphicsPlacementRenderInfo>(), ..Default::default() };
                    if ghostty_kitty_graphics_placement_render_info(it, img, self.term, &mut info) != GHOSTTY_SUCCESS || !info.viewport_visible {
                        continue;
                    }
                    let mut generation = 0u64;
                    ghostty_kitty_graphics_image_get(img, GHOSTTY_KITTY_IMAGE_DATA_GENERATION, &mut generation as *mut _ as *mut c_void);
                    out.push(Placement {
                        image: id,
                        generation,
                        col: info.viewport_col,
                        row: info.viewport_row,
                        width: info.pixel_width,
                        height: info.pixel_height,
                        source: [info.source_x, info.source_y, info.source_width, info.source_height],
                        z,
                    });
                }
            }
            ghostty_kitty_graphics_placement_iterator_free(it);
        }
        out.sort_by_key(|p| p.z);
        out
    }

    /// An image's pixels as BGRA (what GPUI uploads), cropped to `source`.
    pub fn image_bgra(&self, id: u32, source: [u32; 4]) -> Option<(u32, u32, Vec<u8>)> {
        unsafe {
            let mut g: GhosttyKittyGraphics = std::ptr::null_mut();
            ghostty_terminal_get(self.term, GHOSTTY_TERMINAL_DATA_KITTY_GRAPHICS, &mut g as *mut _ as *mut c_void);
            let img = (!g.is_null()).then(|| ghostty_kitty_graphics_image(g, id)).filter(|i| !i.is_null())?;
            let (mut w, mut h, mut fmt) = (0u32, 0u32, GHOSTTY_KITTY_IMAGE_FORMAT_RGBA);
            let (mut ptr, mut len): (*const u8, usize) = (std::ptr::null(), 0);
            ghostty_kitty_graphics_image_get(img, GHOSTTY_KITTY_IMAGE_DATA_WIDTH, &mut w as *mut _ as *mut c_void);
            ghostty_kitty_graphics_image_get(img, GHOSTTY_KITTY_IMAGE_DATA_HEIGHT, &mut h as *mut _ as *mut c_void);
            ghostty_kitty_graphics_image_get(img, GHOSTTY_KITTY_IMAGE_DATA_FORMAT, &mut fmt as *mut _ as *mut c_void);
            if ghostty_kitty_graphics_image_get(img, GHOSTTY_KITTY_IMAGE_DATA_DATA_PTR, &mut ptr as *mut _ as *mut c_void) != GHOSTTY_SUCCESS || ptr.is_null() {
                return None;
            }
            ghostty_kitty_graphics_image_get(img, GHOSTTY_KITTY_IMAGE_DATA_DATA_LEN, &mut len as *mut _ as *mut c_void);
            let px = std::slice::from_raw_parts(ptr, len);
            let bpp = match fmt {
                GHOSTTY_KITTY_IMAGE_FORMAT_RGB => 3,
                GHOSTTY_KITTY_IMAGE_FORMAT_GRAY_ALPHA => 2,
                GHOSTTY_KITTY_IMAGE_FORMAT_GRAY => 1,
                _ => 4,
            };
            let [sx, sy, sw, sh] = source;
            let (sw, sh) = (sw.min(w.saturating_sub(sx)), sh.min(h.saturating_sub(sy)));
            if sw == 0 || sh == 0 {
                return None;
            }
            let mut out = Vec::with_capacity((sw * sh * 4) as usize);
            for y in sy..sy + sh {
                for x in sx..sx + sw {
                    let i = ((y * w + x) as usize) * bpp;
                    let p = px.get(i..i + bpp)?;
                    let (r, g, b, a) = match bpp {
                        4 => (p[0], p[1], p[2], p[3]),
                        3 => (p[0], p[1], p[2], 255),
                        2 => (p[0], p[0], p[0], p[1]),
                        _ => (p[0], p[0], p[0], 255),
                    };
                    out.extend_from_slice(&[b, g, r, a]);
                }
            }
            Some((sw, sh, out))
        }
    }

    /// Feeds one mouse step of a selection gesture (cell + pixel position in the grid).
    /// Applies the resulting selection; a plain click clears it.
    pub fn select(&mut self, step: Select, col: u16, row: u16, x: f32, y: f32, cell_w: f32, height: f32) {
        unsafe {
            let mut r = GhosttyGridRef { size: std::mem::size_of::<GhosttyGridRef>(), ..Default::default() };
            let mut p = GhosttyPoint { tag: GHOSTTY_POINT_TAG_VIEWPORT, ..Default::default() };
            p.value.coordinate = GhosttyPointCoordinate { x: col.min(self.cols.saturating_sub(1)), y: row.min(self.rows.saturating_sub(1)) as u32 };
            if ghostty_terminal_grid_ref(self.term, p, &mut r) != GHOSTTY_SUCCESS {
                return;
            }
            // Ghostty takes the cell width as a whole number: at zoom a cell is
            // 9.75 px, and 9 put "the middle of a cell" in the wrong place, so
            // the highlight jumped between cells while dragging. Positions and
            // geometry go in 1/64 px, where the width stays exact.
            let pos = GhosttySurfacePosition { x: (x * SUBPIXEL) as f64, y: (y * SUBPIXEL) as f64 };
            let e = match step {
                Select::Press => self.press,
                Select::Drag => self.drag,
                Select::Release => self.release,
            };
            ghostty_selection_gesture_event_set(e, GHOSTTY_SELECTION_GESTURE_EVENT_OPT_REF, &r as *const _ as *const c_void);
            ghostty_selection_gesture_event_set(e, GHOSTTY_SELECTION_GESTURE_EVENT_OPT_POSITION, &pos as *const _ as *const c_void);
            match step {
                Select::Press => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
                    ghostty_selection_gesture_event_set(e, GHOSTTY_SELECTION_GESTURE_EVENT_OPT_TIME_NS, &now as *const _ as *const c_void);
                    // GPUI doesn't expose the platform's double-click interval.
                    let interval = 500_000_000u64;
                    let distance = f64::from(4.0 * SUBPIXEL);
                    ghostty_selection_gesture_event_set(e, GHOSTTY_SELECTION_GESTURE_EVENT_OPT_REPEAT_INTERVAL_NS, &interval as *const _ as *const c_void);
                    ghostty_selection_gesture_event_set(e, GHOSTTY_SELECTION_GESTURE_EVENT_OPT_REPEAT_DISTANCE, &distance as *const _ as *const c_void);
                }
                Select::Drag => {
                    let g = GhosttySelectionGestureGeometry {
                        columns: self.cols as u32,
                        cell_width: (cell_w.max(1.0) * SUBPIXEL).round() as u32,
                        padding_left: 0,
                        screen_height: (height.max(1.0) * SUBPIXEL).round() as u32,
                    };
                    ghostty_selection_gesture_event_set(e, GHOSTTY_SELECTION_GESTURE_EVENT_OPT_GEOMETRY, &g as *const _ as *const c_void);
                }
                Select::Release => {}
            }
            let mut sel = GhosttySelection { size: std::mem::size_of::<GhosttySelection>(), ..Default::default() };
            match ghostty_selection_gesture_event(self.gesture, self.term, e, &mut sel) {
                GHOSTTY_SUCCESS => {
                    ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_SELECTION, &sel as *const _ as *const c_void);
                }
                _ if matches!(step, Select::Press) => {
                    ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_SELECTION, std::ptr::null());
                }
                _ => {}
            }
        }
    }

    /// The selected text, if anything is selected.
    pub fn selection_text(&self) -> Option<String> {
        unsafe {
            let opts = GhosttyTerminalSelectionFormatOptions {
                size: std::mem::size_of::<GhosttyTerminalSelectionFormatOptions>(),
                emit: GHOSTTY_FORMATTER_FORMAT_PLAIN,
                unwrap: true,
                trim: true,
                ..Default::default()
            };
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len = 0usize;
            if ghostty_terminal_selection_format_alloc(self.term, std::ptr::null(), opts, &mut ptr, &mut len) != GHOSTTY_SUCCESS {
                return None;
            }
            if ptr.is_null() {
                return None;
            }
            let text = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).into_owned();
            ghostty_free(std::ptr::null(), ptr, len);
            (!text.is_empty()).then_some(text)
        }
    }

    fn grid_ref(&self, tag: GhosttyPointTag, x: u16, y: u32) -> Option<GhosttyGridRef> {
        let mut r = GhosttyGridRef { size: std::mem::size_of::<GhosttyGridRef>(), ..Default::default() };
        let mut p = GhosttyPoint { tag, ..Default::default() };
        p.value.coordinate = GhosttyPointCoordinate { x, y };
        (unsafe { ghostty_terminal_grid_ref(self.term, p, &mut r) } == GHOSTTY_SUCCESS).then_some(r)
    }

    /// The link at a viewport cell: a link the program marked (OSC 8), or a
    /// URL or path in the text. Follows lines the terminal wrapped, also into
    /// rows scrolled out of view.
    pub fn link_at(&self, col: u16, row: u16, find: impl FnOnce(&str, usize) -> Option<std::ops::Range<usize>>) -> Option<LinkHit> {
        if col >= self.cols || row >= self.rows {
            return None;
        }
        // Screen rows count from the top of the scrollback; the viewport starts at `top`.
        let top = unsafe {
            let r = self.grid_ref(GHOSTTY_POINT_TAG_VIEWPORT, 0, 0)?;
            let mut p = GhosttyPointCoordinate::default();
            if ghostty_terminal_point_from_grid_ref(self.term, &r, GHOSTTY_POINT_TAG_SCREEN, &mut p) != GHOSTTY_SUCCESS {
                return None;
            }
            p.y
        };
        let hovered = top + row as u32;
        let wraps = |y: u32| unsafe {
            let Some(r) = self.grid_ref(GHOSTTY_POINT_TAG_SCREEN, 0, y) else { return false };
            let mut line: GhosttyRow = Default::default();
            let mut wrap = false;
            ghostty_grid_ref_row(&r, &mut line) == GHOSTTY_SUCCESS
                && ghostty_row_get(line, GHOSTTY_ROW_DATA_WRAP, &mut wrap as *mut _ as *mut c_void) == GHOSTTY_SUCCESS
                && wrap
        };
        // A URL longer than this many rows isn't one worth finding.
        const REACH: u32 = 32;
        let mut first = hovered;
        while first > 0 && hovered - first < REACH && wraps(first - 1) {
            first -= 1;
        }
        let mut last = hovered;
        while last - hovered < REACH && wraps(last) && self.grid_ref(GHOSTTY_POINT_TAG_SCREEN, 0, last + 1).is_some() {
            last += 1;
        }

        struct Spot {
            y: u32,
            x: u16,
            width: u16,
            byte: usize,
            uri: Option<String>,
        }
        let mut text = String::new();
        let mut spots: Vec<Spot> = Vec::new();
        for y in first..=last {
            let mut r = self.grid_ref(GHOSTTY_POINT_TAG_SCREEN, 0, y)?;
            for x in 0..self.cols {
                r.x = x;
                let (wide, linked) = unsafe {
                    let mut cell: GhosttyCell = Default::default();
                    ghostty_grid_ref_cell(&r, &mut cell);
                    let mut wide: GhosttyCellWide = GHOSTTY_CELL_WIDE_NARROW;
                    ghostty_cell_get(cell, GHOSTTY_CELL_DATA_WIDE, &mut wide as *mut _ as *mut c_void);
                    let mut linked = false;
                    ghostty_cell_get(cell, GHOSTTY_CELL_DATA_HAS_HYPERLINK, &mut linked as *mut _ as *mut c_void);
                    (wide, linked)
                };
                if wide == GHOSTTY_CELL_WIDE_SPACER_TAIL || wide == GHOSTTY_CELL_WIDE_SPACER_HEAD {
                    continue;
                }
                let byte = text.len();
                let mut cps = [0u32; 16];
                let mut len = 0usize;
                unsafe { ghostty_grid_ref_graphemes(&r, cps.as_mut_ptr(), cps.len(), &mut len) };
                let before = text.len();
                text.extend(cps[..len.min(cps.len())].iter().filter_map(|c| char::from_u32(*c)));
                if text.len() == before {
                    text.push(' ');
                }
                let uri = linked.then(|| hyperlink_uri(&r)).flatten();
                let width = if wide == GHOSTTY_CELL_WIDE_WIDE { 2 } else { 1 };
                spots.push(Spot { y, x, width, byte, uri });
            }
        }
        let at = spots.iter().position(|s| s.y == hovered && s.x <= col && col < s.x + s.width)?;
        let (target, chosen): (String, Vec<&Spot>) = match spots[at].uri.clone() {
            Some(uri) => {
                let same = |s: &&Spot| s.uri.as_deref() == Some(uri.as_str());
                let start = spots[..at].iter().rposition(|s| !same(&s)).map_or(0, |i| i + 1);
                let end = spots[at..].iter().position(|s| !same(&s)).map_or(spots.len(), |i| at + i);
                (uri, spots[start..end].iter().collect())
            }
            None => {
                let range = find(&text, spots[at].byte)?;
                (text[range.clone()].to_owned(), spots.iter().filter(|s| range.contains(&s.byte)).collect())
            }
        };
        let mut spans = Spans::new();
        for s in chosen {
            let Some(vy) = s.y.checked_sub(top).filter(|vy| *vy < self.rows as u32) else { continue };
            let end = s.x + s.width - 1;
            match spans.last_mut() {
                Some(last) if last.0 == vy as u16 => last.2 = end,
                _ => spans.push((vy as u16, s.x, end)),
            }
        }
        Some(LinkHit { target, spans })
    }

    pub fn clear_selection(&mut self) {
        unsafe { ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_SELECTION, std::ptr::null()) };
    }

    /// Replaces the terminal with a Rex snapshot (Ghostty `GHOSTSNP` v1, the
    /// whole stream up to and including FINISH): its screens, history, modes,
    /// title and unfinished VT input. Later `write`s continue from it. The
    /// size becomes the snapshot's; this view's colors, callbacks and limits
    /// stay (and its cell size, when the snapshot has none). On an error the
    /// terminal is left as it was.
    ///
    /// Kitty graphics records are skipped (their checksums still checked):
    /// this Ghostty can't decode them, so images from before the snapshot
    /// don't show.
    pub fn import_snapshot(&mut self, snapshot: &[u8]) -> anyhow::Result<()> {
        let records = known_snapshot_records(snapshot)?;
        let term = decode_snapshot(&records)?;
        let (cols, rows) = unsafe {
            let get_u16 = |data| {
                let mut v = 0u16;
                ghostty_terminal_get(term, data, &mut v as *mut _ as *mut c_void);
                v
            };
            let (cols, rows) = (get_u16(GHOSTTY_TERMINAL_DATA_COLS), get_u16(GHOSTTY_TERMINAL_DATA_ROWS));
            let mut state = std::ptr::null_mut();
            if cols == 0 || rows == 0 || cols as usize * rows as usize > MAX_SNAPSHOT_CELLS || ghostty_render_state_new(std::ptr::null(), &mut state) != GHOSTTY_SUCCESS {
                ghostty_terminal_free(term);
                anyhow::bail!("cannot show a {cols}x{rows} snapshot");
            }
            let px = |t, data| {
                let mut v = 0u32;
                ghostty_terminal_get(t, data, &mut v as *mut _ as *mut c_void);
                v
            };
            if px(term, GHOSTTY_TERMINAL_DATA_WIDTH_PX) == 0 || px(term, GHOSTTY_TERMINAL_DATA_HEIGHT_PX) == 0 {
                // Before the callbacks are set, so a program that asked for
                // size reports gets none from the display.
                let cell_w = px(self.term, GHOSTTY_TERMINAL_DATA_WIDTH_PX) / u32::from(self.cols.max(1));
                let cell_h = px(self.term, GHOSTTY_TERMINAL_DATA_HEIGHT_PX) / u32::from(self.rows.max(1));
                ghostty_terminal_resize(term, cols, rows, cell_w.max(1), cell_h.max(1));
            }
            configure(term, &mut self.shared);
            // The gesture holds references into the terminal it was used with.
            ghostty_selection_gesture_reset(self.gesture, self.term);
            ghostty_terminal_free(self.term);
            ghostty_render_state_free(self.shared.state);
            self.term = term;
            self.shared.state = state;
            (cols, rows)
        };
        self.shared.held_since = None;
        // The snapshot carries the program's title.
        self.shared.title_changed = true;
        (self.cols, self.rows) = (cols, rows);
        self.apply_theme();
        self.seen.clear();
        self.seen_with = (0, 0);
        self.drawn = Default::default();
        // What it learned from the old terminal's bytes says nothing of this one.
        self.win32 = Default::default();
        Ok(())
    }

    /// Kitty images load only from the stream itself, never from this
    /// machine's files or shared memory (kept across `import_snapshot`).
    pub fn deny_local_media(&mut self) {
        self.shared.local_media = false;
        unsafe { configure(self.term, &mut self.shared) };
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.win32.watch(bytes);
        unsafe { ghostty_terminal_vt_write(self.term, bytes.as_ptr(), bytes.len()) };
    }

    pub fn allow_clipboard_write(&mut self, allow: bool) {
        self.shared.clipboard_write = allow;
    }

    pub fn take_clipboard(&mut self) -> [Option<String>; 2] {
        std::mem::take(&mut self.shared.clipboard)
    }

    pub fn resize(&mut self, cols: u16, rows: u16, cell_w: u32, cell_h: u32) {
        if cols == 0 || rows == 0 {
            return;
        }
        self.cols = cols;
        self.rows = rows;
        unsafe { ghostty_terminal_resize(self.term, cols, rows, cell_w.max(1), cell_h.max(1)) };
    }

    pub fn take_title(&mut self) -> Option<String> {
        if !std::mem::take(&mut self.shared.title_changed) {
            return None;
        }
        let mut s = GhosttyString::default();
        unsafe { ghostty_terminal_get(self.term, GHOSTTY_TERMINAL_DATA_TITLE, &mut s as *mut _ as *mut c_void) };
        if s.ptr.is_null() {
            return Some(String::new());
        }
        let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn kitty_keyboard_flags(&self) -> u8 {
        let mut flags = 0u8;
        unsafe { ghostty_terminal_get(self.term, GHOSTTY_TERMINAL_DATA_KITTY_KEYBOARD_FLAGS, &mut flags as *mut _ as *mut c_void) };
        flags
    }

    fn get_bool(&self, data: GhosttyTerminalData) -> bool {
        let mut v = false;
        unsafe { ghostty_terminal_get(self.term, data, &mut v as *mut _ as *mut c_void) };
        v
    }

    fn mode(&self, mode: GhosttyMode) -> bool {
        let mut cfg = GhosttyTerminalModeConfig { mode, value: false };
        unsafe { ghostty_terminal_get(self.term, GHOSTTY_TERMINAL_DATA_MODE, &mut cfg as *mut _ as *mut c_void) };
        cfg.value
    }

    pub fn mouse_tracking(&self) -> bool {
        self.get_bool(GHOSTTY_TERMINAL_DATA_MOUSE_TRACKING)
    }

    pub fn alt_screen(&self) -> bool {
        let mut screen: GhosttyTerminalScreen = GHOSTTY_TERMINAL_SCREEN_PRIMARY;
        unsafe { ghostty_terminal_get(self.term, GHOSTTY_TERMINAL_DATA_ACTIVE_SCREEN, &mut screen as *mut _ as *mut c_void) };
        screen == GHOSTTY_TERMINAL_SCREEN_ALTERNATE
    }

    pub fn scroll_viewport(&mut self, delta: isize) {
        let mut s = GhosttyTerminalScrollViewport { tag: GHOSTTY_SCROLL_VIEWPORT_DELTA, ..Default::default() };
        s.value.delta = delta;
        unsafe { ghostty_terminal_scroll_viewport(self.term, s) };
    }

    pub fn scroll_to_bottom(&mut self) {
        let s = GhosttyTerminalScrollViewport { tag: GHOSTTY_SCROLL_VIEWPORT_BOTTOM, ..Default::default() };
        unsafe { ghostty_terminal_scroll_viewport(self.term, s) };
    }

    /// Wraps pasted text the way the program asked (bracketed paste or not).
    pub fn paste_bytes(&self, text: &str) -> Vec<u8> {
        if self.mode(BRACKETED_PASTE) {
            let clean = text.replace("\x1b[201~", "");
            [b"\x1b[200~".as_slice(), clean.as_bytes(), b"\x1b[201~"].concat()
        } else {
            text.replace("\r\n", "\r").replace('\n', "\r").into_bytes()
        }
    }

    /// Whether output since the last frame changed what's on screen: a title,
    /// or a cursor parked where it was, needs no frame.
    pub fn shows_change(&mut self) -> bool {
        if self.shared.held_since.is_some() {
            return true;
        }
        unsafe {
            let state = self.shared.state;
            ghostty_render_state_update(state, self.term);
            let mut dirty: GhosttyRenderStateDirty = GHOSTTY_RENDER_STATE_DIRTY_FULL;
            ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_DIRTY, &mut dirty as *mut _ as *mut c_void);
            dirty != GHOSTTY_RENDER_STATE_DIRTY_FALSE || self.drawable() != self.drawn
        }
    }

    /// The cursor and the colors (from the updated render state), and the kitty
    /// images' generation.
    unsafe fn drawable(&self) -> (CursorKey, u64, u64) {
        unsafe {
            let mut cur = GhosttyRenderStateCursor { size: std::mem::size_of::<GhosttyRenderStateCursor>(), ..Default::default() };
            ghostty_render_state_get(self.shared.state, GHOSTTY_RENDER_STATE_DATA_CURSOR, &mut cur as *mut _ as *mut c_void);
            let cursor = (cur.viewport_has_value, cur.viewport_x, cur.viewport_y, cur.visible, cur.visual_style as i32);
            let mut c = GhosttyRenderStateColors { size: std::mem::size_of::<GhosttyRenderStateColors>(), ..Default::default() };
            ghostty_render_state_get(self.shared.state, GHOSTTY_RENDER_STATE_DATA_COLORS, &mut c as *mut _ as *mut c_void);
            let mut h = std::hash::DefaultHasher::new();
            let rgb = |h: &mut std::hash::DefaultHasher, x: GhosttyColorRgb| std::hash::Hash::hash(&(x.r, x.g, x.b), h);
            for x in [c.background, c.foreground].into_iter().chain(c.palette).chain(c.cursor_has_value.then_some(c.cursor)) {
                rgb(&mut h, x);
            }
            let colors = std::hash::Hasher::finish(&h);
            let mut generation = 0u64;
            let mut g: GhosttyKittyGraphics = std::ptr::null_mut();
            if ghostty_terminal_get(self.term, GHOSTTY_TERMINAL_DATA_KITTY_GRAPHICS, &mut g as *mut _ as *mut c_void) == GHOSTTY_SUCCESS && !g.is_null() {
                ghostty_kitty_graphics_get(g, GHOSTTY_KITTY_GRAPHICS_DATA_GENERATION, &mut generation as *mut _ as *mut c_void);
            }
            (cursor, generation, colors)
        }
    }

    /// Updates the render state (respecting synchronized output) and reads one frame.
    pub fn frame(&mut self) -> Frame {
        unsafe {
            if let Some(since) = self.shared.held_since
                && since.elapsed() > MAX_HOLD
            {
                let cfg = GhosttyTerminalModeConfig { mode: SYNC_OUTPUT, value: false };
                ghostty_terminal_set(self.term, GHOSTTY_TERMINAL_OPT_MODE, &cfg as *const _ as *const c_void);
                self.shared.held_since = None;
            }
            let state = self.shared.state;
            if self.shared.held_since.is_none() {
                ghostty_render_state_update(state, self.term);
            }

            let mut colors = GhosttyRenderStateColors { size: std::mem::size_of::<GhosttyRenderStateColors>(), ..Default::default() };
            ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_COLORS, &mut colors as *mut _ as *mut c_void);
            let fg_default = Rgb::from(colors.foreground);
            let bg_default = Rgb::from(colors.background);

            // Rows libghostty keeps clean are taken as read last frame (see
            // "Row Identity" in its render.h); a resize or new colors (which
            // don't mark rows dirty) read them all.
            let with = (self.cols, self.drawable().2);
            let mut dirty: GhosttyRenderStateDirty = GHOSTTY_RENDER_STATE_DIRTY_FULL;
            ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_DIRTY, &mut dirty as *mut _ as *mut c_void);
            let all = dirty == GHOSTTY_RENDER_STATE_DIRTY_FULL || with != self.seen_with;
            let mut seen = HashMap::with_capacity(self.rows as usize);
            let mut rows = Vec::with_capacity(self.rows as usize);
            ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_ROW_ITERATOR, &mut self.rows_it as *mut _ as *mut c_void);
            while ghostty_render_state_row_iterator_next(self.rows_it) {
                let mut sel = GhosttyRenderStateRowSelection { size: std::mem::size_of::<GhosttyRenderStateRowSelection>(), ..Default::default() };
                let selected = ghostty_render_state_row_get(self.rows_it, GHOSTTY_RENDER_STATE_ROW_DATA_SELECTION, &mut sel as *mut _ as *mut c_void)
                    == GHOSTTY_SUCCESS;
                let selection = selected.then_some((sel.start_x, sel.end_x));
                let mut id = GhosttyRenderStateRowId::default();
                let known = ghostty_render_state_row_get(self.rows_it, GHOSTTY_RENDER_STATE_ROW_DATA_ID, &mut id as *mut _ as *mut c_void) == GHOSTTY_SUCCESS;
                // Everything changed: no row is kept (but each is remembered).
                let mut row_dirty = true;
                if !all {
                    ghostty_render_state_row_get(self.rows_it, GHOSTTY_RENDER_STATE_ROW_DATA_DIRTY, &mut row_dirty as *mut _ as *mut c_void);
                }
                let same = (known && !row_dirty).then(|| self.seen.get(&id.bits)).flatten().filter(|(_, s)| *s == selection);
                let row = match same {
                    Some((row, _)) => row.clone(),
                    None => {
                        ghostty_render_state_row_get(self.rows_it, GHOSTTY_RENDER_STATE_ROW_DATA_CELLS, &mut self.cells as *mut _ as *mut c_void);
                        let mut row = Vec::with_capacity(self.cols as usize);
                        let mut x: u16 = 0;
                        while ghostty_render_state_row_cells_next(self.cells) {
                            row.push(self.read_cell(fg_default, selected && x >= sel.start_x && x <= sel.end_x));
                            x += 1;
                        }
                        Rc::new(row)
                    }
                };
                if known {
                    seen.insert(id.bits, (row.clone(), selection));
                }
                rows.push(row);
            }
            (self.seen, self.seen_with) = (seen, with);

            let mut cur = GhosttyRenderStateCursor { size: std::mem::size_of::<GhosttyRenderStateCursor>(), ..Default::default() };
            ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_CURSOR, &mut cur as *mut _ as *mut c_void);
            let cursor = (cur.visible && cur.viewport_has_value).then(|| Cursor {
                x: if cur.wide_tail { cur.viewport_x.saturating_sub(1) } else { cur.viewport_x },
                y: cur.viewport_y,
                shape: match cur.visual_style {
                    GHOSTTY_RENDER_STATE_CURSOR_VISUAL_STYLE_BAR => CursorShape::Bar,
                    GHOSTTY_RENDER_STATE_CURSOR_VISUAL_STYLE_UNDERLINE => CursorShape::Underline,
                    GHOSTTY_RENDER_STATE_CURSOR_VISUAL_STYLE_BLOCK_HOLLOW => CursorShape::Hollow,
                    _ => CursorShape::Block,
                },
                color: if colors.cursor_has_value { colors.cursor.into() } else { fg_default },
            });

            self.drawn = self.drawable();
            ghostty_render_state_clean(state);
            let cursor_cell = cur.viewport_has_value.then_some((cur.viewport_x, cur.viewport_y));
            Frame { rows, all, cursor, cursor_cell, bg: bg_default }
        }
    }

    unsafe fn read_cell(&mut self, fg_default: Rgb, selected: bool) -> Cell {
        unsafe {
            let c = self.cells;
            let mut raw: GhosttyCell = Default::default();
            ghostty_render_state_row_cells_get(c, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_RAW, &mut raw as *mut _ as *mut c_void);
            let mut wide: GhosttyCellWide = GHOSTTY_CELL_WIDE_NARROW;
            ghostty_cell_get(raw, GHOSTTY_CELL_DATA_WIDE, &mut wide as *mut _ as *mut c_void);

            let mut style = GhosttyStyle { size: std::mem::size_of::<GhosttyStyle>(), ..Default::default() };
            ghostty_render_state_row_cells_get(c, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_STYLE, &mut style as *mut _ as *mut c_void);

            let mut fg = GhosttyColorRgb::default();
            let fg = if ghostty_render_state_row_cells_get(c, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_FG_COLOR, &mut fg as *mut _ as *mut c_void)
                == GHOSTTY_SUCCESS
            {
                Rgb::from(fg)
            } else {
                fg_default
            };
            let mut bg = GhosttyColorRgb::default();
            let bg = (ghostty_render_state_row_cells_get(c, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_BG_COLOR, &mut bg as *mut _ as *mut c_void)
                == GHOSTTY_SUCCESS)
                .then(|| Rgb::from(bg));

            let (mut fg, mut bg) = (fg, bg);
            if style.inverse {
                let new_fg = bg.unwrap_or(self.theme.bg);
                bg = Some(fg);
                fg = new_fg;
            }
            if selected {
                bg = Some(self.theme.selection_bg);
            }
            let mut text = String::new();
            if wide != GHOSTTY_CELL_WIDE_SPACER_TAIL && wide != GHOSTTY_CELL_WIDE_SPACER_HEAD && !style.invisible {
                let mut len: u32 = 0;
                ghostty_render_state_row_cells_get(c, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_GRAPHEMES_LEN, &mut len as *mut _ as *mut c_void);
                if len > 0 {
                    let mut cps = vec![0u32; len as usize];
                    ghostty_render_state_row_cells_get(c, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_GRAPHEMES_BUF, cps.as_mut_ptr() as *mut c_void);
                    text = cps.into_iter().filter_map(char::from_u32).collect();
                }
            }

            // Contrast adjustment is opt-in; graphics always keep their colors.
            if self.theme.minimum_contrast > 1.0 && !preserves_graphics_color(&text) {
                fg = readable(fg, bg.unwrap_or(self.theme.bg), self.theme.minimum_contrast);
            }

            Cell {
                text,
                fg,
                bg,
                bold: style.bold,
                italic: style.italic,
                faint: style.faint,
                underline: style.underline != 0,
                strike: style.strikethrough,
                wide: wide == GHOSTTY_CELL_WIDE_WIDE,
            }
        }
    }

    /// Encodes one key press with the program's current keyboard modes.
    /// `consumed`: the modifiers that went into making `text` (Shift for ":",
    /// Option for "\u{df}" on a Mac), as Ghostty reports them. Without it the
    /// kitty keyboard protocol reports shift+; and Neovim never sees ":".
    pub fn encode_key(&mut self, key: GhosttyKey, mods: GhosttyMods, consumed: GhosttyMods, text: Option<&str>, unshifted: Option<char>) -> Vec<u8> {
        unsafe {
            ghostty_key_encoder_setopt_from_terminal(self.keys, self.term);
            #[cfg(target_os = "macos")]
            {
                let option = if gpui_macos::option_as_alt() { GHOSTTY_OPTION_AS_ALT_TRUE } else { GHOSTTY_OPTION_AS_ALT_FALSE };
                ghostty_key_encoder_setopt(self.keys, GHOSTTY_KEY_ENCODER_OPT_MACOS_OPTION_AS_ALT, &option as *const _ as *const c_void);
            }
            let e = self.key_event;
            ghostty_key_event_set_action(e, GHOSTTY_KEY_ACTION_PRESS);
            ghostty_key_event_set_key(e, key);
            ghostty_key_event_set_mods(e, mods);
            let printable = text.is_some_and(|t| !t.is_empty() && !t.chars().any(|c| c.is_control()));
            ghostty_key_event_set_consumed_mods(e, if printable { consumed } else { 0 });
            match text {
                Some(t) if printable => {
                    ghostty_key_event_set_utf8(e, t.as_ptr() as *const _, t.len())
                }
                _ => ghostty_key_event_set_utf8(e, std::ptr::null(), 0),
            }
            ghostty_key_event_set_unshifted_codepoint(e, unshifted.map_or(0, |c| c as u32));
            let mut buf = [0u8; 128];
            let mut len = 0usize;
            let r = ghostty_key_encoder_encode(self.keys, e, buf.as_mut_ptr() as *mut _, buf.len(), &mut len);
            if r != GHOSTTY_SUCCESS {
                return Vec::new();
            }
            buf[..len].to_vec()
        }
    }

    /// Encodes a mouse event for a program that tracks the mouse. Positions are in pixels.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_mouse(
        &mut self,
        action: GhosttyMouseAction,
        button: Option<GhosttyMouseButton>,
        mods: GhosttyMods,
        x: f32,
        y: f32,
        // (columns, rows, cell width, cell height), cells in px.
        size: (u32, u32, f32, f32),
        any_pressed: bool,
    ) -> Vec<u8> {
        // Ghostty takes whole-pixel cells; at zoom a cell is 11.7 px, and
        // rounding it alone made the reported column run ahead of the pointer
        // (2 cells by mid-line). So the position moves into a grid of whole
        // cells: same column and row exactly, pixels (SGR-pixels mode) within
        // a few percent.
        let (cols, rows, cw, ch) = size;
        let (cwi, chi) = (cw.round().max(1.0), ch.round().max(1.0));
        let (x, y) = (x / cw.max(1.0) * cwi, y / ch.max(1.0) * chi);
        unsafe {
            ghostty_mouse_encoder_setopt_from_terminal(self.mouse, self.term);
            let s = GhosttyMouseEncoderSize {
                size: std::mem::size_of::<GhosttyMouseEncoderSize>(),
                screen_width: cols * cwi as u32,
                screen_height: rows * chi as u32,
                cell_width: cwi as u32,
                cell_height: chi as u32,
                ..Default::default()
            };
            ghostty_mouse_encoder_setopt(self.mouse, GHOSTTY_MOUSE_ENCODER_OPT_SIZE, &s as *const _ as *const c_void);
            ghostty_mouse_encoder_setopt(self.mouse, GHOSTTY_MOUSE_ENCODER_OPT_ANY_BUTTON_PRESSED, &any_pressed as *const _ as *const c_void);
            let e = self.mouse_event;
            ghostty_mouse_event_set_action(e, action);
            match button {
                Some(b) => ghostty_mouse_event_set_button(e, b),
                None => ghostty_mouse_event_clear_button(e),
            }
            ghostty_mouse_event_set_mods(e, mods);
            ghostty_mouse_event_set_position(e, GhosttyMousePosition { x, y });
            let mut buf = [0u8; 64];
            let mut len = 0usize;
            let r = ghostty_mouse_encoder_encode(self.mouse, e, buf.as_mut_ptr() as *mut _, buf.len(), &mut len);
            if r != GHOSTTY_SUCCESS {
                return Vec::new();
            }
            buf[..len].to_vec()
        }
    }
}

impl Drop for Vt {
    fn drop(&mut self) {
        unsafe {
            ghostty_selection_gesture_event_free(self.press);
            ghostty_selection_gesture_event_free(self.drag);
            ghostty_selection_gesture_event_free(self.release);
            ghostty_selection_gesture_free(self.gesture, self.term);
            ghostty_mouse_event_free(self.mouse_event);
            ghostty_mouse_encoder_free(self.mouse);
            ghostty_key_event_free(self.key_event);
            ghostty_key_encoder_free(self.keys);
            ghostty_render_state_row_cells_free(self.cells);
            ghostty_render_state_row_iterator_free(self.rows_it);
            ghostty_terminal_free(self.term);
            ghostty_render_state_free(self.shared.state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_programs_terminal_never_loads_images_from_local_files() {
        let medium = |vt: &Vt| unsafe {
            let (mut file, mut shm) = (true, true);
            ghostty_terminal_get(vt.term, GHOSTTY_TERMINAL_DATA_KITTY_IMAGE_MEDIUM_FILE, &mut file as *mut _ as *mut c_void);
            ghostty_terminal_get(vt.term, GHOSTTY_TERMINAL_DATA_KITTY_IMAGE_MEDIUM_SHARED_MEM, &mut shm as *mut _ as *mut c_void);
            (file, shm)
        };
        let mut vt = Vt::new(20, 5);
        vt.deny_local_media();
        assert_eq!(medium(&vt), (false, false));
        // A file transmission is refused, and nothing is displayed.
        vt.write(b"\x1b_Ga=T,t=f,f=100;L2V0Yy9wYXNzd2Q=\x1b\\");
        assert!(vt.placements().is_empty());
    }

    #[test]
    fn scrollback_retains_five_thousand_styled_lines() {
        for cols in [80, 200] {
            let mut vt = Vt::new(cols, 25);
            for line in 1..=5000 {
                vt.write(format!("\x1b[1;31m{line:04}\x1b[0m {}\r\n", "x".repeat(cols as usize - 6)).as_bytes());
            }
            vt.scroll_viewport(-10_000);
            for first in (1..=5000).step_by(25) {
                let frame = vt.frame();
                for (offset, row) in frame.rows.iter().enumerate() {
                    let text: String = row.iter().map(|c| c.text.as_str()).collect();
                    assert!(text.starts_with(&format!("{:04} ", first + offset)), "{cols} columns: {text:?}");
                }
                vt.scroll_viewport(25);
            }
        }
    }

    #[test]
    fn styled_text_reaches_the_frame() {
        let mut vt = Vt::new(20, 3);
        vt.write(b"hi \x1b[1;31mred\x1b[0m\r\n\xe4\xb8\xad!");
        let f = vt.frame();
        assert_eq!(f.rows.len(), 3);
        let first: String = f.rows[0].iter().map(|c| c.text.as_str()).collect();
        assert!(first.starts_with("hi red"), "{first:?}");
        assert!(f.rows[0][3].bold);
        assert_eq!(f.rows[0][3].fg, theme().palette16[1]);
        assert!(f.rows[1][0].wide);
        assert_eq!(f.rows[1][0].text, "中");
        assert_eq!(f.rows[1][1].text, "");
        assert_eq!(f.rows[1][2].text, "!");
        let c = f.cursor.unwrap();
        assert_eq!((c.x, c.y), (3, 1));
    }

    #[test]
    fn a_frame_reads_again_only_the_rows_that_changed() {
        let mut vt = Vt::new(20, 4);
        // The cursor ends on the last row: the row it leaves counts as changed.
        vt.write(b"one\r\ntwo\r\nthree\r\n");
        let before = vt.frame();
        vt.write(b"\x1b[2;1Hchanged");
        let after = vt.frame();
        let same = |y: usize| Rc::ptr_eq(&before.rows[y], &after.rows[y]);
        assert!(same(0) && same(2), "untouched rows aren't read again");
        assert!(!same(1));
        assert!(after.rows[1].iter().map(|c| c.text.as_str()).collect::<String>().starts_with("changed"));
        vt.write(b"\x1b]4;1;rgb:12/34/56\x1b\\");
        let recolored = vt.frame();
        assert!(!Rc::ptr_eq(&after.rows[0], &recolored.rows[0]), "a palette change reads every row");
    }

    #[test]
    fn resize_queues_a_report_only_when_the_program_requested_it() {
        let mut vt = Vt::new(20, 4);
        vt.resize(30, 5, 9, 18);
        assert!(vt.take_replies().is_empty(), "a shell receives no resize input");
        vt.write(b"\x1b[?2048h");
        vt.take_replies();
        vt.resize(40, 6, 9, 18);
        assert_eq!(vt.take_replies(), b"\x1b[48;6;40;108;360t");
        assert!(vt.take_replies().is_empty(), "the report is sent only once");
        vt.write(b"\x1b[?2048l");
        vt.resize(50, 7, 9, 18);
        assert!(vt.take_replies().is_empty());
    }

    #[test]
    fn text_that_would_vanish_turns_readable() {
        let (ink, white, dark_red) = (Rgb(0x25, 0x27, 0x2c), Rgb(0xff, 0xff, 0xff), Rgb(0x46, 0x1e, 0x20));
        assert_eq!(readable(ink, white, 1.6), ink);
        assert_ne!(readable(ink, dark_red, 1.6), ink);
        assert_eq!(readable(Rgb(0xfa, 0xfa, 0xfa), white, 1.6), Rgb(0x1b, 0x1b, 0x1e));
        // Dim text keeps its color.
        assert_eq!(readable(Rgb(0x7b, 0x7e, 0x87), white, 1.6), Rgb(0x7b, 0x7e, 0x87));
    }

    #[test]
    fn program_colors_are_unchanged_by_default_and_contrast_reloads_live() {
        let mut vt = Vt::new(8, 4);
        let original = theme();
        assert_eq!(original.minimum_contrast, 1.0);
        vt.write(b"\x1b[38;2;215;153;33;48;2;104;157;106m XX  \x1b[0m\r\n\x1b[38;5;178;48;5;72m XX  \x1b[0m\r\n\x1b[33;46m XX  \x1b[0m");
        let expected = [Rgb(215, 153, 33), Rgb(215, 175, 0), original.palette16[3]];
        let before = vt.frame();
        for (row, fg) in before.rows.iter().zip(expected) {
            assert_eq!(row[1].fg, fg);
        }
        vt.set_theme(Theme { minimum_contrast: 1.6, ..original.clone() });
        let adjusted = vt.frame();
        for (i, fg) in expected.iter().enumerate() {
            assert_ne!(adjusted.rows[i][1].fg, *fg);
            assert!(!Rc::ptr_eq(&before.rows[i], &adjusted.rows[i]));
        }
        vt.set_theme(original);
        let restored = vt.frame();
        for (i, fg) in expected.iter().enumerate() {
            assert_eq!(restored.rows[i][1].fg, *fg);
        }
    }

    #[test]
    fn graphics_keep_low_contrast_colors_in_frames() {
        let mut vt = Vt::new(8, 2);
        vt.set_theme(Theme { minimum_contrast: 1.6, ..theme() });
        let fg = Rgb(30, 31, 40);
        for code in (0x2500..=0x259f).chain(0xe0b0..=0xe0d7).chain(0x1fb00..=0x1fbff).chain(0x1cc00..=0x1cebf).chain([0x23fa]) {
            let ch = char::from_u32(code).unwrap();
            vt.write(format!("\x1b[H\x1b[38;2;30;31;40;48;2;32;33;42m{ch}X").as_bytes());
            let frame = vt.frame();
            assert_eq!(frame.rows[0][0].fg, fg, "{code:x}");
            let text = frame.rows[0].iter().find(|c| c.text == "X").unwrap();
            assert_ne!(text.fg, fg, "ordinary text still gets contrast adjustment");
        }
        for code in [0x24ff, 0x25a0, 0xe0af, 0xe0d8, 0x1faff, 0x1fc00, 0x1cbff, 0x1cec0] {
            assert!(!preserves_graphics_color(&char::from_u32(code).unwrap().to_string()), "{code:x}");
        }
    }

    #[test]
    fn repeated_clicks_select_words_then_lines() {
        let mut vt = Vt::new(30, 3);
        vt.write(b"hello world\r\nsecond line");
        for (x, expected) in [(12.0, None), (14.0, Some("hello")), (13.0, Some("hello world"))] {
            vt.select(Select::Press, 1, 0, x, 5.0, 10.0, 60.0);
            vt.select(Select::Release, 1, 0, x, 5.0, 10.0, 60.0);
            assert_eq!(vt.selection_text().as_deref(), expected);
        }
        // A nearby cell outside the pixel tolerance starts a new gesture.
        vt.select(Select::Press, 2, 0, 27.0, 5.0, 10.0, 60.0);
        vt.select(Select::Release, 2, 0, 27.0, 5.0, 10.0, 60.0);
        assert_eq!(vt.selection_text(), None);
    }

    #[test]
    fn keys_follow_the_program_modes() {
        let mut vt = Vt::new(20, 3);
        assert_eq!(vt.encode_key(GHOSTTY_KEY_A, 0, 0, Some("a"), Some('a')), b"a");
        assert_eq!(vt.encode_key(GHOSTTY_KEY_C, GHOSTTY_MODS_CTRL as u16, 0, None, Some('c')), b"\x03");
        assert_eq!(vt.encode_key(GHOSTTY_KEY_ARROW_UP, 0, 0, None, None), b"\x1b[A");
        vt.write(b"\x1b[?1h"); // application cursor keys
        assert_eq!(vt.encode_key(GHOSTTY_KEY_ARROW_UP, 0, 0, None, None), b"\x1bOA");
    }

    #[test]
    fn a_selection_shown_while_dragging_matches_the_rows_it_covers() {
        let mut vt = Vt::new(20, 6);
        vt.write(b"aaaa\r\nbbbb\r\ncccc\r\ndddd\r\neeee\r\n");
        let highlighted = |f: &Frame| f.rows.iter().map(|r| r.iter().any(|c| c.bg == Some(theme().selection_bg))).collect::<Vec<_>>();
        vt.frame();
        vt.select(Select::Press, 0, 0, 1.0, 5.0, 10.0, 20.0);
        for row in 1..5 {
            vt.select(Select::Drag, 2, row, 25.0, row as f32 * 20.0 + 5.0, 10.0, 20.0);
            vt.frame();
        }
        vt.select(Select::Drag, 2, 1, 25.0, 25.0, 10.0, 20.0);
        assert_eq!(highlighted(&vt.frame()), [true, true, false, false, false, false], "back up to row 1");
    }

    #[test]
    fn a_drag_ends_under_the_pointer_with_fractional_cells() {
        // At zoom 1.3 a cell is 9.75 px wide: the selection must end where the
        // pointer is, not run ahead of it as x grows.
        let mut vt = Vt::new(80, 2);
        let line: String = (0..80).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
        vt.write(line.as_bytes());
        let cw = 9.75;
        let x = 39.0 * cw + 6.0; // past the middle of column 39
        vt.select(Select::Press, 0, 0, 1.0, 5.0, cw, 40.0);
        vt.select(Select::Drag, 39, 0, x, 5.0, cw, 40.0);
        vt.select(Select::Release, 39, 0, x, 5.0, cw, 40.0);
        assert_eq!(vt.selection_text().as_deref(), Some(&line[..40]));
    }

    #[test]
    fn a_cell_joins_the_drag_only_past_its_middle_with_fractional_cells() {
        // Just before the middle of column 39 (9.75 px cells): 39 stays out. A
        // cell width rounded down to 9 puts the pointer past "the middle" and
        // the highlight flickers between cells as the pointer moves.
        let mut vt = Vt::new(80, 2);
        let line: String = (0..80).map(|i| char::from(b'a' + (i % 26) as u8)).collect();
        vt.write(line.as_bytes());
        let cw = 9.75;
        let x = 39.0 * cw + 4.0;
        vt.select(Select::Press, 0, 0, 1.0, 5.0, cw, 40.0);
        vt.select(Select::Drag, 39, 0, x, 5.0, cw, 40.0);
        vt.select(Select::Release, 39, 0, x, 5.0, cw, 40.0);
        assert_eq!(vt.selection_text().as_deref(), Some(&line[..39]));
    }

    #[test]
    fn mouse_reports_the_cell_under_the_pointer_with_fractional_cells() {
        // Programs that take the mouse (pi, vim) get the pointer's cell. At
        // zoom 1.3 a cell is 11.7 px; rounded to 11 the column ran ahead.
        let mut vt = Vt::new(80, 2);
        vt.write(b"\x1b[?1000h\x1b[?1006h");
        let (cw, ch) = (11.7, 30.0);
        let x = 39.0 * cw + 5.0; // inside column 39 (1-based 40)
        let bytes = vt.encode_mouse(GHOSTTY_MOUSE_ACTION_PRESS, Some(GHOSTTY_MOUSE_BUTTON_LEFT), 0, x, 10.0, (80, 2, cw, ch), false);
        assert_eq!(String::from_utf8_lossy(&bytes), "\x1b[<0;40;1M");
    }

    #[test]
    fn dragging_selects_and_copies_text() {
        let mut vt = Vt::new(20, 3);
        vt.write(b"hello world\r\nsecond");
        vt.select(Select::Press, 0, 0, 2.0, 5.0, 10.0, 60.0);
        vt.select(Select::Drag, 4, 0, 46.0, 5.0, 10.0, 60.0);
        vt.select(Select::Release, 4, 0, 46.0, 5.0, 10.0, 60.0);
        assert_eq!(vt.selection_text().as_deref(), Some("hello"));
        vt.clear_selection();
        assert_eq!(vt.selection_text(), None);
    }

    #[test]
    fn kitty_images_are_stored_placed_and_acknowledged() {
        let mut vt = Vt::new(20, 5);
        vt.resize(20, 5, 8, 16);
        // A 1x1 red PNG, transmitted and displayed, asking for a reply.
        vt.write(b"\x1b_Ga=T,f=100,i=7,q=0;iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==\x1b\\");
        let p = vt.placements();
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!((p[0].image, p[0].col, p[0].row), (7, 0, 0));
        let (w, h, bgra) = vt.image_bgra(7, p[0].source).unwrap();
        assert_eq!((w, h), (1, 1));
        assert_eq!(&bgra[..], &[0, 0, 255, 255]);
        let reply = String::from_utf8(vt.take_replies()).unwrap();
        assert!(reply.contains("i=7") && reply.contains("OK"), "{reply:?}");
    }

    #[test]
    fn links_follow_wrapped_lines() {
        let mut vt = Vt::new(20, 4);
        vt.write(b"go https://example.com/a/long/path ok");
        let hit = vt.link_at(5, 1, crate::links::find).unwrap();
        assert_eq!(hit.target, "https://example.com/a/long/path");
        assert_eq!(hit.spans, vec![(0, 3, 19), (1, 0, 13)]);
        assert_eq!(vt.link_at(1, 0, crate::links::find), None);
        assert_eq!(vt.link_at(16, 1, crate::links::find), None);
    }

    #[test]
    fn links_wrapped_out_of_view_keep_their_whole_text() {
        let mut vt = Vt::new(10, 2);
        vt.write(b"https://example.com/abcdefgh");
        // Three rows of link on a two-row screen: the first scrolled away.
        let hit = vt.link_at(2, 0, crate::links::find).unwrap();
        assert_eq!(hit.target, "https://example.com/abcdefgh");
        assert_eq!(hit.spans, vec![(0, 0, 9), (1, 0, 7)]);
    }

    #[test]
    fn marked_links_open_their_uri() {
        let mut vt = Vt::new(30, 2);
        vt.write(b"see \x1b]8;;https://herdr.dev\x1b\\the docs\x1b]8;;\x1b\\ now");
        let hit = vt.link_at(6, 0, crate::links::find).unwrap();
        assert_eq!(hit.target, "https://herdr.dev");
        assert_eq!(hit.spans, vec![(0, 4, 11)]);
        assert_eq!(vt.link_at(13, 0, crate::links::find), None);
    }

    #[test]
    fn osc52_writes_are_decoded_and_bounded() {
        use base64::Engine;
        let mut vt = Vt::new(80, 24);
        vt.write(b"\x1b]52;c;aGVs");
        assert_eq!(vt.take_clipboard(), [None, None]);
        vt.write(b"bG8=\x07");
        assert_eq!(vt.take_clipboard(), [Some("hello".into()), None]);
        vt.write(b"\x1b]52;c;8J+YgA==\x1b\\");
        assert_eq!(vt.take_clipboard(), [Some("😀".into()), None]);
        for selector in b"01234567" {
            vt.write(format!("\x1b]52;{};aGk=\x07", *selector as char).as_bytes());
            assert_eq!(vt.take_clipboard(), [Some("hi".into()), None]);
        }
        vt.write(b"\x1b]52;p;aGk=\x07");
        let expected = if cfg!(target_os = "linux") { Some("hi".into()) } else { None };
        assert_eq!(vt.take_clipboard(), [None, expected]);
        for sequence in [b"\x1b]52;c;?\x07".as_slice(), b"\x1b]52;c;%%%\x07", b"\x1b]52;c;/w==\x07", b"\x1b]52;s;aGk=\x07"] {
            vt.write(sequence);
            assert_eq!(vt.take_clipboard(), [None, None]);
            assert!(vt.take_replies().is_empty());
        }
        let limit = base64::engine::general_purpose::STANDARD.encode(vec![b'x'; MAX_CLIPBOARD_BYTES]);
        vt.write(format!("\x1b]52;c;{limit}\x07").as_bytes());
        assert_eq!(vt.take_clipboard()[0].as_ref().map(String::len), Some(MAX_CLIPBOARD_BYTES));
        let huge = base64::engine::general_purpose::STANDARD.encode(vec![b'x'; MAX_CLIPBOARD_BYTES + 1]);
        vt.write(format!("\x1b]52;c;{huge}\x07").as_bytes());
        assert_eq!(vt.take_clipboard(), [None, None]);
        vt.write(b"\x1b]52;c;b2s=\x07");
        assert_eq!(vt.take_clipboard(), [Some("ok".into()), None]);
        vt.allow_clipboard_write(false);
        vt.write(b"\x1b]52;c;aGk=\x07");
        assert_eq!(vt.take_clipboard(), [None, None]);
        vt.allow_clipboard_write(true);
        vt.write(b"\x1b]52;c;YQ==\x07\x1b]52;c;Yg==\x07");
        assert_eq!(vt.take_clipboard(), [Some("b".into()), None]);
        vt.write(b"\x1b]52;c;YQ==\x07\x1b]52;c;\x07");
        assert_eq!(vt.take_clipboard(), [Some(String::new()), None]);
        vt.write(b"\x1b]52;p;\x1b\\");
        let expected = if cfg!(target_os = "linux") { Some(String::new()) } else { None };
        assert_eq!(vt.take_clipboard(), [None, expected]);
    }

    #[test]
    fn title_is_reported_once() {
        let mut vt = Vt::new(20, 3);
        vt.write(b"\x1b]2;hello\x07");
        assert_eq!(vt.take_title().as_deref(), Some("hello"));
        assert_eq!(vt.take_title(), None);
    }

    fn snapshot_of(vt: &Vt) -> Vec<u8> {
        unsafe {
            let (mut ptr, mut len) = (std::ptr::null_mut(), 0usize);
            ok(ghostty_snapshot_encode_alloc(vt.term, std::ptr::null(), &mut ptr, &mut len), "snapshot_encode_alloc");
            let bytes = std::slice::from_raw_parts(ptr, len).to_vec();
            ghostty_free(std::ptr::null(), ptr, len);
            bytes
        }
    }

    fn lines(f: &Frame) -> Vec<String> {
        f.rows.iter().map(|r| r.iter().map(|c| if c.text.is_empty() && !c.wide { " " } else { c.text.as_str() }).collect::<String>().trim_end().to_owned()).collect()
    }

    /// A record of an unknown tag, as newer encoders add (Kitty graphics).
    fn unknown_record(tag: u16, payload: &[u8]) -> Vec<u8> {
        let mut header = tag.to_le_bytes().to_vec();
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let crc = crc32c(&[&header, payload]);
        [header, crc.to_le_bytes().to_vec(), payload.to_vec()].concat()
    }

    #[test]
    fn crc32c_matches_the_standard_check_value() {
        assert_eq!(crc32c(&[b"1234", b"56789"]), 0xe306_9283);
    }

    #[test]
    fn a_snapshot_restores_the_screen_size_cursor_and_history() {
        let mut source = Vt::new(30, 5);
        // Unfinished input is carried only while tracked.
        let track: usize = 1 << 16;
        unsafe { ghostty_terminal_set(source.term, GHOSTTY_TERMINAL_OPT_CONTINUATION_MAX_BYTES, &track as *const _ as *const c_void) };
        for i in 0..20 {
            source.write(format!("history {i}\r\n").as_bytes());
        }
        source.write(b"\x1b]2;remote title\x07plain \x1b[1;31mred\x1b[0m\r\n\xe4\xb8\xad wide\x1b[5;12Hend\x1b[3;4H\x1b[1;3");
        let before = source.frame();
        let bytes = snapshot_of(&source);

        let mut vt = Vt::new(10, 3);
        vt.write(b"old screen");
        vt.take_title();
        vt.import_snapshot(&bytes).unwrap();
        assert_eq!((vt.cols, vt.rows), (30, 5));
        let after = vt.frame();
        assert!(after.all);
        assert_eq!(lines(&after), lines(&before));
        assert_eq!(lines(&after)[3], "plain red");
        assert_eq!(lines(&after)[4], "中  wide    end");
        let red = &after.rows[3][6];
        assert!(red.bold);
        assert_eq!(red.fg, theme().palette16[1]);
        assert!(after.rows[4][0].wide);
        let (c, b) = (after.cursor.unwrap(), before.cursor.unwrap());
        assert_eq!((c.x, c.y), (b.x, b.y));
        assert_eq!((c.x, c.y), (3, 2));
        assert_eq!(vt.take_title().as_deref(), Some("remote title"));
        // The unfinished SGR continues from the snapshot.
        vt.write(b"2mX");
        let f = vt.frame();
        assert_eq!(f.rows[2][3].text, "X");
        assert!(f.rows[2][3].bold);
        assert_eq!(f.rows[2][3].fg, theme().palette16[2]);
        // History came along.
        vt.scroll_viewport(-100);
        assert_eq!(lines(&vt.frame())[0], "history 0");
        // And the callbacks: a device query is answered.
        vt.scroll_to_bottom();
        vt.write(b"\x1b[6n");
        assert_eq!(vt.take_replies(), b"\x1b[3;5R");
        vt.write(b"\x1b]2;next\x07");
        assert_eq!(vt.take_title().as_deref(), Some("next"));
        // The view's colors stay.
        vt.set_theme(Theme { fg: Rgb(1, 2, 3), ..theme() });
        vt.write(b"\x1b[0m\r\nZ");
        let f = vt.frame();
        assert_eq!(f.rows[3][0].text, "Z");
        assert_eq!(f.rows[3][0].fg, readable(Rgb(1, 2, 3), theme().bg));
    }

    #[test]
    fn records_of_unknown_tags_are_skipped_once_checked() {
        let mut source = Vt::new(20, 3);
        source.write(b"kept");
        let bytes = snapshot_of(&source);
        // Before FINISH, as Kitty graphics records come.
        let finish = bytes.len() - 10;
        let with = [&bytes[..finish], &unknown_record(9, b"pixels"), &unknown_record(0x4000, b""), &bytes[finish..]].concat();
        let mut vt = Vt::new(20, 3);
        vt.import_snapshot(&with).unwrap();
        assert_eq!(lines(&vt.frame())[0], "kept");

        let mut damaged = unknown_record(8, b"meta");
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let bad = [&bytes[..finish], &damaged, &bytes[finish..]].concat();
        assert!(Vt::new(20, 3).import_snapshot(&bad).is_err());
    }

    #[test]
    fn a_bad_snapshot_leaves_the_terminal_as_it_was() {
        let mut source = Vt::new(20, 3);
        source.write(b"from the snapshot");
        let bytes = snapshot_of(&source);
        let mut vt = Vt::new(12, 4);
        vt.write(b"still here");
        let before = lines(&vt.frame());

        let mut corrupt = bytes.clone();
        let mid = 10 + 10 + 5; // inside TERMINAL's payload
        corrupt[mid] ^= 0x40;
        let mut trailing = bytes.clone();
        trailing.push(b'x');
        let mut unfinished = bytes.clone();
        unfinished.truncate(bytes.len() - 10);
        let mut version = bytes.clone();
        version[8] = 2;
        for bad in [&corrupt[..], &trailing, &unfinished, &version, &bytes[..9], b""] {
            assert!(vt.import_snapshot(bad).is_err());
            assert_eq!((vt.cols, vt.rows), (12, 4));
            assert_eq!(lines(&vt.frame()), before);
        }
        vt.write(b"!");
        assert_eq!(lines(&vt.frame())[0], "still here!");
        // And a good one still imports.
        vt.import_snapshot(&bytes).unwrap();
        assert_eq!(lines(&vt.frame())[0], "from the snapshot");
    }
}
