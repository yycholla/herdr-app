//! Splits a Rex terminal stream into the snapshot it starts with, the
//! program's output, and the server's own APC messages. See docs/rex.md.
//!
//! After WELCOME the stream is one byte sequence; WebSocket message
//! boundaries mean nothing, so any piece may arrive split anywhere.
//!
//! 1. A Ghostty `GHOSTSNP` version-1 snapshot: a ten-byte envelope, then
//!    records of u16 tag, u32 payload length, u32 CRC32C and payload (little
//!    endian), ending with the empty tag-6 FINISH record. Only the framing is
//!    read here; Ghostty's decoder validates checksums, order and contents
//!    (`Vt::import_snapshot`).
//! 2. Live program output, with Rex messages placed where they're safe to
//!    apply: `ESC _ rex1;<decimal nonce>;<JSON> ESC \`. Only the WELCOME's
//!    nonce authorizes one. Any other APC, including a look-alike with a wrong
//!    nonce (a program printed it), is program output and passes through
//!    untouched; its content streams without being buffered, so large Kitty
//!    graphics sequences cost nothing here.
//!
//! An error is final: part of the chunk may already have been handed out, so
//! the stream can't be resumed and the display must start over.

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

/// The most snapshot bytes buffered before FINISH.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
/// The largest authorized Rex APC, introducer and terminator included.
pub const MAX_APC_BYTES: usize = 64 * 1024;
/// The most visible cells a snapshot or a resize may declare.
pub const MAX_GRID_CELLS: usize = 65_536;

const ENVELOPE: usize = 10;
const RECORD_HEADER: usize = 10;
const TAG_TERMINAL: u16 = 1;
const TAG_FINISH: u16 = 6;

#[derive(Debug, PartialEq)]
pub enum Piece {
    /// The whole `GHOSTSNP` snapshot, through its FINISH record.
    Snapshot(Vec<u8>),
    /// Program output to feed the display.
    Data(Vec<u8>),
    /// The terminal's size changed (`rex1` resize).
    Resize { cols: u16, rows: u16 },
    /// New default colors (`rex1` theme), as sent.
    Theme(Value),
    /// The program ended (`rex1` child_exited), as sent.
    ChildExited(Value),
}

pub struct Decoder {
    /// `ESC _ rex1;<nonce>;`: how an authorized message starts.
    prefix: Vec<u8>,
    /// Snapshot bytes until FINISH; `None` once the snapshot was handed out.
    snapshot: Option<Vec<u8>>,
    /// Where the next unread snapshot record starts.
    record: usize,
    /// Live bytes not yet classified: a final ESC, or a possible Rex APC.
    pending: Vec<u8>,
    /// Inside an APC that isn't ours: its bytes go straight to the display.
    passthrough: bool,
}

impl Decoder {
    pub fn new(nonce: u64) -> Decoder {
        Decoder {
            prefix: format!("\x1b_rex1;{nonce};").into_bytes(),
            snapshot: Some(Vec::new()),
            record: ENVELOPE,
            pending: Vec::new(),
            passthrough: false,
        }
    }

    /// Decodes the next stream bytes into the pieces they complete, in
    /// stream order. Adjacent output is merged into one `Data`.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Piece>> {
        let mut out = Vec::new();
        let tail;
        let live = match &mut self.snapshot {
            None => bytes,
            Some(snapshot) => {
                snapshot.extend_from_slice(bytes);
                let Some(end) = snapshot_end(snapshot, &mut self.record)? else {
                    ensure!(snapshot.len() <= MAX_SNAPSHOT_BYTES, "Rex snapshot exceeds the client limit");
                    return Ok(out);
                };
                let mut snapshot = self.snapshot.take().unwrap_or_default();
                // Bytes after FINISH in the same chunk are already live output.
                tail = snapshot.split_off(end);
                out.push(Piece::Snapshot(snapshot));
                &tail[..]
            }
        };
        self.live(live, &mut out)?;
        Ok(out)
    }

    fn live(&mut self, bytes: &[u8], out: &mut Vec<Piece>) -> Result<()> {
        let pending = if self.pending.is_empty() { None } else { Some(std::mem::take(&mut self.pending)) };
        let joined;
        let input = match pending {
            None => bytes,
            Some(mut p) => {
                p.extend_from_slice(bytes);
                joined = p;
                &joined[..]
            }
        };
        let mut at = 0;
        while at < input.len() {
            let rest = &input[at..];
            if self.passthrough {
                let (len, ended) = match rest.iter().position(|b| apc_exit(*b)) {
                    // ESC starts the next sequence (maybe one of ours): look at it again.
                    Some(i) if rest[i] == 0x1b => (i, true),
                    Some(i) => (i + 1, true),
                    None => (rest.len(), false),
                };
                data(out, &rest[..len]);
                at += len;
                self.passthrough = !ended;
                continue;
            }
            let Some(start) = rest.windows(2).position(|w| w == b"\x1b_") else {
                // Hold a final ESC: an APC may begin in the next chunk.
                let len = rest.len() - usize::from(rest.last() == Some(&0x1b));
                data(out, &rest[..len]);
                at += len;
                break;
            };
            data(out, &rest[..start]);
            at += start;
            let rest = &input[at..];
            let compared = rest.len().min(self.prefix.len());
            if rest[..compared] != self.prefix[..compared] {
                // Someone else's APC (or a forged one): the program's output.
                data(out, &rest[..2]);
                at += 2;
                self.passthrough = true;
                continue;
            }
            // Ours so far: wait for its terminator. (The prefix holds no ESC
            // after the introducer, so ESC \ can only follow the whole prefix.)
            let Some(end) = rest[2..].windows(2).position(|w| w == b"\x1b\\").map(|i| i + 4) else {
                ensure!(rest.len() <= MAX_APC_BYTES, "Rex APC exceeds the client limit");
                break;
            };
            ensure!(end <= MAX_APC_BYTES, "Rex APC exceeds the client limit");
            if let Some(piece) = message(&rest[self.prefix.len()..end - 2])? {
                out.push(piece);
            }
            at += end;
        }
        self.pending = input[at..].to_vec();
        Ok(())
    }
}

/// Whether the VT parser leaves an APC string at this byte: CAN, SUB, ESC
/// (which starts a new sequence) and the C1 controls, except SOS, PM and APC,
/// which only start another string (Ghostty's parse table).
fn apc_exit(b: u8) -> bool {
    matches!(b, 0x18 | 0x1a | 0x1b | 0x80..=0x9f) && !matches!(b, 0x98 | 0x9e | 0x9f)
}

/// An authorized message; `None` for a type this client doesn't know.
fn message(json: &[u8]) -> Result<Option<Piece>> {
    let message: Value = serde_json::from_slice(json).context("decode Rex terminal APC")?;
    Ok(match message["type"].as_str() {
        Some("resize") => {
            let dim = |key: &str| -> Result<u16> {
                let v = message[key].as_u64().with_context(|| format!("Rex resize lacks {key}"))?;
                u16::try_from(v).ok().filter(|v| *v > 0).with_context(|| format!("invalid Rex resize {key} {v}"))
            };
            let (cols, rows) = (dim("cols")?, dim("rows")?);
            ensure!(usize::from(cols) * usize::from(rows) <= MAX_GRID_CELLS, "Rex resize {cols}x{rows} exceeds the client limit");
            Some(Piece::Resize { cols, rows })
        }
        Some("theme") => Some(Piece::Theme(message)),
        Some("child_exited") => Some(Piece::ChildExited(message)),
        _ => None,
    })
}

/// Appends program output, merging it into the previous `Data`.
fn data(out: &mut Vec<Piece>, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    match out.last_mut() {
        Some(Piece::Data(d)) => d.extend_from_slice(bytes),
        _ => out.push(Piece::Data(bytes.to_vec())),
    }
}

/// Finds the end of FINISH without interpreting terminal state, resuming at
/// `record`. `None`: more bytes are needed.
fn snapshot_end(bytes: &[u8], record: &mut usize) -> Result<Option<usize>> {
    if bytes.len() < ENVELOPE {
        ensure!(b"GHOSTSNP".starts_with(&bytes[..bytes.len().min(8)]), "the Rex stream doesn't start with a Ghostty snapshot");
        return Ok(None);
    }
    ensure!(&bytes[..8] == b"GHOSTSNP", "the Rex stream doesn't start with a Ghostty snapshot");
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != 1 {
        bail!("unsupported Ghostty snapshot version {version}");
    }
    // TERMINAL comes first; its payload starts with the columns and rows.
    if bytes.len() >= ENVELOPE + RECORD_HEADER + 4 {
        let tag = u16::from_le_bytes([bytes[10], bytes[11]]);
        ensure!(tag == TAG_TERMINAL, "the Rex snapshot must begin with terminal state");
        let cols = usize::from(u16::from_le_bytes([bytes[20], bytes[21]]));
        let rows = usize::from(u16::from_le_bytes([bytes[22], bytes[23]]));
        ensure!(cols > 0 && rows > 0 && cols * rows <= MAX_GRID_CELLS, "the Rex snapshot's {cols}x{rows} grid exceeds the client limit");
    }
    while bytes.len().saturating_sub(*record) >= RECORD_HEADER {
        let h = &bytes[*record..*record + RECORD_HEADER];
        let tag = u16::from_le_bytes([h[0], h[1]]);
        let len = u32::from_le_bytes([h[2], h[3], h[4], h[5]]) as usize;
        let end = (*record + RECORD_HEADER).checked_add(len).context("Rex snapshot record overflow")?;
        // Refused before its payload is buffered.
        ensure!(end <= MAX_SNAPSHOT_BYTES, "Rex snapshot record exceeds the client limit");
        if bytes.len() < end {
            return Ok(None);
        }
        *record = end;
        if tag == TAG_FINISH {
            ensure!(len == 0, "the Rex snapshot's FINISH has a payload");
            return Ok(Some(end));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A framing-valid snapshot: TERMINAL (80x24 prefix), one opaque record,
    /// FINISH. Checksums are Ghostty's to check, not this decoder's.
    fn snapshot() -> Vec<u8> {
        let mut b = b"GHOSTSNP\x01\x00".to_vec();
        b.extend_from_slice(&[1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 80, 0, 24, 0]);
        b.extend_from_slice(&[3, 0, 3, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c']);
        b.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b
    }

    fn apc(nonce: u64, json: &Value) -> Vec<u8> {
        format!("\x1b_rex1;{nonce};{json}\x1b\\").into_bytes()
    }

    /// A decoder past its snapshot.
    fn live(nonce: u64) -> Decoder {
        let mut d = Decoder::new(nonce);
        assert_eq!(d.push(&snapshot()).unwrap(), vec![Piece::Snapshot(snapshot())]);
        d
    }

    /// Pushes every chunk, merging `Data` across chunks.
    fn feed(d: &mut Decoder, chunks: &[&[u8]]) -> Vec<Piece> {
        let mut out = Vec::new();
        for chunk in chunks {
            for piece in d.push(chunk).unwrap() {
                match piece {
                    Piece::Data(bytes) => data(&mut out, &bytes),
                    other => out.push(other),
                }
            }
        }
        out
    }

    #[test]
    fn snapshot_then_data_in_one_chunk() {
        let mut d = Decoder::new(7);
        let bytes = [snapshot(), b"live".to_vec()].concat();
        assert_eq!(d.push(&bytes).unwrap(), vec![Piece::Snapshot(snapshot()), Piece::Data(b"live".to_vec())]);
        assert!(d.snapshot.is_none());
        assert_eq!(d.push(b"more").unwrap(), vec![Piece::Data(b"more".to_vec())]);
    }

    #[test]
    fn snapshot_split_at_every_byte_boundary() {
        let bytes = [snapshot(), b"tail".to_vec()].concat();
        let finish = snapshot().len();
        let want = vec![Piece::Snapshot(snapshot()), Piece::Data(b"tail".to_vec())];
        for split in 0..=bytes.len() {
            let mut d = Decoder::new(7);
            let first = d.push(&bytes[..split]).unwrap();
            assert_eq!(first.is_empty(), split < finish, "split {split}: {first:?}");
            let mut d2 = Decoder::new(7);
            assert_eq!(feed(&mut d2, &[&bytes[..split], &bytes[split..]]), want, "split {split}");
        }
        let mut d = Decoder::new(7);
        let bytewise: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(feed(&mut d, &bytewise), want);
    }

    #[test]
    fn snapshot_framing_is_checked() {
        assert!(Decoder::new(1).push(b"NOTASNAP").is_err(), "wrong magic");
        assert!(Decoder::new(1).push(b"GHOST").unwrap().is_empty(), "a magic prefix waits");
        assert!(Decoder::new(1).push(b"GHOSTSNP\x02\x00").is_err(), "unknown version");
        let mut bad = snapshot();
        bad[10] = 3;
        assert!(Decoder::new(1).push(&bad).is_err(), "TERMINAL comes first");
        let mut huge = snapshot();
        huge[20..24].copy_from_slice(&[0, 1, 1, 1]); // 256x257
        assert!(Decoder::new(1).push(&huge).is_err(), "grid bound");
        let mut empty = snapshot();
        empty[20..22].copy_from_slice(&[0, 0]);
        assert!(Decoder::new(1).push(&empty).is_err(), "no columns");
        // A record past the bound is refused before its payload arrives.
        let mut big = b"GHOSTSNP\x01\x00\x01\x00".to_vec();
        big.extend_from_slice(&u32::MAX.to_le_bytes());
        big.extend_from_slice(&[0; 4]);
        assert!(Decoder::new(1).push(&big).is_err());
        let mut finish = snapshot();
        let at = finish.len() - 8;
        finish[at] = 1; // FINISH with a payload
        finish.push(0);
        assert!(Decoder::new(1).push(&finish).is_err());
    }

    #[test]
    fn messages_decode_in_stream_order() {
        let mut d = live(42);
        let theme = json!({"type": "theme", "foreground": "#ffffff", "palette": ["1=ff0000"], "scheme": "dark"});
        let exited = json!({"type": "child_exited", "exit_code": 7});
        let bytes = [
            b"a".to_vec(),
            apc(42, &json!({"type": "resize", "cols": 100, "rows": 30, "cell_width_px": 0, "cell_height_px": 0, "owner": null})),
            b"b".to_vec(),
            apc(42, &theme),
            apc(42, &json!({"type": "something_new", "x": 1})),
            apc(42, &exited),
            b"after".to_vec(),
        ]
        .concat();
        assert_eq!(
            d.push(&bytes).unwrap(),
            vec![
                Piece::Data(b"a".to_vec()),
                Piece::Resize { cols: 100, rows: 30 },
                Piece::Data(b"b".to_vec()),
                Piece::Theme(theme),
                Piece::ChildExited(exited),
                Piece::Data(b"after".to_vec()),
            ]
        );
    }

    #[test]
    fn an_apc_split_anywhere_decodes_the_same() {
        let resize = apc(42, &json!({"type": "resize", "cols": 10, "rows": 3}));
        let bytes = [b"hello".to_vec(), resize, b"world\x1b[0m".to_vec()].concat();
        let want = vec![Piece::Data(b"hello".to_vec()), Piece::Resize { cols: 10, rows: 3 }, Piece::Data(b"world\x1b[0m".to_vec())];
        for split in 0..=bytes.len() {
            let mut d = live(42);
            assert_eq!(feed(&mut d, &[&bytes[..split], &bytes[split..]]), want, "split {split}");
        }
        let mut d = live(42);
        let bytewise: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(feed(&mut d, &bytewise), want);
    }

    #[test]
    fn a_wrong_nonce_is_program_output() {
        for nonce in [41, 421, 4] {
            let bytes = [apc(nonce, &json!({"type": "resize", "cols": 1, "rows": 1})), b"x".to_vec()].concat();
            for split in 0..=bytes.len() {
                let mut d = live(42);
                assert_eq!(feed(&mut d, &[&bytes[..split], &bytes[split..]]), vec![Piece::Data(bytes.clone())], "nonce {nonce} split {split}");
            }
        }
        // Ours right after a forged one still counts.
        let mut d = live(42);
        let forged = apc(41, &json!({"type": "child_exited", "exit_code": 1}));
        let bytes = [forged.clone(), apc(42, &json!({"type": "resize", "cols": 2, "rows": 2}))].concat();
        assert_eq!(d.push(&bytes).unwrap(), vec![Piece::Data(forged), Piece::Resize { cols: 2, rows: 2 }]);
    }

    #[test]
    fn other_apcs_stream_through_without_buffering() {
        let mut d = live(42);
        assert_eq!(d.push(b"\x1b_Ga=T,f=100;").unwrap(), vec![Piece::Data(b"\x1b_Ga=T,f=100;".to_vec())]);
        let chunk = vec![b'A'; 256 * 1024];
        for _ in 0..4 {
            assert_eq!(d.push(&chunk).unwrap(), vec![Piece::Data(chunk.clone())]);
            assert!(d.pending.is_empty());
        }
        // The terminator split across chunks.
        assert_eq!(d.push(b"AA\x1b").unwrap(), vec![Piece::Data(b"AA".to_vec())]);
        let bytes = [b"\\shown".to_vec(), apc(42, &json!({"type": "resize", "cols": 5, "rows": 5}))].concat();
        assert_eq!(d.push(&bytes).unwrap(), vec![Piece::Data(b"\x1b\\shown".to_vec()), Piece::Resize { cols: 5, rows: 5 }]);
    }

    #[test]
    fn an_apc_cut_short_does_not_hide_ours() {
        let resize = apc(42, &json!({"type": "resize", "cols": 10, "rows": 3}));
        for end in [&[0x18u8][..], &[0x1a], &[0x9c], &[0x8d], b"\x1b\\"] {
            let mut d = live(42);
            let out = feed(&mut d, &[b"\x1b_not-rex", end, &resize]);
            assert_eq!(out, vec![Piece::Data([b"\x1b_not-rex".as_slice(), end].concat()), Piece::Resize { cols: 10, rows: 3 }]);
        }
        // An ESC starting another sequence ends the APC too.
        let mut d = live(42);
        assert_eq!(feed(&mut d, &[b"\x1b_Gabc", &resize]), vec![Piece::Data(b"\x1b_Gabc".to_vec()), Piece::Resize { cols: 10, rows: 3 }]);
        // A C1 APC opener only starts another string: still not ours.
        let mut d = live(42);
        let bytes = [b"\x1b_G\x9f".to_vec(), resize.clone()].concat();
        let out = feed(&mut d, &[&bytes]);
        assert_eq!(out, vec![Piece::Data(b"\x1b_G\x9f".to_vec()), Piece::Resize { cols: 10, rows: 3 }]);
    }

    #[test]
    fn an_oversized_rex_apc_is_an_error() {
        // Unterminated: refused once it outgrows the bound.
        let mut d = live(42);
        assert!(d.push(b"\x1b_rex1;42;{\"type\":\"theme\",\"x\":\"").unwrap().is_empty());
        assert!(d.push(&vec![b'x'; MAX_APC_BYTES]).is_err());
        // Terminated in one chunk but too large.
        let big = apc(42, &json!({"type": "theme", "x": "y".repeat(MAX_APC_BYTES)}));
        assert!(live(42).push(&big).is_err());
        // Exactly at the bound is fine.
        let head = apc(42, &json!({"type": "theme", "x": ""})).len();
        let fits = json!({"type": "theme", "x": "y".repeat(MAX_APC_BYTES - head)});
        assert_eq!(apc(42, &fits).len(), MAX_APC_BYTES);
        assert_eq!(live(42).push(&apc(42, &fits)).unwrap(), vec![Piece::Theme(fits)]);
    }

    #[test]
    fn invalid_rex_messages_are_errors() {
        for bad in [
            json!({"type": "resize", "cols": 0, "rows": 3}),
            json!({"type": "resize", "cols": 70000, "rows": 1}),
            json!({"type": "resize", "cols": 256, "rows": 257}),
            json!({"type": "resize", "rows": 3}),
        ] {
            assert!(live(42).push(&apc(42, &bad)).is_err(), "{bad}");
        }
        assert!(live(42).push(b"\x1b_rex1;42;not json\x1b\\").is_err());
        let largest = apc(42, &json!({"type": "resize", "cols": 256, "rows": 256}));
        assert_eq!(live(42).push(&largest).unwrap(), vec![Piece::Resize { cols: 256, rows: 256 }]);
    }

    #[test]
    fn bytes_after_child_exited_still_decode() {
        let mut d = live(9);
        let exited = json!({"type": "child_exited", "exit_code": 0});
        let out = feed(&mut d, &[&apc(9, &exited), b"bye\x1b", b"[m"]);
        assert_eq!(out, vec![Piece::ChildExited(exited), Piece::Data(b"bye\x1b[m".to_vec())]);
    }
}
