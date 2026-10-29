//! One block's data connection: a WebSocket at `/api/data` (subprotocol
//! `rex.data.terminal.v1`) that streams the block's bytes. See docs/rex.md.
//!
//! Only the connection lives here: the ticket, HELLO/WELCOME, RESUME and the
//! raw byte stream. What the bytes mean (snapshot, APC messages) is the
//! reader's business. Tickets and resume tokens are never logged.

use super::transport::{Control, Endpoint, RexStream, open_websocket};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine as _;
use serde_json::json;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tungstenite::protocol::CloseFrame;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::{Message, WebSocket};

pub const SUBPROTOCOL: &str = "rex.data.terminal.v1";
/// Each stream message holds 1 to 64 KiB.
const MAX_CHUNK_BYTES: usize = 65_536;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a blocked `read` looks at its `DataStop`.
const STOP_POLL: Duration = Duration::from_millis(250);
/// Bounds the only writes after WELCOME: pongs and the close frame.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

const HELLO: u8 = 0x01;
const RESUME: u8 = 0x02;
const WELCOME: u8 = 0x81;
const REJECT: u8 = 0x82;

/// The server closed the stream with a status other than "it ended" (1000)
/// or "block closed" (4000). Downcast it from `read`'s error. Status 1013
/// asks for a fresh `open`; a dropped connection (any other error) can resume.
#[derive(Clone, Debug, PartialEq)]
pub struct DataClosed {
    pub code: u16,
    pub reason: String,
}

impl std::fmt::Display for DataClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the Rex server closed the data connection: {} ({})", self.reason, self.code)
    }
}
impl std::error::Error for DataClosed {}

/// Stops a `DataConn` from another thread: its blocked `read` sends a close
/// frame (ending the stream) and returns `Ok(None)` within a quarter second.
#[derive(Clone)]
pub struct DataStop(Arc<AtomicBool>);

impl DataStop {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The WELCOME's fields. The token is private, so there is no Debug.
struct Welcome {
    token: [u8; 16],
    grace_ms: u32,
    nonce: u64,
}

impl Welcome {
    fn parse(bytes: &[u8]) -> Result<Welcome> {
        if bytes.first() == Some(&REJECT) {
            let reason = bytes.get(1).copied().unwrap_or(0);
            let why = match reason {
                0x01 => "unknown, expired or used ticket or token",
                0x02 => "this client already has a connection to that block's data",
                0x03 => "the stream is not available",
                0x04 => "a limit was reached",
                0x05 => "malformed or late handshake",
                0x06 => "the server failed",
                0x07 => "wrong subprotocol for the ticket",
                _ => "unknown reason",
            };
            bail!("the Rex server rejected the data connection: {why} (0x{reason:02x})");
        }
        ensure!(bytes.len() == 32 && bytes[0] == WELCOME, "bad Rex data WELCOME");
        ensure!(bytes[17..20] == [0, 0, 0], "bad Rex data WELCOME (reserved bytes)");
        let token = bytes[1..17].try_into()?;
        let grace_ms = u32::from_le_bytes(bytes[20..24].try_into()?);
        let nonce = u64::from_le_bytes(bytes[24..32].try_into()?);
        ensure!(nonce != 0, "bad Rex data WELCOME (zero nonce)");
        Ok(Welcome { token, grace_ms, nonce })
    }
}

fn decode_ticket(ticket: &str) -> Result<[u8; 16]> {
    ensure!(ticket.len() == 22, "a Rex data ticket is 22 base64url characters");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ticket)
        .map_err(|_| anyhow!("bad Rex data ticket encoding"))?;
    bytes.try_into().map_err(|_| anyhow!("a Rex data ticket is 16 bytes"))
}

/// Opens `/api/data`, sends `request` (HELLO or RESUME) and reads the answer.
fn handshake(endpoint: &Endpoint, request: Vec<u8>) -> Result<(WebSocket<RexStream>, Welcome)> {
    let mut socket = open_websocket(endpoint, "/api/data", SUBPROTOCOL, MAX_CHUNK_BYTES)?;
    socket.send(Message::binary(request)).context("cannot start the Rex data handshake")?;
    let welcome = loop {
        match socket.read() {
            Ok(Message::Binary(bytes)) => break Welcome::parse(&bytes)?,
            Ok(Message::Close(frame)) => {
                let (code, reason) = frame.map_or((1005, String::new()), |f| (u16::from(f.code), f.reason.to_string()));
                bail!("the Rex server closed the data connection during its handshake: {reason} ({code})")
            }
            Ok(Message::Text(_)) => bail!("the Rex server answered the data handshake with text"),
            Ok(_) => continue,
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                bail!("timed out waiting for the Rex data WELCOME")
            }
            Err(e) => return Err(e).context("reading the Rex data WELCOME"),
        }
    };
    socket.get_ref().set_read_timeout(Some(STOP_POLL))?;
    socket.get_ref().set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok((socket, welcome))
}

pub struct DataConn {
    socket: Option<WebSocket<RexStream>>,
    /// The latest WELCOME's resume token. Never log it.
    token: [u8; 16],
    grace_ms: u32,
    nonce: u64,
    /// Stream bytes `read` has returned, across every connection of the stream.
    received: u64,
    /// The stream is over: closed by us, or ended by the server.
    ended: bool,
    stop: Arc<AtomicBool>,
}

impl DataConn {
    /// Gets a ticket with `data.connect` and completes HELLO/WELCOME. The
    /// control connection must be attached to the session (`session.attach`
    /// or `session.bootstrap`).
    pub fn open(control: &Control, endpoint: &Endpoint, session_id: &str, block_id: &str) -> Result<DataConn> {
        let reply = control.call(
            "data.connect",
            json!({"session_id": session_id, "block_id": block_id, "data_ref_id": "terminal", "subprotocol": SUBPROTOCOL}),
            CONNECT_TIMEOUT,
        )?;
        let ticket = decode_ticket(reply["ticket"].as_str().context("data.connect returned no ticket")?)?;
        let mut hello = Vec::with_capacity(17);
        hello.push(HELLO);
        hello.extend_from_slice(&ticket);
        let (socket, welcome) = handshake(endpoint, hello).with_context(|| format!("opening the data of {block_id}"))?;
        Ok(DataConn {
            socket: Some(socket),
            token: welcome.token,
            grace_ms: welcome.grace_ms,
            nonce: welcome.nonce,
            received: 0,
            ended: false,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The channel nonce that authorizes this stream's Rex APC messages.
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// A handle that stops this connection from another thread.
    pub fn stopper(&self) -> DataStop {
        DataStop(self.stop.clone())
    }

    /// The next bytes, blocking. `Ok(None)`: the server closed the stream.
    /// Also `Ok(None)` once stopped (`DataStop`) or closed. An error is a
    /// dropped connection (try `resume`) or a `DataClosed` from the server.
    pub fn read(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if self.stop.load(Ordering::Acquire) {
                self.close();
            }
            if self.ended {
                return Ok(None);
            }
            let socket = self.socket.as_mut().context("the Rex data connection dropped; resume it")?;
            match socket.read() {
                Ok(Message::Binary(bytes)) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    self.received += bytes.len() as u64;
                    return Ok(Some(bytes.into()));
                }
                Ok(Message::Close(frame)) => {
                    let (code, reason) = frame.map_or((1005, String::new()), |f| (u16::from(f.code), f.reason.to_string()));
                    // Send tungstenite's close reply now, completing the
                    // handshake, and hang up.
                    let _ = socket.flush();
                    if let Some(socket) = self.socket.take() {
                        socket.get_ref().shutdown();
                    }
                    if matches!(code, 1000 | 4000) {
                        self.ended = true;
                        return Ok(None);
                    }
                    return Err(anyhow::Error::new(DataClosed { code, reason }));
                }
                // Pings are answered by tungstenite; the server sends nothing else.
                Ok(_) => continue,
                Err(tungstenite::Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    bail!("the Rex data connection closed")
                }
                Err(e) => return Err(e).context("reading Rex data"),
            }
        }
    }

    /// After a transport failure: RESUME with the bytes accepted so far.
    /// An error means start over with a fresh `open` and a fresh display.
    pub fn resume(&mut self, endpoint: &Endpoint) -> Result<()> {
        ensure!(!self.ended && !self.stop.load(Ordering::Acquire), "the Rex data stream has ended");
        // Hang up the old connection without a close frame: a close would end
        // the stream. Bytes it read ahead but `read` never returned don't count.
        if let Some(old) = self.socket.take() {
            old.get_ref().shutdown();
        }
        let mut request = Vec::with_capacity(25);
        request.push(RESUME);
        request.extend_from_slice(&self.token);
        request.extend_from_slice(&self.received.to_le_bytes());
        let (mut socket, welcome) = handshake(endpoint, request).context("resuming Rex data")?;
        if welcome.nonce != self.nonce {
            let _ = socket.close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() }));
            socket.get_ref().shutdown();
            bail!("the resumed Rex data stream has a different nonce");
        }
        self.socket = Some(socket);
        self.token = welcome.token;
        self.grace_ms = welcome.grace_ms;
        Ok(())
    }

    /// Ends the stream (the block keeps running).
    pub fn close(&mut self) {
        self.ended = true;
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() }));
            socket.get_ref().shutdown();
        }
    }
}

impl Drop for DataConn {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::rex::transport::tests::{Peer, accept, control_peer, remove_socket, request, respond, socket_path};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use std::time::Instant;

    const TICKET: &str = "AAECAwQFBgcICQoLDA0ODw";

    #[test]
    fn tickets_decode_exactly() {
        assert_eq!(decode_ticket(TICKET).unwrap(), std::array::from_fn(|i| i as u8));
        assert!(decode_ticket("AAECAwQFBgcICQoLDA0ODx").is_err(), "noncanonical trailing bits");
        assert!(decode_ticket("AAECAwQFBgcICQoLDA0OD=").is_err());
        assert!(decode_ticket("AAECAwQFBgcICQoLDA0OD+").is_err());
        assert!(decode_ticket("short").is_err());
    }

    fn welcome_bytes(token: u8, grace_ms: u32, nonce: u64) -> Vec<u8> {
        let mut bytes = vec![WELCOME];
        bytes.extend([token; 16]);
        bytes.extend([0, 0, 0]);
        bytes.extend(grace_ms.to_le_bytes());
        bytes.extend(nonce.to_le_bytes());
        bytes
    }

    #[test]
    fn welcome_has_an_exact_layout() {
        let welcome = Welcome::parse(&welcome_bytes(9, 60_000, 77)).unwrap();
        assert_eq!((welcome.token, welcome.grace_ms, welcome.nonce), ([9; 16], 60_000, 77));
        let good = welcome_bytes(9, 60_000, 77);
        assert!(Welcome::parse(&good[..31]).is_err());
        let mut reserved = good.clone();
        reserved[18] = 1;
        assert!(Welcome::parse(&reserved).is_err());
        assert!(Welcome::parse(&welcome_bytes(9, 60_000, 0)).is_err());
        let error = Welcome::parse(&[REJECT, 0x02]).err().unwrap();
        assert!(error.to_string().contains("already has a connection"), "{error}");
        assert!(Welcome::parse(&[REJECT, 0x99]).is_err());
    }

    /// The data side of a fake server: reads the handshake, checks it, and
    /// answers with `answer`.
    fn data_peer(listener: &UnixListener, expect: &[u8], answer: Vec<u8>) -> Peer {
        let mut peer = accept(listener, "/api/data", SUBPROTOCOL);
        match peer.read().unwrap() {
            Message::Binary(bytes) => assert_eq!(&bytes[..], expect),
            other => panic!("expected a binary handshake, got {other:?}"),
        }
        peer.send(Message::binary(answer)).unwrap();
        peer
    }

    fn hello_bytes() -> Vec<u8> {
        let mut hello = vec![HELLO];
        hello.extend(0..16u8);
        hello
    }

    fn resume_bytes(token: u8, received: u64) -> Vec<u8> {
        let mut resume = vec![RESUME];
        resume.extend([token; 16]);
        resume.extend(received.to_le_bytes());
        resume
    }

    /// A fake server that answers `data.connect` with `TICKET`, then hands the
    /// listener to `script` for the data connections.
    fn serve(script: impl FnOnce(&UnixListener) + Send + 'static) -> (Arc<Control>, Endpoint, thread::JoinHandle<()>) {
        let path = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let endpoint = Endpoint::parse(path.to_str().unwrap()).unwrap();
        let server = thread::spawn(move || {
            let mut control = accept(&listener, "/api/control", "rex.control.v1");
            control_peer(&mut control);
            let r = request(&mut control);
            assert_eq!(r["method"], "data.connect");
            assert_eq!(r["payload"]["data_ref_id"], "terminal");
            assert_eq!(r["payload"]["subprotocol"], SUBPROTOCOL);
            assert_eq!(r["payload"]["block_id"], "block:1");
            respond(&mut control, &r, 0, json!({"ticket": TICKET, "expires_in_ms": 60000}));
            script(&listener);
            remove_socket(&path);
        });
        let control = Control::connect(&endpoint, "test").unwrap();
        (control, endpoint, server)
    }

    #[test]
    fn streams_bytes_and_resumes_after_a_drop() {
        let (control, endpoint, server) = serve(|listener| {
            let mut peer = data_peer(listener, &hello_bytes(), welcome_bytes(1, 60_000, 42));
            peer.send(Message::binary(b"GHOSTSNP".to_vec())).unwrap();
            peer.send(Message::binary(b"abc".to_vec())).unwrap();
            // Drop without a close frame: the stream waits for a resume.
            drop(peer);
            let mut peer = data_peer(listener, &resume_bytes(1, 11), welcome_bytes(2, 60_000, 42));
            peer.send(Message::binary(b"def".to_vec())).unwrap();
            drop(peer);
            // A second resume carries the newer token and the full count.
            let mut peer = data_peer(listener, &resume_bytes(2, 14), welcome_bytes(3, 60_000, 42));
            peer.send(Message::Ping(Default::default())).unwrap();
            peer.send(Message::binary(b"!".to_vec())).unwrap();
            peer.close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() })).unwrap();
            while peer.read().is_ok() {}
        });
        let mut data = DataConn::open(&control, &endpoint, "session:1", "block:1").unwrap();
        assert_eq!(data.nonce(), 42);
        assert_eq!(data.grace_ms, 60_000);
        let mut got = Vec::new();
        loop {
            match data.read() {
                Ok(Some(bytes)) => got.extend(bytes),
                Ok(None) => break,
                Err(_) => data.resume(&endpoint).unwrap(),
            }
        }
        assert_eq!(got, b"GHOSTSNPabcdef!");
        assert_eq!(data.received, 15);
        server.join().unwrap();
    }

    #[test]
    fn a_resume_with_another_nonce_or_a_reject_fails() {
        let (control, endpoint, server) = serve(|listener| {
            drop(data_peer(listener, &hello_bytes(), welcome_bytes(1, 60_000, 42)));
            drop(data_peer(listener, &resume_bytes(1, 0), welcome_bytes(2, 60_000, 43)));
            drop(data_peer(listener, &resume_bytes(1, 0), vec![REJECT, 0x03]));
        });
        let mut data = DataConn::open(&control, &endpoint, "session:1", "block:1").unwrap();
        assert!(data.read().is_err());
        let error = data.resume(&endpoint).unwrap_err();
        assert!(format!("{error:#}").contains("different nonce"), "{error:#}");
        let error = data.resume(&endpoint).unwrap_err();
        assert!(format!("{error:#}").contains("not available"), "{error:#}");
        server.join().unwrap();
    }

    #[test]
    fn a_server_close_is_reported_by_status() {
        let (control, endpoint, server) = serve(|listener| {
            let mut peer = data_peer(listener, &hello_bytes(), welcome_bytes(1, 60_000, 42));
            peer.close(Some(CloseFrame { code: CloseCode::Again, reason: "data reconnect required".into() })).unwrap();
            while peer.read().is_ok() {}
        });
        let mut data = DataConn::open(&control, &endpoint, "session:1", "block:1").unwrap();
        let error = data.read().unwrap_err();
        let closed = error.downcast_ref::<DataClosed>().expect("a DataClosed");
        assert_eq!(closed, &DataClosed { code: 1013, reason: "data reconnect required".into() });
        server.join().unwrap();
    }

    #[test]
    fn a_stop_ends_a_blocked_read_with_a_close_frame() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (control, endpoint, server) = serve(move |listener| {
            let mut peer = data_peer(listener, &hello_bytes(), welcome_bytes(1, 60_000, 42));
            let code = loop {
                match peer.read() {
                    Ok(Message::Close(frame)) => break frame.map(|f| f.code),
                    Ok(_) => continue,
                    Err(e) => panic!("no close frame: {e}"),
                }
            };
            tx.send(code).unwrap();
        });
        let mut data = DataConn::open(&control, &endpoint, "session:1", "block:1").unwrap();
        let stop = data.stopper();
        let reader = thread::spawn(move || {
            let started = Instant::now();
            let result = data.read().unwrap();
            (result, started.elapsed())
        });
        thread::sleep(Duration::from_millis(100));
        stop.stop();
        let (result, waited) = reader.join().unwrap();
        assert_eq!(result, None);
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(CloseCode::Normal));
        server.join().unwrap();
    }

    /// Against the real local server: makes its own disposable session,
    /// reads the start of its shell's stream, and destroys the session.
    #[test]
    #[ignore]
    fn live_terminal_stream_starts_with_a_snapshot() {
        const T: Duration = Duration::from_secs(10);
        struct Destroy<'a>(&'a Control, String);
        impl Drop for Destroy<'_> {
            fn drop(&mut self) {
                let session = json!({"session_id": self.1});
                let _ = self.0.call("session.attach", session.clone(), T);
                let destroyed = self.0.call("session.destroy", session, T);
                assert!(destroyed.is_ok() || std::thread::panicking(), "{destroyed:?}");
            }
        }
        let endpoint = Endpoint::discover(None).unwrap();
        let control = Control::connect(&endpoint, "herdr-rex-test").unwrap();
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        let label = format!("herdr-rex-test-{}-{nanos:08x}", std::process::id());
        let created = control
            .call(
                "session.create",
                json!({"label": label, "initial_windows": [{"layout": {"block": {"flavor": "com.superlogical.terminal.shell"}}}]}),
                T,
            )
            .unwrap();
        let session = created["session_id"].as_str().unwrap().to_owned();
        let _destroy = Destroy(&control, session.clone());
        let block = created["initial_windows"][0]["block_ids"][0].as_str().unwrap().to_owned();
        control.call("session.attach", json!({"session_id": session}), T).unwrap();
        let mut data = DataConn::open(&control, &endpoint, &session, &block).unwrap();
        assert_ne!(data.nonce(), 0);
        let mut got = Vec::new();
        while got.len() < 8 {
            got.extend(data.read().unwrap().expect("the stream ended early"));
        }
        assert_eq!(&got[..8], b"GHOSTSNP");
        assert_eq!(data.received, got.len() as u64);
        data.close();
        assert_eq!(data.read().unwrap(), None);
    }
}
