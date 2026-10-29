//! The Rex control connection: a WebSocket at `/api/control` (subprotocol
//! `rex.control.v1`) carrying method calls and events. See docs/rex.md.
//!
//! One IO thread owns the socket. Callers on any thread queue requests through
//! a channel (in the order they called) and wait for their own response; the
//! IO thread writes queued requests, reads whatever the server sent without
//! blocking, routes responses by id and hands every event to `events()`.

use anyhow::{Context, Result, anyhow, bail, ensure};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tungstenite::client::{IntoClientRequest, client_with_config};
use tungstenite::http::HeaderValue;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::{HandshakeError, Message, WebSocket};
use url::{Host, Url};

/// The control API revision this client speaks (and requires).
pub const API_REVISION: u64 = 7;
/// Our own message limit; the connection uses the smaller of this and the server's.
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
/// A hello must stay under 512 bytes (it can carry a reconnect token).
const MAX_HELLO_BYTES: usize = 511;
const MAX_LABEL_BYTES: usize = 128;
/// How long the IO thread waits between reads: short while calls are waiting
/// or messages are flowing, backing off to `POLL_IDLE` when nothing happens.
const POLL_BUSY: Duration = Duration::from_millis(1);
const POLL_IDLE: Duration = Duration::from_millis(16);
/// Ping after this much silence; give up after `DEAD_AFTER` of it.
const PING_AFTER: Duration = Duration::from_secs(120);
const DEAD_AFTER: Duration = Duration::from_secs(300);
/// How long a dropped `Control` spends saying goodbye.
const CLOSE_GRACE: Duration = Duration::from_millis(500);

/// Where the Rex server listens.
#[derive(Clone, Debug, PartialEq)]
pub struct Endpoint {
    /// `unix:///path/server.sock`, `ws://host:port` or `wss://host:port`.
    pub origin: String,
}

impl Endpoint {
    /// `configured` (settings.json `rex_server`: a socket path or origin), else
    /// `REX_SERVER`, else `$XDG_RUNTIME_DIR/rex/server.sock`
    /// (`/run/user/<uid>/rex/server.sock` without it). An empty value counts as
    /// unset; a malformed one is an error rather than a silent fallback.
    pub fn discover(configured: Option<&str>) -> Result<Endpoint> {
        discover_from(
            configured,
            std::env::var("REX_SERVER").ok().as_deref(),
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            current_uid(),
        )
    }

    /// A socket path (`/run/user/1000/rex/server.sock`) or an origin
    /// (`unix:///…`, `ws://`, `wss://`, `http://`, `https://`), normalized to
    /// `unix:///…`, `ws://host[:port]` or `wss://host[:port]`. Rejects
    /// credentials, queries, fragments and paths: the server decides who may
    /// connect, and the API paths are fixed.
    pub fn parse(value: &str) -> Result<Endpoint> {
        let value = value.trim();
        ensure!(!value.is_empty(), "the Rex server address is empty");
        ensure!(value.len() <= 4096, "the Rex server address is longer than 4096 bytes");
        ensure!(!value.chars().any(char::is_control), "the Rex server address has control characters");
        if value.starts_with('/') {
            return Ok(Endpoint { origin: format!("unix://{value}") });
        }
        if let Some(path) = value.strip_prefix("unix://") {
            ensure!(path.starts_with('/'), "a Rex socket path must be absolute: {value}");
            return Ok(Endpoint { origin: format!("unix://{path}") });
        }
        let mut url = Url::parse(value).with_context(|| format!("not a Rex server address: {value}"))?;
        ensure!(
            matches!(url.scheme(), "http" | "https" | "ws" | "wss"),
            "a Rex server address is a socket path or a unix://, ws://, wss://, http:// or https:// origin"
        );
        ensure!(url.host().is_some(), "the Rex server address has no host");
        ensure!(
            url.username().is_empty() && url.password().is_none(),
            "the Rex server address must not contain credentials; the server authorizes connections itself"
        );
        ensure!(url.query().is_none() && url.fragment().is_none(), "the Rex server address must not have a query or fragment");
        ensure!(matches!(url.path(), "" | "/"), "the Rex server address must be an origin, without a path");
        let scheme = if matches!(url.scheme(), "https" | "wss") { "wss" } else { "ws" };
        url.set_scheme(scheme).map_err(|()| anyhow!("bad Rex server address scheme"))?;
        Ok(Endpoint { origin: url.origin().ascii_serialization() })
    }

    /// The WebSocket URL of one of the fixed API paths.
    fn websocket_url(&self, path: &str) -> Result<String> {
        ensure!(matches!(path, "/api/control" | "/api/data"), "not a Rex WebSocket path: {path}");
        Ok(if self.origin.starts_with("unix://") {
            // Over a Unix socket the host only names the Host header.
            format!("ws://rex{path}")
        } else {
            format!("{}{path}", self.origin)
        })
    }

    /// Opens the transport, bounded by `timeout` (DNS, connect, TLS).
    fn connect_stream(&self, timeout: Duration) -> Result<RexStream> {
        let deadline = Instant::now() + timeout;
        if let Some(path) = self.origin.strip_prefix("unix://") {
            #[cfg(unix)]
            {
                let stream = UnixStream::connect(path).with_context(|| format!("cannot connect to the Rex server at {path}"))?;
                let stream = RexStream::Unix(stream);
                stream.set_read_timeout(Some(remaining(deadline)?))?;
                stream.set_write_timeout(Some(remaining(deadline)?))?;
                return Ok(stream);
            }
            #[cfg(not(unix))]
            bail!("Unix sockets are not supported here: {path}");
        }
        let url = Url::parse(&self.origin).context("bad Rex server address")?;
        let port = url.port_or_known_default().context("the Rex server address has no port")?;
        let host = url.host().context("the Rex server address has no host")?;
        let addresses = match &host {
            Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(*ip), port)],
            Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(*ip), port)],
            Host::Domain(name) => resolve(name, port, deadline)?,
        };
        let tcp = connect_tcp(addresses, deadline)?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(remaining(deadline)?))?;
        tcp.set_write_timeout(Some(remaining(deadline)?))?;
        if url.scheme() != "wss" {
            return Ok(RexStream::Tcp(tcp));
        }
        let name = match host {
            Host::Domain(name) => name.to_owned(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        let name = ServerName::try_from(name).context("bad Rex TLS server name")?;
        let mut tls = StreamOwned::new(ClientConnection::new(tls_config()?, name)?, tcp);
        while tls.conn.is_handshaking() {
            tls.sock.set_read_timeout(Some(remaining(deadline)?))?;
            tls.sock.set_write_timeout(Some(remaining(deadline)?))?;
            tls.conn
                .complete_io(&mut tls.sock)
                .context("Rex TLS handshake (is the certificate trusted and for this host?)")?;
        }
        let stream = RexStream::Tls(Box::new(tls));
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        Ok(stream)
    }
}

fn discover_from(configured: Option<&str>, env: Option<&str>, runtime_dir: Option<PathBuf>, uid: Option<u32>) -> Result<Endpoint> {
    fn set(value: Option<&str>) -> Option<&str> {
        value.map(str::trim).filter(|value| !value.is_empty())
    }
    if let Some(value) = set(configured) {
        return Endpoint::parse(value).context("settings.json rex_server");
    }
    if let Some(value) = set(env) {
        return Endpoint::parse(value).context("REX_SERVER");
    }
    let runtime = match runtime_dir.filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) => {
            ensure!(dir.is_absolute(), "XDG_RUNTIME_DIR must be an absolute path");
            dir
        }
        None => PathBuf::from(format!("/run/user/{}", uid.context("cannot find the Rex server: no XDG_RUNTIME_DIR")?)),
    };
    let path = runtime.join("rex").join("server.sock");
    let path = path.to_str().context("the Rex socket path is not UTF-8")?;
    Endpoint::parse(path)
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    unsafe extern "C" {
        safe fn geteuid() -> u32;
    }
    Some(geteuid())
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    ensure!(!left.is_zero(), "timed out connecting to the Rex server");
    Ok(left)
}

/// System DNS can take longer than its caller allows. Lookups run on one worker
/// so a stuck resolver costs one thread, not one per attempt.
fn resolve(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>> {
    type Lookup = (String, u16, mpsc::SyncSender<io::Result<Vec<SocketAddr>>>);
    static RESOLVER: OnceLock<Mutex<mpsc::SyncSender<Lookup>>> = OnceLock::new();
    let resolver = RESOLVER.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<Lookup>(4);
        let _ = std::thread::Builder::new().name("rex-dns".into()).spawn(move || {
            while let Ok((host, port, reply)) = rx.recv() {
                let _ = reply.try_send((host.as_str(), port).to_socket_addrs().map(|a| a.take(32).collect()));
            }
        });
        Mutex::new(tx)
    });
    let (tx, rx) = mpsc::sync_channel(1);
    resolver
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .try_send((host.to_owned(), port, tx))
        .map_err(|_| anyhow!("the DNS resolver is busy; try again"))?;
    rx.recv_timeout(remaining(deadline)?)
        .map_err(|_| anyhow!("timed out resolving {host}"))?
        .with_context(|| format!("cannot resolve {host}"))
}

fn connect_tcp(addresses: Vec<SocketAddr>, deadline: Instant) -> Result<TcpStream> {
    let mut failure = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, remaining(deadline)?) {
            Ok(stream) => return Ok(stream),
            Err(error) => failure = Some(error),
        }
    }
    match failure {
        Some(error) => Err(error).context("cannot connect to the Rex server"),
        None => bail!("the Rex server's host has no addresses"),
    }
}

/// Verifies against the system's roots, loaded once.
fn tls_config() -> Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<std::result::Result<Arc<ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let native = rustls_native_certs::load_native_certs();
            let mut roots = RootCertStore::empty();
            let (accepted, _) = roots.add_parsable_certificates(native.certs);
            if accepted == 0 {
                return Err("no usable system CA certificates for Rex TLS".into());
            }
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map(|builder| Arc::new(builder.with_root_certificates(roots).with_no_client_auth()))
                .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(|e| anyhow!(e))
}

/// The socket under a Rex WebSocket.
pub(crate) enum RexStream {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl RexStream {
    fn tcp(&self) -> Option<&TcpStream> {
        match self {
            #[cfg(unix)]
            RexStream::Unix(_) => None,
            RexStream::Tcp(s) => Some(s),
            RexStream::Tls(s) => Some(&s.sock),
        }
    }

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            RexStream::Unix(s) => s.set_read_timeout(timeout),
            _ => self.tcp().map_or(Ok(()), |s| s.set_read_timeout(timeout)),
        }
    }

    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            RexStream::Unix(s) => s.set_write_timeout(timeout),
            _ => self.tcp().map_or(Ok(()), |s| s.set_write_timeout(timeout)),
        }
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            RexStream::Unix(s) => s.set_nonblocking(nonblocking),
            _ => self.tcp().map_or(Ok(()), |s| s.set_nonblocking(nonblocking)),
        }
    }

    /// Hangs up without a close frame.
    pub(crate) fn shutdown(&self) {
        let _ = match self {
            #[cfg(unix)]
            RexStream::Unix(s) => s.shutdown(Shutdown::Both),
            _ => self.tcp().map_or(Ok(()), |s| s.shutdown(Shutdown::Both)),
        };
    }
}

impl Read for RexStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            RexStream::Unix(s) => s.read(buf),
            RexStream::Tcp(s) => s.read(buf),
            RexStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for RexStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            RexStream::Unix(s) => s.write(buf),
            RexStream::Tcp(s) => s.write(buf),
            RexStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            RexStream::Unix(s) => s.flush(),
            RexStream::Tcp(s) => s.flush(),
            RexStream::Tls(s) => s.flush(),
        }
    }
}

/// Opens an uncompressed WebSocket on one of the fixed API paths, checking the
/// server agreed to `subprotocol`. The socket is blocking, with the handshake
/// timeout still set on it.
pub(crate) fn open_websocket(endpoint: &Endpoint, path: &str, subprotocol: &str, max_message: usize) -> Result<WebSocket<RexStream>> {
    let url = endpoint.websocket_url(path)?;
    let stream = endpoint.connect_stream(HANDSHAKE_TIMEOUT)?;
    let mut request = url.into_client_request()?;
    request.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_str(subprotocol)?);
    let config = WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(0)
        .max_write_buffer_size(16 * MAX_MESSAGE_BYTES)
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message));
    let (socket, response) = client_with_config(request, stream, Some(config)).map_err(|error| match error {
        HandshakeError::Failure(tungstenite::Error::Http(response)) => {
            let status = response.status();
            if matches!(status.as_u16(), 401 | 403) {
                anyhow!("the Rex server refused this connection (HTTP {status})")
            } else {
                anyhow!("the Rex server rejected the WebSocket upgrade (HTTP {status})")
            }
        }
        HandshakeError::Interrupted(_) => anyhow!("timed out opening the Rex WebSocket"),
        HandshakeError::Failure(error) => anyhow!("Rex WebSocket handshake: {error}"),
    })?;
    ensure!(
        response.headers().get("Sec-WebSocket-Protocol").and_then(|v| v.to_str().ok()) == Some(subprotocol),
        "the Rex server did not agree to {subprotocol}"
    );
    Ok(socket)
}

/// A Rex API error: its `code` (e.g. `conflict`, `not_found`) and message.
#[derive(Clone, Debug, PartialEq)]
pub struct RexError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for RexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}
impl std::error::Error for RexError {}

/// One server or session event, as the server sent it.
#[derive(Clone, Debug)]
pub struct Event {
    /// Its type, such as `session_view_changed`. A `session_event` is named by
    /// the event it wraps (see `session_id`); every other event by its own
    /// type (`session_created`, `client_perform_requested`, …).
    pub kind: String,
    /// The whole event message.
    pub message: Value,
}

impl Event {
    pub(crate) fn from_message(message: Value) -> Event {
        let outer = &message["payload"];
        let kind = match outer["type"].as_str() {
            Some("session_event") => outer["payload"]["event"]["type"].as_str(),
            other => other,
        }
        .unwrap_or_default()
        .to_owned();
        Event { kind, message }
    }

    /// The session a `session_event` came from.
    pub fn session_id(&self) -> Option<&str> {
        let outer = &self.message["payload"];
        if outer["type"] == "session_event" { outer["payload"]["session_id"].as_str() } else { None }
    }

    /// The event's own fields (unwrapping a `session_event`).
    pub fn body(&self) -> &Value {
        let outer = &self.message["payload"];
        if outer["type"] == "session_event" { &outer["payload"]["event"]["payload"] } else { &outer["payload"] }
    }
}

enum Failure {
    Rex(RexError),
    Lost,
}

type Reply = std::result::Result<(u64, Value), Failure>;

#[derive(Default)]
struct Routes {
    replies: HashMap<u64, mpsc::Sender<Reply>>,
    /// Set (under the lock) once the IO thread stops: no new calls get routed.
    closed: bool,
}

pub struct Control {
    routes: Arc<Mutex<Routes>>,
    next_id: AtomicU64,
    /// Requests for the IO thread. Dropping it (`close`, or with `Control`)
    /// closes the socket.
    outgoing: Mutex<Option<mpsc::Sender<String>>>,
    message_limit: usize,
    events: async_channel::Receiver<Event>,
    lost: async_channel::Receiver<()>,
}

impl Control {
    /// Opens the connection and says hello as `client_label` (API revision 7).
    pub fn connect(endpoint: &Endpoint, client_label: &str) -> Result<Arc<Control>> {
        Control::connect_resuming(endpoint, client_label, None)
    }

    /// Like `connect`, continuing the client of an earlier connection when
    /// `reconnect_token` (from its welcome) is still good (the welcome says whether it was).
    pub fn connect_resuming(endpoint: &Endpoint, client_label: &str, reconnect_token: Option<&str>) -> Result<Arc<Control>> {
        let mut socket = open_websocket(endpoint, "/api/control", "rex.control.v1", MAX_MESSAGE_BYTES)?;
        socket.send(Message::text(hello(client_label, reconnect_token))).context("cannot send the Rex hello")?;
        let welcome = read_welcome(&mut socket)?;
        let limit = welcome["limits"]["max_message_bytes"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|&n| n > 0)
            .unwrap_or(MAX_MESSAGE_BYTES)
            .min(MAX_MESSAGE_BYTES);
        socket.set_config(|config| {
            config.max_message_size = Some(limit);
            config.max_frame_size = Some(limit);
        });
        socket.get_ref().set_read_timeout(None)?;
        socket.get_ref().set_write_timeout(None)?;
        socket.get_ref().set_nonblocking(true)?;

        let routes = Arc::new(Mutex::new(Routes::default()));
        let (outgoing, requests) = mpsc::channel::<String>();
        let (events_tx, events) = async_channel::unbounded();
        let (lost_tx, lost) = async_channel::bounded::<()>(1);
        let io_routes = routes.clone();
        std::thread::Builder::new().name("rex-control".into()).spawn(move || {
            let _lost_tx = lost_tx;
            match io_loop(&mut socket, &requests, &io_routes, &events_tx) {
                Ok(()) => tracing::debug!("Rex control connection closed"),
                Err(error) => tracing::warn!("Rex control connection lost: {error:#}"),
            }
            socket.get_ref().shutdown();
            let mut routes = io_routes.lock().unwrap_or_else(|e| e.into_inner());
            routes.closed = true;
            for (_, reply) in routes.replies.drain() {
                let _ = reply.send(Err(Failure::Lost));
            }
        })?;
        Ok(Arc::new(Control { routes, next_id: AtomicU64::new(1), outgoing: Mutex::new(Some(outgoing)), message_limit: limit, events, lost }))
    }

    /// Calls a method and waits for its result. Safe from any thread; calls
    /// reach the server in the order they were made. A Rex error comes back as
    /// a `RexError` (downcast it from the anyhow error).
    pub fn call(&self, method: &str, payload: Value, timeout: Duration) -> Result<Value> {
        self.call_seq(method, payload, timeout).map(|(_, payload)| payload)
    }

    /// `call`, also returning the response's `seq`: the last event the server
    /// had queued for this connection when it started the request. Events with
    /// a `seq` at or below it are already part of the result.
    pub fn call_seq(&self, method: &str, payload: Value, timeout: Duration) -> Result<(u64, Value)> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut request = json!({"type": "request", "id": format!("h{id}"), "method": method});
        if !payload.is_null() {
            request["payload"] = payload;
        }
        let text = request.to_string();
        ensure!(text.len() <= self.message_limit, "{method}: the request is larger than the Rex message limit");
        let (tx, rx) = mpsc::channel();
        {
            // Queue under the routes lock, so calls go out in the order they got
            // here and none slips in after the IO thread gave up.
            let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
            if routes.closed {
                bail!("{method}: lost the Rex server");
            }
            routes.replies.insert(id, tx);
            let sent = self.outgoing.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|o| o.send(text).is_ok());
            if !sent {
                routes.replies.remove(&id);
                bail!("{method}: lost the Rex server");
            }
        }
        match rx.recv_timeout(timeout) {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(Failure::Rex(error))) => Err(anyhow::Error::new(error)),
            Ok(Err(Failure::Lost)) | Err(RecvTimeoutError::Disconnected) => bail!("{method}: lost the Rex server"),
            Err(RecvTimeoutError::Timeout) => {
                self.routes.lock().unwrap_or_else(|e| e.into_inner()).replies.remove(&id);
                bail!("{method}: no reply from the Rex server within {timeout:?}")
            }
        }
    }

    /// Leaves the server now (a close frame; sessions stay), though other
    /// holders of this `Control` remain: calls fail, `events` and `lost` close.
    pub fn close(&self) {
        self.outgoing.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    /// Every event, in order. Meant for one reader. Closes with the connection.
    pub fn events(&self) -> async_channel::Receiver<Event> {
        self.events.clone()
    }

    /// Closes when the connection drops.
    pub fn lost(&self) -> async_channel::Receiver<()> {
        self.lost.clone()
    }

    /// Whether the connection is gone.
    pub fn is_lost(&self) -> bool {
        self.routes.lock().unwrap_or_else(|e| e.into_inner()).closed
    }
}

fn hello(label: &str, reconnect_token: Option<&str>) -> String {
    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else {
        "other"
    };
    let mut end = label.len().min(MAX_LABEL_BYTES);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    let mut hello = json!({
        "type": "hello",
        "api_revision": API_REVISION,
        "api_min_revision": API_REVISION,
        "client": {"kind": "app", "platform": platform, "name": "herdr", "version": env!("CARGO_PKG_VERSION"), "label": &label[..end]},
    });
    if let Some(token) = reconnect_token {
        hello["reconnect_token"] = Value::String(token.to_owned());
    }
    let mut text = hello.to_string();
    if text.len() > MAX_HELLO_BYTES {
        // Only an unusually long token gets here: drop the label, keep the token.
        if let Some(client) = hello["client"].as_object_mut() {
            client.remove("label");
        }
        text = hello.to_string();
    }
    text
}

/// Reads the welcome (the socket still has the handshake timeout set).
fn read_welcome(socket: &mut WebSocket<RexStream>) -> Result<Value> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        ensure!(Instant::now() < deadline, "timed out waiting for the Rex welcome");
        let message = match socket.read() {
            Ok(message) => message,
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                bail!("timed out waiting for the Rex welcome")
            }
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => bail!("the Rex server closed the connection"),
            Err(e) => return Err(e).context("reading the Rex welcome"),
        };
        match message {
            Message::Text(text) => {
                let welcome: Value = serde_json::from_str(&text).context("bad Rex welcome")?;
                ensure!(welcome["type"] == "welcome", "the Rex server sent {} before its welcome", welcome["type"]);
                ensure!(welcome["protocol"] == "rex.control.v1", "the Rex server speaks {}, not rex.control.v1", welcome["protocol"]);
                ensure!(
                    welcome["api_revision"].as_u64() == Some(API_REVISION),
                    "the Rex server chose API revision {} (Herdr needs {API_REVISION})",
                    welcome["api_revision"]
                );
                return Ok(welcome);
            }
            Message::Close(Some(frame)) => bail!("the Rex server refused the connection: {} ({})", frame.reason, u16::from(frame.code)),
            Message::Close(None) => bail!("the Rex server closed the connection"),
            _ => {}
        }
    }
}

fn would_block(error: &tungstenite::Error) -> bool {
    matches!(error, tungstenite::Error::Io(e) if e.kind() == ErrorKind::WouldBlock)
}

/// Runs the connection until the server goes away (`Err`) or `Control` is
/// dropped (`Ok`, after a close frame). The socket is nonblocking: writes that
/// would block stay buffered in tungstenite and are flushed on later turns.
fn io_loop(
    socket: &mut WebSocket<RexStream>,
    requests: &mpsc::Receiver<String>,
    routes: &Mutex<Routes>,
    events: &async_channel::Sender<Event>,
) -> Result<()> {
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut unflushed = false;
    let mut idle = POLL_BUSY;
    let mut heard = Instant::now();
    let mut pinged = false;
    loop {
        let mut active = false;
        // Write what callers queued, in order.
        let mut dropped = false;
        loop {
            match requests.try_recv() {
                Ok(text) => queue.push_back(text),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    dropped = true;
                    break;
                }
            }
        }
        for text in queue.drain(..) {
            active = true;
            unflushed = true;
            match socket.write(Message::text(text)) {
                Ok(()) => {}
                Err(e) if would_block(&e) => {}
                Err(e) => return Err(e).context("writing to the Rex server"),
            }
        }
        if dropped {
            say_goodbye(socket);
            return Ok(());
        }
        if unflushed {
            match socket.flush() {
                Ok(()) => unflushed = false,
                Err(e) if would_block(&e) => {}
                Err(e) => return Err(e).context("writing to the Rex server"),
            }
        }

        // Read everything the server has sent so far.
        loop {
            match socket.read() {
                Ok(message) => {
                    heard = Instant::now();
                    pinged = false;
                    active = true;
                    match message {
                        Message::Text(text) => dispatch(&text, routes, events),
                        Message::Close(Some(frame)) => {
                            bail!("the Rex server closed the connection: {} ({})", frame.reason, u16::from(frame.code))
                        }
                        Message::Close(None) => bail!("the Rex server closed the connection"),
                        // Tungstenite answers pings; nothing else is expected.
                        _ => {}
                    }
                }
                Err(e) if would_block(&e) => break,
                Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => bail!("the Rex server closed the connection"),
                Err(e) => return Err(e).context("reading from the Rex server"),
            }
        }

        let silent = heard.elapsed();
        ensure!(silent < DEAD_AFTER, "the Rex server stopped answering");
        if silent >= PING_AFTER && !pinged {
            pinged = true;
            unflushed = true;
            match socket.write(Message::Ping(Default::default())) {
                Ok(()) => {}
                Err(e) if would_block(&e) => {}
                Err(e) => return Err(e).context("writing to the Rex server"),
            }
        }

        // Wait for a request, or until it is time to read again: soon while
        // calls are waiting or messages flow, backing off when idle.
        let waiting = !routes.lock().unwrap_or_else(|e| e.into_inner()).replies.is_empty();
        idle = if active || waiting || unflushed { POLL_BUSY } else { (idle * 2).min(POLL_IDLE) };
        match requests.recv_timeout(idle) {
            Ok(text) => queue.push_back(text),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                say_goodbye(socket);
                return Ok(());
            }
        }
    }
}

/// Routes one message: a response to its caller, an event to `events`.
/// Anything else (a type a newer server added, a response nobody waits for
/// any more) is skipped.
fn dispatch(text: &str, routes: &Mutex<Routes>, events: &async_channel::Sender<Event>) {
    let Ok(message) = serde_json::from_str::<Value>(text) else {
        tracing::debug!("skipping a Rex message that is not JSON");
        return;
    };
    match message["type"].as_str() {
        Some("response") => {
            let Some(id) = message["id"].as_str().and_then(|id| id.strip_prefix('h')).and_then(|id| id.parse::<u64>().ok()) else {
                return;
            };
            let Some(reply) = routes.lock().unwrap_or_else(|e| e.into_inner()).replies.remove(&id) else {
                return; // its caller timed out
            };
            let seq = message["seq"].as_u64().unwrap_or(0);
            let result = match message.get("error").filter(|e| !e.is_null()) {
                Some(error) => Err(Failure::Rex(RexError {
                    code: error["code"].as_str().unwrap_or("internal").to_owned(),
                    message: error["message"].as_str().unwrap_or("the request failed").to_owned(),
                })),
                None => Ok((seq, message.get("payload").cloned().unwrap_or(Value::Null))),
            };
            let _ = reply.send(result);
        }
        Some("event") => {
            let _ = events.try_send(Event::from_message(message));
        }
        other => tracing::debug!("skipping a Rex message of type {other:?}"),
    }
}

/// Close frame, briefly waiting for the server's: leaving ends this client at
/// once (its sessions stay).
fn say_goodbye(socket: &mut WebSocket<RexStream>) {
    let _ = socket.close(Some(CloseFrame { code: CloseCode::Normal, reason: "".into() }));
    let deadline = Instant::now() + CLOSE_GRACE;
    while Instant::now() < deadline {
        match socket.read() {
            Ok(_) => {}
            Err(e) if would_block(&e) => {
                let _ = socket.flush();
                std::thread::sleep(POLL_BUSY);
            }
            Err(_) => break,
        }
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tungstenite::handshake::server::{Request, Response};

    #[test]
    fn origins_are_normalized_and_suffixes_rejected() {
        for (input, origin) in [
            ("/run/user/1000/rex/server.sock", "unix:///run/user/1000/rex/server.sock"),
            ("unix:///tmp/rex.sock", "unix:///tmp/rex.sock"),
            ("http://localhost:1234", "ws://localhost:1234"),
            ("https://rex.example/", "wss://rex.example"),
            ("ws://127.0.0.1:42", "ws://127.0.0.1:42"),
            ("wss://[::1]:456/", "wss://[::1]:456"),
            ("wss://rex.example:443", "wss://rex.example"),
            ("  /tmp/rex.sock  ", "unix:///tmp/rex.sock"),
        ] {
            assert_eq!(Endpoint::parse(input).unwrap().origin, origin, "{input}");
        }
        for input in [
            "",
            "relative.sock",
            "unix://relative",
            "ftp://example.com",
            "tcp://127.0.0.1:1234",
            "https://user:secret@example.com",
            "https://user@example.com",
            "wss://example.com?token=secret",
            "https://example.com/#secret",
            "http://example.com/api/control",
            "http://example.com/prefix/",
            "https://",
            "https://exa\nmple.com",
        ] {
            assert!(Endpoint::parse(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn websocket_urls_use_the_fixed_paths() {
        let unix = Endpoint::parse("/tmp/rex.sock").unwrap();
        assert_eq!(unix.websocket_url("/api/control").unwrap(), "ws://rex/api/control");
        assert_eq!(unix.websocket_url("/api/data").unwrap(), "ws://rex/api/data");
        let tls = Endpoint::parse("https://rex.example:8443").unwrap();
        assert_eq!(tls.websocket_url("/api/control").unwrap(), "wss://rex.example:8443/api/control");
        assert!(tls.websocket_url("/other").is_err());
    }

    #[test]
    fn discovery_prefers_settings_then_env_then_runtime_dir() {
        let run = Some(PathBuf::from("/run/user/7"));
        assert_eq!(discover_from(Some("/a.sock"), Some("/b.sock"), run.clone(), Some(7)).unwrap().origin, "unix:///a.sock");
        assert_eq!(discover_from(Some("  "), Some("ws://h:1"), run.clone(), Some(7)).unwrap().origin, "ws://h:1");
        assert_eq!(discover_from(None, Some(""), run.clone(), Some(7)).unwrap().origin, "unix:///run/user/7/rex/server.sock");
        assert_eq!(discover_from(None, None, None, Some(1000)).unwrap().origin, "unix:///run/user/1000/rex/server.sock");
        assert_eq!(discover_from(None, None, Some(PathBuf::new()), Some(5)).unwrap().origin, "unix:///run/user/5/rex/server.sock");
        assert!(discover_from(None, None, Some(PathBuf::from("relative")), Some(5)).is_err());
        assert!(discover_from(None, None, None, None).is_err());
        // A bad configured value is an error, not a silent fallback.
        assert!(discover_from(Some("ftp://x"), Some("/b.sock"), run, Some(7)).is_err());
    }

    #[test]
    fn hello_identifies_an_app_and_stays_small() {
        let value: Value = serde_json::from_str(&hello("studio", None)).unwrap();
        assert_eq!(value["type"], "hello");
        assert_eq!(value["api_revision"], 7);
        assert_eq!(value["api_min_revision"], 7);
        assert_eq!(value["client"]["kind"], "app");
        assert_eq!(value["client"]["label"], "studio");
        assert!(value.get("reconnect_token").is_none());
        let text = hello(&"é".repeat(400), Some(&"t".repeat(64)));
        assert!(text.len() <= MAX_HELLO_BYTES, "{}", text.len());
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["reconnect_token"], "t".repeat(64));
    }

    #[test]
    fn events_are_named_by_what_they_wrap() {
        let event = Event::from_message(json!({"type": "event", "seq": 4, "payload": {"type": "session_event", "payload": {
            "session_id": "session:1", "event": {"type": "session_view_changed", "payload": {"revision": 3}}}}}));
        assert_eq!(event.kind, "session_view_changed");
        assert_eq!(event.session_id(), Some("session:1"));
        assert_eq!(event.body()["revision"], 3);
        let event = Event::from_message(json!({"type": "event", "seq": 1, "payload": {"type": "session_created", "payload": {"session": {}}}}));
        assert_eq!(event.kind, "session_created");
        assert_eq!(event.session_id(), None);
        assert!(event.body()["session"].is_object());
    }

    pub(crate) type Peer = WebSocket<UnixStream>;

    static UNIQUE: AtomicU64 = AtomicU64::new(0);

    /// A fresh socket path in a private temporary directory.
    pub(crate) fn socket_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("herdr-rex-test-{}-{}", std::process::id(), UNIQUE.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.sock");
        let _ = std::fs::remove_file(&path);
        path
    }

    pub(crate) fn remove_socket(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir(dir);
        }
    }

    /// Accepts one WebSocket on `path` with `subprotocol`.
    pub(crate) fn accept(listener: &UnixListener, path: &'static str, subprotocol: &'static str) -> Peer {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        #[allow(clippy::result_large_err)]
        tungstenite::accept_hdr(stream, move |request: &Request, mut response: Response| {
            assert_eq!(request.uri().path(), path);
            assert_eq!(request.headers()["Sec-WebSocket-Protocol"], subprotocol);
            response.headers_mut().insert("Sec-WebSocket-Protocol", HeaderValue::from_static(subprotocol));
            Ok(response)
        })
        .unwrap()
    }

    /// A fake Rex server's control side: checks the hello, sends a welcome,
    /// then runs `script`.
    pub(crate) fn control_peer(peer: &mut Peer) {
        let hello: Value = serde_json::from_str(peer.read().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["client"]["label"], "test");
        send(
            peer,
            json!({"type": "welcome", "protocol": "rex.control.v1", "api_revision": 7,
                "limits": {"max_message_bytes": 65536}, "client": {"id": "client:1", "reconnect_token": "secret"}}),
        );
    }

    fn mock(script: impl FnOnce(&mut Peer) + Send + 'static) -> (Arc<Control>, thread::JoinHandle<()>) {
        let path = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let endpoint = Endpoint::parse(path.to_str().unwrap()).unwrap();
        let server = thread::spawn(move || {
            let mut peer = accept(&listener, "/api/control", "rex.control.v1");
            control_peer(&mut peer);
            script(&mut peer);
        });
        let control = Control::connect(&endpoint, "test").unwrap();
        // Connected: the path can go now, even if the server thread never ends.
        remove_socket(&path);
        (control, server)
    }

    pub(crate) fn send(peer: &mut Peer, value: Value) {
        peer.send(Message::text(value.to_string())).unwrap();
    }

    pub(crate) fn request(peer: &mut Peer) -> Value {
        loop {
            if let Message::Text(text) = peer.read().unwrap() {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    pub(crate) fn respond(peer: &mut Peer, request: &Value, seq: u64, payload: Value) {
        send(peer, json!({"type": "response", "id": request["id"], "seq": seq, "payload": payload}));
    }

    const T: Duration = Duration::from_secs(5);

    #[test]
    fn the_message_limit_is_negotiated() {
        let (control, server) = mock(|peer| {
            let r = request(peer);
            respond(peer, &r, 0, json!({}));
        });
        let error = control.call("x", json!({"text": "x".repeat(70_000)}), T).unwrap_err();
        assert!(error.to_string().contains("message limit"), "{error}");
        assert_eq!(control.call("ok", Value::Null, T).unwrap(), json!({}));
        server.join().unwrap();
    }

    #[test]
    fn concurrent_callers_get_their_own_responses() {
        const N: usize = 16;
        let (control, server) = mock(|peer| {
            let mut requests: Vec<Value> = (0..N).map(|_| request(peer)).collect();
            // Answer in reverse order, with an unknown message type in between.
            requests.reverse();
            for (i, r) in requests.iter().enumerate() {
                send(peer, json!({"type": "mystery", "id": r["id"]}));
                respond(peer, r, i as u64, json!({"echo": r["payload"]["n"], "method": r["method"]}));
            }
        });
        let handles: Vec<_> = (0..N)
            .map(|n| {
                let control = control.clone();
                thread::spawn(move || {
                    let reply = control.call(&format!("m{n}"), json!({"n": n}), T).unwrap();
                    assert_eq!(reply["echo"], n);
                    assert_eq!(reply["method"], format!("m{n}"));
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        server.join().unwrap();
    }

    #[test]
    fn requests_go_out_in_call_order() {
        let (control, server) = mock(|peer| {
            // All 50 arrive before any response: they were pipelined, in order.
            let requests: Vec<Value> = (0..50).map(|_| request(peer)).collect();
            for (n, r) in requests.iter().enumerate() {
                assert_eq!(r["method"], format!("m{n}"));
                if n % 2 == 0 {
                    assert!(r.get("payload").is_none());
                } else {
                    assert_eq!(r["payload"]["n"], n);
                }
            }
            for r in &requests {
                respond(peer, r, 0, r["method"].clone());
            }
        });
        // Each thread starts only once the previous call is queued (its id
        // taken and its route registered), so call order is well defined.
        let mut handles = Vec::new();
        for n in 0..50u64 {
            let caller = control.clone();
            handles.push(thread::spawn(move || {
                let control = caller;
                let payload = if n % 2 == 0 { Value::Null } else { json!({"n": n}) };
                assert_eq!(control.call(&format!("m{n}"), payload, T).unwrap(), format!("m{n}"));
            }));
            let deadline = Instant::now() + T;
            while control.routes.lock().unwrap().replies.len() < (n + 1) as usize {
                assert!(Instant::now() < deadline);
                thread::yield_now();
            }
        }
        for handle in handles {
            handle.join().unwrap();
        }
        server.join().unwrap();
    }

    #[test]
    fn events_before_a_response_arrive_in_order_with_seq() {
        let (control, server) = mock(|peer| {
            let r = request(peer);
            assert_eq!(r["method"], "session.bootstrap");
            for seq in 1..=3 {
                send(
                    peer,
                    json!({"type": "event", "seq": seq, "payload": {"type": "session_event", "payload": {
                        "session_id": "session:a", "event": {"type": "session_view_changed", "payload": {"revision": seq}}}}}),
                );
            }
            respond(peer, &r, 2, json!({"sessions": []}));
            send(peer, json!({"type": "event", "seq": 4, "payload": {"type": "session_created", "payload": {}}}));
        });
        let events = control.events();
        let (seq, result) = control.call_seq("session.bootstrap", json!({}), T).unwrap();
        assert_eq!((seq, result), (2, json!({"sessions": []})));
        server.join().unwrap();
        let mut got = Vec::new();
        // The events channel closes with the connection.
        while let Ok(event) = events.recv_blocking() {
            got.push((event.message["seq"].as_u64().unwrap(), event.kind));
        }
        let kinds = ["session_view_changed", "session_view_changed", "session_view_changed", "session_created"];
        assert_eq!(got, (1..=4).zip(kinds.map(String::from)).collect::<Vec<_>>());
    }

    #[test]
    fn a_remote_error_leaves_the_connection_usable() {
        let (control, server) = mock(|peer| {
            let r = request(peer);
            send(
                peer,
                json!({"type": "response", "id": r["id"], "seq": 0, "error": {"code": "not_found", "message": "block not found", "status": 404}}),
            );
            peer.send(Message::Ping(Default::default())).unwrap();
            peer.send(Message::binary(vec![1, 2, 3])).unwrap();
            send(peer, json!("not an object"));
            send(peer, json!({"type": "response", "id": "someone-else", "seq": 0}));
            let r = request(peer);
            respond(peer, &r, 0, json!({"ok": true}));
        });
        let error = control.call("block.close", json!({}), T).unwrap_err();
        let rex = error.downcast_ref::<RexError>().expect("a RexError");
        assert_eq!(rex, &RexError { code: "not_found".into(), message: "block not found".into() });
        assert_eq!(control.call("server.status", Value::Null, T).unwrap()["ok"], true);
        server.join().unwrap();
    }

    #[test]
    fn a_timeout_forgets_the_call_and_a_late_response_is_ignored() {
        let (control, server) = mock(|peer| {
            let slow = request(peer);
            let fast = request(peer);
            respond(peer, &slow, 0, json!({"late": true}));
            respond(peer, &fast, 0, json!({"fast": true}));
        });
        let error = control.call("slow", Value::Null, Duration::from_millis(100)).unwrap_err();
        assert!(error.to_string().contains("no reply"), "{error}");
        assert_eq!(control.call("fast", Value::Null, T).unwrap()["fast"], true);
        assert!(control.routes.lock().unwrap().replies.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn calls_fail_fast_once_the_server_is_gone() {
        let (control, server) = mock(|peer| {
            let _unanswered = request(peer);
            // Hang up without a close frame.
        });
        let lost = control.lost();
        let started = Instant::now();
        let error = control.call("never", Value::Null, Duration::from_secs(30)).unwrap_err();
        assert!(error.to_string().contains("lost the Rex server"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
        server.join().unwrap();
        assert!(lost.recv_blocking().is_err());
        assert!(control.is_lost());
        let started = Instant::now();
        assert!(control.call("after", Value::Null, T).unwrap_err().to_string().contains("lost the Rex server"));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn dropping_control_sends_a_close_frame() {
        let (tx, rx) = mpsc::channel();
        let (control, server) = mock(move |peer| {
            let code = loop {
                match peer.read() {
                    Ok(Message::Close(frame)) => break frame.map(|f| f.code),
                    Ok(_) => continue,
                    Err(e) => panic!("no close frame: {e}"),
                }
            };
            tx.send(code).unwrap();
        });
        let lost = control.lost();
        drop(control);
        assert_eq!(rx.recv_timeout(T).unwrap(), Some(CloseCode::Normal));
        server.join().unwrap();
        assert!(lost.recv_blocking().is_err());
    }

    #[test]
    fn a_wrong_api_revision_is_refused() {
        let path = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let endpoint = Endpoint::parse(path.to_str().unwrap()).unwrap();
        let server = thread::spawn(move || {
            let mut peer = accept(&listener, "/api/control", "rex.control.v1");
            let _hello = peer.read().unwrap();
            send(&mut peer, json!({"type": "welcome", "protocol": "rex.control.v1", "api_revision": 6, "limits": {"max_message_bytes": 65536}}));
            let _ = peer.read();
            remove_socket(&path);
        });
        let error = Control::connect(&endpoint, "test").err().unwrap();
        assert!(error.to_string().contains("API revision"), "{error}");
        server.join().unwrap();
    }

    /// Against the real local server: read-only calls only.
    #[test]
    #[ignore]
    fn live_read_only_calls() {
        let endpoint = Endpoint::discover(None).unwrap();
        let control = Control::connect(&endpoint, "herdr-rex-test").unwrap();
        let version = control.call("server.version", Value::Null, T).unwrap();
        assert!(version["rex_version"].is_string(), "{version}");
        let sessions = control.call("session.list", Value::Null, T).unwrap();
        assert!(sessions.is_object(), "{sessions}");
        let error = control.call("no.such.method", Value::Null, T).unwrap_err();
        assert!(error.downcast_ref::<RexError>().is_some(), "{error:#}");
        assert!(control.call("server.version", Value::Null, T).is_ok());
    }
}
