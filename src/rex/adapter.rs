//! herdr-core's API, answered by a Rex server: the `hc::Link` for Rex.
//!
//! Rex owns sessions, windows and blocks. The layout document Herdr reads is
//! projected from the session views (`project::project`), and a document Herdr
//! writes becomes Rex calls (`project::plan`), one at a time, until the views
//! match it. Terminals keep the addresses Herdr knows them by: a block's id,
//! or the address `terminal.run` handed out before Rex made the block.

use super::data::{DataClosed, DataConn, DataStop};
use super::project::{self, Aliases, Bind, Pending, SpaceExtra, Step};
use super::stream::{Decoder, Piece};
use super::transport::{Control, Endpoint, Event, RexError};
use crate::hc::{self, Attached, Core, Kind, Link, RpcError, Stream};
use anyhow::{Context as _, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

const TERMINAL: &str = "com.superlogical.terminal";
const SHELL: &str = "com.superlogical.terminal.shell";
const CALL: Duration = Duration::from_secs(8);
/// How long an attach waits for a new terminal's document to place it before
/// Rex makes it detached.
const PLACE_WAIT: Duration = Duration::from_secs(2);
/// Steps one document write may take before it gives up.
const MAX_STEPS: usize = 64;

pub fn connect() -> Result<Arc<Core>> {
    let endpoint = Endpoint::discover(crate::settings::rex_server().as_deref())?;
    connect_to(endpoint, crate::mods::app_dir().join("rex.json"))
}

/// Connects to `endpoint`, keeping Herdr's own ids for Rex's in `saved`.
pub fn connect_to(endpoint: Endpoint, saved: std::path::PathBuf) -> Result<Arc<Core>> {
    let control = Control::connect(&endpoint, "Herdr").with_context(|| format!("cannot reach the Rex server at {}", endpoint.origin))?;
    let version = control.call("server.version", json!({}), CALL).unwrap_or(Value::Null);
    let link = RexLink::start(control, endpoint, saved)?;
    link.hosts.clone().watch(link.home.clone());
    // Herdr checks a core's generation, version and methods: Rex serves all of them.
    let hello = json!({
        "generation": hc::GENERATION,
        "version": hc::core_min(),
        "methods": hc::USES,
        "features": [],
        "backend": "rex",
        "rex": version,
    });
    Ok(Arc::new(Core::new(hello, Kind::Rex, Box::new(link))))
}

fn rpc(kind: &str, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(RpcError(json!({ "message": message.into(), "data": { "kind": kind } })))
}

/// A Rex failure in herdr-core's words, so the window reacts as it does to the core's.
fn translate(method: &str, e: &anyhow::Error) -> anyhow::Error {
    let kind = match e.downcast_ref::<RexError>().map(|r| r.code.as_str()) {
        Some("not_found" | "session_not_found") => "not_found",
        Some("conflict") => "conflict",
        Some(_) => "failed",
        None => "unavailable",
    };
    rpc(kind, format!("{method}: {e:#}"))
}

fn now_ms() -> u64 {
    crate::model::now_ms()
}

/// A terminal `terminal.run` asked for, before Rex has a block for it.
struct PendingRun {
    spec: Pending,
    labels: Map<String, Value>,
}

/// What Herdr remembers about Rex between runs: its own ids for Rex's, and
/// what Rex doesn't keep about a space.
#[derive(Default, Serialize, Deserialize)]
struct Saved {
    #[serde(default)]
    aliases: BTreeMap<String, String>,
    #[serde(default)]
    extras: BTreeMap<String, SpaceExtra>,
}

/// One event stream for Herdr: every server's events, in one seq order.
#[derive(Default)]
struct Hub {
    subscribers: Vec<async_channel::Sender<Stream>>,
    seq: u64,
}

#[derive(Default)]
struct State {
    /// Sessions in `session.list` order, and their latest views.
    order: Vec<String>,
    views: HashMap<String, Value>,
    /// The layout document as last projected, and its version: goes up only
    /// when the document changes (a stale version makes Herdr drop its edit).
    doc: Value,
    version: u64,
    aliases: Aliases,
    extras: BTreeMap<String, SpaceExtra>,
    /// Terminal records as herdr-core shapes them: by block id, or by
    /// address while pending.
    terminals: BTreeMap<String, Value>,
    /// The session each block is in.
    sessions: HashMap<String, String>,
    pending: BTreeMap<String, PendingRun>,
    placeholders: Vec<String>,
    /// The event stream to Herdr, shared by every server.
    hub: Arc<Mutex<Hub>>,
    /// The machine name Herdr knows this server by (a Rex host's label);
    /// empty for the home server. Addresses Herdr sees are `<prefix>/<address>`.
    prefix: String,
    next_pending: u64,
    channels: HashMap<u32, Channel>,
}

struct Channel {
    session: String,
    block: String,
    stop: Arc<AtomicBool>,
    /// Ends a read blocked in the stream's thread, once it has a connection.
    stopper: Arc<Mutex<Option<DataStop>>>,
}

/// Calls the UI makes without waiting: in order, on their own thread.
enum Input {
    Write { session: String, block: String, data: String },
    Resize { session: String, block: String, cols: u16, rows: u16 },
    Focus { session: String, block: String },
}

struct Inner {
    control: Arc<Control>,
    endpoint: Endpoint,
    /// Where `Saved` lives (`rex.json` in the app's folder).
    saved: std::path::PathBuf,
    state: Mutex<State>,
    /// Signalled when a pending terminal gets its block.
    placed: Condvar,
    /// One document write at a time.
    writing: Mutex<()>,
    inputs: Mutex<mpsc::Sender<Input>>,
}

pub struct RexLink {
    home: Arc<Inner>,
    hosts: Arc<Hosts>,
    hub: Arc<Mutex<Hub>>,
    next_channel: AtomicU32,
    /// The server behind each attached channel.
    routes: Mutex<HashMap<u32, Arc<Inner>>>,
}

impl RexLink {
    fn start(control: Arc<Control>, endpoint: Endpoint, saved: std::path::PathBuf) -> Result<RexLink> {
        let hub = Arc::new(Mutex::new(Hub::default()));
        let home = Inner::open(control, endpoint, saved.clone(), hub.clone(), String::new())?;
        let home_host = home.call("server.status", json!({})).ok().and_then(|s| s["host_id"].as_str().map(str::to_owned));
        let dir = saved.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
        let hosts = Arc::new(Hosts { slots: Mutex::new(BTreeMap::new()), home_host, dir, hub: hub.clone(), stop: AtomicBool::new(false) });
        Ok(RexLink { home, hosts, hub, next_channel: AtomicU32::new(1), routes: Mutex::new(HashMap::new()) })
    }

    /// The server a call's `on` names (a Rex host's label), else the home one.
    fn on(&self, params: &Value) -> Result<Arc<Inner>> {
        match params["on"].as_str().filter(|m| !m.is_empty()) {
            Some(machine) => self.hosts.inner(machine),
            None => Ok(self.home.clone()),
        }
    }

    /// The server an address Herdr uses is on, and the address there.
    fn route<'a>(&self, address: &'a str) -> Result<(Arc<Inner>, &'a str)> {
        match address.split_once('/') {
            Some((machine, local)) => Ok((self.hosts.inner(machine)?, local)),
            None => Ok((self.home.clone(), address)),
        }
    }

    /// Every connected server: home first.
    fn servers(&self) -> Vec<Arc<Inner>> {
        let mut all = vec![self.home.clone()];
        all.extend(self.hosts.slots.lock().unwrap_or_else(std::sync::PoisonError::into_inner).values().filter_map(|h| h.inner.clone()));
        all
    }

    fn channel(&self, channel: u32) -> Option<Arc<Inner>> {
        self.routes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&channel).cloned()
    }
}

impl Inner {
    /// Starts being a client of one server: attached to every session, its
    /// views read, and its events, input and facts each on their own thread.
    fn open(control: Arc<Control>, endpoint: Endpoint, saved_at: std::path::PathBuf, hub: Arc<Mutex<Hub>>, prefix: String) -> Result<Arc<Inner>> {
        let (inputs, queue) = mpsc::channel();
        let saved: Saved = std::fs::read(&saved_at).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let mut state = State { extras: saved.extras, hub, prefix, ..State::default() };
        for (herdr, rex) in &saved.aliases {
            state.aliases.bind(herdr, rex);
        }
        let inner = Arc::new(Inner {
            control,
            endpoint,
            saved: saved_at,
            state: Mutex::new(state),
            placed: Condvar::new(),
            writing: Mutex::new(()),
            inputs: Mutex::new(inputs),
        });
        // Events from here on, every session attached, then the views.
        let boot = inner.control.call("session.bootstrap", json!({ "event_scope": "all", "attach_session_ids": [] }), CALL)?;
        let sessions: Vec<String> = boot
            .pointer("/attach_all/sessions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|s| s["session_id"].as_str().map(str::to_owned))
            .collect();
        for session in &sessions {
            inner.attach_session(session);
        }
        inner.refresh_all();
        inner.prune_saved();
        let pump = inner.clone();
        std::thread::Builder::new().name("rex-events".into()).spawn(move || pump.pump())?;
        let work = inner.clone();
        std::thread::Builder::new().name("rex-input".into()).spawn(move || work.input_loop(&queue))?;
        let facts = inner.clone();
        std::thread::Builder::new().name("rex-facts".into()).spawn(move || {
            let blocks: Vec<(String, String)> = facts.lock().sessions.iter().map(|(b, s)| (b.clone(), s.clone())).collect();
            for (block, session) in blocks {
                facts.learn(&session, &block);
            }
        })?;
        Ok(inner)
    }

    /// Leaves the server: the connection, input and streams end.
    fn close(&self) {
        self.control.close();
        *self.inputs.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = mpsc::channel().0;
        for c in self.lock().channels.values() {
            c.stop.store(true, Ordering::Relaxed);
            if let Some(stopper) = c.stopper.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref() {
                stopper.stop();
            }
        }
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn call(&self, method: &str, payload: Value) -> Result<Value> {
        self.control.call(method, payload, CALL)
    }

    /// A terminal block method (`com.superlogical.terminal.<name>`).
    fn terminal(&self, session: &str, block: &str, name: &str, args: Value) -> Result<Value> {
        self.call(&format!("{TERMINAL}.{name}"), json!({ "session_id": session, "block_id": block, "args": args }))
    }

    fn attach_session(&self, session: &str) {
        if let Err(e) = self.call("session.attach", json!({ "session_id": session })) {
            tracing::warn!("rex: cannot attach session {session}: {e:#}");
        }
    }

    // ---- views -------------------------------------------------------------

    /// Reads every session and its view again, and the blocks in it.
    fn refresh_all(&self) {
        let Ok(list) = self.call("session.list", json!({})) else { return };
        let order: Vec<String> = list["sessions"].as_array().into_iter().flatten().filter_map(|s| s["session_id"].as_str().map(str::to_owned)).collect();
        let mut views = HashMap::new();
        let mut blocks = HashMap::new();
        for session in &order {
            if let Ok(view) = self.call("session.view", json!({ "session_id": session })) {
                views.insert(session.clone(), view);
            }
            if let Ok(listed) = self.call("session.list_blocks", json!({ "session_id": session })) {
                blocks.insert(session.clone(), listed["blocks"].as_array().cloned().unwrap_or_default());
            }
        }
        let mut s = self.lock();
        let gone: Vec<String> = s.order.iter().filter(|id| !order.contains(id)).cloned().collect();
        s.order = order;
        for (session, view) in views {
            let newer = s.views.get(&session).is_none_or(|old| old["revision"].as_u64() <= view["revision"].as_u64());
            if newer {
                s.views.insert(session, view);
            }
        }
        for session in gone {
            s.views.remove(&session);
        }
        for (session, listed) in blocks {
            Self::sync_blocks(&mut s, &session, &listed);
        }
        Self::retab(&mut s);
        Self::changed(&mut s);
        drop(s);
        self.placed.notify_all();
    }

    /// Reads one session's view if `revision` is newer than the one held.
    fn refresh_view(&self, session: &str, revision: Option<u64>) {
        if let Some(r) = revision
            && self.lock().views.get(session).and_then(|v| v["revision"].as_u64()).is_some_and(|held| held >= r)
        {
            return;
        }
        let Ok(view) = self.call("session.view", json!({ "session_id": session })) else { return };
        let mut s = self.lock();
        let newer = s.views.get(session).is_none_or(|old| old["revision"].as_u64() < view["revision"].as_u64());
        if newer {
            s.views.insert(session.to_owned(), view);
            if !s.order.iter().any(|o| o == session) {
                s.order.push(session.to_owned());
            }
            Self::retab(&mut s);
            Self::changed(&mut s);
        }
    }

    /// The views or ids changed: if the document did too, a new version and
    /// news for Herdr to read it again.
    fn changed(s: &mut State) {
        let doc = project::project(&Self::views(s), &s.aliases, &s.extras);
        if doc == s.doc && s.version > 0 {
            return;
        }
        s.doc = doc;
        s.version += 1;
        Self::emit(s, json!({ "method": "event", "params": { "type": "doc" } }));
    }

    fn emit(s: &State, mut line: Value) {
        let mut hub = s.hub.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        hub.seq += 1;
        line["params"]["seq"] = hub.seq.into();
        let mut bytes = line.to_string().into_bytes();
        bytes.push(b'\n');
        hub.subscribers.retain(|tx| tx.try_send(Stream::Data(bytes.clone())).is_ok());
    }

    fn emit_terminal(s: &mut State, kind: &str, address: &str, mut data: Value) {
        if data.get("address").is_some() {
            data = Self::shown(s, data);
        }
        if let Some(record) = data.get_mut("record") {
            *record = Self::shown(s, record.take());
        }
        let address = Self::qualified(s, address);
        Self::emit(s, json!({ "method": "event", "params": { "type": kind, "terminal": address, "data": data } }));
    }

    /// An address as Herdr sees it: `<host>/<address>` on a Rex host.
    fn qualified(s: &State, address: &str) -> String {
        if s.prefix.is_empty() { address.to_owned() } else { format!("{}/{address}", s.prefix) }
    }

    /// A terminal record as Herdr sees it.
    fn shown(s: &State, mut record: Value) -> Value {
        if let Some(address) = record["address"].as_str() {
            record["address"] = Self::qualified(s, address).into();
        }
        record
    }

    fn address(s: &State, block: &str) -> String {
        s.aliases.herdr(block).to_owned()
    }

    /// The block behind an address Herdr uses, once Rex has made it.
    fn block_of(s: &State, address: &str) -> Option<String> {
        if s.pending.contains_key(address) {
            return None;
        }
        let block = s.aliases.rex(address);
        s.terminals.contains_key(block).then(|| block.to_owned())
    }

    fn fresh_record(address: &str, name: &Value, labels: Map<String, Value>, argv: &[String], cwd: &str) -> Value {
        json!({
            "address": address,
            "name": name,
            "labels": labels,
            "argv": argv,
            "cwd": cwd,
            "state": "live",
            "created_ms": now_ms(),
            "screen": "exact",
            "cols": 0,
            "rows": 0,
            "title": "",
            "status": null,
            "records": {},
            "reported": false,
            "turn": 0,
            "keep": true,
        })
    }

    /// Records the terminal blocks `session.list_blocks` reports for a session.
    fn sync_blocks(s: &mut State, session: &str, listed: &[Value]) {
        for b in listed {
            let Some(block) = b["block_id"].as_str() else { continue };
            if b["creator_name"].as_str().is_some_and(|c| c != TERMINAL) {
                continue;
            }
            s.sessions.insert(block.to_owned(), session.to_owned());
            if s.terminals.contains_key(block) {
                continue;
            }
            let address = Self::address(s, block);
            let record = Self::fresh_record(&address, &b["label"], Map::new(), &[], "");
            s.terminals.insert(block.to_owned(), record.clone());
            Self::emit_terminal(s, "created", &address, record);
        }
    }

    /// Keeps each terminal's `herdr.space`/`herdr.tab` labels where its block is,
    /// so the window finds terminals it hasn't placed yet.
    fn retab(s: &mut State) {
        let mut place: HashMap<String, String> = HashMap::new();
        for session in &s.order {
            let Some(view) = s.views.get(session) else { continue };
            for w in view["windows"].as_array().into_iter().flatten() {
                let window = w["window_id"].as_str().unwrap_or_default();
                for layer in w["layers"].as_array().into_iter().flatten() {
                    for b in layer["blocks"].as_array().into_iter().flatten() {
                        if let Some(block) = b["block_id"].as_str() {
                            place.insert(block.to_owned(), window.to_owned());
                        }
                    }
                }
            }
        }
        let blocks: Vec<String> = s.terminals.keys().filter(|k| !s.pending.contains_key(*k)).cloned().collect();
        for block in blocks {
            let Some(session) = s.sessions.get(&block).cloned() else { continue };
            let space = s.aliases.herdr(&session).to_owned();
            let tab = place.get(&block).map(|w| s.aliases.herdr(w).to_owned()).unwrap_or_default();
            let address = Self::address(s, &block);
            let Some(t) = s.terminals.get_mut(&block) else { continue };
            let labels = t["labels"].as_object().cloned().unwrap_or_default();
            let mut next = labels.clone();
            next.insert("herdr.space".into(), space.into());
            next.insert("herdr.tab".into(), tab.into());
            if next != labels {
                t["labels"] = Value::Object(next);
                let record = t.clone();
                let labels = record["labels"].clone();
                Self::emit_terminal(s, "labels", &address, json!({ "labels": labels, "record": record }));
            }
        }
    }

    /// Fills in what a terminal shows: title, status, size and what runs in it.
    fn learn(&self, session: &str, block: &str) {
        let title = self.terminal(session, block, "title", json!({})).ok();
        let status = self.terminal(session, block, "program_status", json!({})).ok();
        let process = self.terminal(session, block, "process", json!({})).ok();
        let size = self.terminal(session, block, "size", json!({})).ok();
        let mut s = self.lock();
        let address = Self::address(&s, block);
        if !s.terminals.contains_key(block) {
            return;
        }
        if let Some(title) = title.as_ref().and_then(|t| t["title"].as_str()) {
            s.terminals.get_mut(block).unwrap()["title"] = title.into();
            Self::emit_terminal(&mut s, "title", &address, json!({ "title": title }));
        }
        if let Some(records) = status.as_ref().and_then(|v| v["records"].as_array()) {
            for r in records {
                let id = r["id"].as_str().unwrap_or_default().to_owned();
                Self::set_status(&mut s, block, &id, Some(r));
            }
            Self::emit_status(&mut s, block);
        }
        if let Some(p) = &process {
            let t = s.terminals.get_mut(block).unwrap();
            if let Some(pid) = p.pointer("/child/pid") {
                t["pid"] = pid.clone();
            }
            if let Some(cwd) = p.pointer("/child/cwd").and_then(Value::as_str) {
                t["cwd"] = cwd.into();
            }
            if let Some(f) = p.get("foreground").filter(|f| f.is_object()) {
                let fg = foreground(f);
                t["foreground"] = fg.clone();
                Self::emit_terminal(&mut s, "foreground", &address, fg);
            }
        }
        if let Some(size) = &size {
            let cols = size.pointer("/size/columns").or_else(|| size.get("columns")).cloned().unwrap_or(Value::Null);
            let rows = size.pointer("/size/rows").or_else(|| size.get("rows")).cloned().unwrap_or(Value::Null);
            if cols.is_u64() && rows.is_u64() {
                let t = s.terminals.get_mut(block).unwrap();
                t["cols"] = cols.clone();
                t["rows"] = rows.clone();
                Self::emit_terminal(&mut s, "size", &address, json!({ "cols": cols, "rows": rows }));
            }
        }
    }

    /// One 7501 record changed (`None`: removed). The root record is `""`.
    fn set_status(s: &mut State, block: &str, id: &str, record: Option<&Value>) {
        let Some(t) = s.terminals.get_mut(block) else { return };
        let shaped = record.map(|r| {
            json!({
                "state": r["state"].as_str().unwrap_or("idle"),
                "kind": r.get("kind").cloned().unwrap_or(Value::Null),
                "progress": r.get("progress").cloned().unwrap_or(Value::Null),
                "app": r.get("effective_app").or_else(|| r.get("app")).cloned().unwrap_or_else(|| "".into()),
                "title": r.get("title").cloned().unwrap_or_else(|| "".into()),
                "msg": r.get("msg").cloned().unwrap_or_else(|| "".into()),
            })
        });
        if id.is_empty() {
            let was = t["status"]["state"].as_str().map(str::to_owned);
            let now = shaped.as_ref().and_then(|r| r["state"].as_str()).map(str::to_owned);
            if was.as_deref() == Some("working") && now.as_deref() != Some("working") {
                t["turn"] = (t["turn"].as_u64().unwrap_or(0) + 1).into();
            }
            t["status"] = shaped.unwrap_or(Value::Null);
            t["status_ms"] = now_ms().into();
        } else if let Some(records) = t["records"].as_object_mut() {
            match shaped {
                Some(r) => records.insert(id.to_owned(), r),
                None => records.remove(id),
            };
        }
        if record.is_some() {
            t["reported"] = true.into();
        }
    }

    fn emit_status(s: &mut State, block: &str) {
        let address = Self::address(s, block);
        let Some(t) = s.terminals.get(block) else { return };
        let (status, records, reported, turn) = (t["status"].clone(), t["records"].clone(), t["reported"].clone(), t["turn"].clone());
        Self::emit_terminal(s, "status", &address, json!({ "status": status, "records": records, "reported": reported }));
        Self::emit_terminal(s, "turn", &address, json!({ "turn": turn }));
    }

    // ---- events ------------------------------------------------------------

    fn pump(self: Arc<Self>) {
        let events = self.control.events();
        while let Ok(event) = events.recv_blocking() {
            self.handle(&event);
        }
        // Lost the home server: Herdr reconnects and reads everything again.
        // A host's loss shows in the machine list; its terminals reattach later.
        let s = self.lock();
        if s.prefix.is_empty() {
            s.hub.lock().unwrap_or_else(std::sync::PoisonError::into_inner).subscribers.clear();
        }
    }

    fn handle(&self, event: &Event) {
        let outer = &event.message["payload"];
        match outer["type"].as_str().unwrap_or(event.kind.as_str()) {
            "session_created" => {
                if let Some(session) = outer.pointer("/payload/session/session_id").and_then(Value::as_str) {
                    self.attach_session(session);
                    self.refresh_all();
                }
            }
            "session_destroyed" | "session_moved" => self.refresh_all(),
            // Another client's action for this one, or a call to make for it:
            // Herdr offers none, so say so at once rather than keep it waiting.
            "client_call_requested" | "client_perform_requested" => {
                if let Some(call) = outer.pointer("/payload/call_id").and_then(Value::as_str) {
                    let error = json!({ "code": "not_supported", "message": "Herdr doesn't perform Rex client actions" });
                    let _ = self.call("client.reply", json!({ "call_id": call, "error": error }));
                }
            }
            "session_event" => {
                let session = outer.pointer("/payload/session_id").and_then(Value::as_str).unwrap_or_default();
                let inner = &outer["payload"]["event"];
                self.session_event(session, inner["type"].as_str().unwrap_or_default(), &inner["payload"]);
            }
            _ => {}
        }
    }

    fn session_event(&self, session: &str, kind: &str, p: &Value) {
        match kind {
            "session_view_changed" => self.refresh_view(session, p["revision"].as_u64()),
            "session_label_changed" => self.refresh_view(session, None),
            "block_created" => {
                if let Ok(listed) = self.call("session.list_blocks", json!({ "session_id": session })) {
                    let listed = listed["blocks"].as_array().cloned().unwrap_or_default();
                    {
                        let mut s = self.lock();
                        Self::sync_blocks(&mut s, session, &listed);
                        Self::retab(&mut s);
                    }
                    self.placed.notify_all();
                    if let Some(block) = p["block_id"].as_str() {
                        self.learn(session, block);
                    }
                }
            }
            "block_closed" => {
                let Some(block) = p["block_id"].as_str() else { return };
                let mut s = self.lock();
                if s.terminals.remove(block).is_some() {
                    let address = Self::address(&s, block);
                    Self::emit_terminal(&mut s, "removed", &address, json!({}));
                }
                s.sessions.remove(block);
                s.placeholders.retain(|b| b != block);
            }
            "block_event" => {
                let Some(block) = p["block_id"].as_str() else { return };
                self.block_event(block, p["name"].as_str().unwrap_or_default(), &p["payload"]);
            }
            _ => {}
        }
    }

    fn block_event(&self, block: &str, name: &str, p: &Value) {
        let mut s = self.lock();
        if !s.terminals.contains_key(block) {
            return;
        }
        let address = Self::address(&s, block);
        match name {
            "title_changed" => {
                let title = p["title"].as_str().unwrap_or_default();
                s.terminals.get_mut(block).unwrap()["title"] = title.into();
                Self::emit_terminal(&mut s, "title", &address, json!({ "title": title }));
            }
            "program_status_changed" => {
                let id = p["id"].as_str().unwrap_or_default().to_owned();
                Self::set_status(&mut s, block, &id, Some(&p["record"]));
                Self::emit_status(&mut s, block);
            }
            "program_status_removed" => {
                for id in p["ids"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                    Self::set_status(&mut s, block, id, None);
                }
                Self::emit_status(&mut s, block);
            }
            "process_changed" => {
                let fg = p.get("foreground").filter(|f| f.is_object()).map_or(Value::Null, foreground);
                s.terminals.get_mut(block).unwrap()["foreground"] = fg.clone();
                Self::emit_terminal(&mut s, "foreground", &address, fg);
            }
            "size_changed" => {
                let (cols, rows) = (p["columns"].clone(), p["rows"].clone());
                let t = s.terminals.get_mut(block).unwrap();
                t["cols"] = cols.clone();
                t["rows"] = rows.clone();
                Self::emit_terminal(&mut s, "size", &address, json!({ "cols": cols, "rows": rows }));
            }
            "child_exited" => {
                let data = json!({ "reason": "exited", "exit_code": p["exit_code"], "signal": null, "finished_ms": now_ms() });
                let t = s.terminals.get_mut(block).unwrap();
                for k in ["reason", "exit_code", "signal", "finished_ms"] {
                    t[k] = data[k].clone();
                }
                t["state"] = "finished".into();
                Self::emit_terminal(&mut s, "finished", &address, data);
            }
            _ => {}
        }
    }

    // ---- input -------------------------------------------------------------

    fn send(&self, input: Input) {
        let _ = self.inputs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).send(input);
    }

    fn input_loop(&self, queue: &mpsc::Receiver<Input>) {
        while let Ok(input) = queue.recv() {
            let result = match input {
                Input::Write { session, block, data } => self.terminal(&session, &block, "write", json!({ "data": data })),
                Input::Resize { session, block, cols, rows } => {
                    self.terminal(&session, &block, "resize", json!({ "columns": cols.max(1), "rows": rows.max(1) }))
                }
                Input::Focus { session, block } => {
                    // The size follows the client people are looking at, as in Rex.app.
                    let _ = self.call("session.own_block", json!({ "session_id": session, "block_ids": [block], "mode": "take" }));
                    let _ = self.call("block.event", json!({ "session_id": session, "block_id": block, "event": { "type": "focus", "payload": { "action": "in" } } }));
                    self.call("session.focus_block", json!({ "session_id": session, "block_id": block }))
                }
            };
            if let Err(e) = result {
                tracing::debug!("rex input: {e:#}");
            }
        }
    }

    // ---- terminals ---------------------------------------------------------

    /// The block for an address, making a terminal `terminal.run` asked for
    /// if its document hasn't placed it in time.
    fn materialize(&self, address: &str) -> Result<(String, String)> {
        let deadline = Instant::now() + PLACE_WAIT;
        let mut s = self.lock();
        loop {
            if let Some(block) = Self::block_of(&s, address) {
                let session = s.sessions.get(&block).cloned().ok_or_else(|| rpc("not_found", format!("{address}: no session")))?;
                return Ok((session, block));
            }
            if !s.pending.contains_key(address) {
                return Err(rpc("not_found", format!("no terminal {address}")));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            s = self.placed.wait_timeout(s, left).unwrap_or_else(std::sync::PoisonError::into_inner).0;
        }
        // Not in any tab: a detached block in its space's session.
        let run = s.pending.get(address).ok_or_else(|| rpc("not_found", format!("no terminal {address}")))?;
        let space = run.labels.get("herdr.space").and_then(Value::as_str).unwrap_or_default();
        let session = Some(s.aliases.rex(space).to_owned()).filter(|id| s.views.contains_key(id)).or_else(|| s.order.first().cloned());
        let spec = run.spec.clone();
        drop(s);
        let session = if let Some(session) = session {
            session
        } else {
            let created = self.call("session.create", json!({})).map_err(|e| translate("session.create", &e))?;
            let id = created["session_id"].as_str().ok_or_else(|| anyhow!("session.create returned no id"))?.to_owned();
            self.attach_session(&id);
            id
        };
        let made = self
            .call("session.new_block", json!({ "session_id": session, "flavor": SHELL, "options": spec.options, "label": spec.label }))
            .map_err(|e| translate("session.new_block", &e))?;
        let block = made["block_id"].as_str().ok_or_else(|| anyhow!("session.new_block returned no id"))?.to_owned();
        self.bound(&session, address, &block);
        Ok((session, block))
    }

    /// Rex made `block` for the terminal Herdr calls `address`.
    fn bound(&self, session: &str, address: &str, block: &str) {
        {
            let mut s = self.lock();
            s.aliases.bind(address, block);
            s.sessions.insert(block.to_owned(), session.to_owned());
            // Its block_created may have come first and announced it by its id.
            if s.terminals.remove(block).is_some() && address != block {
                Self::emit_terminal(&mut s, "removed", block, json!({}));
            }
            let mut record = s.terminals.remove(address).unwrap_or_else(|| Self::fresh_record(address, &Value::Null, Map::new(), &[], ""));
            if let Some(run) = s.pending.remove(address) {
                record["labels"] = Value::Object(run.labels);
            }
            s.terminals.insert(block.to_owned(), record);
            Self::retab(&mut s);
            self.save(&s);
        }
        self.placed.notify_all();
        self.learn(session, block);
    }

    fn run(&self, p: &Value) -> Result<Value> {
        let argv: Vec<String> = p["argv"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_owned)).collect();
        let cwd = p["cwd"].as_str().unwrap_or_default();
        let mut options = json!({ "cwd": cwd });
        if !argv.is_empty() {
            options["command"] = json!(argv);
        }
        let label = argv.first().map_or_else(|| "shell".to_owned(), |a| a.rsplit('/').next().unwrap_or(a).to_owned());
        let labels = p["labels"].as_object().cloned().unwrap_or_default();
        let mut s = self.lock();
        s.next_pending += 1;
        let address = format!("r{}", s.next_pending);
        let record = Self::fresh_record(&address, &json!(label), labels.clone(), &argv, cwd);
        // Known by its address until a document or an attach makes its block.
        s.terminals.insert(address.clone(), record.clone());
        s.pending.insert(address.clone(), PendingRun { spec: Pending { options, label }, labels });
        Self::emit_terminal(&mut s, "created", &address, record.clone());
        Ok(Self::shown(&s, record))
    }

    fn record(&self, address: &str) -> Result<Value> {
        let s = self.lock();
        let key = Self::block_of(&s, address).unwrap_or_else(|| address.to_owned());
        s.terminals.get(&key).cloned().map(|r| Self::shown(&s, r)).ok_or_else(|| rpc("not_found", format!("no terminal {address}")))
    }

    /// Every terminal record as Herdr sees it (`all`: finished ones too).
    fn records(&self, all: bool) -> Vec<Value> {
        let s = self.lock();
        s.terminals.values().filter(|t| all || t["state"] == "live").map(|t| Self::shown(&s, t.clone())).collect()
    }

    fn kill(&self, address: &str) -> Result<Value> {
        let found = {
            let mut s = self.lock();
            if s.pending.remove(address).is_some() {
                s.terminals.remove(address);
                Self::emit_terminal(&mut s, "removed", address, json!({}));
                return Ok(json!({}));
            }
            Self::block_of(&s, address).and_then(|b| s.sessions.get(&b).map(|session| (session.clone(), b)))
        };
        let (session, block) = found.ok_or_else(|| rpc("not_found", format!("no terminal {address}")))?;
        self.call("block.close", json!({ "session_id": session, "block_id": block })).map_err(|e| translate("block.close", &e))?;
        Ok(json!({}))
    }

    fn label(&self, p: &Value) -> Result<Value> {
        let address = p["terminal"].as_str().unwrap_or_default();
        let mut s = self.lock();
        let key = Self::block_of(&s, address).unwrap_or_else(|| address.to_owned());
        let Some(t) = s.terminals.get_mut(&key) else { return Err(rpc("not_found", format!("no terminal {address}"))) };
        for (k, v) in p["labels"].as_object().into_iter().flatten() {
            if v.is_null() || v.as_str() == Some("") {
                if let Some(l) = t["labels"].as_object_mut() {
                    l.remove(k);
                }
            } else {
                t["labels"][k] = v.clone();
            }
        }
        let record = t.clone();
        Self::emit_terminal(&mut s, "labels", address, json!({ "labels": record["labels"], "record": record }));
        Ok(Self::shown(&s, record))
    }

    fn read(&self, p: &Value) -> Result<Value> {
        let address = p["terminal"].as_str().unwrap_or_default();
        let (session, block) = self.materialize(address)?;
        let out = self
            .terminal(&session, &block, "format", json!({ "format": "text", "trim": true, "max_bytes": 983_040 }))
            .map_err(|e| translate("terminal.read", &e))?;
        let text = out["content"].as_str().unwrap_or_default();
        let rows = self.record(address).ok().and_then(|r| r["rows"].as_u64()).unwrap_or(0);
        let want = usize::try_from(p["lines"].as_u64().unwrap_or(0) + rows.max(1)).unwrap_or(usize::MAX);
        let lines: Vec<&str> = text.lines().collect();
        let tail = lines[lines.len().saturating_sub(want)..].join("\n");
        Ok(json!({ "text": tail, "complete": out.get("id").is_none(), "how": "history" }))
    }

    // ---- the layout document ----------------------------------------------

    /// The views in session order, each with the terminal blocks running in
    /// its session outside any window (`detached_block_ids`, for `plan`).
    fn views(s: &State) -> Vec<Value> {
        s.order
            .iter()
            .filter_map(|id| {
                let mut view = s.views.get(id)?.clone();
                let mut placed = HashSet::new();
                for w in view["windows"].as_array().into_iter().flatten() {
                    for layer in w["layers"].as_array().into_iter().flatten() {
                        placed.extend(layer["blocks"].as_array().into_iter().flatten().filter_map(|b| b["block_id"].as_str()));
                    }
                }
                let mut detached: Vec<&str> =
                    s.sessions.iter().filter(|(b, session)| *session == id && !placed.contains(b.as_str()) && s.terminals.contains_key(*b)).map(|(b, _)| b.as_str()).collect();
                detached.sort_unstable();
                view["detached_block_ids"] = json!(detached);
                Some(view)
            })
            .collect()
    }

    fn doc_get(&self) -> Value {
        let mut s = self.lock();
        Self::changed(&mut s);
        json!({ "value": s.doc, "version": s.version })
    }

    fn doc_set(&self, p: &Value) -> Result<Value> {
        let _writing = self.writing.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let desired = &p["value"];
        if self.lock().version != p["version"].as_u64().unwrap_or(0) {
            return Err(rpc("conflict", "the Rex sessions changed: read them again"));
        }
        let mut failures = 0;
        for _ in 0..MAX_STEPS {
            let step = {
                let s = self.lock();
                let pending: HashMap<String, Pending> = s.pending.iter().map(|(a, r)| (a.clone(), r.spec.clone())).collect();
                project::plan(&Self::views(&s), &s.aliases, desired, &pending, &s.placeholders).into_iter().next()
            };
            let Some(step) = step else {
                // Done: Herdr's pane ids for the blocks, so its focus stays put.
                project::bind_panes(desired, &mut self.lock().aliases);
                break;
            };
            if let Err(e) = self.apply(&step) {
                tracing::warn!("rex: {} failed: {e:#}", step.method);
                failures += 1;
                if failures > 2 {
                    self.refresh_all();
                    return Err(translate(&step.method, &e));
                }
            }
            // Each step plans from the views the last one changed.
            self.refresh_all();
        }
        let mut s = self.lock();
        for space in desired["spaces"].as_array().into_iter().flatten() {
            let session = s.aliases.rex(space["id"].as_str().unwrap_or_default()).to_owned();
            if s.views.contains_key(&session) {
                let folder = space["folder"].as_str().unwrap_or_default().to_owned();
                let unnamed = space["name"].as_str().unwrap_or_default().is_empty();
                s.extras.insert(session, SpaceExtra { folder, unnamed });
            }
        }
        self.save(&s);
        Self::changed(&mut s);
        Ok(json!({ "version": s.version }))
    }

    fn apply(&self, step: &Step) -> Result<()> {
        let result = self.call(&step.method, step.payload.clone())?;
        let session = step.payload["session_id"].as_str().unwrap_or_default();
        match &step.bind {
            Bind::None => {}
            Bind::Session { space } => {
                let session = result["session_id"].as_str().ok_or_else(|| anyhow!("no session_id"))?;
                self.lock().aliases.bind(space, session);
                self.attach_session(session);
            }
            Bind::Window { tab, blocks } => {
                let window = result["window_id"].as_str().ok_or_else(|| anyhow!("no window_id"))?;
                self.lock().aliases.bind(tab, window);
                self.bind_blocks(session, blocks, &result["block_ids"]);
            }
            Bind::Blocks(blocks) => {
                let ids = if result["block_ids"].is_array() { result["block_ids"].clone() } else { json!([result["block_id"]]) };
                self.bind_blocks(session, blocks, &ids);
            }
        }
        Ok(())
    }

    fn bind_blocks(&self, session: &str, addresses: &[Option<String>], ids: &Value) {
        let ids: Vec<&str> = ids.as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        for (address, block) in addresses.iter().zip(ids) {
            match address {
                Some(address) => self.bound(session, address, block),
                None => self.lock().placeholders.push(block.to_owned()),
            }
        }
    }

    fn save(&self, s: &State) {
        let saved = Saved { aliases: s.aliases.to_rex.iter().map(|(h, r)| (h.clone(), r.clone())).collect(), extras: s.extras.clone() };
        if let Ok(bytes) = serde_json::to_vec_pretty(&saved) {
            let _ = std::fs::write(&self.saved, bytes);
        }
    }

    /// Forgets saved ids of sessions, windows and blocks that are gone.
    fn prune_saved(&self) {
        let mut s = self.lock();
        let mut live: HashSet<String> = s.order.iter().cloned().collect();
        live.extend(s.terminals.keys().cloned());
        for view in s.views.values() {
            for w in view["windows"].as_array().into_iter().flatten() {
                if let Some(id) = w["window_id"].as_str() {
                    live.insert(id.to_owned());
                }
            }
        }
        let stale: Vec<String> =
            s.aliases.to_herdr.keys().filter(|r| !live.contains(r.strip_prefix(project::PANE_KEY).unwrap_or(r))).cloned().collect();
        for rex in stale {
            if let Some(herdr) = s.aliases.to_herdr.remove(&rex) {
                s.aliases.to_rex.remove(&herdr);
            }
        }
        s.extras.retain(|session, _| live.contains(session));
        self.save(&s);
    }

    // ---- data --------------------------------------------------------------

    fn attach(self: &Arc<Self>, channel: u32, address: &str, cols: u16, rows: u16) -> Result<Attached> {
        let (session, block) = self.materialize(address)?;
        let _ = self.call("session.own_block", json!({ "session_id": session, "block_ids": [block], "mode": "request" }));
        let _ = self.terminal(&session, &block, "resize", json!({ "columns": cols.max(1), "rows": rows.max(1) }));
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = Arc::new(Mutex::new(None));
        let (tx, rx) = async_channel::unbounded();
        let record = {
            let mut s = self.lock();
            s.channels.insert(channel, Channel { session: session.clone(), block: block.clone(), stop: stop.clone(), stopper: stopper.clone() });
            s.terminals.get(&block).cloned().map(|r| Self::shown(&s, r)).unwrap_or(Value::Null)
        };
        let worker = self.clone();
        std::thread::Builder::new().name(format!("rex-data-{channel}")).spawn(move || worker.stream(&session, &block, &tx, &stop, &stopper))?;
        Ok(Attached { channel, stream: rx, terminal: record })
    }

    /// Relays one block's stream until it ends, the view detaches, or the
    /// connection breaks for good (then Herdr attaches again).
    fn stream(&self, session: &str, block: &str, tx: &async_channel::Sender<Stream>, stop: &AtomicBool, stopper: &Mutex<Option<DataStop>>) {
        let ended = |inner: &Inner| {
            if inner.lock().terminals.contains_key(block) { Stream::Lost } else { Stream::Closed(json!({ "reason": "removed" })) }
        };
        let mut conn = match DataConn::open(&self.control, &self.endpoint, session, block) {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("rex: cannot stream {block}: {e:#}");
                let _ = tx.try_send(ended(self));
                return;
            }
        };
        *stopper.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(conn.stopper());
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let mut decoder = Decoder::new(conn.nonce());
        while !stop.load(Ordering::Relaxed) && !tx.is_closed() {
            let bytes = match conn.read() {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    let _ = tx.try_send(ended(self));
                    break;
                }
                Err(e) => {
                    // A close with a status means start over; a dropped connection resumes.
                    let resumable = e.downcast_ref::<DataClosed>().is_none();
                    if resumable && !stop.load(Ordering::Relaxed) && conn.resume(&self.endpoint).is_ok() {
                        continue;
                    }
                    tracing::debug!("rex: stream {block} ended: {e:#}");
                    let _ = tx.try_send(ended(self));
                    break;
                }
            };
            let pieces = match decoder.push(&bytes) {
                Ok(pieces) => pieces,
                Err(e) => {
                    tracing::warn!("rex: bad stream from {block}: {e:#}");
                    let _ = tx.try_send(Stream::Lost);
                    break;
                }
            };
            for piece in pieces {
                let item = match piece {
                    Piece::Snapshot(bytes) => Stream::Snapshot(bytes),
                    Piece::Data(bytes) => Stream::Data(bytes),
                    Piece::ChildExited(why) => {
                        let _ = tx.try_send(Stream::Closed(json!({ "reason": "exited", "exit_code": why["exit_code"] })));
                        conn.close();
                        return;
                    }
                    // The display follows the size Herdr asks for; colors are Herdr's.
                    Piece::Resize { .. } | Piece::Theme(_) => continue,
                };
                if tx.try_send(item).is_err() {
                    break;
                }
            }
        }
        conn.close();
    }

    fn channel(&self, channel: u32) -> Option<(String, String)> {
        self.lock().channels.get(&channel).map(|c| (c.session.clone(), c.block.clone()))
    }
}

/// How long the host manager waits between looks at the host list.
const HOSTS_EVERY: Duration = Duration::from_secs(5);

/// The other Rex servers the home server lists (`hosts.list`): Herdr's
/// machines in Rex mode. Each connected one is a server of its own.
struct Hosts {
    slots: Mutex<BTreeMap<String, Host>>,
    /// The home server's host_id: a host that is the home server isn't listed.
    home_host: Option<String>,
    /// Where each host's `Saved` file goes.
    dir: std::path::PathBuf,
    hub: Arc<Mutex<Hub>>,
    stop: AtomicBool,
}

struct Host {
    /// The host as Rex stores it (sent back unchanged on rename).
    entry: Value,
    state: &'static str,
    why: Option<String>,
    since_ms: Option<u64>,
    inner: Option<Arc<Inner>>,
}

/// An endpoint from a host entry as the transport takes it: one with a
/// scheme as it is, `host:port` a plain listener, a bare name a tailnet's HTTPS.
fn endpoint_candidates(endpoint: &str) -> Vec<String> {
    let endpoint = endpoint.trim();
    if endpoint.contains("://") {
        vec![endpoint.to_owned()]
    } else if endpoint.rsplit_once(':').is_some_and(|(_, port)| port.parse::<u16>().is_ok()) {
        vec![format!("ws://{endpoint}"), format!("wss://{endpoint}")]
    } else {
        vec![format!("wss://{endpoint}")]
    }
}

/// What to call a server added by address: its host's first name, or its IP.
fn label_for(target: &str) -> String {
    let host = target.split("://").last().unwrap_or(target);
    let host = host.split('/').next().unwrap_or(host);
    let host = host.rsplit_once(':').filter(|(_, p)| p.parse::<u16>().is_ok()).map_or(host, |(h, _)| h);
    let host = host.trim_matches(['[', ']']);
    if host.parse::<std::net::IpAddr>().is_ok() { host.to_owned() } else { host.split('.').next().unwrap_or(host).to_owned() }
}

impl Hosts {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Host>> {
        self.slots.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The connected server Herdr calls `machine`.
    fn inner(&self, machine: &str) -> Result<Arc<Inner>> {
        match self.lock().get(machine) {
            Some(Host { inner: Some(inner), .. }) => Ok(inner.clone()),
            Some(h) => Err(rpc("unavailable", format!("{machine} is {}{}", h.state, h.why.as_ref().map(|w| format!(": {w}")).unwrap_or_default()))),
            None => Err(rpc("not_found", format!("no machine {machine}"))),
        }
    }

    /// Keeps the hosts connected, in the background, until the link closes.
    fn watch(self: Arc<Self>, home: Arc<Inner>) {
        let _ = std::thread::Builder::new().name("rex-hosts".into()).spawn(move || {
            while !self.stop.load(Ordering::Relaxed) && !home.control.is_lost() {
                self.tend(&home);
                std::thread::sleep(HOSTS_EVERY);
            }
        });
    }

    /// Reads the host list, forgets removed hosts and connects the others.
    fn tend(&self, home: &Arc<Inner>) {
        let Ok(listed) = home.call("hosts.list", json!({})) else { return };
        let hosts: Vec<Value> = listed["hosts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|h| self.home_host.is_none() || h["host_id"].as_str() != self.home_host.as_deref())
            .cloned()
            .collect();
        let labels: Vec<String> = hosts.iter().filter_map(|h| h["label"].as_str().map(str::to_owned)).collect();
        let gone: Vec<Host> = {
            let mut slots = self.lock();
            let gone = slots.keys().filter(|l| !labels.contains(l)).cloned().collect::<Vec<_>>();
            for host in &hosts {
                let Some(label) = host["label"].as_str() else { continue };
                let slot = slots.entry(label.to_owned()).or_insert_with(|| Host { entry: Value::Null, state: "connecting", why: None, since_ms: Some(now_ms()), inner: None });
                slot.entry = host.clone();
            }
            gone.iter().filter_map(|l| slots.remove(l)).collect()
        };
        for host in gone {
            if let Some(inner) = host.inner {
                inner.close();
            }
        }
        for label in labels {
            let (lost, entry) = {
                let slots = self.lock();
                let Some(h) = slots.get(&label) else { continue };
                (h.inner.as_ref().is_none_or(|i| i.control.is_lost()), h.entry.clone())
            };
            if lost {
                self.connect(&label, &entry);
            }
        }
    }

    /// Tries a host's endpoints in order; the first that answers is its server.
    fn connect(&self, label: &str, entry: &Value) {
        let mut why = String::from("it has no endpoints");
        for endpoint in entry["endpoints"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            for origin in endpoint_candidates(endpoint) {
                let opened = Endpoint::parse(&origin).and_then(|e| {
                    let control = Control::connect(&e, "Herdr")?;
                    let id = entry["id"].as_str().unwrap_or(label).replace(|c: char| !c.is_ascii_alphanumeric(), "-");
                    Inner::open(control, e, self.dir.join(format!("rex-{id}.json")), self.hub.clone(), label.to_owned())
                });
                match opened {
                    Ok(inner) => {
                        let mut slots = self.lock();
                        if let Some(h) = slots.get_mut(label) {
                            let was = h.inner.replace(inner);
                            (h.state, h.why, h.since_ms) = ("connected", None, None);
                            drop(slots);
                            if let Some(old) = was {
                                old.close();
                            }
                        } else {
                            inner.close();
                        }
                        return;
                    }
                    Err(e) => why = format!("{endpoint}: {e:#}"),
                }
            }
        }
        if let Some(h) = self.lock().get_mut(label) {
            if h.state != "unreachable" {
                h.since_ms = Some(now_ms());
            }
            h.state = "unreachable";
            h.why = Some(why);
            if let Some(old) = h.inner.take() {
                old.close();
            }
        }
    }

    /// The hosts as `hc machine ls` shows machines.
    fn list(&self, home: &Arc<Inner>) -> Vec<Value> {
        if self.lock().is_empty() {
            self.tend(home);
        }
        self.lock()
            .iter()
            .map(|(label, h)| {
                let endpoints: Vec<&str> = h.entry["endpoints"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                json!({
                    "name": label,
                    "target": endpoints.join(", "),
                    "id": h.entry["id"],
                    "host": label,
                    "version": "",
                    "state": h.state,
                    "since_ms": h.since_ms,
                    "why": h.why,
                    "session": null,
                    "temporary": false,
                    "via": false,
                })
            })
            .collect()
    }

    fn view(&self, home: &Arc<Inner>, label: &str) -> Result<Value> {
        self.list(home).into_iter().find(|m| m["name"] == label).ok_or_else(|| rpc("not_found", format!("no machine {label}")))
    }

    /// Adds a Rex server by address, once it answers, to Rex's host list.
    fn add(&self, home: &Arc<Inner>, target: &str, name: Option<&str>) -> Result<Value> {
        let target = target.trim();
        if target.is_empty() {
            return Err(rpc("bad_request", "Give the Rex server's address: a tailnet name, host:port, or a ws:// or wss:// origin"));
        }
        let label = name.map(str::trim).filter(|n| !n.is_empty()).map_or_else(|| label_for(target), str::to_owned);
        // It answers first, so the list only holds servers that work.
        let mut reached = None;
        let mut why = String::new();
        for origin in endpoint_candidates(target) {
            match Endpoint::parse(&origin).and_then(|e| Control::connect(&e, "Herdr")) {
                Ok(control) => {
                    reached = control.call("server.status", json!({}), CALL).ok();
                    control.close();
                    if reached.is_some() {
                        break;
                    }
                }
                Err(e) => why = format!("{e:#}"),
            }
        }
        let Some(status) = reached else { return Err(rpc("unreachable", format!("Can't reach a Rex server at {target}: {why}"))) };
        if self.home_host.is_some() && status["host_id"].as_str() == self.home_host.as_deref() {
            return Err(rpc("bad_request", format!("{target} is this Rex server")));
        }
        let mut host = json!({ "label": label, "endpoints": [target], "added_from": "Herdr" });
        if let Some(id) = status["host_id"].as_str() {
            host["host_id"] = id.into();
        }
        home.call("hosts.put", json!({ "host": host })).map_err(|e| translate("hosts.put", &e))?;
        self.tend(home);
        self.view(home, &label)
    }

    fn remove(&self, home: &Arc<Inner>, machine: &str) -> Result<Value> {
        let id = self.lock().get(machine).map(|h| h.entry["id"].clone()).ok_or_else(|| rpc("not_found", format!("no machine {machine}")))?;
        home.call("hosts.remove", json!({ "id": id })).map_err(|e| translate("hosts.remove", &e))?;
        self.tend(home);
        Ok(json!({ "removed": true }))
    }

    fn rename(&self, home: &Arc<Inner>, machine: &str, new_name: &str) -> Result<Value> {
        let mut entry = self.lock().get(machine).map(|h| h.entry.clone()).ok_or_else(|| rpc("not_found", format!("no machine {machine}")))?;
        entry["label"] = new_name.trim().into();
        if let Some(e) = entry.as_object_mut() {
            e.remove("updated_at");
            e.remove("source");
        }
        home.call("hosts.put", json!({ "host": entry })).map_err(|e| translate("hosts.put", &e))?;
        // Its spaces and terminals are addressed by the old name: start it over.
        if let Some(old) = self.lock().remove(machine).and_then(|h| h.inner) {
            old.close();
        }
        self.tend(home);
        self.view(home, new_name.trim())
    }
}

/// Rex's foreground process as herdr-core reports one.
fn foreground(f: &Value) -> Value {
    let name = f.get("script").or_else(|| f.get("name")).and_then(Value::as_str).unwrap_or_default();
    let name = name.rsplit('/').next().unwrap_or(name);
    json!({ "pid": f["pid"], "name": name, "argv": [f.get("argv0").and_then(Value::as_str).unwrap_or(name)], "cwd": f["cwd"].as_str().unwrap_or_default() })
}

impl Link for RexLink {
    fn call_timeout(&self, method: &str, params: Value, _timeout: Duration) -> Result<Value> {
        let address = params["terminal"].as_str().unwrap_or_default();
        match method {
            "terminal.run" => self.on(&params)?.run(&params),
            "terminal.list" => {
                let all = params["all"].as_bool().unwrap_or(false);
                Ok(json!({ "terminals": self.servers().iter().flat_map(|s| s.records(all)).collect::<Vec<_>>() }))
            }
            // Rex keeps every terminal until it's closed: keep changes nothing.
            "terminal.get" | "terminal.keep" => {
                let (server, local) = self.route(address)?;
                server.record(local)
            }
            "terminal.kill" => {
                let (server, local) = self.route(address)?;
                server.kill(local)
            }
            "terminal.label" => {
                let (server, local) = self.route(address)?;
                let mut params = params.clone();
                params["terminal"] = local.into();
                server.label(&params)
            }
            "terminal.read" => {
                let (server, local) = self.route(address)?;
                let mut params = params.clone();
                params["terminal"] = local.into();
                server.read(&params)
            }
            "doc.get" => Ok(self.on(&params)?.doc_get()),
            "doc.set" => self.on(&params)?.doc_set(&params),
            "machine.list" => Ok(json!({ "machines": self.hosts.list(&self.home) })),
            "machine.add" => self.hosts.add(&self.home, params["target"].as_str().unwrap_or_default(), params["name"].as_str()),
            "machine.rm" => self.hosts.remove(&self.home, params["machine"].as_str().unwrap_or_default()),
            "machine.rename" => {
                self.hosts.rename(&self.home, params["machine"].as_str().unwrap_or_default(), params["new_name"].as_str().unwrap_or_default())
            }
            "server.status" => {
                let version = self.home.call("server.version", json!({})).ok().and_then(|v| v["rex_version"].as_str().map(|v| format!("rex {v}")));
                Ok(json!({ "version": version, "installed_by": "rex", "backend": "rex", "endpoint": self.home.endpoint.origin }))
            }
            other => Err(rpc("unsupported", format!("{other} isn't available with a Rex server"))),
        }
    }

    fn subscribe(&self) -> Result<(u32, async_channel::Receiver<Stream>, Value)> {
        let (tx, rx) = async_channel::unbounded();
        // Subscribed first: whatever changes while the snapshot is read comes after its seq.
        let seq = {
            let mut hub = self.hub.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            hub.subscribers.push(tx);
            hub.seq
        };
        let terminals: Vec<Value> = self.servers().iter().flat_map(|s| s.records(true)).collect();
        let channel = self.next_channel.fetch_add(1, Ordering::Relaxed);
        Ok((channel, rx, json!({ "channel": channel, "seq": seq, "terminals": terminals })))
    }

    fn attach(&self, terminal: &str, cols: u16, rows: u16, _display: Value) -> Result<Attached> {
        let (server, local) = self.route(terminal)?;
        let channel = self.next_channel.fetch_add(1, Ordering::Relaxed);
        let attached = server.attach(channel, local, cols, rows)?;
        self.routes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(channel, server);
        Ok(attached)
    }

    fn input(&self, channel: u32, bytes: &[u8]) {
        if let Some(server) = self.channel(channel)
            && let Some((session, block)) = server.channel(channel)
        {
            server.send(Input::Write { session, block, data: String::from_utf8_lossy(bytes).into_owned() });
        }
    }

    /// Rex's terminal answers device queries itself: the display copy never does.
    fn reply(&self, _channel: u32, _bytes: &[u8]) {}

    fn credit(&self, _channel: u32, _n: usize) {}

    fn resize(&self, channel: u32, cols: u16, rows: u16) {
        if let Some(server) = self.channel(channel)
            && let Some((session, block)) = server.channel(channel)
        {
            server.send(Input::Resize { session, block, cols, rows });
        }
    }

    fn focus(&self, channel: u32, focused: bool) {
        if focused
            && let Some(server) = self.channel(channel)
            && let Some((session, block)) = server.channel(channel)
        {
            server.send(Input::Focus { session, block });
        }
    }

    fn detach(&self, channel: u32) {
        let Some(server) = self.routes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&channel) else { return };
        if let Some(c) = server.lock().channels.remove(&channel) {
            c.stop.store(true, Ordering::Relaxed);
            if let Some(stopper) = c.stopper.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref() {
                stopper.stop();
            }
        }
    }

    fn lost(&self) -> async_channel::Receiver<()> {
        self.home.control.lost()
    }

    fn close(&self) {
        self.hosts.stop.store(true, Ordering::Relaxed);
        for server in self.servers() {
            server.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Axis;
    use crate::mirror::Document;
    use crate::model::{Model, Tab};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    /// A Rex server of the test's own: its socket, state and config in a
    /// fresh folder, so nothing touches the person's sessions.
    struct Server {
        child: Child,
        dir: PathBuf,
        endpoint: Endpoint,
        /// `127.0.0.1:<port>`, when it also listens on TCP.
        address: Option<String>,
    }

    impl Server {
        fn start() -> Server {
            Server::start_with(false)
        }

        /// One that other servers' clients reach over TCP, as a Rex host.
        fn start_with(tcp: bool) -> Server {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!("herdr-rex-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("init.lua"), "").unwrap();
            let origin = format!("unix://{}", dir.join("rex.sock").display());
            let address = tcp.then(|| {
                let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                reserved.local_addr().unwrap().to_string()
            });
            let mut command = Command::new("rex");
            command.args(["server", "run", "--restore=false", "--listen", &origin, "--state-dir"]).arg(dir.join("state")).arg("--config").arg(dir.join("init.lua"));
            if let Some(address) = &address {
                command.args(["--extra-listen", &format!("http://{address}"), "--allow-anonymous"]);
            }
            let child = command
                .env("SHELL", "/bin/sh")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("rex on PATH");
            let endpoint = Endpoint::parse(&origin).unwrap();
            let server = Server { child, dir, endpoint, address };
            let deadline = Instant::now() + Duration::from_secs(10);
            while Control::connect(&server.endpoint, "herdr-test").is_err() {
                assert!(Instant::now() < deadline, "the isolated Rex server didn't start");
                std::thread::sleep(Duration::from_millis(50));
            }
            server
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn until(what: &str, mut ok: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ok() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn write(core: &Core, model: &Model) {
        let version = core.call("doc.get", json!({ "name": "herdr-app" })).unwrap()["version"].clone();
        let value = serde_json::to_value(Document::capture(model, None)).unwrap();
        core.call("doc.set", json!({ "name": "herdr-app", "version": version, "value": value })).unwrap();
    }

    fn document(core: &Core) -> Value {
        core.call("doc.get", json!({ "name": "herdr-app" })).unwrap()["value"].clone()
    }

    /// Every terminal in a projected tab, in tree order.
    fn terminals(node: &Value, out: &mut Vec<String>) {
        if let Some(t) = node.pointer("/content/terminal").and_then(Value::as_str) {
            out.push(t.to_owned());
        }
        for child in node["children"].as_array().into_iter().flatten() {
            terminals(child, out);
        }
    }

    fn tab_terminals(doc: &Value, space: usize, tab: usize) -> Vec<String> {
        let mut out = Vec::new();
        terminals(&doc["spaces"][space]["tabs"][tab]["root"], &mut out);
        out
    }

    #[test]
    #[ignore = "starts an isolated Rex server: needs `rex` on PATH"]
    fn herdr_drives_its_own_rex_server_as_spaces_tabs_and_panes() {
        let server = Server::start();
        let core = connect_to(server.endpoint.clone(), server.dir.join("rex.json")).unwrap();
        let rex = Control::connect(&server.endpoint, "herdr-test-observer").unwrap();
        let rex_call = |method: &str, payload: Value| rex.call(method, payload, CALL).unwrap();
        let sessions = || rex_call("session.list", json!({}))["sessions"].as_array().cloned().unwrap_or_default();
        let view = |i: usize| {
            let session = sessions()[i]["session_id"].clone();
            rex_call("session.attach", json!({ "session_id": session }))["view"].clone()
        };
        assert_eq!(document(&core)["spaces"], json!([]));
        let (_, events, _) = core.subscribe().unwrap();

        // A space with one terminal: a session, a window, a block.
        let labels = json!({ "herdr.space": "p1", "herdr.tab": "c1" });
        let t1 = core.run(vec![], Some("/tmp".into()), labels.clone(), None).unwrap();
        let mut model = Model::default();
        model.add_space("p1", "work", "/tmp", Tab::new("c1", "", "x1", &t1));
        write(&core, &model);
        assert_eq!(sessions().len(), 1);
        assert_eq!(sessions()[0]["label"], "work");
        let doc = document(&core);
        assert_eq!(doc["spaces"][0]["id"], "p1", "Herdr's ids survive the round trip");
        assert_eq!(doc["spaces"][0]["tabs"][0]["id"], "c1");
        assert_eq!(tab_terminals(&doc, 0, 0), [t1.clone()]);
        assert!(std::iter::from_fn(|| events.try_recv().ok()).any(|e| matches!(e, Stream::Data(d) if String::from_utf8_lossy(&d).contains("\"created\""))));

        // Its stream: the snapshot first, then what the program prints.
        let attached = core.attach(&t1, 80, 24, json!({})).unwrap();
        let mut seen = Vec::new();
        let mut snapshot = false;
        until("the snapshot", || {
            while let Ok(item) = attached.stream.try_recv() {
                snapshot |= matches!(item, Stream::Snapshot(ref b) if b.starts_with(b"GHOSTSNP"));
            }
            snapshot
        });
        // Any shell (Rex starts the person's own): only the output reads herdr-42.
        core.input(attached.channel, b"printf 'herdr-%s\\n' 42\r");
        until("the program's output", || {
            while let Ok(item) = attached.stream.try_recv() {
                if let Stream::Data(b) = item {
                    seen.extend(b);
                }
            }
            String::from_utf8_lossy(&seen).contains("herdr-42")
        });

        // Split right: a horizontal split in the same window.
        let t2 = core.run(vec![], Some("/tmp".into()), labels.clone(), None).unwrap();
        assert!(model.split("x1", Axis::Row, "x2", &t2));
        write(&core, &model);
        let layout = &view(0)["windows"][0]["layers"][0]["layout"];
        assert_eq!(layout["split"]["direction"], "horizontal");
        assert_eq!(tab_terminals(&document(&core), 0, 0), [t1.clone(), t2.clone()]);

        // Close that pane: the block goes and the window holds one again.
        model.remove_pane("x2");
        write(&core, &model);
        core.call("terminal.kill", json!({ "terminal": t2 })).unwrap();
        until("the closed terminal to go", || core.call("terminal.get", json!({ "terminal": t2 })).is_err());
        assert!(view(0)["windows"][0]["layers"][0]["layout"]["block_id"].is_string());

        // A named tab is a second window, in order.
        let t3 = core.run(vec!["sh".into()], Some("/tmp".into()), json!({ "herdr.space": "p1", "herdr.tab": "c2" }), None).unwrap();
        model.add_tab("p1", Tab::new("c2", "logs", "x3", &t3));
        write(&core, &model);
        let windows = view(0)["windows"].as_array().cloned().unwrap();
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[1]["label"], "logs");
        assert_eq!(document(&core)["spaces"][0]["tabs"][1]["id"], "c2");

        // Another client's change reaches Herdr's document.
        let window = windows[1]["window_id"].clone();
        rex_call("session.set_window_label", json!({ "session_id": sessions()[0]["session_id"], "window_id": window, "label": "build" }));
        until("the rename from another client", || document(&core)["spaces"][0]["tabs"][1]["name"] == "build");

        // Closing the space destroys the session.
        model.remove_space("p1");
        write(&core, &model);
        until("the session to go", || sessions().is_empty());
        core.detach(attached.channel);
    }

    #[test]
    fn host_endpoints_and_names_follow_the_rex_cli() {
        assert_eq!(endpoint_candidates("studio.tail1234.ts.net"), ["wss://studio.tail1234.ts.net"]);
        assert_eq!(endpoint_candidates("192.168.1.20:7297"), ["ws://192.168.1.20:7297", "wss://192.168.1.20:7297"]);
        assert_eq!(endpoint_candidates("wss://rex.example"), ["wss://rex.example"]);
        assert_eq!(label_for("studio.tail1234.ts.net"), "studio");
        assert_eq!(label_for("192.168.1.20:7297"), "192.168.1.20");
        assert_eq!(label_for("wss://attic.example:443"), "attic");
        assert_eq!(label_for("[::1]:7297"), "::1");
    }

    fn cli(core: &Core, args: &[&str]) -> (i32, Value) {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let (code, out, _) = crate::hc::machine_cli(core, &args);
        (code, serde_json::from_str(&out).unwrap())
    }

    #[test]
    #[ignore = "starts two isolated Rex servers: needs `rex` on PATH"]
    fn rex_hosts_are_herdrs_machines_with_their_own_spaces() {
        let home = Server::start();
        let studio = Server::start_with(true);
        let core = connect_to(home.endpoint.clone(), home.dir.join("rex.json")).unwrap();
        assert_eq!(cli(&core, &["machine", "ls", "--json"]), (0, json!({ "machines": [] })));

        // Added by address: Rex's own host list holds it, and Herdr connects.
        let address = studio.address.clone().unwrap();
        let (code, added) = cli(&core, &["machine", "add", &address, "--name", "studio", "--json"]);
        assert_eq!(code, 0, "{added}");
        assert_eq!(added["state"], "connected", "{added}");
        let rex = Control::connect(&home.endpoint, "herdr-test-observer").unwrap();
        let hosts = rex.call("hosts.list", json!({}), CALL).unwrap();
        assert_eq!(hosts["hosts"][0]["label"], "studio");
        assert_eq!(hosts["hosts"][0]["endpoints"], json!([address]));
        let (code, error) = cli(&core, &["machine", "add", "127.0.0.1:1", "--json"]);
        assert_eq!(code, 1);
        assert!(error["error"]["message"].as_str().unwrap().contains("Can't reach"), "{error}");

        // A space there is a session on that server; its terminals are studio/….
        let t = core.run(vec![], Some("/tmp".into()), json!({ "herdr.space": "p1", "herdr.tab": "c1" }), Some("studio")).unwrap();
        assert!(t.starts_with("studio/"), "{t}");
        let mut model = Model::default();
        model.add_space("p1", "remote", "/tmp", Tab::new("c1", "", "x1", t.strip_prefix("studio/").unwrap()));
        let doc = |on: &str| core.call("doc.get", json!({ "name": "herdr-app", "on": on })).unwrap();
        let value = serde_json::to_value(Document::capture(&model, None)).unwrap();
        core.call("doc.set", json!({ "name": "herdr-app", "on": "studio", "version": doc("studio")["version"], "value": value })).unwrap();
        let there = Control::connect(&studio.endpoint, "herdr-test-observer").unwrap();
        let sessions = there.call("session.list", json!({}), CALL).unwrap();
        assert_eq!(sessions["sessions"][0]["label"], "remote");
        assert_eq!(rex.call("session.list", json!({}), CALL).unwrap()["sessions"], json!([]), "nothing on the home server");
        assert_eq!(doc("studio")["value"]["spaces"][0]["id"], "p1");
        let listed = core.call("terminal.list", json!({})).unwrap();
        assert!(listed["terminals"].as_array().unwrap().iter().any(|r| r["address"] == t), "{listed}");
        let attached = core.attach(&t, 80, 24, json!({})).unwrap();
        until("the remote snapshot", || matches!(attached.stream.try_recv(), Ok(Stream::Snapshot(_))));

        // Renamed and removed through the same `hc machine` calls the mods make.
        assert_eq!(cli(&core, &["machine", "rename", "studio", "attic"]).1["name"], "attic");
        assert_eq!(rex.call("hosts.list", json!({}), CALL).unwrap()["hosts"][0]["label"], "attic");
        assert_eq!(cli(&core, &["machine", "rm", "attic"]).0, 0);
        assert_eq!(rex.call("hosts.list", json!({}), CALL).unwrap()["hosts"], json!([]));
        assert_eq!(there.call("session.list", json!({}), CALL).unwrap()["sessions"].as_array().map(Vec::len), Some(1), "its sessions keep running");

        // Closing (switching backends) ends the connection at once.
        let lost = core.closed();
        core.close();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut lost = Box::pin(lost);
        let waker = std::task::Waker::noop();
        while std::future::Future::poll(lost.as_mut(), &mut std::task::Context::from_waker(waker)).is_pending() {
            assert!(Instant::now() < deadline, "the link didn't close");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
