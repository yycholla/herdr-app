//! Rex sessions as Herdr's layout document, and the Rex calls that make the
//! sessions match a document Herdr wrote. Pure data. See docs/rex.md.
//!
//! # Mapping
//!
//! - A session is a space (`session.list` order), a window a tab (window
//!   order), the window's tiled layer the tab's pane tree, a terminal block
//!   (creator `com.superlogical.terminal`) a terminal pane.
//! - Ids: Herdr's own id from [`Aliases`] when one is bound, else the Rex id.
//!   A pane's id is the Herdr id bound to `pane:<block id>` (see
//!   [`bind_panes`]), else `pane-<block id>`. A tab's root is a row whose id is
//!   the tab's, as Herdr makes them; inner containers take the Rex split id.
//! - A split is a row (`horizontal`) or column (`vertical`) of two children
//!   sized `{"weight": ratio}` and `{"weight": 1 - ratio}`, Herdr's proportional
//!   size. Nested splits stay nested (one container per split); a horizontal
//!   split at the root shares the root row.
//! - Window labels Rex made (`Window 89abcdef`) show as unnamed tabs.
//! - Floating layers can't be drawn faithfully by Herdr's `floating` (one block
//!   snapped to an edge), and non-terminal blocks have no Herdr content, so
//!   neither is projected: a tab shows its tiled tree without non-terminal
//!   blocks (their splits collapse). `plan` never moves, detaches or closes
//!   them, and never closes a window or destroys a session that holds one.
//!
//! # Planning
//!
//! Herdr's n-ary rows and columns and Rex's binary splits are compared in one
//! normal form: same-direction nesting flattens into one list of children
//! whose weights sum to 1, so any nesting of one arrangement matches, and
//! `plan(views, project(views))` is empty. Steps are only the next ones: the
//! caller runs them in order, reads the views again and plans again. In one
//! call each window gets one kind of change (removals, one rearrangement, one
//! insertion, or its resizes), and no window is changed by two windows' steps,
//! so every step is valid when its turn comes. Per window:
//!
//! 1. Terminals no space wants leave (`block.close` for placeholders, else
//!    `session.detach_block`), but never the window's last block.
//! 2. With none of its wanted blocks in place yet, it's seeded beside its
//!    first block (a placeholder, or blocks on their way out).
//! 3. Blocks in place but arranged differently: a swap when only places
//!    differ, one move when a single block is out of place, else all but one
//!    are detached and placed again.
//! 4. Missing panes go in shallowest first: new terminals with
//!    `session.new_split` (beside a block or a split), existing blocks (other
//!    windows, detached) with `session.move_block`. Rex moves blocks only
//!    beside blocks, so when the only anchor is a split, all but one of its
//!    blocks are detached first and placed again afterwards.
//! 5. Splits whose ratio is off by more than 0.01 are resized.
//!
//! Blocks can't move between sessions: a terminal the document puts in
//! another space stays where it is.

use crate::layout::{Axis, Content, Kind, Node, Size};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The creator of terminal blocks: the only blocks Herdr shows.
pub const TERMINAL_CREATOR: &str = "com.superlogical.terminal";
/// The flavor of terminals Herdr creates.
pub const SHELL_FLAVOR: &str = "com.superlogical.terminal.shell";
/// [`Aliases`] key prefix binding Herdr pane ids to the blocks they show.
pub const PANE_KEY: &str = "pane:";
/// A ratio this close to the wanted one is left alone.
const RATIO_SLACK: f64 = 0.01;
/// Ratios Rex is asked for stay in this range.
const MIN_RATIO: f64 = 0.05;
const MAX_RATIO: f64 = 0.95;

/// Ids Herdr chose for things before Rex made them, both ways, so a space,
/// tab, pane or terminal keeps its Herdr id after Rex creates it.
#[derive(Clone, Debug, Default)]
pub struct Aliases {
    /// Herdr id → Rex id (session, window, block).
    pub to_rex: HashMap<String, String>,
    /// Rex id → Herdr id.
    pub to_herdr: HashMap<String, String>,
}

impl Aliases {
    pub fn bind(&mut self, herdr: &str, rex: &str) {
        self.to_rex.insert(herdr.to_owned(), rex.to_owned());
        self.to_herdr.insert(rex.to_owned(), herdr.to_owned());
    }
    pub fn herdr<'a>(&'a self, rex: &'a str) -> &'a str {
        self.to_herdr.get(rex).map_or(rex, String::as_str)
    }
    pub fn rex<'a>(&'a self, herdr: &'a str) -> &'a str {
        self.to_rex.get(herdr).map_or(herdr, String::as_str)
    }
}

/// What Herdr keeps about a space that Rex doesn't: by session id.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpaceExtra {
    pub folder: String,
    /// Herdr named it automatically: show it unnamed though Rex gave it a label.
    pub unnamed: bool,
}

/// A terminal Herdr asked for that Rex hasn't made yet: the `options` of a
/// `com.superlogical.terminal.shell` block and its label.
#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    pub options: Value,
    pub label: String,
}

/// What a step's result names, so later steps and documents find it.
#[derive(Clone, Debug, PartialEq)]
pub enum Bind {
    None,
    /// `session.create`: result `session_id` is this space.
    Session { space: String },
    /// `session.new_window`: result `window_id` is this tab, and `block_ids`
    /// are these terminals (Herdr addresses, in layout order; None: a placeholder).
    Window { tab: String, blocks: Vec<Option<String>> },
    /// `session.new_split`/`session.new_block`: result `block_ids` (or `block_id`) are these.
    Blocks(Vec<Option<String>>),
}

/// One Rex call to make.
#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    pub method: String,
    pub payload: Value,
    pub bind: Bind,
}

/// The layout document (mirror::Document as JSON) for these session views
/// (`session.view` results, in `session.list` order).
pub fn project(views: &[Value], aliases: &Aliases, extras: &BTreeMap<String, SpaceExtra>) -> Value {
    let world = World::new(views);
    let spaces: Vec<Value> = world
        .sessions
        .iter()
        .map(|s| {
            let extra = extras.get(&s.id);
            let name = if extra.is_some_and(|e| e.unnamed) { "" } else { s.label.as_str() };
            let tabs: Vec<Value> = s
                .windows
                .iter()
                .map(|w| {
                    let id = aliases.herdr(&w.id);
                    let root = serde_json::to_value(tab_root(w, id, aliases)).unwrap_or(Value::Null);
                    json!({ "id": id, "name": tab_name(&w.label), "root": root })
                })
                .collect();
            json!({
                "id": aliases.herdr(&s.id),
                "name": name,
                "folder": extra.map_or("", |e| e.folder.as_str()),
                "tabs": tabs,
            })
        })
        .collect();
    json!({ "spaces": spaces })
}

/// Remembers which Herdr pane shows which block, for every terminal pane in
/// `desired` whose block is known, so `project` keeps Herdr's pane ids (and
/// with them focus). Call it once `plan` has nothing left to do.
pub fn bind_panes(desired: &Value, aliases: &mut Aliases) {
    let mut binds = Vec::new();
    for space in array(desired, "spaces") {
        for tab in array(space, "tabs") {
            let Some(root) = tab.get("root").and_then(|r| serde_json::from_value::<Node>(r.clone()).ok()) else { continue };
            for node in root.terminals() {
                let Some(address) = node.terminal() else { continue };
                let block = aliases.rex(address);
                let known = block != address || block.starts_with("block:");
                if known && !node.id.is_empty() && node.id != default_pane_id(block) {
                    binds.push((node.id.clone(), format!("{PANE_KEY}{block}")));
                }
            }
        }
    }
    for (pane, key) in binds {
        aliases.bind(&pane, &key);
    }
}

/// The next calls that bring the sessions closer to `desired` (a document).
/// The caller makes them, reads the views again and asks again, until this
/// returns nothing. `pending`: terminals to create, by Herdr address.
/// `placeholders`: blocks made only to hold a window open, to close once unused.
///
/// A desired terminal whose block is in no view counts as a detached block of
/// its space's session when that session's view carries `detached_block_ids`
/// (from `session.list_blocks`) naming it, or, without that field, when its
/// Rex id starts with `block:`.
pub fn plan(views: &[Value], aliases: &Aliases, desired: &Value, pending: &HashMap<String, Pending>, placeholders: &[String]) -> Vec<Step> {
    let world = World::new(views);
    let spaces = parse_desired(desired);

    // Every block the document mentions, in any space: never detached or closed.
    let mut wanted = HashSet::new();
    for space in &spaces {
        for tab in &space.tabs {
            for node in tab.root.terminals() {
                if let Some(address) = node.terminal() {
                    wanted.insert(aliases.rex(address).to_owned());
                }
            }
        }
    }

    // Spaces and tabs as sessions and windows, and each tab's panes.
    let mut resolve = Resolve { world: &world, aliases, pending, claimed: HashSet::new() };
    let mut used_sessions = HashSet::new();
    let mut used_windows = HashSet::new();
    let mut plans = Vec::new();
    for space in &spaces {
        let si = world.session_index(aliases.rex(&space.id)).filter(|si| used_sessions.insert(*si));
        let mut tabs = Vec::new();
        for tab in &space.tabs {
            let window = aliases.rex(&tab.id);
            let wi = si.and_then(|si| world.sessions[si].window_index(window)).filter(|_| used_windows.insert(window.to_owned()));
            // A tab whose window is in another session isn't made again here.
            let skip = wi.is_none() && world.window_anywhere(window);
            let tree = if skip { None } else { resolve.tree(&tab.root, si) };
            tabs.push(TabPlan { tab, wi, skip, tree });
        }
        plans.push(SpacePlan { space, si, tabs });
    }

    let mut by_window = HashMap::new();
    for sp in &plans {
        let Some(si) = sp.si else { continue };
        for tp in &sp.tabs {
            if let Some(wi) = tp.wi {
                by_window.insert(world.sessions[si].windows[wi].id.clone(), tp.tree.clone());
            }
        }
    }
    let cx = Cx { world: &world, wanted, placeholders: placeholders.iter().map(String::as_str).collect(), pending, by_window };

    let mut steps = Vec::new();
    for sp in plans.iter().filter(|sp| sp.si.is_none()) {
        let mut payload = json!({});
        if !sp.space.name.is_empty() {
            payload["label"] = json!(sp.space.name);
        }
        steps.push(Step { method: "session.create".into(), payload, bind: Bind::Session { space: sp.space.id.clone() } });
    }
    for sp in &plans {
        if let Some(si) = sp.si {
            steps.extend(cx.plan_session(si, &sp.tabs));
        }
    }
    for (si, sess) in world.sessions.iter().enumerate() {
        if used_sessions.contains(&si) {
            continue;
        }
        let keep = sess.windows.iter().any(|w| !w.protected.is_empty() || w.terminals.iter().any(|b| cx.wanted.contains(b)));
        if keep {
            for wi in 0..sess.windows.len() {
                steps.extend(cx.cleanup(si, wi));
            }
        } else {
            steps.push(call("session.destroy", json!({ "session_id": sess.id })));
        }
    }
    for sp in &plans {
        let Some(si) = sp.si else { continue };
        let sess = &world.sessions[si];
        if !sp.space.name.is_empty() && sp.space.name != sess.label {
            steps.push(call("session.set_label", json!({ "session_id": sess.id, "label": sp.space.name })));
        }
    }
    let target: Vec<&str> = plans.iter().filter_map(|sp| sp.si).map(|si| world.sessions[si].id.as_str()).collect();
    let current: Vec<&str> = world.sessions.iter().map(|s| s.id.as_str()).collect();
    for (id, before) in order_moves(&target, &current) {
        steps.push(call("session.move", json!({ "session_id": id, "before_session_id": before })));
    }
    steps
}

// ---------------------------------------------------------------------------
// Rex views

/// A layer's split tree, as `session.view` has it.
#[derive(Clone, Debug, PartialEq)]
enum Tree {
    Leaf(String),
    Split { id: String, horizontal: bool, ratio: f64, before: Box<Tree>, after: Box<Tree> },
}

impl Tree {
    fn parse(v: &Value, depth: usize) -> Option<Tree> {
        if depth > 64 {
            return None;
        }
        if let Some(block) = v.get("block_id").and_then(Value::as_str) {
            return Some(Tree::Leaf(block.to_owned()));
        }
        let split = v.get("split")?.as_object()?;
        Some(Tree::Split {
            id: split.get("split_id").and_then(Value::as_str).unwrap_or_default().to_owned(),
            // Rex: draw a direction you don't know as horizontal.
            horizontal: split.get("direction").and_then(Value::as_str) != Some("vertical"),
            ratio: split.get("ratio").and_then(Value::as_f64).filter(|r| r.is_finite() && *r > 0.0 && *r < 1.0).unwrap_or(0.5),
            before: Box::new(Tree::parse(split.get("before")?, depth + 1)?),
            after: Box::new(Tree::parse(split.get("after")?, depth + 1)?),
        })
    }

    fn id(&self) -> &str {
        match self {
            Tree::Leaf(b) => b,
            Tree::Split { id, .. } => id,
        }
    }

    fn leaves(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Tree::Leaf(b) => out.push(b),
            Tree::Split { before, after, .. } => {
                before.collect(out);
                after.collect(out);
            }
        }
    }

    fn first_leaf(&self) -> &str {
        match self {
            Tree::Leaf(b) => b,
            Tree::Split { before, .. } => before.first_leaf(),
        }
    }

    /// Without the blocks `keep` refuses; a split left with one side gives way to it, as in Rex.
    fn prune(&self, keep: &dyn Fn(&str) -> bool) -> Option<Tree> {
        match self {
            Tree::Leaf(b) => keep(b).then(|| self.clone()),
            Tree::Split { id, horizontal, ratio, before, after } => match (before.prune(keep), after.prune(keep)) {
                (Some(b), Some(a)) => Some(Tree::Split { id: id.clone(), horizontal: *horizontal, ratio: *ratio, before: Box::new(b), after: Box::new(a) }),
                (Some(only), None) | (None, Some(only)) => Some(only),
                (None, None) => None,
            },
        }
    }

    /// The smallest subtree holding every block in `set`.
    fn lca(&self, set: &HashSet<&str>) -> Option<&Tree> {
        let count = |t: &Tree| t.leaves().iter().filter(|b| set.contains(*b)).count();
        if set.is_empty() || count(self) < set.len() {
            return None;
        }
        let mut t = self;
        loop {
            match t {
                Tree::Split { before, .. } if count(before) == set.len() => t = before,
                Tree::Split { after, .. } if count(after) == set.len() => t = after,
                _ => return Some(t),
            }
        }
    }
}

struct Win {
    id: String,
    label: String,
    /// The tiled layer's tree (None: empty, or one Herdr can't read).
    tiled: Option<Tree>,
    /// Terminal blocks in the tiled tree.
    terminals: HashSet<String>,
    /// Blocks `plan` never touches: floating, non-terminal, unreadable.
    protected: HashSet<String>,
    /// How many blocks the window holds, in any layer.
    blocks: usize,
}

struct Sess {
    id: String,
    label: String,
    windows: Vec<Win>,
    /// `detached_block_ids`, when the caller added it to the view.
    detached: Option<HashSet<String>>,
}

impl Sess {
    fn window_index(&self, id: &str) -> Option<usize> {
        self.windows.iter().position(|w| w.id == id)
    }
}

struct World {
    sessions: Vec<Sess>,
    /// Each tiled terminal block's session and window.
    home: HashMap<String, (usize, usize)>,
    /// Every block in any view.
    seen: HashSet<String>,
}

impl World {
    fn new(views: &[Value]) -> World {
        let mut ids = HashSet::new();
        let sessions: Vec<Sess> = views.iter().filter_map(parse_session).filter(|s| ids.insert(s.id.clone())).collect();
        let mut home = HashMap::new();
        let mut seen = HashSet::new();
        for (si, s) in sessions.iter().enumerate() {
            for (wi, w) in s.windows.iter().enumerate() {
                for b in &w.terminals {
                    home.insert(b.clone(), (si, wi));
                    seen.insert(b.clone());
                }
                seen.extend(w.protected.iter().cloned());
            }
        }
        World { sessions, home, seen }
    }

    fn session_index(&self, id: &str) -> Option<usize> {
        self.sessions.iter().position(|s| s.id == id)
    }

    fn window_anywhere(&self, id: &str) -> bool {
        self.sessions.iter().any(|s| s.window_index(id).is_some())
    }
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn array<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn parse_session(v: &Value) -> Option<Sess> {
    let id = v.get("session_id")?.as_str()?.to_owned();
    let detached = v.get("detached_block_ids").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect());
    let mut seen = HashSet::new();
    let windows = array(v, "windows").iter().filter_map(parse_window).filter(|w| seen.insert(w.id.clone())).collect();
    Some(Sess { id, label: text(v, "label"), windows, detached })
}

fn parse_window(v: &Value) -> Option<Win> {
    let id = v.get("window_id")?.as_str()?.to_owned();
    let mut win = Win { id, label: text(v, "label"), tiled: None, terminals: HashSet::new(), protected: HashSet::new(), blocks: 0 };
    let mut all = HashSet::new();
    for (i, layer) in array(v, "layers").iter().enumerate() {
        let listed: Vec<(String, String)> = array(layer, "blocks")
            .iter()
            .filter_map(|b| Some((b.get("block_id")?.as_str()?.to_owned(), text(b, "creator_name"))))
            .collect();
        let tree = layer.get("layout").filter(|l| !l.is_null()).map(|l| Tree::parse(l, 0));
        let in_tree: Vec<String> = tree.iter().flatten().flat_map(Tree::leaves).map(str::to_owned).collect();
        all.extend(listed.iter().map(|b| b.0.clone()));
        all.extend(in_tree.iter().cloned());
        // Rex: the first layer is the tiled one; draw a kind you don't know as floating.
        let tiled = i == 0 && layer.get("kind").and_then(Value::as_str) == Some("tiled");
        if tiled && let Some(Some(t)) = tree {
            for (b, creator) in &listed {
                if creator == TERMINAL_CREATOR && in_tree.contains(b) {
                    win.terminals.insert(b.clone());
                }
            }
            win.tiled = Some(t);
        }
        let terminals = &win.terminals;
        let others: Vec<String> = listed.into_iter().map(|b| b.0).chain(in_tree).filter(|b| !terminals.contains(b)).collect();
        win.protected.extend(others);
    }
    win.blocks = all.len();
    Some(win)
}

// ---------------------------------------------------------------------------
// Projection

fn default_pane_id(block: &str) -> String {
    format!("pane-{block}")
}

fn pane_id(block: &str, aliases: &Aliases) -> String {
    aliases.to_herdr.get(&format!("{PANE_KEY}{block}")).cloned().unwrap_or_else(|| default_pane_id(block))
}

/// Rex's own window label, made from its id: `Window 89abcdef`.
fn default_window_label(label: &str) -> bool {
    label.strip_prefix("Window ").is_some_and(|s| s.len() == 8 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn tab_name(label: &str) -> &str {
    if default_window_label(label) { "" } else { label }
}

fn weighted(mut node: Node, weight: f64) -> Node {
    // Herdr keeps weights as f32.
    #[allow(clippy::cast_possible_truncation)]
    let weight = weight as f32;
    node.size = Some(Size::Weight { weight });
    node
}

fn node_of(tree: &Tree, aliases: &Aliases) -> Node {
    match tree {
        Tree::Leaf(b) => Node::block(pane_id(b, aliases), Content::Terminal { terminal: aliases.herdr(b).to_owned() }),
        Tree::Split { id, horizontal, ratio, before, after } => Node::container(
            id.clone(),
            if *horizontal { Axis::Row } else { Axis::Column },
            vec![weighted(node_of(before, aliases), *ratio), weighted(node_of(after, aliases), 1.0 - ratio)],
        ),
    }
}

fn tab_root(win: &Win, id: &str, aliases: &Aliases) -> Node {
    let shown = win.tiled.as_ref().and_then(|t| t.prune(&|b| win.terminals.contains(b)));
    let children = match &shown {
        None => vec![],
        Some(Tree::Split { horizontal: true, ratio, before, after, .. }) => {
            vec![weighted(node_of(before, aliases), *ratio), weighted(node_of(after, aliases), 1.0 - ratio)]
        }
        Some(t) => vec![node_of(t, aliases)],
    };
    Node::container(id, Axis::Row, children)
}

// ---------------------------------------------------------------------------
// The desired document

struct DesiredSpace {
    id: String,
    name: String,
    tabs: Vec<DesiredTab>,
}

struct DesiredTab {
    id: String,
    name: String,
    root: Node,
}

fn parse_desired(doc: &Value) -> Vec<DesiredSpace> {
    let mut space_ids = HashSet::new();
    let mut tab_ids = HashSet::new();
    let mut spaces = Vec::new();
    for space in array(doc, "spaces") {
        let id = text(space, "id");
        if !space_ids.insert(id.clone()) {
            continue;
        }
        let tabs = array(space, "tabs")
            .iter()
            .filter_map(|tab| {
                let id = text(tab, "id");
                tab_ids.insert(id.clone()).then(|| DesiredTab {
                    id,
                    name: text(tab, "name"),
                    root: tab
                        .get("root")
                        .and_then(|r| serde_json::from_value(r.clone()).ok())
                        .unwrap_or_else(|| Node::container("", Axis::Row, vec![])),
                })
            })
            .collect();
        spaces.push(DesiredSpace { id, name: text(space, "name"), tabs });
    }
    spaces
}

/// A pane the document wants: a Rex block (placed or detached), or a new terminal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Want {
    Block(String),
    New(String),
}

/// A pane tree in normal form: lists hold two or more children, none in the
/// list's own direction, with weights that sum to 1.
#[derive(Clone, Debug)]
enum NTree {
    Leaf(Want),
    List { horizontal: bool, kids: Vec<(f64, NTree)> },
}

fn sane(w: f64) -> f64 {
    if w.is_finite() && w > 0.0 { w } else { 1e-3 }
}

/// A list in normal form (None when empty; the child itself when alone).
fn list(horizontal: bool, kids: Vec<(f64, NTree)>) -> Option<NTree> {
    let mut flat = Vec::new();
    for (w, kid) in kids {
        let w = sane(w);
        match kid {
            NTree::List { horizontal: h, kids: inner } if h == horizontal => {
                let sum: f64 = inner.iter().map(|k| k.0).sum();
                flat.extend(inner.into_iter().map(|(iw, k)| (w * iw / sum, k)));
            }
            kid => flat.push((w, kid)),
        }
    }
    match flat.len() {
        0 => None,
        1 => flat.pop().map(|k| k.1),
        _ => {
            let sum: f64 = flat.iter().map(|k| k.0).sum();
            for k in &mut flat {
                k.0 /= sum;
            }
            Some(NTree::List { horizontal, kids: flat })
        }
    }
}

impl NTree {
    fn from_tree(tree: &Tree) -> NTree {
        match tree {
            Tree::Leaf(b) => NTree::Leaf(Want::Block(b.clone())),
            Tree::Split { horizontal, ratio, before, after, .. } => {
                list(*horizontal, vec![(*ratio, NTree::from_tree(before)), (1.0 - ratio, NTree::from_tree(after))]).unwrap_or_else(|| NTree::from_tree(before))
            }
        }
    }

    fn kids(&self) -> &[(f64, NTree)] {
        match self {
            NTree::List { kids, .. } => kids,
            NTree::Leaf(_) => &[],
        }
    }

    fn at(&self, path: &[usize]) -> &NTree {
        path.iter().fold(self, |n, &i| n.kids().get(i).map_or(n, |k| &k.1))
    }

    fn leaves(&self) -> Vec<&Want> {
        match self {
            NTree::Leaf(w) => vec![w],
            NTree::List { kids, .. } => kids.iter().flat_map(|k| k.1.leaves()).collect(),
        }
    }

    fn blocks(&self) -> Vec<&str> {
        self.leaves()
            .into_iter()
            .filter_map(|w| match w {
                Want::Block(b) => Some(b.as_str()),
                Want::New(_) => None,
            })
            .collect()
    }

    /// Every leaf with its path, in layout order.
    fn paths(&self) -> Vec<(Vec<usize>, &Want)> {
        match self {
            NTree::Leaf(w) => vec![(vec![], w)],
            NTree::List { kids, .. } => kids
                .iter()
                .enumerate()
                .flat_map(|(i, k)| {
                    k.1.paths().into_iter().map(move |(mut p, w)| {
                        p.insert(0, i);
                        (p, w)
                    })
                })
                .collect(),
        }
    }

    fn prune(&self, keep: &dyn Fn(&Want) -> bool) -> Option<NTree> {
        match self {
            NTree::Leaf(w) => keep(w).then(|| self.clone()),
            NTree::List { horizontal, kids } => list(*horizontal, kids.iter().filter_map(|(w, k)| k.prune(keep).map(|k| (*w, k))).collect()),
        }
    }

    fn any(&self, f: &dyn Fn(&Want) -> bool) -> bool {
        self.leaves().into_iter().any(f)
    }
}

/// Same arrangement (directions and child counts); with `leaves`, the same blocks in each place too.
fn same(a: &NTree, b: &NTree, leaves: bool) -> bool {
    match (a, b) {
        (NTree::Leaf(x), NTree::Leaf(y)) => !leaves || x == y,
        (NTree::List { horizontal: h1, kids: k1 }, NTree::List { horizontal: h2, kids: k2 }) => {
            h1 == h2 && k1.len() == k2.len() && k1.iter().zip(k2).all(|(x, y)| same(&x.1, &y.1, leaves))
        }
        _ => false,
    }
}

struct Resolve<'a> {
    world: &'a World,
    aliases: &'a Aliases,
    pending: &'a HashMap<String, Pending>,
    /// Blocks and new terminals the document already placed: the first place wins.
    claimed: HashSet<String>,
}

impl Resolve<'_> {
    /// The tab's panes `plan` can place in session `si` (None: a session to create).
    fn tree(&mut self, node: &Node, si: Option<usize>) -> Option<NTree> {
        match &node.kind {
            Kind::Block { content: Content::Terminal { terminal } } => self.leaf(terminal, si).map(NTree::Leaf),
            // Mods, tab and agent blocks have no Rex block.
            Kind::Block { .. } => None,
            Kind::Row { children } | Kind::Stack { children, .. } | Kind::Column { children } => {
                let kids = children
                    .iter()
                    .filter_map(|c| {
                        let weight = match c.size {
                            Some(Size::Weight { weight }) => f64::from(weight),
                            _ => 1.0,
                        };
                        self.tree(c, si).map(|t| (weight, t))
                    })
                    .collect();
                list(!matches!(node.kind, Kind::Column { .. }), kids)
            }
        }
    }

    fn leaf(&mut self, address: &str, si: Option<usize>) -> Option<Want> {
        let block = self.aliases.rex(address);
        if let Some(&(s, _)) = self.world.home.get(block) {
            // Blocks can't move between sessions; one placed twice stays at its first place.
            return (Some(s) == si && self.claimed.insert(block.to_owned())).then(|| Want::Block(block.to_owned()));
        }
        if self.world.seen.contains(block) {
            return None;
        }
        let pending = self.pending.contains_key(address);
        let Some(si) = si else {
            return (pending && self.claimed.insert(address.to_owned())).then(|| Want::New(address.to_owned()));
        };
        let detached = match &self.world.sessions[si].detached {
            Some(set) => set.contains(block),
            None => block.starts_with("block:"),
        };
        let bound = self.aliases.to_rex.contains_key(address);
        if detached && (bound || !pending) {
            return self.claimed.insert(block.to_owned()).then(|| Want::Block(block.to_owned()));
        }
        (pending && self.claimed.insert(address.to_owned())).then(|| Want::New(address.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Planning

struct SpacePlan<'d> {
    space: &'d DesiredSpace,
    si: Option<usize>,
    tabs: Vec<TabPlan<'d>>,
}

struct TabPlan<'d> {
    tab: &'d DesiredTab,
    wi: Option<usize>,
    skip: bool,
    tree: Option<NTree>,
}

enum Outcome {
    Idle,
    /// Steps for one window, the windows they change, and whether one of
    /// them may close a window the document keeps.
    Do { steps: Vec<Step>, touch: Vec<usize>, empties: bool },
    /// A move that would empty a tab able to fill itself first.
    Defer { step: Step },
}

fn call(method: &str, payload: Value) -> Step {
    Step { method: method.into(), payload, bind: Bind::None }
}

fn direction(horizontal: bool) -> &'static str {
    if horizontal { "horizontal" } else { "vertical" }
}

fn side(after: bool) -> &'static str {
    if after { "after" } else { "before" }
}

fn clamp(ratio: f64) -> f64 {
    if ratio.is_finite() { ratio.clamp(MIN_RATIO, MAX_RATIO) } else { 0.5 }
}

/// The ratio of a split putting `moved` beside `anchor` (weights in their list).
fn split_ratio(anchor: f64, moved: f64, after: bool) -> f64 {
    clamp(if after { anchor / (anchor + moved) } else { moved / (anchor + moved) })
}

/// Moves (id, before id) that put `current`'s members of `target` in `target`'s order.
fn order_moves<'a>(target: &[&'a str], current: &[&'a str]) -> Vec<(&'a str, &'a str)> {
    let mut cur: Vec<&str> = current.iter().copied().filter(|c| target.contains(c)).collect();
    let mut moves = Vec::new();
    for (i, want) in target.iter().enumerate() {
        if cur.get(i) == Some(want) {
            continue;
        }
        let (Some(at), Some(&before)) = (cur.iter().position(|c| c == want), cur.get(i)) else { continue };
        cur.remove(at);
        cur.insert(i, want);
        moves.push((*want, before));
    }
    moves
}

/// A `new_window`/`new_split` layout of new terminals, right-nested, and their addresses in layout order.
fn layout_of(tree: &NTree, pending: &HashMap<String, Pending>) -> (Value, Vec<Option<String>>) {
    match tree {
        NTree::Leaf(Want::New(address)) => {
            let mut block = json!({ "flavor": SHELL_FLAVOR });
            if let Some(p) = pending.get(address) {
                if !p.options.is_null() {
                    block["options"] = p.options.clone();
                }
                if !p.label.is_empty() {
                    block["label"] = json!(p.label);
                }
            }
            (json!({ "block": block }), vec![Some(address.clone())])
        }
        // Only new terminals are laid out; anything else would be a placeholder.
        NTree::Leaf(Want::Block(_)) => (placeholder_layout(), vec![None]),
        NTree::List { horizontal, kids } => chain(*horizontal, kids, pending),
    }
}

fn chain(horizontal: bool, kids: &[(f64, NTree)], pending: &HashMap<String, Pending>) -> (Value, Vec<Option<String>>) {
    let Some((first, rest)) = kids.split_first() else { return (placeholder_layout(), vec![None]) };
    if rest.is_empty() {
        return layout_of(&first.1, pending);
    }
    let total: f64 = kids.iter().map(|k| k.0).sum();
    let (before, mut blocks) = layout_of(&first.1, pending);
    let (after, more) = chain(horizontal, rest, pending);
    blocks.extend(more);
    let split = json!({ "direction": direction(horizontal), "ratio": clamp(first.0 / total), "before": before, "after": after });
    (json!({ "split": split }), blocks)
}

fn placeholder_layout() -> Value {
    json!({ "block": { "flavor": SHELL_FLAVOR } })
}

/// Where missing panes go: the list at `path` (their nearest ancestor holding
/// a placed block), their child `m` of it, and the nearest children before and
/// after it that hold placed blocks.
struct Slot {
    path: Vec<usize>,
    m: usize,
    prev: Option<usize>,
    next: Option<usize>,
}

fn slot(d: &NTree, leaf: &[usize], placed: &dyn Fn(&Want) -> bool) -> Option<Slot> {
    for len in (0..leaf.len()).rev() {
        let list = d.at(&leaf[..len]);
        if !list.any(placed) {
            continue;
        }
        let kids = list.kids();
        let m = leaf[len];
        let holds = |j: &usize| kids[*j].1.any(placed);
        return Some(Slot { path: leaf[..len].to_vec(), m, prev: (0..m).rev().find(holds), next: (m + 1..kids.len()).find(holds) });
    }
    None
}

/// A place to split beside: a block or a split, and the placed blocks under it.
struct Anchor {
    id: String,
    block: bool,
    after: bool,
    weight: f64,
    blocks: Vec<String>,
}

fn anchor(d: &NTree, slot: &Slot, j: usize, after: bool, placed: &dyn Fn(&Want) -> bool, tiled: &Tree) -> Option<Anchor> {
    let NTree::List { horizontal, kids } = d.at(&slot.path) else { return None };
    let (weight, kid) = kids.get(j)?;
    let mut node = kid.prune(placed)?;
    // A child that merged into this list's direction: split beside its nearest member.
    loop {
        let inner = match &node {
            NTree::List { horizontal: h, kids: inner } if h == horizontal => if after { inner.last() } else { inner.first() }.map(|k| k.1.clone()),
            _ => None,
        };
        match inner {
            Some(inner) => node = inner,
            None => break,
        }
    }
    let blocks: Vec<String> = node.blocks().into_iter().map(str::to_owned).collect();
    let (id, block) = match &node {
        NTree::Leaf(Want::Block(b)) => (b.clone(), true),
        NTree::Leaf(Want::New(_)) => return None,
        NTree::List { .. } => (tiled.lca(&blocks.iter().map(String::as_str).collect())?.id().to_owned(), false),
    };
    Some(Anchor { id, block, after, weight: *weight, blocks })
}

/// Resizes giving the splits of `real` (pruned to the placed blocks, in the
/// same arrangement as `d`) `d`'s weights: (horizontal, before, after, ratio).
fn resizes(real: &Tree, d: &NTree, out: &mut Vec<(bool, String, String, f64)>) {
    let NTree::List { horizontal, kids } = d else { return };
    let weights: Vec<f64> = kids.iter().map(|k| k.0).collect();
    let mut members = Vec::new();
    visit_chain(real, *horizontal, 0, &weights, out, &mut members);
    if members.len() != kids.len() {
        return;
    }
    for (member, kid) in members.into_iter().zip(kids) {
        resizes(member, &kid.1, out);
    }
}

/// Walks the splits of one direction under `node` (one list in normal form),
/// collecting the list's members; returns how many it covers.
fn visit_chain<'t>(node: &'t Tree, horizontal: bool, start: usize, weights: &[f64], out: &mut Vec<(bool, String, String, f64)>, members: &mut Vec<&'t Tree>) -> usize {
    match node {
        Tree::Split { horizontal: h, ratio, before, after, .. } if *h == horizontal => {
            let left = visit_chain(before, horizontal, start, weights, out, members);
            let right = visit_chain(after, horizontal, start + left, weights, out, members);
            let sum = |a: usize, b: usize| weights.get(a..b).map_or(0.0, |w| w.iter().sum::<f64>());
            let total = sum(start, start + left + right);
            if total > 0.0 {
                let want = clamp(sum(start, start + left) / total);
                if (ratio - want).abs() > RATIO_SLACK {
                    out.push((horizontal, before.first_leaf().to_owned(), after.first_leaf().to_owned(), want));
                }
            }
            left + right
        }
        _ => {
            members.push(node);
            1
        }
    }
}

struct Cx<'a> {
    world: &'a World,
    wanted: HashSet<String>,
    placeholders: HashSet<&'a str>,
    pending: &'a HashMap<String, Pending>,
    /// The wanted panes of every window the document keeps.
    by_window: HashMap<String, Option<NTree>>,
}

impl Cx<'_> {
    fn session(&self, si: usize) -> &Sess {
        &self.world.sessions[si]
    }

    fn remove(&self, si: usize, block: &str) -> Step {
        let sid = &self.session(si).id;
        if self.placeholders.contains(block) {
            call("block.close", json!({ "session_id": sid, "block_id": block }))
        } else {
            call("session.detach_block", json!({ "session_id": sid, "block_id": block }))
        }
    }

    fn detach_all(&self, si: usize, wi: usize, blocks: &[String]) -> Outcome {
        if blocks.is_empty() {
            return Outcome::Idle;
        }
        let sid = &self.session(si).id;
        let steps = blocks.iter().map(|b| call("session.detach_block", json!({ "session_id": sid, "block_id": b }))).collect();
        Outcome::Do { steps, touch: vec![wi], empties: false }
    }

    /// A window the document doesn't keep: closed, unless it holds blocks
    /// wanted elsewhere (they move out first) or protected ones (then only
    /// its unwanted terminals leave, and the window stays).
    fn cleanup(&self, si: usize, wi: usize) -> Vec<Step> {
        let win = &self.session(si).windows[wi];
        if !win.protected.is_empty() {
            let mut unwanted: Vec<&String> = win.terminals.iter().filter(|b| !self.wanted.contains(*b)).collect();
            unwanted.sort();
            return unwanted.into_iter().map(|b| self.remove(si, b)).collect();
        }
        if win.terminals.iter().any(|b| self.wanted.contains(b)) {
            return vec![];
        }
        vec![call("session.close_window", json!({ "session_id": self.session(si).id, "window_id": win.id }))]
    }

    fn plan_session(&self, si: usize, tabs: &[TabPlan<'_>]) -> Vec<Step> {
        let sess = self.session(si);
        let kept: HashSet<usize> = tabs.iter().filter_map(|t| t.wi).collect();
        let mut touched = HashSet::new();
        let mut structural = Vec::new();
        for wi in (0..sess.windows.len()).filter(|wi| !kept.contains(wi)) {
            let steps = self.cleanup(si, wi);
            if !steps.is_empty() {
                touched.insert(wi);
                structural.extend(steps);
            }
        }
        let mut empties = false;
        let mut deferred = Vec::new();
        for tp in tabs {
            let Some(wi) = tp.wi else { continue };
            match self.plan_window(si, wi, tp.tree.as_ref()) {
                Outcome::Do { steps, touch, empties: e } if touch.iter().all(|w| !touched.contains(w)) => {
                    touched.extend(touch);
                    structural.extend(steps);
                    empties |= e;
                }
                Outcome::Defer { step } => deferred.push(step),
                _ => {}
            }
        }
        // Every tab waits on another: let the first go.
        if structural.is_empty()
            && let Some(step) = deferred.into_iter().next()
        {
            structural.push(step);
            empties = true;
        }
        let mut steps = structural;
        for tp in tabs.iter().filter(|t| t.wi.is_none() && !t.skip) {
            let (layout, blocks) = match tp.tree.as_ref().and_then(|t| t.prune(&|w| matches!(w, Want::New(_)))) {
                Some(new) => layout_of(&new, self.pending),
                None => (placeholder_layout(), vec![None]),
            };
            let mut payload = json!({ "session_id": sess.id, "layout": layout, "focus": false });
            if !tp.tab.name.is_empty() {
                payload["window_label"] = json!(tp.tab.name);
            }
            steps.push(Step { method: "session.new_window".into(), payload, bind: Bind::Window { tab: tp.tab.id.clone(), blocks } });
        }
        // A window a move may close this round can't be named yet.
        if empties {
            return steps;
        }
        for tp in tabs {
            let Some(wi) = tp.wi else { continue };
            let win = &sess.windows[wi];
            let name = &tp.tab.name;
            let rename = if name.is_empty() { !default_window_label(&win.label) } else { *name != win.label };
            if rename {
                steps.push(call("session.set_window_label", json!({ "session_id": sess.id, "window_id": win.id, "label": name })));
            }
        }
        let target: Vec<&str> = tabs.iter().filter_map(|t| t.wi).map(|wi| sess.windows[wi].id.as_str()).collect();
        let current: Vec<&str> = sess.windows.iter().map(|w| w.id.as_str()).collect();
        for (id, before) in order_moves(&target, &current) {
            steps.push(call("session.move_window", json!({ "session_id": sess.id, "window_id": id, "before_window_id": before })));
        }
        steps
    }

    /// Moves block `x` beside block `anchor`, in window `wi`.
    #[allow(clippy::too_many_arguments)]
    fn move_to(&self, si: usize, wi: usize, x: &str, anchor: &str, horizontal: bool, after: bool, ratio: f64) -> Outcome {
        let sess = self.session(si);
        let step = call(
            "session.move_block",
            json!({
                "session_id": sess.id,
                "block_id": x,
                "anchor_block_id": anchor,
                "direction": direction(horizontal),
                "side": side(after),
                "ratio": clamp(ratio),
            }),
        );
        let mut touch = vec![wi];
        let mut empties = false;
        if let Some(&(s2, w2)) = self.world.home.get(x)
            && s2 == si
            && w2 != wi
        {
            touch.push(w2);
            let src = &sess.windows[w2];
            if src.blocks == 1 {
                match self.by_window.get(&src.id) {
                    Some(Some(d)) => {
                        // The source tab can fill itself from somewhere else first.
                        let can_seed = d.any(&|w| match w {
                            Want::New(_) => true,
                            Want::Block(b) => self.world.home.get(b).is_none_or(|&(_, w3)| w3 != wi),
                        });
                        if can_seed {
                            return Outcome::Defer { step };
                        }
                        empties = true;
                    }
                    Some(None) => empties = true,
                    None => {}
                }
            }
        }
        Outcome::Do { steps: vec![step], touch, empties }
    }

    /// Creates the new terminals `panes` beside block or split `anchor`, in window `wi`.
    #[allow(clippy::too_many_arguments)]
    fn new_split(&self, si: usize, wi: usize, anchor: &str, horizontal: bool, after: bool, ratio: f64, panes: &NTree) -> Outcome {
        let (layout, blocks) = layout_of(panes, self.pending);
        let payload = json!({
            "session_id": self.session(si).id,
            "anchor_id": anchor,
            "direction": direction(horizontal),
            "side": side(after),
            "ratio": clamp(ratio),
            "layout": layout,
        });
        Outcome::Do { steps: vec![Step { method: "session.new_split".into(), payload, bind: Bind::Blocks(blocks) }], touch: vec![wi], empties: false }
    }

    fn plan_window(&self, si: usize, wi: usize, d: Option<&NTree>) -> Outcome {
        let win = &self.session(si).windows[wi];
        let tree_blocks: Vec<&str> = win.tiled.as_ref().map(Tree::leaves).unwrap_or_default();
        let terminals: Vec<&str> = tree_blocks.iter().copied().filter(|b| win.terminals.contains(*b)).collect();
        let in_d: HashSet<&str> = d.map(NTree::blocks).unwrap_or_default().into_iter().collect();
        let present: HashSet<String> = terminals.iter().filter(|b| in_d.contains(*b)).map(|b| (*b).to_owned()).collect();

        // 1. Terminals nobody wants leave, unless that would close the window.
        let removable: Vec<&str> = terminals.iter().copied().filter(|b| !self.wanted.contains(*b)).collect();
        if !removable.is_empty() {
            if win.blocks > removable.len() {
                return Outcome::Do { steps: removable.iter().map(|b| self.remove(si, b)).collect(), touch: vec![wi], empties: false };
            }
            if d.is_none() {
                return Outcome::Idle;
            }
        }
        let (Some(d), Some(tiled)) = (d, win.tiled.as_ref()) else { return Outcome::Idle };

        // 2. Nothing wanted in place yet: start beside whatever is there.
        if present.is_empty() {
            let anchor = tiled.first_leaf();
            if let Some(x) = d.blocks().first() {
                return self.move_to(si, wi, x, anchor, true, true, 0.5);
            }
            return self.new_split(si, wi, anchor, true, true, 0.5, d);
        }

        let placed = |w: &Want| matches!(w, Want::Block(b) if present.contains(b));
        let (Some(cn), Some(dp)) = (tiled.prune(&|b| present.contains(b)).map(|t| NTree::from_tree(&t)), d.prune(&placed)) else {
            return Outcome::Idle;
        };

        // 3. The blocks in place are arranged differently.
        if !same(&cn, &dp, true) {
            return self.rearrange(si, wi, d, (&cn, &dp), &present, tiled);
        }

        // 4. Missing panes, shallowest first.
        let missing: Vec<Vec<usize>> = d.paths().into_iter().filter(|(_, w)| !placed(w)).map(|(p, _)| p).collect();
        if !missing.is_empty() {
            return self.insert(si, wi, d, &missing, &placed, tiled);
        }

        // 5. Sizes.
        let Some(real) = tiled.prune(&|b| present.contains(b)) else { return Outcome::Idle };
        let mut out = Vec::new();
        resizes(&real, d, &mut out);
        if out.is_empty() {
            return Outcome::Idle;
        }
        let sid = &self.session(si).id;
        let steps = out
            .into_iter()
            .map(|(horizontal, before, after, ratio)| {
                call(
                    "session.resize_pane",
                    json!({ "session_id": sid, "direction": direction(horizontal), "before_block_id": before, "after_block_id": after, "ratio": ratio }),
                )
            })
            .collect();
        Outcome::Do { steps, touch: vec![wi], empties: false }
    }

    fn rearrange(&self, si: usize, wi: usize, d: &NTree, (cn, dp): (&NTree, &NTree), present: &HashSet<String>, tiled: &Tree) -> Outcome {
        // Only places differ: swap the first two out of place.
        if same(cn, dp, false) {
            if let Some((Want::Block(u), Want::Block(v))) = cn.leaves().into_iter().zip(dp.leaves()).find(|(u, v)| u != v) {
                let sid = &self.session(si).id;
                let step = call("session.swap_blocks", json!({ "session_id": sid, "block_id": u, "other_block_id": v }));
                return Outcome::Do { steps: vec![step], touch: vec![wi], empties: false };
            }
            return Outcome::Idle;
        }
        // One block out of place: move it.
        for (path, want) in d.paths() {
            let Want::Block(y) = want else { continue };
            if !present.contains(y) || present.len() < 2 {
                continue;
            }
            let others = |w: &Want| matches!(w, Want::Block(b) if b != y && present.contains(b));
            let real = tiled.prune(&|b| b != y.as_str() && present.contains(b)).map(|t| NTree::from_tree(&t));
            let (Some(real), Some(rest)) = (real, d.prune(&others)) else { continue };
            if !same(&real, &rest, true) {
                continue;
            }
            let Some(slot) = slot(d, &path, &others) else { continue };
            let NTree::List { horizontal, kids } = d.at(&slot.path) else { continue };
            let anchors = [slot.prev.and_then(|j| anchor(d, &slot, j, true, &others, tiled)), slot.next.and_then(|j| anchor(d, &slot, j, false, &others, tiled))];
            if let Some(a) = anchors.iter().flatten().find(|a| a.block) {
                return self.move_to(si, wi, y, &a.id, *horizontal, a.after, split_ratio(a.weight, kids[slot.m].0, a.after));
            }
            // Rex moves blocks only beside blocks: leave one where the split is.
            if let Some(a) = anchors.iter().flatten().next() {
                return self.detach_all(si, wi, &a.blocks[1..]);
            }
        }
        // Anything else: keep the first block and place the rest again.
        let mut rest: Vec<String> = d.blocks().into_iter().filter(|b| present.contains(*b)).map(str::to_owned).collect();
        rest.remove(0);
        self.detach_all(si, wi, &rest)
    }

    fn insert(&self, si: usize, wi: usize, d: &NTree, missing: &[Vec<usize>], placed: &dyn Fn(&Want) -> bool, tiled: &Tree) -> Outcome {
        let best = missing.iter().filter_map(|p| slot(d, p, placed)).enumerate().min_by_key(|(order, s)| (s.path.len(), *order));
        let Some((_, slot)) = best else { return Outcome::Idle };
        let NTree::List { horizontal, kids } = d.at(&slot.path) else { return Outcome::Idle };
        let (weight, panes) = &kids[slot.m];
        let anchors = [slot.prev.and_then(|j| anchor(d, &slot, j, true, placed, tiled)), slot.next.and_then(|j| anchor(d, &slot, j, false, placed, tiled))];
        let Some(x) = panes.blocks().first().map(|b| (*b).to_owned()) else {
            // All new terminals: create them in one call, beside a block or a split.
            let Some(a) = anchors.iter().flatten().next() else { return Outcome::Idle };
            return self.new_split(si, wi, &a.id, *horizontal, a.after, split_ratio(a.weight, *weight, a.after), panes);
        };
        if let Some(a) = anchors.iter().flatten().find(|a| a.block) {
            return self.move_to(si, wi, &x, &a.id, *horizontal, a.after, split_ratio(a.weight, *weight, a.after));
        }
        match anchors.iter().flatten().next() {
            Some(a) => self.detach_all(si, wi, &a.blocks[1..]),
            None => Outcome::Idle,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)] // Test fixtures.
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // A small Rex: the methods `plan` emits, as the API reference describes them.

    #[derive(Clone, Debug)]
    enum S {
        Leaf(String),
        Split { id: String, h: bool, ratio: f64, before: Box<S>, after: Box<S> },
    }

    impl S {
        fn json(&self) -> Value {
            match self {
                S::Leaf(b) => json!({ "rect": [0, 0, 1, 1], "block_id": b }),
                S::Split { id, h, ratio, before, after } => json!({ "rect": [0, 0, 1, 1], "split": {
                    "split_id": id, "direction": direction(*h), "ratio": ratio, "before": before.json(), "after": after.json() } }),
            }
        }
        fn leaves(&self, out: &mut Vec<String>) {
            match self {
                S::Leaf(b) => out.push(b.clone()),
                S::Split { before, after, .. } => {
                    before.leaves(out);
                    after.leaves(out);
                }
            }
        }
        fn has(&self, id: &str) -> bool {
            match self {
                S::Leaf(b) => b == id,
                S::Split { id: s, before, after, .. } => s == id || before.has(id) || after.has(id),
            }
        }
        fn has_block(&self, b: &str) -> bool {
            let mut v = vec![];
            self.leaves(&mut v);
            v.iter().any(|x| x == b)
        }
    }

    fn without(t: S, b: &str) -> Option<S> {
        match t {
            S::Leaf(x) => (x != b).then_some(S::Leaf(x)),
            S::Split { id, h, ratio, before, after } => match (without(*before, b), without(*after, b)) {
                (Some(x), Some(y)) => Some(S::Split { id, h, ratio, before: Box::new(x), after: Box::new(y) }),
                (Some(x), None) | (None, Some(x)) => Some(x),
                (None, None) => None,
            },
        }
    }

    fn replace_at(t: &mut S, id: &str, f: &mut dyn FnMut(S) -> S) -> bool {
        let hit = match t {
            S::Leaf(b) => b == id,
            S::Split { id: s, .. } => s == id,
        };
        if hit {
            let old = std::mem::replace(t, S::Leaf(String::new()));
            *t = f(old);
            return true;
        }
        match t {
            S::Split { before, after, .. } => replace_at(before, id, f) || replace_at(after, id, f),
            S::Leaf(_) => false,
        }
    }

    /// The innermost split in direction `h` with `b1` before and `b2` after it.
    fn resize_in(t: &mut S, h: bool, b1: &str, b2: &str, r: f64) -> bool {
        let S::Split { h: sh, ratio, before, after, .. } = t else { return false };
        if resize_in(before, h, b1, b2, r) || resize_in(after, h, b1, b2, r) {
            return true;
        }
        if *sh == h && before.has_block(b1) && after.has_block(b2) {
            *ratio = r;
            return true;
        }
        false
    }

    fn swap_in(t: &mut S, a: &str, b: &str) {
        match t {
            S::Leaf(x) if x == a => *x = b.to_owned(),
            S::Leaf(x) if x == b => *x = a.to_owned(),
            S::Leaf(_) => {}
            S::Split { before, after, .. } => {
                swap_in(before, a, b);
                swap_in(after, a, b);
            }
        }
    }

    struct SWin {
        id: String,
        label: String,
        tiled: Option<S>,
        floating: Vec<S>,
    }

    struct SSess {
        id: String,
        label: String,
        windows: Vec<SWin>,
    }

    #[derive(Default)]
    struct Sim {
        sessions: Vec<SSess>,
        creators: HashMap<String, String>,
        /// Detached block → its session.
        detached: HashMap<String, String>,
        n: u32,
    }

    fn default_label(window: &str) -> String {
        format!("Window {}", &window[window.len() - 8..])
    }

    impl Sim {
        fn fresh(&mut self, kind: &str) -> String {
            self.n += 1;
            format!("{kind}:{:08x}", self.n)
        }

        fn block(&mut self, creator: &str) -> String {
            let id = self.fresh("block");
            self.creators.insert(id.clone(), creator.to_owned());
            id
        }

        fn add_session(&mut self, label: &str) -> String {
            let id = self.fresh("session");
            self.sessions.push(SSess { id: id.clone(), label: label.into(), windows: vec![] });
            id
        }

        fn add_window(&mut self, session: &str, label: Option<&str>, tiled: Option<S>, floating: Vec<S>) -> String {
            let id = self.fresh("window");
            let label = label.map_or_else(|| default_label(&id), str::to_owned);
            let si = self.si(session);
            self.sessions[si].windows.push(SWin { id: id.clone(), label, tiled, floating });
            id
        }

        fn si(&self, id: &str) -> usize {
            self.sessions.iter().position(|s| s.id == id).unwrap_or_else(|| panic!("no session {id}"))
        }

        fn wi(&self, si: usize, id: &str) -> usize {
            self.sessions[si].windows.iter().position(|w| w.id == id).unwrap_or_else(|| panic!("no window {id}"))
        }

        fn views(&self) -> Vec<Value> {
            self.sessions
                .iter()
                .map(|s| {
                    let windows: Vec<Value> = s
                        .windows
                        .iter()
                        .map(|w| {
                            let mut layers = vec![self.layer(&format!("layer:t{}", w.id), "tiled", w.tiled.as_ref())];
                            for (i, f) in w.floating.iter().enumerate() {
                                layers.push(self.layer(&format!("layer:f{i}{}", w.id), "floating", Some(f)));
                            }
                            json!({ "window_id": w.id, "label": w.label, "layers": layers })
                        })
                        .collect();
                    json!({ "revision": 1, "session_id": s.id, "label": s.label, "windows": windows })
                })
                .collect()
        }

        fn layer(&self, id: &str, kind: &str, t: Option<&S>) -> Value {
            let mut ids = vec![];
            if let Some(t) = t {
                t.leaves(&mut ids);
            }
            let blocks: Vec<Value> = ids.iter().map(|b| json!({ "block_id": b, "label": "shell", "creator_name": self.creators[b], "flavor": "x" })).collect();
            json!({ "layer_id": id, "kind": kind, "bounds": [0, 0, 1, 1], "layout": t.map_or(Value::Null, S::json), "blocks": blocks })
        }

        fn build(&mut self, v: &Value, ids: &mut Vec<String>) -> S {
            if let Some(b) = v.get("block") {
                assert_eq!(b["flavor"], SHELL_FLAVOR);
                let id = self.block(TERMINAL_CREATOR);
                ids.push(id.clone());
                return S::Leaf(id);
            }
            let s = &v["split"];
            let ratio = s.get("ratio").and_then(Value::as_f64).unwrap_or(0.5);
            assert!(ratio > 0.0 && ratio < 1.0, "bad ratio in {v}");
            let before = self.build(&s["before"], ids);
            let after = self.build(&s["after"], ids);
            S::Split { id: self.fresh("split"), h: s["direction"] == "horizontal", ratio, before: Box::new(before), after: Box::new(after) }
        }

        /// The window whose tiled tree holds this block or split.
        fn locate(&self, id: &str) -> Option<(usize, usize)> {
            self.sessions.iter().enumerate().find_map(|(si, s)| s.windows.iter().position(|w| w.tiled.as_ref().is_some_and(|t| t.has(id))).map(|wi| (si, wi)))
        }

        fn placed_anywhere(&self, b: &str) -> bool {
            self.sessions.iter().flat_map(|s| &s.windows).any(|w| w.tiled.iter().chain(&w.floating).any(|t| t.has_block(b)))
        }

        /// Takes a placed block out of its tree; an emptied window closes.
        fn take(&mut self, b: &str) {
            let mut found = false;
            for s in &mut self.sessions {
                for w in &mut s.windows {
                    if w.tiled.as_ref().is_some_and(|t| t.has_block(b)) {
                        w.tiled = without(w.tiled.take().unwrap(), b);
                        found = true;
                    }
                    if w.floating.iter().any(|t| t.has_block(b)) {
                        w.floating = std::mem::take(&mut w.floating).into_iter().filter_map(|t| without(t, b)).collect();
                        found = true;
                    }
                }
                s.windows.retain(|w| w.tiled.is_some() || !w.floating.is_empty());
            }
            assert!(found, "block {b} isn't placed");
        }

        fn session_of_block(&self, b: &str) -> Option<String> {
            if let Some(s) = self.detached.get(b) {
                return Some(s.clone());
            }
            self.sessions.iter().find(|s| s.windows.iter().any(|w| w.tiled.iter().chain(&w.floating).any(|t| t.has_block(b)))).map(|s| s.id.clone())
        }

        fn apply(&mut self, step: &Step, aliases: &mut Aliases, placeholders: &mut Vec<String>) {
            let p = &step.payload;
            let s = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_owned);
            let sid = s("session_id");
            match step.method.as_str() {
                "session.create" => {
                    let id = self.fresh("session");
                    let label = s("label").unwrap_or_else(|| format!("auto-{}", self.n));
                    assert!(!label.is_empty());
                    self.sessions.push(SSess { id: id.clone(), label, windows: vec![] });
                    let Bind::Session { space } = &step.bind else { panic!("{step:?}") };
                    aliases.bind(space, &id);
                }
                "session.destroy" => {
                    let i = self.si(&sid.unwrap());
                    self.sessions.remove(i);
                }
                "session.set_label" => {
                    let i = self.si(&sid.unwrap());
                    let label = s("label").unwrap();
                    assert!(!label.is_empty());
                    self.sessions[i].label = label;
                }
                "session.move" => {
                    let id = sid.unwrap();
                    let i = self.si(&id);
                    let sess = self.sessions.remove(i);
                    match s("before_session_id") {
                        Some(b) => {
                            assert_ne!(b, id);
                            let j = self.si(&b);
                            self.sessions.insert(j, sess);
                        }
                        None => self.sessions.push(sess),
                    }
                }
                "session.new_window" => {
                    let si = self.si(&sid.unwrap());
                    let mut ids = vec![];
                    let tree = self.build(&p["layout"], &mut ids);
                    let id = self.fresh("window");
                    let label = s("window_label").unwrap_or_else(|| default_label(&id));
                    self.sessions[si].windows.push(SWin { id: id.clone(), label, tiled: Some(tree), floating: vec![] });
                    let Bind::Window { tab, blocks } = &step.bind else { panic!("{step:?}") };
                    assert_eq!(blocks.len(), ids.len());
                    aliases.bind(tab, &id);
                    for (slot, b) in blocks.iter().zip(&ids) {
                        match slot {
                            Some(a) => aliases.bind(a, b),
                            None => placeholders.push(b.clone()),
                        }
                    }
                }
                "session.close_window" => {
                    let si = self.si(&sid.unwrap());
                    let wi = self.wi(si, &s("window_id").unwrap());
                    self.sessions[si].windows.remove(wi);
                }
                "session.set_window_label" => {
                    let si = self.si(&sid.unwrap());
                    let id = s("window_id").unwrap();
                    let wi = self.wi(si, &id);
                    let label = s("label").unwrap_or_default();
                    self.sessions[si].windows[wi].label = if label.is_empty() { default_label(&id) } else { label };
                }
                "session.move_window" => {
                    let si = self.si(&sid.unwrap());
                    let id = s("window_id").unwrap();
                    let wi = self.wi(si, &id);
                    let w = self.sessions[si].windows.remove(wi);
                    match s("before_window_id") {
                        Some(b) => {
                            assert_ne!(b, id);
                            let j = self.wi(si, &b);
                            self.sessions[si].windows.insert(j, w);
                        }
                        None => self.sessions[si].windows.push(w),
                    }
                }
                "session.new_split" => {
                    let anchor = s("anchor_id").unwrap();
                    let h = p["direction"] == "horizontal";
                    let after = p["side"] == "after";
                    let ratio = p.get("ratio").and_then(Value::as_f64).unwrap_or(0.5);
                    assert!(ratio > 0.0 && ratio < 1.0);
                    let (si, wi) = self.locate(&anchor).unwrap_or_else(|| panic!("anchor not in a window: {step:?}"));
                    assert_eq!(self.sessions[si].id, sid.unwrap());
                    let mut ids = vec![];
                    let mut new = Some(self.build(&p["layout"], &mut ids));
                    let split = self.fresh("split");
                    let tree = self.sessions[si].windows[wi].tiled.as_mut().unwrap();
                    assert!(replace_at(tree, &anchor, &mut |old| {
                        let n = new.take().unwrap();
                        let (before, after) = if after { (old, n) } else { (n, old) };
                        S::Split { id: split.clone(), h, ratio, before: Box::new(before), after: Box::new(after) }
                    }));
                    let Bind::Blocks(blocks) = &step.bind else { panic!("{step:?}") };
                    assert_eq!(blocks.len(), ids.len());
                    for (slot, b) in blocks.iter().zip(&ids) {
                        match slot {
                            Some(a) => aliases.bind(a, b),
                            None => placeholders.push(b.clone()),
                        }
                    }
                }
                "session.move_block" => {
                    let b = s("block_id").unwrap();
                    let anchor = s("anchor_block_id").unwrap();
                    let sid = sid.unwrap();
                    assert_ne!(b, anchor);
                    assert_eq!(self.session_of_block(&b).as_deref(), Some(sid.as_str()), "{step:?}");
                    let (asi, _) = self.locate(&anchor).unwrap_or_else(|| panic!("anchor not placed: {step:?}"));
                    assert_eq!(self.sessions[asi].id, sid);
                    assert!(self.creators.contains_key(&anchor), "anchor must be a block: {step:?}");
                    if self.detached.remove(&b).is_none() {
                        self.take(&b);
                    }
                    let h = p.get("direction").is_none_or(|d| d == "horizontal");
                    let after = p.get("side").is_none_or(|d| d == "after");
                    let ratio = p.get("ratio").and_then(Value::as_f64).unwrap_or(0.5);
                    assert!(ratio > 0.0 && ratio < 1.0);
                    let split = self.fresh("split");
                    let (si, wi) = self.locate(&anchor).unwrap();
                    let tree = self.sessions[si].windows[wi].tiled.as_mut().unwrap();
                    assert!(replace_at(tree, &anchor, &mut |old| {
                        let n = S::Leaf(b.clone());
                        let (before, after) = if after { (old, n) } else { (n, old) };
                        S::Split { id: split.clone(), h, ratio, before: Box::new(before), after: Box::new(after) }
                    }));
                }
                "session.detach_block" => {
                    let b = s("block_id").unwrap();
                    assert_eq!(self.session_of_block(&b), sid);
                    self.take(&b);
                    self.detached.insert(b, sid.unwrap());
                }
                "block.close" => {
                    let b = s("block_id").unwrap();
                    assert_eq!(self.session_of_block(&b), sid);
                    if self.detached.remove(&b).is_none() {
                        self.take(&b);
                    }
                    self.creators.remove(&b);
                }
                "session.resize_pane" => {
                    let (b1, b2) = (s("before_block_id").unwrap(), s("after_block_id").unwrap());
                    assert_ne!(b1, b2);
                    let ratio = p["ratio"].as_f64().unwrap();
                    assert!(ratio > 0.0 && ratio < 1.0);
                    let (si, wi) = self.locate(&b1).unwrap();
                    assert_eq!(self.locate(&b2), Some((si, wi)), "{step:?}");
                    let tree = self.sessions[si].windows[wi].tiled.as_mut().unwrap();
                    assert!(resize_in(tree, p["direction"] == "horizontal", &b1, &b2, ratio), "no such split: {step:?}");
                }
                "session.swap_blocks" => {
                    let (a, b) = (s("block_id").unwrap(), s("other_block_id").unwrap());
                    assert_ne!(a, b);
                    assert!(self.placed_anywhere(&a) && self.placed_anywhere(&b));
                    for w in self.sessions.iter_mut().flat_map(|s| &mut s.windows) {
                        for t in w.tiled.iter_mut().chain(&mut w.floating) {
                            swap_in(t, &a, &b);
                        }
                    }
                }
                m => panic!("unexpected method {m}"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // The adapter's loop.

    #[derive(Default)]
    struct Env {
        sim: Sim,
        aliases: Aliases,
        placeholders: Vec<String>,
        pending: HashMap<String, Pending>,
        extras: BTreeMap<String, SpaceExtra>,
        /// The steps of the last `settle`.
        steps: Vec<Step>,
        /// Run only the first planned step each round, as an adapter may.
        one_at_a_time: bool,
    }

    impl Env {
        fn doc(&self) -> Value {
            project(&self.sim.views(), &self.aliases, &self.extras)
        }

        fn plan(&self, desired: &Value) -> Vec<Step> {
            plan(&self.sim.views(), &self.aliases, desired, &self.pending, &self.placeholders)
        }

        /// Plans and runs steps until there are none; returns the rounds it took.
        fn settle(&mut self, desired: &Value) -> usize {
            // Herdr's `terminal.run`: addresses no block has yet are pending.
            for space in array(desired, "spaces") {
                for tab in array(space, "tabs") {
                    let root: Node = serde_json::from_value(tab["root"].clone()).unwrap();
                    for n in root.terminals() {
                        let a = n.terminal().unwrap();
                        if !self.aliases.to_rex.contains_key(a) && !a.starts_with("block:") {
                            self.pending.entry(a.to_owned()).or_insert_with(|| Pending { options: json!({ "cwd": "/w" }), label: String::new() });
                        }
                    }
                }
            }
            self.steps.clear();
            let cap = if self.one_at_a_time { 60 } else { 20 };
            for round in 0..cap {
                let mut steps = self.plan(desired);
                assert_eq!(steps, self.plan(desired), "plan is deterministic");
                if steps.is_empty() {
                    bind_panes(desired, &mut self.aliases);
                    assert_eq!(self.plan(&self.doc()), vec![], "a projected document needs nothing");
                    return round;
                }
                if self.one_at_a_time {
                    steps.truncate(1);
                }
                for step in &steps {
                    self.sim.apply(step, &mut self.aliases, &mut self.placeholders);
                    self.steps.push(step.clone());
                }
                let aliases = &self.aliases;
                self.pending.retain(|a, _| !aliases.to_rex.contains_key(a));
            }
            panic!("no convergence after {cap} rounds: {:#?}", self.steps);
        }

        /// Settles and checks Rex now shows exactly `desired`.
        fn converge(&mut self, desired: &Value) -> usize {
            let rounds = self.settle(desired);
            assert_same(&self.doc(), desired);
            rounds
        }

        fn methods(&self) -> Vec<&str> {
            self.steps.iter().map(|s| s.method.as_str()).collect()
        }

        fn block(&self, address: &str) -> String {
            self.aliases.rex(address).to_owned()
        }
    }

    // -----------------------------------------------------------------------
    // Documents, as Herdr writes them.

    fn t(pane: &str, address: &str) -> Node {
        crate::model::pane(pane, address)
    }

    fn row(id: &str, kids: Vec<Node>) -> Node {
        Node::container(id, Axis::Row, kids)
    }

    fn col(id: &str, kids: Vec<Node>) -> Node {
        Node::container(id, Axis::Column, kids)
    }

    fn w(mut n: Node, weight: f32) -> Node {
        n.size = Some(Size::Weight { weight });
        n
    }

    fn tab(id: &str, name: &str, root: Node) -> Value {
        json!({ "id": id, "name": name, "root": serde_json::to_value(root).unwrap() })
    }

    fn space(id: &str, name: &str, tabs: Vec<Value>) -> Value {
        json!({ "id": id, "name": name, "folder": "", "tabs": tabs })
    }

    fn doc(spaces: Vec<Value>) -> Value {
        json!({ "spaces": spaces })
    }

    fn tab_mut<'a>(d: &'a mut Value, id: &str) -> &'a mut Value {
        d["spaces"].as_array_mut().unwrap().iter_mut().flat_map(|s| s["tabs"].as_array_mut().unwrap().iter_mut()).find(|t| t["id"] == id).unwrap()
    }

    fn space_mut<'a>(d: &'a mut Value, id: &str) -> &'a mut Value {
        d["spaces"].as_array_mut().unwrap().iter_mut().find(|s| s["id"] == id).unwrap()
    }

    /// Changes a tab's panes with Herdr's own tree operations.
    fn edit(d: &mut Value, id: &str, f: impl FnOnce(&mut Node)) {
        let t = tab_mut(d, id);
        let mut root: Node = serde_json::from_value(t["root"].clone()).unwrap();
        f(&mut root);
        t["root"] = serde_json::to_value(root).unwrap();
    }

    /// A pane tree with nesting, ids of containers and exact sizes set aside.
    #[derive(Debug)]
    enum Canon {
        Leaf(String),
        List(bool, Vec<(f64, Canon)>),
    }

    fn canon(v: &Value) -> Option<Canon> {
        if v["type"] == "block" {
            return Some(Canon::Leaf(format!("{}={}", v["id"].as_str().unwrap(), v["content"]["terminal"].as_str().unwrap())));
        }
        let h = v["type"] == "row";
        let mut kids = vec![];
        for c in v["children"].as_array().into_iter().flatten() {
            let wt = c["size"]["weight"].as_f64().unwrap_or(1.0);
            match canon(c) {
                Some(Canon::List(h2, inner)) if h2 == h => {
                    let sum: f64 = inner.iter().map(|k| k.0).sum();
                    kids.extend(inner.into_iter().map(|(iw, k)| (wt * iw / sum, k)));
                }
                Some(k) => kids.push((wt, k)),
                None => {}
            }
        }
        match kids.len() {
            0 => None,
            1 => kids.pop().map(|k| k.1),
            _ => {
                let sum: f64 = kids.iter().map(|k| k.0).sum();
                Some(Canon::List(h, kids.into_iter().map(|(wt, k)| (wt / sum, k)).collect()))
            }
        }
    }

    fn close(a: &Canon, b: &Canon, slack: f64) -> bool {
        match (a, b) {
            (Canon::Leaf(x), Canon::Leaf(y)) => x == y,
            (Canon::List(h1, k1), Canon::List(h2, k2)) => h1 == h2 && k1.len() == k2.len() && k1.iter().zip(k2).all(|(x, y)| (x.0 - y.0).abs() < slack && close(&x.1, &y.1, slack)),
            _ => false,
        }
    }

    /// Spaces (id, name, folder) and their tabs (id, name).
    type Outline = Vec<(String, String, String, Vec<(String, String)>)>;

    /// Same spaces, tabs, names and panes (pane ids and addresses included), in the same arrangement.
    fn assert_same(got: &Value, want: &Value) {
        assert_same_within(got, want, 0.02);
    }

    fn assert_same_within(got: &Value, want: &Value, slack: f64) {
        let outline = |d: &Value| -> Outline {
            array(d, "spaces")
                .iter()
                .map(|s| (text(s, "id"), text(s, "name"), text(s, "folder"), array(s, "tabs").iter().map(|t| (text(t, "id"), text(t, "name"))).collect()))
                .collect()
        };
        assert_eq!(outline(got), outline(want), "\ngot {got:#}\nwant {want:#}");
        for (gs, ws) in array(got, "spaces").iter().zip(array(want, "spaces")) {
            for (gt, wt) in array(gs, "tabs").iter().zip(array(ws, "tabs")) {
                let (g, w) = (canon(&gt["root"]), canon(&wt["root"]));
                let ok = match (&g, &w) {
                    (Some(g), Some(w)) => close(g, w, slack),
                    (None, None) => true,
                    _ => false,
                };
                assert!(ok, "tab {}: got {g:?}, want {w:?}", wt["id"]);
            }
        }
    }

    /// One space `p1` "work" with tab `c1` holding terminals `t1`..`tn` in a row (panes `x1`..).
    fn base(env: &mut Env, n: usize) -> Value {
        let panes = (1..=n).map(|i| t(&format!("x{i}"), &format!("t{i}"))).collect();
        let d = doc(vec![space("p1", "work", vec![tab("c1", "", row("c1", panes))])]);
        env.converge(&d);
        env.doc()
    }

    // -----------------------------------------------------------------------
    // Fixtures: session views as Rex sends them.

    fn term(id: &str) -> Value {
        json!({ "block_id": id, "label": "shell", "creator_name": TERMINAL_CREATOR, "flavor": SHELL_FLAVOR, "host_id": "h", "owner": "client:1" })
    }

    fn leaf(id: &str) -> Value {
        json!({ "rect": [0, 0, 1, 1], "block_id": id })
    }

    fn split(id: &str, dir: &str, ratio: f64, before: Value, after: Value) -> Value {
        json!({ "rect": [0, 0, 1, 1], "split": { "split_id": id, "direction": dir, "ratio": ratio, "before": before, "after": after } })
    }

    fn layer(kind: &str, layout: Value, blocks: Vec<Value>) -> Value {
        json!({ "layer_id": format!("layer:{kind}{}", blocks.len()), "kind": kind, "bounds": [0, 0, 1, 1], "layout": layout, "blocks": blocks })
    }

    fn window(id: &str, label: &str, layers: Vec<Value>) -> Value {
        json!({ "window_id": id, "label": label, "focused_block_id": null, "layers": layers })
    }

    fn view(id: &str, label: &str, windows: Vec<Value>) -> Value {
        json!({ "revision": 3, "session_id": id, "label": label, "active_window_id": null, "windows": windows })
    }

    fn fixtures() -> Vec<Vec<Value>> {
        vec![
            vec![view("session:1", "work", vec![window("window:1", "Window 0a1b2c3d", vec![layer("tiled", leaf("block:a"), vec![term("block:a")])])])],
            vec![view(
                "session:1",
                "work",
                vec![window(
                    "window:1",
                    "editor",
                    vec![layer(
                        "tiled",
                        split("split:1", "horizontal", 0.25, leaf("block:a"), split("split:2", "vertical", 0.5, leaf("block:b"), leaf("block:c"))),
                        vec![term("block:a"), term("block:b"), term("block:c")],
                    )],
                )],
            )],
            vec![
                view(
                    "session:1",
                    "one",
                    vec![
                        window("window:1", "Window 0000000a", vec![layer("tiled", split("split:1", "vertical", 0.75, leaf("block:a"), leaf("block:b")), vec![term("block:a"), term("block:b")])]),
                        window("window:2", "logs", vec![layer("tiled", leaf("block:c"), vec![term("block:c")])]),
                    ],
                ),
                view("session:2", "two", vec![window("window:3", "x", vec![layer("tiled", leaf("block:d"), vec![term("block:d")])])]),
                view("session:3", "empty", vec![]),
            ],
            // A floating layer, and a web block in the tiled one.
            vec![view(
                "session:1",
                "mixed",
                vec![window(
                    "window:1",
                    "w",
                    vec![
                        layer(
                            "tiled",
                            split("split:1", "horizontal", 0.5, leaf("block:a"), split("split:2", "vertical", 0.5, leaf("block:web"), leaf("block:b"))),
                            vec![term("block:a"), json!({ "block_id": "block:web", "label": "docs", "creator_name": "com.example.web", "flavor": "com.example.web.page" }), term("block:b")],
                        ),
                        layer("floating", leaf("block:f"), vec![term("block:f")]),
                    ],
                )],
            )],
            // An empty tiled layer under a floating one, and a direction Rex may add later.
            vec![view(
                "session:1",
                "odd",
                vec![
                    window("window:1", "w", vec![layer("tiled", Value::Null, vec![]), layer("floating", leaf("block:f"), vec![term("block:f")])]),
                    window("window:2", "v", vec![layer("tiled", split("split:9", "diagonal", 0.5, leaf("block:a"), leaf("block:b")), vec![term("block:a"), term("block:b")])]),
                ],
            )],
        ]
    }

    // -----------------------------------------------------------------------
    // project

    #[test]
    fn projects_a_single_terminal() {
        let got = project(&fixtures()[0], &Aliases::default(), &BTreeMap::new());
        assert_eq!(
            got,
            json!({ "spaces": [{ "id": "session:1", "name": "work", "folder": "", "tabs": [{ "id": "window:1", "name": "", "root": {
                "id": "window:1", "type": "row", "children": [
                    { "id": "pane-block:a", "type": "block", "content": { "terminal": "block:a" } } ] } }] }] })
        );
    }

    #[test]
    fn projects_nested_splits_as_rows_and_columns_sized_by_ratio() {
        let got = project(&fixtures()[1], &Aliases::default(), &BTreeMap::new());
        let pane = |b: &str, wt: f64| json!({ "id": format!("pane-{b}"), "type": "block", "content": { "terminal": b }, "size": { "weight": wt } });
        assert_eq!(
            got["spaces"][0]["tabs"][0],
            json!({ "id": "window:1", "name": "editor", "root": { "id": "window:1", "type": "row", "children": [
                pane("block:a", 0.25),
                { "id": "split:2", "type": "column", "size": { "weight": 0.75 }, "children": [pane("block:b", 0.5), pane("block:c", 0.5)] } ] } })
        );
        // A vertical split at the root sits in the tab's row.
        let got = project(&fixtures()[2], &Aliases::default(), &BTreeMap::new());
        let root = &got["spaces"][0]["tabs"][0]["root"];
        assert_eq!((root["type"].as_str(), root["children"].as_array().unwrap().len()), (Some("row"), 1));
        assert_eq!(root["children"][0]["type"], "column");
        assert_eq!(root["children"][0]["children"][0]["size"], json!({ "weight": 0.75 }));
    }

    #[test]
    fn projects_sessions_and_windows_in_order_with_names_and_extras() {
        let mut extras = BTreeMap::new();
        extras.insert("session:2".to_owned(), SpaceExtra { folder: "/src".into(), unnamed: true });
        let got = project(&fixtures()[2], &Aliases::default(), &extras);
        let outline: Vec<Value> = got["spaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| json!([s["id"], s["name"], s["folder"], s["tabs"].as_array().unwrap().iter().map(|t| json!([t["id"], t["name"]])).collect::<Vec<_>>()]))
            .collect();
        assert_eq!(
            outline,
            vec![
                json!(["session:1", "one", "", [["window:1", ""], ["window:2", "logs"]]]),
                json!(["session:2", "", "/src", [["window:3", "x"]]]),
                json!(["session:3", "empty", "", []]),
            ]
        );
    }

    #[test]
    fn projects_herdr_ids_where_bound() {
        let mut aliases = Aliases::default();
        aliases.bind("p1", "session:1");
        aliases.bind("c1", "window:1");
        aliases.bind("t1", "block:a");
        aliases.bind("x1", "pane:block:a");
        let got = project(&fixtures()[0], &aliases, &BTreeMap::new());
        assert_eq!(got["spaces"][0]["id"], "p1");
        assert_eq!(got["spaces"][0]["tabs"][0]["id"], "c1");
        assert_eq!(got["spaces"][0]["tabs"][0]["root"]["id"], "c1");
        assert_eq!(got["spaces"][0]["tabs"][0]["root"]["children"][0], json!({ "id": "x1", "type": "block", "content": { "terminal": "t1" } }));
    }

    #[test]
    fn floating_layers_and_non_terminal_blocks_are_left_out() {
        let got = project(&fixtures()[3], &Aliases::default(), &BTreeMap::new());
        let root = &got["spaces"][0]["tabs"][0]["root"];
        // The web block's split gives way: a and b side by side, nothing floating.
        let ids: Vec<&str> = root["children"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["pane-block:a", "pane-block:b"]);
        assert!(!got.to_string().contains("block:f") && !got.to_string().contains("block:web"));
    }

    #[test]
    fn empty_layouts_project_empty_tabs_and_unknown_directions_as_rows() {
        let got = project(&fixtures()[4], &Aliases::default(), &BTreeMap::new());
        assert_eq!(got["spaces"][0]["tabs"][0]["root"], json!({ "id": "window:1", "type": "row", "children": [] }));
        assert_eq!(got["spaces"][0]["tabs"][1]["root"]["children"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn projected_documents_need_no_steps() {
        for views in fixtures() {
            let d = project(&views, &Aliases::default(), &BTreeMap::new());
            assert_eq!(plan(&views, &Aliases::default(), &d, &HashMap::new(), &[]), vec![], "{d:#}");
        }
    }

    #[test]
    fn same_arrangement_in_any_nesting_needs_no_steps() {
        let views = &fixtures()[1];
        let pane = |b: &str| t(&format!("pane-{b}"), b);
        // Herdr's n-ary row (a | b/c) written flat, and the column nested twice.
        let d = doc(vec![json!({ "id": "session:1", "name": "work", "folder": "", "tabs": [tab("window:1", "editor", row("window:1", vec![
            w(pane("block:a"), 1.0),
            w(col("s", vec![w(col("s2", vec![pane("block:b")]), 1.0), pane("block:c")]), 3.0)]))] })]);
        assert_eq!(plan(views, &Aliases::default(), &d, &HashMap::new(), &[]), vec![]);
    }

    // -----------------------------------------------------------------------
    // plan: one step at a time

    #[test]
    fn a_new_space_with_one_terminal_is_a_session_then_a_window() {
        let mut env = Env::default();
        let d = doc(vec![space("p1", "work", vec![tab("c1", "", row("c1", vec![t("x1", "t1")]))])]);
        env.want_label("t1", "build");
        let first = env.plan(&d);
        assert_eq!(first, vec![Step { method: "session.create".into(), payload: json!({ "label": "work" }), bind: Bind::Session { space: "p1".into() } }]);
        assert_eq!(env.converge(&d), 2);
        let sid = env.aliases.rex("p1").to_owned();
        assert_eq!(
            env.steps[1],
            Step {
                method: "session.new_window".into(),
                payload: json!({ "session_id": sid, "focus": false, "layout": { "block": { "flavor": SHELL_FLAVOR, "options": { "cwd": "/w" }, "label": "build" } } }),
                bind: Bind::Window { tab: "c1".into(), blocks: vec![Some("t1".into())] },
            }
        );
    }

    impl Env {
        fn want_label(&mut self, address: &str, label: &str) {
            self.pending.insert(address.into(), Pending { options: json!({ "cwd": "/w" }), label: label.into() });
        }
    }

    #[test]
    fn a_new_tab_lays_out_all_its_new_terminals_in_one_window() {
        let mut env = Env::default();
        let mut d = base(&mut env, 1);
        let root = row("c2", vec![w(t("x2", "t2"), 1.0), w(col("s1", vec![t("x3", "t3"), t("x4", "t4")]), 1.0), w(t("x5", "t5"), 2.0)]);
        d["spaces"][0]["tabs"].as_array_mut().unwrap().push(tab("c2", "tests", root));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.new_window"]);
        let layout = &env.steps[0].payload["layout"];
        // Right-nested: t2 | (t3/t4 | t5), with ratios from the weights.
        assert_eq!(layout["split"]["ratio"], 0.25);
        assert!((layout["split"]["after"]["split"]["ratio"].as_f64().unwrap() - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(layout["split"]["after"]["split"]["before"]["split"]["direction"], "vertical");
        assert_eq!(env.steps[0].payload["window_label"], "tests");
        assert_eq!(env.steps[0].bind, Bind::Window { tab: "c2".into(), blocks: ["t2", "t3", "t4", "t5"].map(|a| Some(a.to_owned())).to_vec() });
    }

    #[test]
    fn splitting_right_and_down_creates_beside_the_pane() {
        let mut env = Env::default();
        let mut d = base(&mut env, 1);
        edit(&mut d, "c1", |r| assert!(r.split("x1", Axis::Row, t("x2", "t2"), "s1".into())));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.new_split"]);
        assert_eq!(env.steps[0].payload["anchor_id"], env.block("t1").as_str());
        assert_eq!((env.steps[0].payload["direction"].as_str(), env.steps[0].payload["side"].as_str()), (Some("horizontal"), Some("after")));

        let mut d = env.doc();
        edit(&mut d, "c1", |r| assert!(r.split("x2", Axis::Column, t("x3", "t3"), "s2".into())));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.new_split"]);
        assert_eq!(env.steps[0].payload["anchor_id"], env.block("t2").as_str());
        assert_eq!(env.steps[0].payload["direction"], "vertical");
    }

    #[test]
    fn splitting_inside_a_row_of_three_keeps_the_order_and_sizes() {
        let mut env = Env::default();
        let mut d = base(&mut env, 1);
        // Herdr's n-ary inserts: [x1, x2] then x1 again: [x1, x3, x2] with halved shares.
        edit(&mut d, "c1", |r| {
            r.split("x1", Axis::Row, t("x2", "t2"), "s1".into());
            r.split("x1", Axis::Row, t("x3", "t3"), "s2".into());
        });
        env.converge(&d);
        assert!(env.methods().iter().all(|m| ["session.new_split", "session.resize_pane"].contains(m)), "{:?}", env.methods());
        // And a fourth between x3 and x2, and a column in the middle.
        let mut d = env.doc();
        edit(&mut d, "c1", |r| {
            r.split("x3", Axis::Row, t("x4", "t4"), "s3".into());
            r.split("x4", Axis::Column, t("x5", "t5"), "s4".into());
        });
        env.converge(&d);
    }

    #[test]
    fn closing_a_pane_detaches_its_block() {
        let mut env = Env::default();
        let mut d = base(&mut env, 3);
        let b2 = env.block("t2");
        edit(&mut d, "c1", |r| assert!(r.remove("x2").is_some()));
        env.converge(&d);
        assert_eq!(env.steps[0], call("session.detach_block", json!({ "session_id": env.block("p1"), "block_id": b2 })));
        assert!(env.sim.detached.contains_key(&b2), "the terminal keeps running until Herdr kills it");
    }

    #[test]
    fn resizing_moves_the_border() {
        let mut env = Env::default();
        let mut d = base(&mut env, 2);
        edit(&mut d, "c1", |r| {
            r.children_mut().unwrap()[0].size = Some(Size::Weight { weight: 0.7 });
            r.children_mut().unwrap()[1].size = Some(Size::Weight { weight: 0.3 });
        });
        env.converge(&d);
        assert_eq!(env.methods(), ["session.resize_pane"]);
        let p = &env.steps[0].payload;
        assert_eq!((p["before_block_id"].as_str(), p["after_block_id"].as_str()), (Some(env.block("t1").as_str()), Some(env.block("t2").as_str())));
        assert!((p["ratio"].as_f64().unwrap() - 0.7).abs() < 1e-6);
        // Within the slack: nothing.
        let mut d = env.doc();
        edit(&mut d, "c1", |r| r.children_mut().unwrap()[0].size = Some(Size::Weight { weight: 0.705 }));
        assert_eq!(env.plan(&d), vec![]);
    }

    #[test]
    fn moving_a_pane_to_another_tab() {
        let mut env = Env::default();
        let mut d = base(&mut env, 2);
        d["spaces"][0]["tabs"].as_array_mut().unwrap().push(tab("c2", "", row("c2", vec![t("x3", "t3")])));
        env.converge(&d);
        let mut d = env.doc();
        let mut moved = None;
        edit(&mut d, "c1", |r| moved = r.remove("x2"));
        let mut moved = moved.unwrap();
        moved.size = None;
        edit(&mut d, "c2", |r| assert!(r.split("x3", Axis::Column, moved, "s5".into())));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.move_block"]);
        assert_eq!(env.steps[0].payload["anchor_block_id"], env.block("t3").as_str());
        assert_eq!(env.steps[0].payload["direction"], "vertical");
    }

    #[test]
    fn moving_a_pane_into_a_new_tab_holds_it_open_with_a_placeholder() {
        let mut env = Env::default();
        let mut d = base(&mut env, 2);
        let b2 = env.block("t2");
        let mut moved = None;
        edit(&mut d, "c1", |r| moved = r.remove("x2"));
        let mut moved = moved.unwrap();
        moved.size = None;
        d["spaces"][0]["tabs"].as_array_mut().unwrap().push(tab("c9", "", row("c9", vec![moved])));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.new_window", "session.move_block", "block.close"]);
        assert_eq!(env.steps[0].bind, Bind::Window { tab: "c9".into(), blocks: vec![None] });
        assert_eq!(env.steps[1].payload["block_id"], b2.as_str());
        assert_eq!(env.steps[2].payload["block_id"], env.placeholders[0].as_str());
        assert!(!env.sim.creators.contains_key(&env.placeholders[0]), "the placeholder closed");
        assert_eq!(env.block("t2"), b2, "the same terminal");
    }

    #[test]
    fn moving_a_pane_into_a_new_tab_with_new_terminals_needs_no_placeholder() {
        let mut env = Env::default();
        let mut d = base(&mut env, 2);
        let mut moved = None;
        edit(&mut d, "c1", |r| moved = r.remove("x2"));
        let mut moved = moved.unwrap();
        moved.size = None;
        d["spaces"][0]["tabs"].as_array_mut().unwrap().push(tab("c9", "", col("c9", vec![t("x8", "t8"), moved])));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.new_window", "session.move_block"]);
        assert!(env.placeholders.is_empty());
    }

    #[test]
    fn swapping_two_panes() {
        let mut env = Env::default();
        let mut d = base(&mut env, 3);
        edit(&mut d, "c1", |r| assert!(r.swap("x1", "x3")));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.swap_blocks"]);
    }

    #[test]
    fn dragging_a_pane_to_an_edge_moves_one_block() {
        let mut env = Env::default();
        let mut d = base(&mut env, 4);
        // Model::move_pane(x4 → left of x2): out, split after x2, then swap places.
        edit(&mut d, "c1", |r| {
            let mut p = r.remove("x4").unwrap();
            p.size = None;
            assert!(r.split("x2", Axis::Row, p, "s9".into()));
            assert!(r.swap("x4", "x2"));
        });
        env.converge(&d);
        // Only places changed: swaps, and sizes.
        assert!(env.methods().iter().all(|m| ["session.swap_blocks", "session.resize_pane"].contains(m)), "{:?}", env.methods());
        // And below another pane.
        let mut d = env.doc();
        edit(&mut d, "c1", |r| {
            let mut p = r.remove("x1").unwrap();
            p.size = None;
            assert!(r.split("x3", Axis::Column, p, "s10".into()));
        });
        env.converge(&d);
        assert_eq!(env.methods()[0], "session.move_block");
    }

    #[test]
    fn a_move_beside_a_split_detaches_and_places_again() {
        let mut env = Env::default();
        // c1: x1 / x2; c2: x3 | x4. Move x3 to the left of c1's whole column.
        let d = doc(vec![space(
            "p1",
            "work",
            vec![tab("c1", "", row("c1", vec![col("s1", vec![t("x1", "t1"), t("x2", "t2")])])), tab("c2", "", row("c2", vec![t("x3", "t3"), t("x4", "t4")]))],
        )]);
        env.converge(&d);
        let mut d = env.doc();
        let mut moved = None;
        edit(&mut d, "c2", |r| moved = r.remove("x3"));
        let mut moved = moved.unwrap();
        moved.size = None;
        edit(&mut d, "c1", |r| {
            let column = r.children()[0].clone();
            r.children_mut().unwrap()[0] = row("s7", vec![moved, column]);
        });
        env.converge(&d);
        let b2 = env.block("t2");
        assert_eq!(env.steps[0], call("session.detach_block", json!({ "session_id": env.block("p1"), "block_id": b2 })));
        assert_eq!(env.steps[1].payload["block_id"], env.block("t3").as_str());
        assert_eq!(env.steps[2].payload["block_id"], b2.as_str());
    }

    #[test]
    fn rearranging_everything_rebuilds_the_tab() {
        let mut env = Env::default();
        let d = doc(vec![space("p1", "work", vec![tab("c1", "", row("c1", vec![col("s1", vec![t("x1", "t1"), t("x2", "t2")]), col("s2", vec![t("x3", "t3"), t("x4", "t4")])]))])]);
        env.converge(&d);
        let mut d = env.doc();
        // Transposed: rows of columns become columns of rows.
        let p = |i: u8| t(&format!("x{i}"), &format!("t{i}"));
        let root = row("c1", vec![col("s3", vec![row("s4", vec![p(1), p(3)]), row("s5", vec![p(2), p(4)])])]);
        tab_mut(&mut d, "c1")["root"] = serde_json::to_value(root).unwrap();
        let rounds = env.converge(&d);
        assert!(rounds <= 10, "{rounds} rounds");
    }

    #[test]
    fn tabs_trading_their_only_panes() {
        let mut env = Env::default();
        let d = doc(vec![space("p1", "work", vec![tab("c1", "", row("c1", vec![t("x1", "t1")])), tab("c2", "", row("c2", vec![t("x2", "t2")]))])]);
        env.converge(&d);
        let mut d = env.doc();
        let (r1, r2) = (tab_mut(&mut d, "c1")["root"]["children"].clone(), tab_mut(&mut d, "c2")["root"]["children"].clone());
        tab_mut(&mut d, "c1")["root"]["children"] = r2;
        tab_mut(&mut d, "c2")["root"]["children"] = r1;
        env.converge(&d);
    }

    #[test]
    fn closing_tabs_and_spaces() {
        let mut env = Env::default();
        let d = doc(vec![
            space("p1", "work", vec![tab("c1", "", row("c1", vec![t("x1", "t1")])), tab("c2", "", row("c2", vec![t("x2", "t2"), t("x3", "t3")]))]),
            space("p2", "play", vec![tab("c3", "", row("c3", vec![t("x4", "t4")]))]),
        ]);
        env.converge(&d);
        let mut d = env.doc();
        space_mut(&mut d, "p1")["tabs"].as_array_mut().unwrap().retain(|t| t["id"] != "c2");
        env.converge(&d);
        assert_eq!(env.methods(), ["session.close_window"]);
        d["spaces"].as_array_mut().unwrap().retain(|s| s["id"] != "p2");
        env.converge(&d);
        assert_eq!(env.methods(), ["session.destroy"]);
        assert_eq!(env.sim.sessions.len(), 1);
    }

    #[test]
    fn renaming_and_reordering_tabs_and_spaces() {
        let mut env = Env::default();
        let d = doc(vec![
            space("p1", "work", vec![tab("c1", "", row("c1", vec![t("x1", "t1")])), tab("c2", "b", row("c2", vec![t("x2", "t2")])), tab("c3", "c", row("c3", vec![t("x3", "t3")]))]),
            space("p2", "play", vec![tab("c4", "", row("c4", vec![t("x4", "t4")]))]),
        ]);
        env.converge(&d);
        let mut d = env.doc();
        {
            let tabs = space_mut(&mut d, "p1")["tabs"].as_array_mut().unwrap();
            tabs.rotate_left(1);
            tabs[0]["name"] = json!("");
            tabs[2]["name"] = json!("first");
        }
        space_mut(&mut d, "p2")["name"] = json!("games");
        d["spaces"].as_array_mut().unwrap().reverse();
        env.converge(&d);
        let mut methods = env.methods();
        methods.sort_unstable();
        methods.dedup();
        assert_eq!(methods, ["session.move", "session.move_window", "session.set_label", "session.set_window_label"]);
        // A cleared name gives the window back Rex's own label.
        let c2 = env.block("c2");
        let label = &env.sim.sessions.iter().flat_map(|s| &s.windows).find(|w| w.id == c2).unwrap().label;
        assert!(default_window_label(label), "{label}");
    }

    #[test]
    fn a_session_herdr_left_unnamed_keeps_its_rex_label() {
        let mut env = Env::default();
        let mut d = base(&mut env, 1);
        space_mut(&mut d, "p1")["name"] = json!("");
        assert_eq!(env.plan(&d), vec![]);
    }

    #[test]
    fn a_detached_terminal_is_placed_where_the_document_puts_it() {
        let mut env = Env::default();
        let mut d = base(&mut env, 1);
        let sid = env.block("p1");
        let b = env.sim.block(TERMINAL_CREATOR);
        env.sim.detached.insert(b.clone(), sid);
        env.aliases.bind("r7", &b);
        edit(&mut d, "c1", |r| assert!(r.split("x1", Axis::Column, t("x7", "r7"), "s1".into())));
        env.converge(&d);
        assert_eq!(env.methods(), ["session.move_block"]);
        assert_eq!(env.steps[0].payload["block_id"], b.as_str());
    }

    #[test]
    fn rex_made_left_nested_splits_take_herdr_inserts() {
        let mut env = Env::default();
        let sid = env.sim.add_session("rex");
        let (a, b, c) = (env.sim.block(TERMINAL_CREATOR), env.sim.block(TERMINAL_CREATOR), env.sim.block(TERMINAL_CREATOR));
        let inner = S::Split { id: "split:in".into(), h: true, ratio: 0.5, before: Box::new(S::Leaf(a.clone())), after: Box::new(S::Leaf(b.clone())) };
        let tree = S::Split { id: "split:out".into(), h: true, ratio: 2.0 / 3.0, before: Box::new(inner), after: Box::new(S::Leaf(c)) };
        env.sim.add_window(&sid, None, Some(tree), vec![]);
        let mut d = env.doc();
        assert_eq!(env.plan(&d), vec![]);
        let tab_id = d["spaces"][0]["tabs"][0]["id"].as_str().unwrap().to_owned();
        edit(&mut d, &tab_id, |r| assert!(r.split(&format!("pane-{b}"), Axis::Row, t("x9", "t9"), "s1".into())));
        env.converge(&d);
        assert_eq!(env.methods()[0], "session.new_split");
        let _ = a;
    }

    #[test]
    fn floating_and_non_terminal_blocks_are_never_touched() {
        let mut env = Env::default();
        let sid = env.sim.add_session("mixed");
        let (a, web, f) = (env.sim.block(TERMINAL_CREATOR), env.sim.block("com.example.web"), env.sim.block(TERMINAL_CREATOR));
        let tree = S::Split { id: "split:1".into(), h: true, ratio: 0.5, before: Box::new(S::Leaf(a.clone())), after: Box::new(S::Leaf(web.clone())) };
        env.sim.add_window(&sid, Some("w"), Some(tree), vec![S::Leaf(f.clone())]);
        let other = env.sim.add_session("other");
        let g = env.sim.block(TERMINAL_CREATOR);
        env.sim.add_window(&other, Some("v"), Some(S::Leaf(g.clone())), vec![]);
        let d = env.doc();
        assert_eq!(env.plan(&d), vec![]);
        // Herdr splits beside a: still never near web or f.
        let mut d2 = d.clone();
        edit(&mut d2, d["spaces"][0]["tabs"][0]["id"].as_str().unwrap(), |r| assert!(r.split(&format!("pane-{a}"), Axis::Column, t("x9", "t9"), "s".into())));
        env.converge(&d2);
        // Closing the tab and the whole space: terminals go, the window and session stay.
        let mut d3 = env.doc();
        d3["spaces"][0]["tabs"] = json!([]);
        env.settle(&d3);
        assert!(env.methods().iter().all(|m| *m == "session.detach_block"), "{:?}", env.methods());
        env.settle(&json!({ "spaces": [] }));
        for step in &env.steps {
            let s = step.payload.to_string();
            assert!(!s.contains(&web) && !s.contains(&f), "{step:?}");
            assert_ne!(step.method, "session.close_window");
            assert!(step.method != "session.destroy" || step.payload["session_id"] == other.as_str());
        }
        assert!(env.sim.placed_anywhere(&web) && env.sim.placed_anywhere(&f));
        assert_eq!(env.sim.sessions.len(), 1);
    }

    #[test]
    fn a_terminal_moved_to_another_space_stays_put() {
        let mut env = Env::default();
        let d = doc(vec![
            space("p1", "work", vec![tab("c1", "", row("c1", vec![t("x1", "t1"), t("x2", "t2")]))]),
            space("p2", "play", vec![tab("c2", "", row("c2", vec![t("x3", "t3")]))]),
        ]);
        env.converge(&d);
        let mut d = env.doc();
        let mut moved = None;
        edit(&mut d, "c1", |r| moved = r.remove("x2"));
        edit(&mut d, "c2", |r| assert!(r.split("x3", Axis::Row, moved.unwrap(), "s".into())));
        env.settle(&d);
        assert_eq!(env.methods(), Vec::<&str>::new(), "Rex can't move blocks between sessions; nothing is killed");
    }

    #[test]
    fn unknown_panes_and_mods_are_ignored() {
        let mut env = Env::default();
        let mut d = base(&mut env, 1);
        edit(&mut d, "c1", |r| {
            let viewer = Node::block("m1", Content::Mod { name: "markdown".into(), props: json!({}) });
            assert!(r.split("x1", Axis::Row, viewer, "s".into()));
        });
        assert_eq!(env.plan(&d), vec![]);
        // A tab of nothing Rex can hold is still a window, with a placeholder.
        d["spaces"][0]["tabs"].as_array_mut().unwrap().push(tab("c5", "", row("c5", vec![Node::block("m2", Content::Mod { name: "files".into(), props: Value::Null })])));
        env.settle(&d);
        assert_eq!(env.methods(), ["session.new_window"]);
        assert_eq!(env.plan(&d), vec![], "the placeholder stays: it holds the tab");
    }

    /// A fixed-seed generator: the same edits every run.
    struct Lcg(u64);

    impl Lcg {
        fn pick(&mut self, n: usize) -> usize {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(self.0 >> 33).unwrap() % n.max(1)
        }
    }

    fn root_of(d: &Value, si: usize, ti: usize) -> Node {
        serde_json::from_value(d["spaces"][si]["tabs"][ti]["root"].clone()).unwrap()
    }

    fn set_root(d: &mut Value, si: usize, ti: usize, root: &Node) {
        d["spaces"][si]["tabs"][ti]["root"] = serde_json::to_value(root).unwrap();
    }

    fn pane_ids(root: &Node) -> Vec<String> {
        root.panes().iter().map(|p| p.id.clone()).collect()
    }

    /// Takes a pane out of tab (si, ti), closing the tab (and its space) when it empties, as Herdr does.
    fn take_pane(d: &mut Value, si: usize, ti: usize, pane: &str) -> Node {
        let mut root = root_of(d, si, ti);
        let mut p = root.remove(pane).unwrap();
        p.size = None;
        if root.panes().is_empty() {
            d["spaces"][si]["tabs"].as_array_mut().unwrap().remove(ti);
            if d["spaces"][si]["tabs"].as_array().unwrap().is_empty() {
                d["spaces"].as_array_mut().unwrap().remove(si);
            }
        } else {
            set_root(d, si, ti, &root);
        }
        p
    }

    /// One edit a person could make in Herdr.
    fn mutate(d: &mut Value, rng: &mut Lcg, n: &mut usize) {
        *n += 1;
        let fresh = |n: usize| t(&format!("xn{n}"), &format!("tn{n}"));
        let axis = |rng: &mut Lcg| if rng.pick(2) == 0 { Axis::Row } else { Axis::Column };
        if d["spaces"].as_array().unwrap().is_empty() {
            d["spaces"].as_array_mut().unwrap().push(space(&format!("pn{n}"), "new", vec![tab(&format!("cn{n}"), "", row(&format!("cn{n}"), vec![fresh(*n)]))]));
            return;
        }
        let si = rng.pick(d["spaces"].as_array().unwrap().len());
        let tab_count = d["spaces"][si]["tabs"].as_array().unwrap().len();
        let new_tab = |d: &mut Value, pane: Node, n: usize| {
            let id = format!("cn{n}");
            d["spaces"][si]["tabs"].as_array_mut().unwrap().push(tab(&id, "", row(&id, vec![pane])));
        };
        if tab_count == 0 {
            return new_tab(d, fresh(*n), *n);
        }
        let ti = rng.pick(tab_count);
        let mut root = root_of(d, si, ti);
        let panes = pane_ids(&root);
        let a = panes[rng.pick(panes.len())].clone();
        let b = panes[rng.pick(panes.len())].clone();
        match rng.pick(10) {
            0 | 1 => {
                root.split(&a, axis(rng), fresh(*n), format!("sn{n}"));
                set_root(d, si, ti, &root);
            }
            2 => {
                take_pane(d, si, ti, &a);
            }
            3 if a != b => {
                root.swap(&a, &b);
                set_root(d, si, ti, &root);
            }
            4 if a != b => {
                // Model::move_pane with an edge.
                let mut p = root.remove(&a).unwrap();
                p.size = None;
                root.split(&b, axis(rng), p, format!("sn{n}"));
                if rng.pick(2) == 0 {
                    root.swap(&a, &b);
                }
                set_root(d, si, ti, &root);
            }
            5 if tab_count > 1 => {
                let other = (ti + 1 + rng.pick(tab_count - 1)) % tab_count;
                let other_id = d["spaces"][si]["tabs"][other]["id"].clone();
                let p = take_pane(d, si, ti, &a);
                let Some(si) = d["spaces"].as_array().unwrap().iter().position(|s| array(s, "tabs").iter().any(|t| t["id"] == other_id)) else { return };
                let oi = array(&d["spaces"][si], "tabs").iter().position(|t| t["id"] == other_id).unwrap();
                let mut target = root_of(d, si, oi);
                let ids = pane_ids(&target);
                target.split(&ids[rng.pick(ids.len())], axis(rng), p, format!("sn{n}"));
                set_root(d, si, oi, &target);
            }
            6 if panes.len() > 1 => {
                let p = take_pane(d, si, ti, &a);
                new_tab(d, p, *n);
            }
            7 => {
                let containers: Vec<String> = root.walk().into_iter().filter(|x| x.children().len() > 1).map(|x| x.id.clone()).collect();
                if let Some(c) = containers.get(rng.pick(containers.len())) {
                    for kid in root.find_mut(c).unwrap().children_mut().unwrap() {
                        #[allow(clippy::cast_precision_loss)]
                        let weight = 0.3 + rng.pick(8) as f32 / 10.0;
                        kid.size = Some(Size::Weight { weight });
                    }
                    set_root(d, si, ti, &root);
                }
            }
            8 => new_tab(d, fresh(*n), *n),
            _ => {
                let tabs = d["spaces"][si]["tabs"].as_array_mut().unwrap();
                tabs.rotate_left(1);
                tabs[0]["name"] = json!(["", "logs", "edit"][rng.pick(3)]);
                if rng.pick(3) == 0 {
                    d["spaces"].as_array_mut().unwrap().rotate_left(1);
                }
            }
        }
    }

    #[test]
    fn random_herdr_edits_converge() {
        let mut worst = 0;
        for seed in 0..60 {
            let mut rng = Lcg(seed);
            // Every third run makes one call per round.
            let mut env = Env { one_at_a_time: seed % 3 == 2, ..Env::default() };
            let mut n = 0;
            let d = doc(vec![
                space("p1", "one", vec![tab("c1", "", row("c1", vec![t("x1", "t1"), t("x2", "t2")]))]),
                space("p2", "two", vec![tab("c2", "", row("c2", vec![t("x3", "t3")])), tab("c3", "", row("c3", vec![t("x4", "t4")]))]),
            ]);
            env.converge(&d);
            for _ in 0..30 {
                let mut d = env.doc();
                mutate(&mut d, &mut rng, &mut n);
                let rounds = env.settle(&d);
                if !env.one_at_a_time {
                    worst = worst.max(rounds);
                }
                assert_same(&env.doc(), &d);
            }
        }
        assert!(worst <= 6, "worst case took {worst} rounds");
    }

    #[test]
    fn helpers_keep_order_and_ratios_in_range() {
        assert_eq!(order_moves(&["c", "a", "b"], &["a", "x", "b", "c"]), vec![("c", "a")]);
        assert_eq!(order_moves(&["b", "a"], &["a", "b"]), vec![("b", "a")]);
        assert!(order_moves(&["a", "b"], &["a", "z", "b"]).is_empty());
        assert_eq!(split_ratio(1.0, 0.0, true), MAX_RATIO);
        assert!(default_window_label("Window 89abcdef") && !default_window_label("Window 89abcdeg") && !default_window_label("Window"));
    }
}
