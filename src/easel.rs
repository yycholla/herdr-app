//! Easel panes: a project's GPUI artifacts canvas (easel-ui) as a pane, so
//! what Claude renders with `render_gpui` shows beside its terminal. The
//! layout says `{ "easel": "<project folder>" }`; the view lives while some
//! layout has the pane, starts when it's first shown, and serves the
//! project's socket (one Easel per project, in this app or the standalone
//! viewer).

use crate::layout::{Axis, Content, Node};
use crate::model::Model;
use crate::settings;
use easel_ui::{AlreadyOpen, Easel, Host, Theme};
use gpui::*;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

/// How long a pane that couldn't open waits before trying again.
pub const RETRY: Duration = Duration::from_secs(3);

/// Easel's actions and keys. Before Herdr installs its own keys, which keep
/// the bindings made before them.
pub fn init(cx: &mut App) {
    easel_ui::init(cx);
}

/// Herdr's theme, fonts and sizes, by Herdr's token names.
fn theme() -> Theme {
    let s = settings::get();
    Theme::from_tokens(settings::color_or_literal, s.ui_font_family.clone(), settings::terminal_font(), px(settings::ui_font_size()), px(settings::font_size()))
}

fn host() -> Host {
    Host { theme: theme(), capture: Some(Rc::new(capture)) }
}

/// `bounds` (window coordinates) of the window's last frame.
fn capture(window: &mut Window, bounds: Bounds<Pixels>) -> anyhow::Result<easel_ui::image::RgbaImage> {
    let shot = window.render_to_image()?;
    let scale = window.scale_factor();
    let at = |v: Pixels, max: u32| ((f32::from(v) * scale).round().max(0.0) as u32).min(max);
    let (x, y) = (at(bounds.origin.x, shot.width()), at(bounds.origin.y, shot.height()));
    let (right, bottom) = (at(bounds.origin.x + bounds.size.width, shot.width()), at(bounds.origin.y + bounds.size.height, shot.height()));
    anyhow::ensure!(right > x && bottom > y, "the frame is outside the window");
    Ok(easel_ui::image::imageops::crop_imm(&shot, x, y, right - x, bottom - y).to_image())
}

enum State {
    Open { view: Entity<Easel>, focus: FocusHandle },
    /// Why it didn't open, and when it last tried.
    Failed { reason: String, at: Instant },
}

struct Slot {
    project: String,
    state: State,
}

/// The Easel views by pane id.
#[derive(Default)]
pub struct Panes {
    slots: HashMap<String, Slot>,
    /// The retry of panes that couldn't open, while one waits.
    pub retry: Option<Task<()>>,
}

impl Panes {
    /// Drops the views whose pane left every layout (`owned`: pane → project)
    /// or shows another project, and opens the `shown` ones not open yet. One
    /// that failed tries again when shown again, or `RETRY` after it failed.
    /// True while a shown one waits for that retry.
    pub fn sync(&mut self, owned: &HashMap<String, String>, shown: &[(String, String)], window: &mut Window, cx: &mut App) -> bool {
        self.slots.retain(|pane, slot| {
            let keep = owned.get(pane) == Some(&slot.project)
                && (matches!(slot.state, State::Open { .. }) || shown.iter().any(|(p, _)| p == pane));
            if !keep && let State::Open { view, .. } = &slot.state {
                view.update(cx, |e, cx| e.close(cx));
            }
            keep
        });
        let mut waiting = false;
        for (pane, project) in shown {
            match self.slots.get(pane).map(|s| &s.state) {
                Some(State::Open { .. }) => continue,
                Some(State::Failed { at, .. }) if at.elapsed() < RETRY => {
                    waiting = true;
                    continue;
                }
                _ => {}
            }
            let state = match Easel::open(Path::new(project), host(), window, cx) {
                Ok(view) => {
                    let focus = view.read(cx).focus_handle(cx);
                    State::Open { view, focus }
                }
                Err(e) => {
                    waiting = true;
                    let reason = match e.downcast_ref::<AlreadyOpen>() {
                        Some(o) => format!("Easel for {} is open somewhere else (the standalone viewer?).\nClose it there and it opens here.", o.project.display()),
                        None => format!("Easel didn't open: {e:#}"),
                    };
                    tracing::warn!("easel pane {pane}: {reason}");
                    State::Failed { reason, at: Instant::now() }
                }
            };
            self.slots.insert(pane.clone(), Slot { project: project.clone(), state });
        }
        waiting
    }

    /// The keyboard of an open pane.
    pub fn focus(&self, pane: &str) -> Option<FocusHandle> {
        match &self.slots.get(pane)?.state {
            State::Open { focus, .. } => Some(focus.clone()),
            State::Failed { .. } => None,
        }
    }

    /// The pane's view, or why it isn't there.
    pub fn render(&self, pane: &str) -> AnyElement {
        match self.slots.get(pane).map(|s| &s.state) {
            Some(State::Open { view, .. }) => div().size_full().child(view.clone()).into_any_element(),
            Some(State::Failed { reason, .. }) => div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .p_4()
                .text_center()
                .text_color(settings::color("dim"))
                .child(reason.clone())
                .into_any_element(),
            None => div().size_full().into_any_element(),
        }
    }

    /// Saves and releases every project now (quitting).
    pub fn close_all(&mut self, cx: &mut App) {
        for (_, slot) in self.slots.drain() {
            if let State::Open { view, .. } = slot.state {
                view.update(cx, |e, cx| e.close(cx));
            }
        }
    }

    /// After Herdr's theme, appearance, fonts or zoom changed.
    pub fn restyle(&self, cx: &mut App) {
        for slot in self.slots.values() {
            if let State::Open { view, .. } = &slot.state {
                view.update(cx, |e, cx| e.set_theme(theme(), cx));
            }
        }
    }
}

/// Easel panes in `nodes`: pane id → project.
pub fn panes<'a>(nodes: impl IntoIterator<Item = &'a Node>) -> impl Iterator<Item = (String, String)> {
    nodes.into_iter().filter_map(|n| match n.content() {
        Some(Content::Easel { easel }) => Some((n.id.clone(), easel.clone())),
        _ => None,
    })
}

/// What `easel.open` does.
#[derive(Debug, PartialEq)]
pub enum How {
    /// The project has a pane already.
    Focus(String),
    Split { target: String, axis: Axis },
    Tab { space: String },
}

#[derive(Debug, PartialEq)]
pub struct Opening {
    /// The project root.
    pub project: PathBuf,
    pub how: How,
}

/// `easel.open`'s arguments against the model. `cwd` is a terminal's live
/// folder; `root` the project root a folder belongs to.
pub fn plan(model: &Model, args: &Value, cwd: &dyn Fn(&str) -> Option<String>, root: &dyn Fn(&Path) -> PathBuf) -> Result<Opening, String> {
    let arg = |k: &str| args.get(k).and_then(Value::as_str);
    let tab = match args.get("tab") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(other) => return Err(format!("easel.open tab is true or false, not {other}")),
    };
    let axis = match arg("direction").unwrap_or("right") {
        "right" => Axis::Row,
        "down" => Axis::Column,
        other => return Err(format!("easel.open direction is \"right\" or \"down\", not {other:?}")),
    };
    let target = match (arg("pane"), arg("terminal")) {
        (Some(p), _) => Some(model.tab_of(p).map(|_| p.to_owned()).ok_or_else(|| format!("no pane {p:?}"))?),
        (None, Some(t)) => Some(model.pane_of(t).ok_or_else(|| format!("no pane shows terminal {t:?}"))?),
        (None, None) => model.focused_pane(),
    };
    let space = match &target {
        Some(p) => model.space_of(p),
        None => model.active_space(),
    }
    .ok_or(if tab { "no space yet: make one first (space.new)" } else { "no pane to split" })?;
    if let Some(m) = &space.machine {
        return Err(format!("Easel runs on this machine; that pane is on {m}"));
    }
    let project = match arg("project") {
        Some(p) if Path::new(p).is_absolute() => root(Path::new(p)),
        Some(p) => return Err(format!("easel.open project must be an absolute path, not {p:?}")),
        None => {
            // An Easel pane's own project; a terminal's live folder; the space's.
            let node = target.as_deref().and_then(|p| model.tab_of(p)?.root.find(p));
            let own = node.and_then(|n| match n.content() {
                Some(Content::Easel { easel }) => Some(easel.clone()),
                _ => None,
            });
            let folder = own.or_else(|| cwd(node?.terminal()?)).unwrap_or_else(|| space.folder.clone());
            if folder.is_empty() {
                return Err("no folder to open: pass project".into());
            }
            root(Path::new(&folder))
        }
    };
    let open = model.tabs().flat_map(|t| panes(t.root.walk())).find(|(_, p)| root(Path::new(p)) == project);
    let how = match (open, target) {
        (Some((pane, _)), _) => How::Focus(pane),
        (None, _) if tab => How::Tab { space: space.id.clone() },
        (None, Some(target)) => How::Split { target, axis },
        (None, None) => return Err("no pane to split".into()),
    };
    Ok(Opening { project, how })
}

#[cfg(test)]
mod tests {
    // Not `super::*`: gpui's `test` attribute would shadow the built-in one.
    use super::{How, Opening};
    use crate::layout::{Axis, Content, Node};
    use crate::model::{Model, Tab};
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};

    /// Folders are their own roots, except anything under /src/app.
    fn root(p: &Path) -> PathBuf {
        if p.starts_with("/src/app") { "/src/app".into() } else { p.to_path_buf() }
    }

    fn model() -> Model {
        let mut m = Model::default();
        m.add_space("s1", "", "/home/me", Tab::new("c1", "", "p1", "t1"));
        m.add_tab("s1", Tab::new("c2", "", "p2", "t2"));
        m.add_space("s2", "", "/src/other", Tab::new("c3", "", "p3", "t3"));
        m.focus_pane("p1");
        m
    }

    fn cwd(address: &str) -> Option<String> {
        (address == "t1").then(|| "/src/app/crates/ui".into())
    }

    fn plan(m: &Model, args: Value) -> Result<Opening, String> {
        super::plan(m, &args, &cwd, &root)
    }

    #[test]
    fn opens_beside_the_target_on_its_terminals_project() {
        let m = model();
        let split = |target: &str, axis| Opening { project: "/src/app".into(), how: How::Split { target: target.into(), axis } };
        // The focused pane, its terminal's folder's project, to the right.
        assert_eq!(plan(&m, json!({})), Ok(split("p1", Axis::Row)));
        assert_eq!(plan(&m, json!({ "terminal": "t1", "direction": "down" })), Ok(split("p1", Axis::Column)));
        // No live folder: the space's.
        assert_eq!(plan(&m, json!({ "pane": "p3" })), Ok(Opening { project: "/src/other".into(), how: How::Split { target: "p3".into(), axis: Axis::Row } }));
        assert_eq!(plan(&m, json!({ "pane": "p2", "project": "/src/app/docs" })), Ok(split("p2", Axis::Row)));
        assert_eq!(plan(&m, json!({ "terminal": "t3", "tab": true })), Ok(Opening { project: "/src/other".into(), how: How::Tab { space: "s2".into() } }));
    }

    #[test]
    fn bad_arguments_say_what_is_wrong() {
        let m = model();
        assert_eq!(plan(&m, json!({ "pane": "nope" })), Err("no pane \"nope\"".into()));
        assert_eq!(plan(&m, json!({ "terminal": "t9" })), Err("no pane shows terminal \"t9\"".into()));
        assert!(plan(&m, json!({ "direction": "left" })).unwrap_err().contains("\"right\" or \"down\""));
        assert!(plan(&m, json!({ "project": "src/app" })).unwrap_err().contains("absolute"));
        assert!(plan(&m, json!({ "tab": "yes" })).unwrap_err().contains("true or false"));
        assert_eq!(plan(&Model::default(), json!({})), Err("no pane to split".into()));
        assert!(plan(&Model::default(), json!({ "tab": true, "project": "/src/app" })).unwrap_err().contains("no space"));
        let mut remote = model();
        remote.space_mut("s2").unwrap().machine = Some("studio".into());
        assert_eq!(plan(&remote, json!({ "pane": "p3" })), Err("Easel runs on this machine; that pane is on studio".into()));
    }

    #[test]
    fn a_project_with_a_pane_focuses_it_instead_of_opening_another() {
        let mut m = model();
        assert!(m.split_with("p2", Axis::Row, Node::block("e1", Content::Easel { easel: "/src/app".into() })));
        let focus = Opening { project: "/src/app".into(), how: How::Focus("e1".into()) };
        assert_eq!(plan(&m, json!({ "terminal": "t1" })), Ok(focus));
        // The Easel pane focused: its own project.
        assert_eq!(plan(&m, json!({})).map(|o| o.how), Ok(How::Focus("e1".into())));
        // Any folder in the project finds it, from any tab, as a tab too.
        assert_eq!(plan(&m, json!({ "pane": "p3", "project": "/src/app/crates", "tab": true })).map(|o| o.how), Ok(How::Focus("e1".into())));
        // Another project still opens.
        assert_eq!(plan(&m, json!({ "project": "/src/other" })).map(|o| o.how), Ok(How::Split { target: "p1".into(), axis: Axis::Row }));
    }
}
