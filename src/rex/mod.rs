//! A Rex server as Herdr's backend: Rex owns sessions, windows, blocks and
//! their programs; Herdr shows them as spaces, tabs and panes and turns its
//! changes into Rex calls. See docs/rex.md.

pub mod adapter;
pub mod data;
pub mod project;
pub mod stream;
pub mod transport;

/// Connects to the Rex server people chose (settings.json `rex_server`).
pub fn connect() -> anyhow::Result<std::sync::Arc<crate::hc::Core>> {
    adapter::connect()
}
