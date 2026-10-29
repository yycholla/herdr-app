# Rex backend

Herdr can run its terminals on a Rex server
instead of herdr-core. Pick it from the menu under the Herdr logo (top left),
with `app.backend {"backend": "rex"}`, or with `"backend": "rex"` in
settings.json. Switching restarts the app; terminals keep running on the
backend left behind.

## Who owns what

Rex is authoritative. Herdr is one more Rex client, next to Rex.app and the
`rex` CLI, and everything it shows is shared with them live:

| Rex | Herdr |
| --- | --- |
| session | space |
| window (in order) | tab |
| tiled layer's split tree | the tab's panes |
| terminal block | terminal (its address is the block id) |
| detached block | a running terminal without a pane (peek, agents list) |
| OSC 7501 program status | agent status (working, blocked, done, idle) |

What only Herdr keeps (a space's folder, whether it's named automatically,
and Herdr's own ids for things it created) lives in
`~/.config/herdr-app/rex.json`. Focus, zoom and settled tabs stay per
screen, as with herdr-core; focusing a pane also focuses its block in Rex
and claims its size, as Rex.app does.

## How it works

`hc::Core` is a facade over a `hc::Link`: herdr-core's framed `hc connect`
pipe or `rex::adapter::RexLink`. The adapter answers the herdr-core methods
the app uses, so the window, model and mods are unchanged.

- `src/rex/transport.rs`: the control WebSocket (`/api/control`,
  `rex.control.v1`, API revision 7): concurrent calls, ordered events,
  Unix socket or `ws://`/`wss://`.
- `src/rex/data.rs`: a block's data WebSocket (`/api/data`,
  `rex.data.terminal.v1`) with resume.
- `src/rex/stream.rs`: splits a terminal stream into its Ghostty `GHOSTSNP`
  snapshot, program output, and nonce-authorized `rex1` APC messages.
  `Vt::import_snapshot` loads the snapshot; Herdr's display copy never
  answers device queries (`Link::reply` drops them), since Rex's terminal does.
- `src/rex/project.rs`: projects session views into Herdr's layout
  document, and plans the Rex calls that turn the sessions into a document
  Herdr wrote. `doc.set` runs one planned call at a time, reading the views
  again after each, until nothing is left to do.
- `src/rex/adapter.rs`: the `Link`. `terminal.run` hands out an address
  (`r7`) and creates the block where the next document places it
  (`session.new_window`/`session.new_split`), or detached if none does in
  time. Rex events become herdr-core event lines (`created`, `title`,
  `status`, `foreground`, `finished`, `removed`, `doc`).

## Not yet

- Other machines: Rex hosts aren't offered as Herdr machines yet;
  `terminal.run` with `on` fails.
- Mods that shell out to `hc` still talk to herdr-core.
- Floating layers and non-terminal blocks are kept as Rex has them but not
  shown (see `project.rs`).
- Rex's Lua key bindings (`client.key`) and client actions aren't wired:
  keys go to the terminal as bytes.
