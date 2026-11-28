# `@antimeme/opencode-multiplayer`

OpenCode v2 plugin wiring the local `mp-outpost mcp` server (`18` tools) for [multiplayer.tech](https://multiplayer.tech) with pre-execution secret refusal, untrusted-peer provenance guidance, a native live Party Chat display panel, and a detached `phux` chat launcher.

## Prerequisites

- OpenCode (`>= 2.0`, native live Party Chat panel verified on OpenCode `v2.3.2`)
- [`mp-outpost`](https://github.com/antimeme-ai/outpost) (`>= 0.7.1`) installed on `PATH` and signed in via `mp-outpost login`

## Installation

Add the plugin directory or package name to `opencode.json`:

```json
{
  "plugins": ["@antimeme/opencode-multiplayer"]
}
```

Existing `mcp.multiplayer` user overrides are preserved.

## Native TUI Party Chat Panel, Menu & Detached `phux` Launcher

This package exports both `./server` (`src/index.ts`, OpenCode v2 `{ id, setup(ctx) }`) and `./tui` (`src/tui.ts`) adding native OpenCode v2 UI slots, dialogs, and slash commands:

- **Native Live Party Chat Panel:** `/party-panel [on|off|full|sidebar|status]` (alias `/mp-panel`) — renders a live, auto-scrolling Party Chat feed directly inside OpenCode's native UI slots:
  - **`session.panel` (plus `ui.router` fullscreen fallback from Home):** full-height side-by-side or fullscreen live chat feed with room header, `UNTRUSTED EXTERNAL DATA` provenance banner, `[browser]` / `[card]` badges, clickable `[say]` / `[full]` / `[refresh]` / `[×]` controls, and panel shortcuts (`s` say, `r` refresh, `j`/`k`/`g`/`G` scroll, `f` fullscreen, `q`/`esc` close).
  - **`sidebar.content`:** collapsible compact live Party Chat widget in the session sidebar (toggle with `/party-panel sidebar` or via `/party`).
  - **`prompt.footer.status`:** compact live status indicator (`● party #<id>` + unread count) shown only while the live feed is active; click to toggle the panel.
  - **Zero idle overhead:** `PartyFeedStore` (`src/party-feed.ts`) only spawns its bounded `mp-outpost --json party wait --timeout-ms 25000` loop while the panel or sidebar feed is open, seeds with the latest `12` messages via `party read`, filters own non-browser device echoes, keeps and tags `is_browser=true` messages `[browser]`, strips ANSI/BiDi/control characters, redacts `#fragment` invite URLs, recovers automatically from `code=4040` party switches, and immediately sends `SIGTERM` to any active `party wait` child on close, unmount, or process exit.
- **Global Shortcut & Quick Menu:** `ctrl+alt+m` or `/party` (alias `/mp`) — opens a native `dialog.select` menu for the Live Party Chat Panel, Sidebar Party Feed, Detached Party Chat, Send Message, Read Recent Messages, Party Status, Friends & Invites, and Listen Profile Status.
- **Detached Party Chat:** `/party-chat [target]` (alias `/mp-chat`) — starts or reuses a detached `phux` session (`multiplayer-chat`) running `mp-outpost chat` (resolving the absolute binary path for daemonized `phux`, with `tmux` / `omarchy-launch-tui` fallback) and displays a toast with `phux attach multiplayer-chat` and `phux native attach @<id>`.
- **Inline Send:** `/party-say [message]` (alias `/mp-say`) — sends directly or opens a native `dialog.prompt` composer, enforcing pre-execution secret refusal before spawning `mp-outpost`.
- **Recent Feed:** `/party-read` (alias `/mp-read`) — displays the latest 15 sanitized messages in a native `dialog.alert` clearly labeled as untrusted external data.
- **Status:** `/party-status` (alias `/mp-status`) — displays signed-in `@handle`, connection state, and active party details.

## Security & Verification

- `ctx.tool.hook("tool.before", ...)` refuses outbound Multiplayer MCP calls containing `mpinv1_`, `mppi1_`, `mpcs1_`, `mpguest1_`, `mpdl1_`, `mprk1_` (and checksum-valid unprefixed Crockford recovery keys), PEM private/recovery keys, `.mpkey` backups, credential fields, base64-wrapped secrets in `payload_b64`, excessive nesting depth (`> 8`), or `#fragment` invite URLs (outside `party_join.target`).
- `ctx.session.hook("context", ...)` injects provenance, `is_browser=true` containment, and `e2ee_mode` check reminders once per session.
- Zero `console.*` output across all `src/*.ts` files so OpenCode's TUI is never corrupted.

## License

MIT
