# `@antimeme-ai/opencode-multiplayer`

OpenCode v2 plugin wiring the local `mp-outpost mcp` server (`18` tools) for [multiplayer.tech](https://multiplayer.tech) with pre-execution secret refusal, untrusted-peer provenance guidance, and a native TUI party-chat launcher.

## Prerequisites

- OpenCode (`>= 2.0`)
- [`mp-outpost`](https://github.com/antimeme-ai/outpost) (`>= 0.7.1`) installed on `PATH` and signed in via `mp-outpost login`

## Installation

Add the plugin directory or package name to `opencode.json`:

```json
{
  "plugins": ["@antimeme-ai/opencode-multiplayer"]
}
```

Existing `mcp.multiplayer` user overrides are preserved.

## Native TUI Shortcut & Detached `phux` Party Chat

This package exports both `./server` (`src/index.ts`, OpenCode v2 `{ id, setup(ctx) }`) and `./tui` (`src/tui.ts`) adding:
- **Global Shortcut:** `ctrl+alt+m`
- **Command Palette:** `Open Multiplayer Party Chat`
- **Prompt Slash Command:** `/party-chat [target]` (alias `/mp-chat`)

Invoking it starts or reuses a detached `phux` session (`multiplayer-chat`) running `mp-outpost chat` (resolving the absolute binary path for daemonized `phux`, with `tmux` / `omarchy-launch-tui` fallback) and displays a toast with `phux attach multiplayer-chat` and `phux native attach @<id>`.

## Security & Verification

- `ctx.tool.hook("tool.before", ...)` refuses outbound Multiplayer MCP calls containing `mpinv1_`, `mppi1_`, `mpcs1_`, `mpguest1_`, `mpdl1_`, `mprk1_` (and checksum-valid unprefixed Crockford recovery keys), PEM private/recovery keys, `.mpkey` backups, credential fields, base64-wrapped secrets in `payload_b64`, excessive nesting depth (`> 8`), or `#fragment` invite URLs (outside `party_join.target`).
- `ctx.session.hook("context", ...)` injects provenance, `is_browser=true` containment, and `e2ee_mode` check reminders once per session.
- Zero `console.*` output so OpenCode's TUI is never corrupted.

## License

MIT
