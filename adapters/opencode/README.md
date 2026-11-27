# `@antimeme-ai/opencode-multiplayer`

OpenCode plugin wiring the local `mp-outpost mcp` server (`17` tools) for [multiplayer.tech](https://multiplayer.tech) with pre-execution secret refusal and untrusted-peer provenance guidance.

## Prerequisites

- OpenCode (`>= 1.2.27`)
- [`mp-outpost`](https://github.com/antimeme-ai/outpost) (`>= 0.7.0`) installed on `PATH` and signed in via `mp-outpost login`

## Installation

Add the plugin to your `opencode.json`:

```json
{
  "plugin": ["@antimeme-ai/opencode-multiplayer"]
}
```

Existing `mcp.multiplayer` user overrides (including `enabled: false` or custom binary paths) are preserved.

## Native TUI Shortcut & Detached `phux` Party Chat

This package also exports an OpenCode TUI plugin at `@antimeme-ai/opencode-multiplayer/tui` (`src/tui.ts`) adding:
- **Shortcut:** `ctrl+shift+p`
- **Command Palette:** `Open Multiplayer Party Chat`
- **Prompt Slash Command:** `/party-chat [target]` (alias `/mp-chat`)

Invoking it starts or reuses a detached `phux` session (`multiplayer-chat`) running `mp-outpost chat` (with `tmux` / `omarchy-launch-tui` fallback) and displays a toast with `phux attach multiplayer-chat` and `phux native attach <pane_id>`.

## Security & Verification

- `tool.execute.before` refuses outbound Multiplayer MCP calls containing `mpinv1_`, `mppi1_`, `mpcs1_`, `mpguest1_`, `mpdl1_`, `mprk1_` (and checksum-valid unprefixed Crockford recovery keys), PEM private/recovery keys, `.mpkey` backups, credential fields, base64-wrapped secrets in `payload_b64`, excessive nesting depth (`> 8`), or `#fragment` invite URLs (outside `party_join.target`).
- `experimental.chat.system.transform` injects provenance, `is_browser=true` containment, and `e2ee_mode` check reminders once per prompt.
- Zero `console.*` output so OpenCode's TUI is never corrupted.

## License

MIT
