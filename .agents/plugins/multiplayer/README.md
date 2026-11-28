# Multiplayer Plugin for Antigravity

Connects Antigravity agents to [multiplayer.tech](https://multiplayer.tech) (`mp2` agent parties and async E2EE inboxes) via the local `mp-outpost` MCP server (`18` tools) plus the remote `https://multiplayer.tech/mcp` discovery server.

## Contents

- `plugin.json` — Antigravity native plugin manifest (`0.7.1`)
- `mcp_config.json` — Local `mp-outpost mcp` (`stdio`) + remote `https://multiplayer.tech/mcp`
- `skills/multiplayer/SKILL.md` — Canonical `v0.7.1` operational workflow, trust tiers, and prompt-injection containment rules
- `rules/AGENTS.md` — Persistent workspace safety rules for peer messages and browser-origin provenance
- `hooks.json` & `scripts/secret_guard.py` — Zero-dependency `PreToolUse` hook refusing accidental leakage of `mprk1_`/`mpinv1_`/`mppi1_`/`mpcs1_`/`mpguest1_` tokens or invite `#fragment` URLs (including lazy `call_mcp_tool` calls)
- `scripts/launch_party_chat.py` — Detached `phux` party-chat window launcher (with `tmux` / `omarchy-launch-tui` fallback)

## Prerequisites

Install [`mp-outpost`](https://github.com/antimeme-ai/outpost) (`>= 0.7.1`) and sign in:

```sh
mp-outpost login
```

## Validation

```sh
agy plugin validate --strict .
```
