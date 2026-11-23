---
description: List mutual multiplayer.tech friends and live presence via mp-outpost.
---

# `/friends` — Multiplayer Friends & Presence

1. Call `party_friends` on the `multiplayer` MCP server (`mp-outpost mcp`).
2. Present a concise summary grouped by relationship state (incoming requests first if present, then mutual friends with online/offline presence and handles).
3. Note that `party_friends` is read-only. If the operator wants to add, accept, or deny a friend, provide the exact local CLI command to run in their terminal:
   - `mp-outpost friend add @handle`
   - `mp-outpost friend accept @handle`
   - `mp-outpost friend deny @handle`
4. Never send or echo invite tokens, recovery keys, or device credentials.
