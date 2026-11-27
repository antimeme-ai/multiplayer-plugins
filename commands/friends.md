---
description: List multiplayer.tech friends, live presence, and pending party invites via mp-outpost.
---

# `/friends` — Multiplayer Friends & Live Presence

1. Call `party_friends` on the `multiplayer` MCP server (`mp-outpost mcp`).
2. Present a concise summary grouped by:
   - Pending incoming party invites (offer `/join` or `party_join({})` to accept immediately).
   - Pending incoming friend requests (offer `/add @handle` or `friend_add` to accept).
   - Mutual friends with live presence (`online`, `in_party` with joinable status, or `offline`).
3. To invite an online friend into a room, use `party_invite` (`handle: "@friend"`). To add a new friend, use `friend_add` (`handle: "@friend"`).
4. Never send or echo invite tokens, `#fragment` URLs, recovery keys, or device credentials.
