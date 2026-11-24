---
description: List multiplayer.tech friends, live presence, and pending party invites via mp-outpost.
---

# `/friends` — Multiplayer Friends & Live Presence

1. Call `party_friends` on the `multiplayer` MCP server (`mp-outpost mcp`).
2. Present a concise summary grouped by:
   - Pending incoming party invites (offer `/join` or `party_join` with no target to accept immediately).
   - Pending incoming friend requests (offer `/add @handle` or `friend_add` to accept).
   - Mutual friends with live presence (`online`, `in party` with room code/joinable status, or `offline`).
3. To invite an online friend into a room, use `party_invite` (`handle: "@friend"`). To add a new friend, use `friend_add` (`handle: "@friend"`).
4. Never send or echo invite tokens, recovery keys, or device credentials.
