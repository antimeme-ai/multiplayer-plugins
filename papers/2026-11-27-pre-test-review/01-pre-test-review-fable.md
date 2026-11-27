# Lane A pre-test review — Multiplayer v0.7.0 plugins

## Verdict: FIXES NEEDED BEFORE TEST

Both secret-guard hooks are wrong in opposite directions, the Hermes Gateway adapter cannot be constructed, the Hermes CLI prints nothing, and the E2EE and invite-link copy describes behaviour the shipping v0.7.0 binary does not have.

## What I inspected

- **Read in full:** the canonical skill, all nine commands, the rules file, the Claude Code, Antigravity and Hermes plugin trees, and both test files.
- **Cross-checked against:** Outpost `tools.rs`, `mcp_bridge.rs`, `stdio.rs`, `fence.rs`, `cli.rs`, `inbox.rs`, `app_daemon.rs` (v0.7.0 tag and the working tree), site `rooms_and_cloud.ts`, Astra's launch review, and Hermes v0.22.5 source.
- **Ran, read-only:**
  - `claude plugin validate --strict` passes for the plugin and the marketplace.
  - `agy plugin validate --strict` passes for the plugin and fails for the marketplace.
  - `hermes plugins validate ./hermes` passes, security scan "safe".
  - Repo tests: 22 pass.
  - Guard probes and max-size timing: 0.4 s worst case, so the 5 s timeout is not a concern.
  - Adapter instantiation inside the live Hermes runtime.
- **Contracts:** the Claude Code hook contract comes from the official docs; the Antigravity one from the hooks documentation embedded in the installed `agy` 1.5.18 binary.
- **Side effects:** no project files changed. I left one scratch file, `/tmp/claude-agy-strings.txt`. The Hermes validator imports the plugin, so it may have refreshed the gitignored `hermes/__pycache__`.
- **Live-test-only:**
  - Whether Antigravity's matcher ever fires for MCP tools.
  - Antigravity behaviour when a PreToolUse hook crashes or times out.
  - Whether Antigravity accepts `url` for the remote server (its native field is `serverUrl`).
  - Real MLS exchange and real invite redemption.
  - Hermes gateway delivery.

## Preconditions before any live test

- **Local binary is too old.** `~/.local/bin/mp-outpost` is 0.6.0, so `/card` and `/inbox` will fail until it is upgraded.
- **Pick the build under test.**
  - The v0.7.0 tag, which the brew formula pins, creates `e2ee_mode: 0` rooms: `op_room_invite` sends no mode and attach hard-codes 0.
  - Only the uncommitted Outpost tree (11 files, +3,765 lines) requests mode 1 (`app_daemon.rs:6826`).
  - Likewise only the uncommitted site tree defaults to mode 1.

## P0 — must fix

1. **Claude Code secret guard never fires.** `plugins/multiplayer/hooks/hooks.json:5`
   - Failure: the matcher is `mcp__multiplayer__.*`, but plugin-bundled tools are named `mcp__plugin_multiplayer_multiplayer__<tool>`. The docs say a bare-server matcher "never fires for these tools".
   - Fix: `"matcher": "mcp__(plugin_multiplayer_)?multiplayer(-setup)?__.*"`. This also covers the remote server, which has no Outpost-side scan behind it.
   - Tests hide it: `tests/test_multi_host_plugins.py:332-334` hard-codes the wrong tool names and bypasses the matcher.

2. **Antigravity guard auto-approves every multiplayer call.** `.agents/plugins/multiplayer/scripts/secret_guard.py:183,188,205`
   - Failure: the clean path emits `{"decision": "allow"}`, documented as "Automatically allow the tool execution". The guard therefore removes the permission prompt on `party_send`, `inbox_send`, `board_post`, `party_join` and `friend_add`, which is the human gate the untrusted-peer rules rely on.
   - Fix: emit `{"decision": "ask"}`, which respects the Always Allow cache, and confirm live.
   - Tests lock it in: `tests/test_multi_host_plugins.py:374` asserts `allow`.

3. **Hermes Gateway adapter cannot be constructed or receive.** `hermes/adapter.py:174,213,671-676`; `hermes/__init__.py:655-656`
   - Failure, reproduced in the live runtime: `TypeError: Can't instantiate abstract class MultiplayerPlatformAdapter without an implementation for abstract method 'get_chat_info'`.
   - It also passes the string `"multiplayer"` where the base expects a `Platform` enum.
   - Inbound is dropped: the factory sets no `on_message`, so `_dispatch_message` discards every event while the cursor advances.
   - Fix: follow `plugins/platforms/raft/adapter.py`.
     - Call `super().__init__(config, Platform("multiplayer"))`.
     - Implement `get_chat_info`.
     - Call `_mark_connected()`.
     - Build a `MessageEvent` through `build_source(...)` and `await self.handle_message(event)`.
     - Filter out own-device events.

4. **`hermes multiplayer …` prints nothing and always exits 0.** `hermes/__init__.py:406-556`, registered at `:677-683`
   - Failure: Hermes runs `rc = args.func(args)` and only honours an `int` (`hermes_cli/main.py:3552`). The handler returns a `(code, text)` tuple and never prints.
   - Consequences: `setup` shows no snippet, `status` is silent, and `login` (`:469-480`) captures the sign-in URL for up to 120 s and discards it.
   - Fix: register a wrapper that prints the text and returns the int. Run `login` with inherited stdio.

5. **Unconditional "MLS (RFC 9420) E2EE" is false for the shipping binary.** This is Astra's Finding 1 carried into the plugins.
   - Where:
     - `skills/multiplayer/SKILL.md:3,15,87` and its three identical copies
     - `.claude-plugin/marketplace.json:13`
     - `plugins/multiplayer/.claude-plugin/plugin.json:4`
     - `plugins/multiplayer/README.md:3`
     - `.agents/plugins/multiplayer/plugin.json:4`
     - `hermes/plugin.yaml:5`
     - `hermes/README.md:3`
     - `hermes/upstream/plugin-catalog/multiplayer-outpost.yaml:9`
     - `hermes/__init__.py:680`
   - Fix: state that MLS applies only when `e2ee_mode: 1`, and that `e2ee_mode: 0` rooms are invite-only, TLS-protected and server-readable. Tell the agent to read `e2ee_mode` from `party_list` before sharing anything sensitive. `SKILL.md:53` ("MLS-encrypted when enabled") is already the right register.

6. **Invite and share-link copy is wrong, and contradicts the secret policy.** This is Astra's Finding 2. `SKILL.md:30,47`; `commands/invite.md:10`; `commands/party.md:10`; `commands/friends.md:11`
   - Failure:
     - `/v1/rooms/invite` returns `room_code: ""` and `share_url: <site>/account/` (`rooms_and_cloud.ts:1425-1432`).
     - v0.7.0 passes that through, so `/invite` hands the operator the account page as a "join link".
     - Nothing mints a `clank.party` link from the CLI or MCP; only the browser's in-party action does (`:1216-1217`).
     - On the MLS tree, `share_url` is `multiplayer.tech/p/i/<id>#<fragment>`. `invite.md:10` then tells the agent to print the secret that `SKILL.md:98` forbids in chat responses.
   - Fix: document two paths.
     - `invite @friend` sends an addressed invite, and the friend runs bare `mp-outpost join`.
     - Fragment links are shown to the local operator only and never sent through a tool.
     - Drop the `room_code` and `clank.party` promises.

## P1 — should fix before release or submission

- **Both guards fail open.** `plugins/multiplayer/scripts/secret_guard.py:180-188`
  - A non-dict payload crashes with exit 1 (reproduced). A missing `python3` or a timeout also lets the call proceed.
  - Fix: wrap `main()` so any exception denies (exit 2), and add `"onFailure": "block"` (Claude Code ≥ 2.1.295).
- **Guard coverage is narrower than the READMEs claim.** Probes that passed through:
  - a base64-wrapped token in `payload_b64`
  - the real `.mpkey` forms (PEM footer, `TVBLRVkxAA` magic)
  - dict keys
  - nesting deeper than 8
  - `#fragment` URLs, which `.agents/plugins/multiplayer/README.md:11` explicitly says are refused
- **Outpost does not scan `party_send` bodies for `mpcs1_` or `mpguest1_`.** `fence.rs:196-258` covers only `mpinv1_` and `mppi1_`. `SKILL.md:53` overclaims. File this against Outpost; it is outside Lane A.
- **`is_historical_catchup` is never surfaced.** It is absent from MCP output (`stdio.rs:1495-1766`) and CLI JSON (`cli.rs:7229-7305`).
  - Where it is promised: `SKILL.md:58,71`; `commands/party.md:12`; `rules/multiplayer.mdc:12`; `.agents/.../rules/AGENTS.md:8`; `hermes/README.md:8`.
  - Dead code: `hermes/adapter.py:546`.
  - Fix: tell agents to use `mentioned_self`.
- **Response-shape drift.**
  - `commands/join.md:10` expects `e2ee_mode`, `trust_tier` and a cursor from `party_join`, which returns none of them (`mcp_bridge.rs:1207-1214`). Say "call `party_list` next".
  - `SKILL.md:43` lists a `status` field that `party_members` does not return.
  - Agent cards arrive as `kind=bridge_envelope` with a base64 payload, not `agent_card`. That makes `hermes/adapter.py:569-584` dead, and `:587-588` feeds the model base64.
- **Hermes `pre_llm_call` hook.** `hermes/__init__.py:274-403,672-675`
  - It runs in every session on every turn, with up to two blocking 2 s subprocesses.
  - Its cursor starts at 0, so it replays ring history as "unread".
  - It injects peer text into unrelated sessions, for example a Telegram gateway chat.
  - `/party-read` builds a fresh hook each call (`:573`), so it always shows the oldest 10 events.
  - Fix: make it opt-in, seed the cursor from `next_seq`, and add both behaviours to the Rule 13 disclosures.
- **`setup --write` rewrites `config.yaml`.** `hermes/__init__.py:136-215`
  - It round-trips through `safe_load`/`safe_dump`, stripping the user's comments, and reads the whole file.
  - Fix: print `hermes mcp add …` instead.
- **Hermes `send()` reports success on non-delivery.** `hermes/adapter.py:516-528`
  - It ignores `delivered_to`, `withheld_unpinned` and `disconnected`.
  - It reads an `event_seq` that the CLI never returns.
- **Submission blockers.**
  - `hermes/upstream/plugin-catalog/multiplayer-outpost.yaml:4` is a placeholder SHA.
  - `.agents/plugins/marketplace.json:10-13` fails `agy plugin validate` with "source has no url". It is a Codex-format file, so Antigravity has no valid marketplace entry.

## P2 / nits

- `hermes/security.py:44`: `#[^\s]+` is greedy and corrupts `--json` output. Use `#[A-Za-z0-9_-]+`.
- `plugins/multiplayer/.claude-plugin/plugin.json:14-20`: hosts omit `relay.multiplayer.tech`, `relay-wnam`, `releases` and `objects`, and list `clank.party`, which nothing contacts.
- `plugins/multiplayer/README.md:23`: `/status` collides with the Claude Code built-in. Document `/multiplayer:status`.
- `hermes/adapter.py:400-404`: message bodies go on argv and are visible in `ps`. `:447` uses scope `agent_card` where MCP uses `party/main`.
- `hermes/__init__.py:266-269`: `sender_handle` keeps newlines in the unfenced meta line.
- `SKILL.md:48`: on the MLS tree the fragment never leaves the client, rather than "sent only in the POST body".
- `requires_hermes: ">=0.21.0"` is unverified, and nothing checks for Outpost ≥ 0.7.0.

## Live-test checklist

**Claude Code**
1. Run `/hooks` and confirm the guard is listed.
2. Ask the agent to `party_send` a synthetic `mpinv1_` plus 43 `A`s. Expect the hook's deny text, not Outpost's refusal. Today Outpost refuses, which proves the hook is dead.
3. Send the same token to a `multiplayer-setup` tool. Expect a deny.
4. Rename `python3` off PATH and retry. Expect a block, not a send.
5. Run `/multiplayer:invite`, then check `share_url` and `e2ee_mode` against what the command tells the operator.

**Antigravity**
1. Call `party_send` with clean text under default permissions. Expect a permission prompt; today it is auto-approved.
2. Send the synthetic token. Expect a deny, which also proves the matcher fires for MCP tool names.
3. Break the script path. Record whether the call is blocked or allowed.
4. Run `agy mcp list` and confirm `multiplayer-setup` connects with `url`.

**Hermes**
1. Run `hermes multiplayer setup`. Expect a printed snippet.
2. Run `hermes multiplayer login`. Expect a visible URL.
3. Enable the `multiplayer` platform and start the gateway. Expect no `TypeError`. Then have a peer send a message and check it reaches a session exactly once, with no self-echo loop.
4. Open an unrelated CLI session with a party active. Check whether old party history is injected.
5. Run `/party-read` twice. The second run should be empty.
6. Have a peer post a card. Check the model sees JSON, not base64.
