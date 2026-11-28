"""Integration & strict security oracle tests for OpenClaw, OpenCode, Pi, Claude Code, Antigravity, and Hermes plugins."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import hermes  # noqa: E402
from hermes.security import redact_url_fragments  # noqa: E402

CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _make_synthetic_recovery_key(seed_byte: int = 0x6B) -> str:
    seed = bytes([(seed_byte + i * 7) & 0xFF for i in range(32)])
    digest = hashlib.sha256(b"mp-recovery-v1:" + seed).digest()
    payload = seed + digest[:2]
    bits = int.from_bytes(payload, "big") << 3
    return "".join(CROCKFORD_ALPHABET[(bits >> (shift * 5)) & 0x1F] for shift in range(54, -1, -1))


def _write_strict_fake_outpost(directory: Path) -> Path:
    """Strict mock mp-outpost v0.7.0 CLI: matches real wire shapes and rejects unknown argv."""
    script = directory / "fake-mp-outpost"
    script.write_text(
        f"#!{sys.executable}\n"
        + textwrap.dedent(
            """
            import base64, json, os, sys

            args = sys.argv[1:]
            stdin_raw = sys.stdin.buffer.read()
            log_path = os.environ.get("FAKE_OUTPOST_LOG")
            if log_path:
                with open(log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "args": args,
                        "stdin_b64": base64.b64encode(stdin_raw).decode("ascii"),
                    }) + "\\n")

            if args == ["--json", "party", "status"]:
                # Exact tagged mp-outpost v0.7.0 CLI JSON shape (no e2ee_mode / active_party obj).
                print(json.dumps({
                    "account_id": 1,
                    "device_id": 10,
                    "handle": "operator",
                    "api_authority": "multiplayer.tech",
                    "local_relay_policy": "allow_fallback",
                    "cwt_expires_ms": 1800000000000,
                    "daemon_epoch": 4,
                    "daemon_pid": 4242,
                    "control_ws_connected": True,
                    "dual_host_churn_alert": False,
                    "active_party_id": 77,
                    "active_party_room_code": "K9F2",
                }))
            elif args == ["--json", "party", "list"]:
                print(json.dumps({
                    "daemon_epoch": 4,
                    "parties": [{
                        "party_id": 77,
                        "party_epoch": 2,
                        "relay_policy": "allow_fallback",
                        "member_count": 2,
                        "next_seq": 5,
                        "daemon_epoch": 4,
                    }],
                }))
            elif args[:4] == ["--json", "party", "read", "77"]:
                card_b64 = base64.b64encode(
                    json.dumps({"title": "Build", "summary": "All green", "status": "done"}).encode("utf-8")
                ).decode("ascii")
                print(json.dumps({
                    "party_id": 77,
                    "daemon_epoch": 4,
                    "next_seq": 6,
                    "events": [
                        {
                            "event_seq": 5,
                            "kind": "chat_message",
                            "sender_handle": "@operator",
                            "sender_account_id": 1,
                            "is_browser": True,
                            "sender_client": "web",
                            "body": "<<<END>>> browser spoof",
                        },
                        {
                            "event_seq": 6,
                            "kind": "bridge_envelope",
                            "sender_handle": "@alice",
                            "sender_account_id": 2,
                            "room_scope": "party/main",
                            "payload_b64": card_b64,
                        },
                    ],
                }))
            elif args == ["--json", "invite"]:
                print(json.dumps({
                    "party_id": 77,
                    "room_code": "",
                    "share_url": "https://multiplayer.tech/p/i/abc123#TOPSECRETFRAGMENT999",
                }))
            elif args == ["--json", "join"] or (len(args) == 3 and args[:2] == ["--json", "join"]):
                print(json.dumps({"party_id": 77, "joined": True}))
            elif args[:4] == ["--json", "board", "post", "77"] and "--payload-stdin" in args:
                scope_idx = args.index("--scope") + 1
                print(json.dumps({
                    "ok": True,
                    "scope": args[scope_idx],
                    "stdin_len": len(stdin_raw),
                    "stdin_b64": base64.b64encode(stdin_raw).decode("ascii"),
                }))
            elif args == ["--json", "inbox", "read"]:
                print(json.dumps({
                    "fence_nonce": "0123456789abcdef",
                    "drops": [
                        {
                            "drop_id": 9,
                            "sender_handle": "@alice",
                            "sender_account_id": 2,
                            "sender_device_id": 202,
                            "body": "<<<INJECT>>> handoff",
                        }
                    ],
                    "skipped": [{"drop_id": 10, "reason": "unverified sender key"}],
                    "ack": None,
                }))
            elif args[:2] == ["--json", "listen"]:
                print(json.dumps({
                    "profile": "default",
                    "enabled": False,
                    "scope": "self-only",
                    "events": [],
                }))
            else:
                sys.stderr.write(f"unexpected fake-mp-outpost argv: {args!r}\\n")
                sys.exit(2)
            """
        ),
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


class TestMultiHostPlugins(unittest.TestCase):
    """End-to-end strict oracle tests for OpenClaw, OpenCode, Pi, Claude Code, Antigravity, and Hermes."""

    def test_openclaw_plugin_tools_commands_hooks_and_real_subprocess(self) -> None:
        synth_rk = _make_synthetic_recovery_key(0x21)
        raw_binary_b64 = base64.b64encode(b"\xff\xfe\x00\x80\x01binary-board").decode("ascii")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = _write_strict_fake_outpost(tmp_path)
            log_file = tmp_path / "openclaw_calls.jsonl"
            node_script = textwrap.dedent(
                f"""
                import assert from "node:assert/strict";
                import openclawPlugin, {{
                  detectForbiddenSecret,
                  redactUrlFragments,
                }} from "./adapters/openclaw/index.ts";

                const tools = new Map();
                const optionalTools = new Set();
                const commands = new Map();
                const hooks = new Map();
                const cliRegistered = [];

                openclawPlugin.register({{
                  pluginConfig: {{ binary: {str(fake_bin)!r}, waitTimeoutMs: 12000 }},
                  registerTool(tool, opts) {{
                    tools.set(tool.name, tool);
                    if (opts?.optional) optionalTools.add(tool.name);
                  }},
                  registerCommand(cmd) {{ commands.set(cmd.name, cmd); }},
                  registerCli(fn, opts) {{ cliRegistered.push(opts); }},
                  on(name, handler) {{ hooks.set(name, handler); }},
                }});

                assert.equal(tools.size, 18, "OpenClaw plugin must register all 18 mp-outpost tools");
                assert.ok(!optionalTools.has("outpost_status"));
                assert.ok(!optionalTools.has("inbox_read"));
                assert.ok(optionalTools.has("inbox_ack"));
                assert.ok(optionalTools.has("party_send"));
                assert.ok(optionalTools.has("party_post_card"));
                assert.ok(optionalTools.has("inbox_send"));
                assert.ok(optionalTools.has("party_listen"));

                // party_listen status works and NaN numeric params are rejected before spawn
                const listenRes = JSON.parse((await tools.get("party_listen").execute("tl", {{ action: "status" }})).content[0].text);
                assert.equal(listenRes.scope, "self-only");
                await assert.rejects(
                  () => tools.get("party_wait").execute("tw_nan", {{ party_id: 77, after_seq: 0, timeout_ms: Number.NaN }}),
                  /finite integer/,
                );
                await assert.rejects(
                  () => tools.get("inbox_send").execute("ti_nan", {{ recipient: "@alice", body: "hi", ttl_secs: Number.NaN }}),
                  /finite integer/,
                );
                await assert.rejects(
                  () => tools.get("party_send").execute("ts_flag", {{ party_id: 77, body: "--json" }}),
                  /flag-only/,
                );
                await assert.rejects(
                  () => tools.get("party_send").execute("ts_scope", {{ party_id: 77, body: "hi", room_scope: "--json" }}),
                  /cannot start with '-'/,
                );

                // P0 check: read-only inbox_read must NOT accept ack parameter
                assert.equal(Object.hasOwn(tools.get("inbox_read").parameters.properties, "ack"), false);

                for (const cmd of ["party-status", "party-invite", "party-join", "party-leave", "party-friends", "party-read"]) {{
                  assert.ok(commands.has(cmd), "missing OpenClaw command: " + cmd);
                }}
                assert.equal(cliRegistered.length, 1);

                // Prompt guidance hook
                const promptPatch = await hooks.get("before_prompt_build")();
                assert.ok(promptPatch.prependContext.includes("is_browser=true"));
                assert.ok(promptPatch.prependContext.includes("e2ee_mode"));

                // Pre-exec secret guard blocks secrets without echo + catches base64/fragment/depth
                const b43 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk012345";
                const secret = "mpcs1_" + b43;
                const blocked = await hooks.get("before_tool_call")({{
                  toolName: "party_send",
                  params: {{ party_id: 77, body: secret }},
                }});
                assert.equal(blocked.block, true);
                assert.ok(!blocked.blockReason.includes(b43));

                const fragBlocked = await hooks.get("before_tool_call")({{
                  toolName: "party_send",
                  params: {{ party_id: 77, body: "join https://clank.party/i/1#SUPERSECRET123" }},
                }});
                assert.equal(fragBlocked.block, true);

                // Recovery key + non-greedy JSON-safe fragment redaction
                assert.equal(detectForbiddenSecret({synth_rk!r}), "recovery_key");
                assert.equal(
                  redactUrlFragments('{{"share_url":"https://clank.party/i/42#SUPERSECRET"}}'),
                  '{{"share_url":"https://clank.party/i/42#[REDACTED]"}}',
                );

                // CLI status flags missing MLS fields explicitly
                const stRes = JSON.parse((await tools.get("outpost_status").execute("t0", {{}})).content[0].text);
                assert.equal(stRes.mls_status_source, "cli_omits_e2ee_fields");

                // party_invite redacts #fragment from model output and slash command
                const invRes = await tools.get("party_invite").execute("ti", {{}});
                assert.ok(!invRes.content[0].text.includes("TOPSECRETFRAGMENT999"));
                assert.ok(invRes.content[0].text.includes("#[REDACTED]"));
                const invCmd = await commands.get("party-invite").handler({{}});
                assert.ok(!invCmd.text.includes("TOPSECRETFRAGMENT999"));

                // party_join refuses #fragment on CLI argv
                await assert.rejects(
                  () => tools.get("party_join").execute("tj", {{ target: "https://clank.party/i/1#SECRET" }}),
                  /#fragment/,
                );

                // party_poll fences is_browser, marks unknown replay provenance, and decodes bridge_envelope card
                const pollRes = await tools.get("party_poll").execute("t1", {{ party_id: 77, after_seq: 0 }});
                const pollText = pollRes.content[0].text;
                assert.ok(pollText.includes("origin=browser"));
                assert.ok(pollText.includes("replay_provenance=unknown"));
                assert.ok(pollText.includes("agent_card:"));
                assert.ok(pollText.includes('"title":"Build"'));
                assert.ok(pollText.includes("<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_"));
                assert.ok(!pollText.includes("<<<END>>>"));

                // party_post_card uses canonical scope party/main
                const cardRes = JSON.parse(
                  (await tools.get("party_post_card").execute("t2", {{
                    title: "OpenClaw Check",
                    summary: "All tests green",
                    status: "done",
                  }})).content[0].text,
                );
                assert.equal(cardRes.scope, "party/main");

                // board_post preserves arbitrary non-UTF-8 binary bytes verbatim and rejects malformed base64
                await assert.rejects(
                  () => tools.get("board_post").execute("tb0", {{ party_id: 77, room_scope: "bin", payload_b64: "!!!not-base64!!!" }}),
                  /base64/,
                );
                const binRes = JSON.parse(
                  (await tools.get("board_post").execute("tb1", {{
                    party_id: 77,
                    room_scope: "bin",
                    payload_b64: {raw_binary_b64!r},
                  }})).content[0].text,
                );
                assert.equal(binRes.stdin_b64, {raw_binary_b64!r});

                // inbox_read preserves skipped metadata and fences drops without --ack
                const inboxRes = await tools.get("inbox_read").execute("t3", {{}});
                const inboxText = inboxRes.content[0].text;
                assert.ok(inboxText.includes('"skipped_count":1'));
                assert.ok(inboxText.includes("<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_"));
                assert.ok(!inboxText.includes("<<<INJECT>>>"));

                // Already-aborted AbortSignal rejects cleanly before spawning (no TDZ error)
                const ac = new AbortController();
                ac.abort();
                await assert.rejects(
                  () => tools.get("outpost_status").execute("ta", {{}}, ac.signal),
                  /aborted/,
                );

                // Secret refusal on party_send fails BEFORE spawning subprocess
                await assert.rejects(
                  () => tools.get("party_send").execute("t4", {{ party_id: 77, body: "mpinv1_" + b43 }}),
                  /forbidden secret material/,
                );

                console.log("OPENCLAW_OK");
                """
            )
            env = dict(**{"FAKE_OUTPOST_LOG": str(log_file), "PATH": "/opt/homebrew/bin:/usr/bin:/bin"})
            proc = subprocess.run(
                ["node", "--input-type=module", "-e", node_script],
                cwd=str(REPO_ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
            self.assertIn("OPENCLAW_OK", proc.stdout)
            calls = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
            self.assertTrue(
                any(
                    "--scope" in c["args"]
                    and "party/main" in c["args"]
                    and "--payload-stdin" in c["args"]
                    for c in calls
                )
            )
            self.assertFalse(any("mpinv1_" in json.dumps(c) for c in calls))
            self.assertFalse(any("--ack" in c["args"] for c in calls))

    def test_opencode_plugin_exports_only_initializer_and_enforces_secret_boundary(self) -> None:
        synth_rk = _make_synthetic_recovery_key(0x52)
        b64_secret = base64.b64encode(b"mpinv1_" + b"A" * 44).decode("ascii")
        b64_mpkey = base64.b64encode(b"MPKEY1\x00payload").decode("ascii")
        node_script = textwrap.dedent(
            f"""
            import assert from "node:assert/strict";
            import serverPlugin from "./adapters/opencode/src/index.ts";
            import {{ MULTIPLAYER_MCP_CONFIG, isMultiplayerToolName }} from "./adapters/opencode/src/security.ts";

            // OpenCode v2 contract: default export is {{ id: string, setup(ctx) }}
            assert.equal(serverPlugin.id, "antimeme.multiplayer");
            assert.equal(typeof serverPlugin.setup, "function");
            assert.equal(isMultiplayerToolName("party_listen"), true);

            const mcpMap = new Map();
            const toolHooks = new Map();
            const sessionHooks = new Map();
            await serverPlugin.setup({{
              mcp: {{
                transform(fn) {{
                  fn({{
                    get: (k) => mcpMap.get(k),
                    set: (k, v) => mcpMap.set(k, v),
                    list: () => mcpMap.entries(),
                  }});
                }},
              }},
              tool: {{
                hook(name, fn) {{ toolHooks.set(name, fn); }},
              }},
              session: {{
                hook(name, fn) {{ sessionHooks.set(name, fn); }},
              }},
            }});

            assert.deepEqual(mcpMap.get("multiplayer"), MULTIPLAYER_MCP_CONFIG);

            // Preserves user customization (including enabled: false) on re-setup
            mcpMap.set("multiplayer", {{ type: "local", command: ["/custom/mp-outpost", "mcp"], enabled: false }});
            await serverPlugin.setup({{
              mcp: {{
                transform(fn) {{
                  fn({{
                    get: (k) => mcpMap.get(k),
                    set: (k, v) => mcpMap.set(k, v),
                    list: () => mcpMap.entries(),
                  }});
                }},
              }},
            }});
            assert.equal(mcpMap.get("multiplayer").enabled, false);
            assert.equal(mcpMap.get("multiplayer").command[0], "/custom/mp-outpost");

            // Session context hook injects provenance guidance once
            const sysOut = {{ system: [] }};
            await sessionHooks.get("context")(sysOut);
            await sessionHooks.get("context")(sysOut);
            assert.equal(sysOut.system.length, 1);
            assert.ok(sysOut.system[0].text.includes("is_browser=true"));
            assert.ok(sysOut.system[0].text.includes("e2ee_mode"));

            const beforeHook = toolHooks.get("tool.before");
            // Strengthened secret boundary: recovery key, guest token, credential key, PEM END,
            // base64-wrapped secrets, depth > 8 fail-closed, dict key, and #fragment URL.
            const rk = {synth_rk!r};
            await assert.rejects(
              () => beforeHook({{ name: "multiplayer_party_send", input: {{ party_id: 1, body: "backup " + rk }} }}),
              (err) => err.message.includes("recovery_key") && !err.message.includes(rk),
            );
            await assert.rejects(
              () => beforeHook({{ name: "multiplayer_party_send", input: {{ device_secret: "0123456789abcdef0123456789abcdef" }} }}),
              /device_credential/,
            );
            await assert.rejects(
              () => beforeHook({{ name: "multiplayer_party_send", input: {{ body: "-----END ED25519 PRIVATE KEY-----" }} }}),
              /private_key_pem/,
            );
            await assert.rejects(
              () => beforeHook({{ name: "multiplayer_board_post", input: {{ party_id: 1, room_scope: "s", payload_b64: {b64_secret!r} }} }}),
              /invite_token/,
            );
            await assert.rejects(
              () => beforeHook({{ name: "multiplayer_board_post", input: {{ party_id: 1, room_scope: "s", payload_b64: {b64_mpkey!r} }} }}),
              /recovery_file/,
            );
            await assert.rejects(
              () => beforeHook({{ name: "multiplayer_party_send", input: {{ party_id: 1, body: "join https://clank.party/i/42#SECRETFRAG99" }} }}),
              /invite_url_fragment/,
            );
            // Deeply nested object (>8) fails closed instead of silent pass
            let deep = {{ leaf: "ok" }};
            for (let i = 0; i < 10; i++) deep = {{ nested: deep }};
            await assert.rejects(
              () => beforeHook({{ name: "multiplayer_party_send", input: deep }}),
              /nesting_depth_exceeded/,
            );

            // party_join.target allows #fragment URL over MCP stdio, and clean calls pass
            await beforeHook({{ name: "multiplayer_party_join", input: {{ target: "https://clank.party/i/42#SECRETFRAG99" }} }});
            await beforeHook({{ name: "multiplayer_party_send", input: {{ body: "hello" }} }});
            await beforeHook({{ name: "read_file", input: {{ path: "README.md" }} }});
            console.log("OPENCODE_OK");
            """
        )
        proc = subprocess.run(
            ["node", "--input-type=module", "-e", node_script],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
        self.assertIn("OPENCODE_OK", proc.stdout)

    def test_pi_extension_registers_tools_ui_notify_and_session_start(self) -> None:
        raw_binary_b64 = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00\xff\xfe").decode("ascii")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = _write_strict_fake_outpost(tmp_path)
            node_script = textwrap.dedent(
                f"""
                import assert from "node:assert/strict";
                import multiplayerExtension from "./adapters/pi/index.ts";

                const commands = new Map();
                const tools = new Map();
                const events = new Map();
                multiplayerExtension({{
                  registerCommand(name, spec) {{ commands.set(name, spec); }},
                  registerTool(tool) {{ tools.set(tool.name, tool); }},
                  on(ev, fn) {{ events.set(ev, fn); }},
                }});

                assert.equal(tools.size, 18, "Pi extension must register all 18 LLM tools");
                assert.equal(Object.hasOwn(tools.get("inbox_read").parameters.properties, "ack"), false);
                assert.ok(tools.has("party_listen"), "Pi must register party_listen");
                assert.ok(events.has("before_agent_start"), "Pi must register before_agent_start guidance hook");
                const startPatch = await events.get("before_agent_start")({{ systemPrompt: "base" }});
                assert.ok(startPatch.systemPrompt.includes("is_browser=true"));
                for (const cmd of ["party-status", "party-invite", "party-join", "party-leave", "friend-add", "friends", "party", "party-say", "party-card", "party-inbox"]) {{
                  assert.ok(commands.has(cmd), "missing Pi command: " + cmd);
                }}

                // Real Pi session_start(event, ctx) uses ctx.ui.notify + ctx.ui.setStatus + active_party_room_code
                const notifications = [];
                const statuses = [];
                const uiCtx = {{
                  ui: {{
                    notify(msg, lvl) {{ notifications.push([lvl, msg]); }},
                    setStatus(k, v) {{ statuses.push([k, v]); }},
                  }},
                }};
                await events.get("session_start")({{ reason: "startup" }}, uiCtx);
                assert.ok(statuses.some(([k, v]) => k === "multiplayer" && v.includes("#77") && v.includes("K9F2")));
                assert.ok(notifications.some(([, m]) => m.includes("party #77") && m.includes("K9F2")));

                // tool_call hook refuses secrets and #fragment URLs
                const res = await events.get("tool_call")({{
                  toolName: "party_send",
                  input: {{ party_id: 77, body: "mpcs1_ABCDEFGHIJKLMNOPQRST" }},
                }});
                assert.equal(res.block, true);

                // party_invite redacts #fragment; party_join refuses #fragment on CLI argv
                const inv = await tools.get("party_invite").execute("ci", {{}});
                assert.ok(!inv.content[0].text.includes("TOPSECRETFRAGMENT999"));
                await assert.rejects(
                  () => tools.get("party_join").execute("cj", {{ target: "https://clank.party/i/1#SECRET" }}),
                  /#fragment/,
                );

                // party_poll fences is_browser, marks unknown replay provenance, decodes bridge_envelope card
                const poll = await tools.get("party_poll").execute("c1", {{ party_id: 77, after_seq: 0 }});
                assert.ok(poll.content[0].text.includes("origin=browser"));
                assert.ok(poll.content[0].text.includes("replay_provenance=unknown"));
                assert.ok(poll.content[0].text.includes("agent_card:"));
                assert.ok(poll.content[0].text.includes("<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_"));

                // party_post_card uses canonical scope party/main
                const card = JSON.parse(
                  (await tools.get("party_post_card").execute("cc", {{
                    title: "Pi Check",
                    summary: "All green",
                  }})).content[0].text,
                );
                assert.equal(card.scope, "party/main");

                // board_post preserves arbitrary raw binary bytes via Buffer stdin
                const bin = JSON.parse(
                  (await tools.get("board_post").execute("cb", {{
                    party_id: 77,
                    room_scope: "png",
                    payload_b64: {raw_binary_b64!r},
                  }})).content[0].text,
                );
                assert.equal(bin.stdin_b64, {raw_binary_b64!r});

                // inbox_read preserves skipped metadata
                const inbox = await tools.get("inbox_read").execute("cin", {{}});
                assert.ok(inbox.content[0].text.includes('"skipped_count":1'));

                // Already-aborted AbortSignal rejects without spawning
                const ac = new AbortController();
                ac.abort();
                await assert.rejects(
                  () => tools.get("outpost_status").execute("ca", {{}}, ac.signal),
                  /aborted/,
                );

                console.log("PI_FULL_OK");
                """
            )
            env = dict(**{"MP_OUTPOST_BIN": str(fake_bin), "PATH": "/opt/homebrew/bin:/usr/bin:/bin"})
            proc = subprocess.run(
                ["node", "--input-type=module", "-e", node_script],
                cwd=str(REPO_ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
            self.assertIn("PI_FULL_OK", proc.stdout)

    def test_claude_code_and_antigravity_pretooluse_secret_guards(self) -> None:
        synth_rk = _make_synthetic_recovery_key(0x73)
        secret_tok = "mpinv1_" + ("Z" * 43)
        b64_secret = base64.b64encode(secret_tok.encode("utf-8")).decode("ascii")
        b64_mpkey = base64.b64encode(b"MPKEY1\x00backup").decode("ascii")

        # 0. Verify Claude Code hooks.json matcher regex actually matches plugin-bundled MCP names!
        cc_hooks_cfg = json.loads(
            (REPO_ROOT / "plugins" / "multiplayer" / "hooks" / "hooks.json").read_text(encoding="utf-8")
        )
        matcher = cc_hooks_cfg["hooks"]["PreToolUse"][0]["matcher"]
        matcher_re = re.compile(matcher)
        for tool_name in (
            "mcp__plugin_multiplayer_multiplayer__party_send",
            "mcp__plugin_multiplayer_multiplayer-setup__set_me_up",
            "mcp__multiplayer__party_send",
            "mcp__multiplayer-setup__check_control_plane",
        ):
            self.assertIsNotNone(matcher_re.fullmatch(tool_name), f"matcher {matcher!r} missed {tool_name}")

        cc_hook = REPO_ROOT / "plugins" / "multiplayer" / "scripts" / "secret_guard.py"
        agy_hook = REPO_ROOT / ".agents" / "plugins" / "multiplayer" / "scripts" / "secret_guard.py"

        deep: dict[str, object] = {"leaf": "ok"}
        for _ in range(10):
            deep = {"nested": deep}

        # 1. Claude Code hook: deny on secrets, base64, PEM END, fragment, depth>8, malformed; {} on clean
        cc_cases: list[tuple[str, bool]] = [
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_send", "tool_input": {"body": f"leak {secret_tok}"}}), True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_post_card", "tool_input": {"summary": f"rk {synth_rk}"}}), True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__board_post", "tool_input": {"payload_b64": b64_secret}}), True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__board_post", "tool_input": {"payload_b64": b64_mpkey}}), True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_send", "tool_input": {"body": "-----END ED25519 PRIVATE KEY-----"}}), True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_send", "tool_input": {"body": "join https://clank.party/i/1#MYSECRETFRAG"}}), True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_send", "tool_input": {secret_tok: "in key"}}), True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_send", "tool_input": deep}), True),
            ("not valid json", True),
            ("[]", True),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_join", "tool_input": {"target": "https://clank.party/i/1#MYSECRETFRAG"}}), False),
            (json.dumps({"tool_name": "mcp__plugin_multiplayer_multiplayer__party_send", "tool_input": {"body": "clean status update"}}), False),
        ]
        for raw_in, expect_deny in cc_cases:
            proc = subprocess.run(
                [sys.executable, str(cc_hook)],
                input=raw_in,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr} raw={raw_in[:60]}")
            out = json.loads(proc.stdout)
            if expect_deny:
                self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", msg=raw_in[:80])
                self.assertNotIn(secret_tok, proc.stdout)
                self.assertNotIn(synth_rk, proc.stdout)
            else:
                self.assertEqual(out, {}, msg=raw_in[:80])

        # 2. Antigravity hook: deny on secrets/malformed/depth>8 (including lazy call_mcp_tool); "ask" on clean
        agy_hooks_cfg = json.loads(
            (REPO_ROOT / ".agents" / "plugins" / "multiplayer" / "hooks.json").read_text(encoding="utf-8")
        )
        agy_matcher_re = re.compile(agy_hooks_cfg["multiplayer-secret-guard"]["PreToolUse"][0]["matcher"])
        self.assertIsNotNone(agy_matcher_re.search("call_mcp_tool"))
        self.assertIsNotNone(agy_matcher_re.search("mcp_multiplayer_party_send"))

        agy_cases: list[tuple[str, str]] = [
            (json.dumps({"toolCall": {"name": "mcp_multiplayer_party_send", "args": {"body": f"leak {secret_tok}"}}}), "deny"),
            (json.dumps({"toolCall": {"name": "call_mcp_tool", "args": {"ServerName": "multiplayer_multiplayer", "ToolName": "party_send", "Arguments": {"body": f"leak {secret_tok}"}}}}), "deny"),
            (json.dumps({"toolCall": {"name": "call_mcp_tool", "args": {"ServerName": "multiplayer_multiplayer", "ToolName": "party_send", "Arguments": {"body": "join https://clank.party/i/1#MYSECRETFRAG"}}}}), "deny"),
            (json.dumps({"toolCall": {"name": "call_mcp_tool", "args": {"ServerName": "multiplayer_multiplayer", "ToolName": "party_join", "Arguments": {"target": "https://clank.party/i/1#MYSECRETFRAG"}}}}), "ask"),
            (json.dumps({"toolCall": {"name": "call_mcp_tool", "args": {"ServerName": "linear", "ToolName": "create_issue", "Arguments": {"description": "https://clank.party/i/1#MYSECRETFRAG"}}}}), "ask"),
            (json.dumps({"toolCall": {"name": "mcp_multiplayer_inbox_send", "args": {"body": f"rk {synth_rk}"}}}), "deny"),
            (json.dumps({"toolCall": {"name": "mcp_multiplayer_board_post", "args": {"payload_b64": b64_secret}}}), "deny"),
            (json.dumps({"toolCall": {"name": "mcp_multiplayer_party_send", "args": {"body": "join https://clank.party/i/1#MYSECRETFRAG"}}}), "deny"),
            (json.dumps({"toolCall": {"name": "mcp_multiplayer_party_send", "args": deep}}), "deny"),
            ("[]", "deny"),
            ("", "deny"),
            (json.dumps({"toolCall": {"name": "mcp_multiplayer_party_join", "args": {"target": "https://clank.party/i/1#MYSECRETFRAG"}}}), "ask"),
            (json.dumps({"toolCall": {"name": "mcp_multiplayer_party_send", "args": {"body": "clean status update"}}}), "ask"),
        ]
        for raw_in, expect_decision in agy_cases:
            proc = subprocess.run(
                [sys.executable, str(agy_hook)],
                input=raw_in,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["decision"], expect_decision, msg=raw_in[:80])
            self.assertNotIn(secret_tok, proc.stdout)
            self.assertNotIn(synth_rk, proc.stdout)

        # 3. Antigravity hook decimal-string ID coercion (prevents 15-digit scientific-notation replay truncation)
        lazy_coerce_in = json.dumps(
            {
                "toolCall": {
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "multiplayer_multiplayer",
                        "ToolName": "party_poll",
                        "Arguments": {
                            "party_id": "2162678961511450",
                            "cursor_epoch": "1679057306706682",
                            "after_seq": "74",
                            "limit": 10,
                        },
                    },
                }
            }
        )
        proc = subprocess.run(
            [sys.executable, str(agy_hook)],
            input=lazy_coerce_in,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["decision"], "ask")
        self.assertEqual(
            out["overwrite"],
            {
                "Arguments": {
                    "party_id": 2162678961511450,
                    "cursor_epoch": 1679057306706682,
                    "after_seq": 74,
                    "limit": 10,
                }
            },
        )

        # Eager tool call coerces drop_ids list elements without touching non-ID keys
        eager_coerce_in = json.dumps(
            {
                "toolCall": {
                    "name": "mcp_multiplayer_inbox_ack",
                    "args": {"drop_ids": ["1679057306706682", 42]},
                }
            }
        )
        proc = subprocess.run(
            [sys.executable, str(agy_hook)],
            input=eager_coerce_in,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out, {"decision": "ask", "overwrite": {"drop_ids": [1679057306706682, 42]}})

        # Out-of-range (> MAX_SAFE_INTEGER) or non-decimal strings are NOT coerced, and integer calls omit overwrite
        for no_overwrite_args in (
            {"party_id": 2162678961511450, "cursor_epoch": 1679057306706682, "after_seq": 74},
            {"party_id": "9007199254740992", "after_seq": 0},
            {"party_id": "not-a-number", "after_seq": 0},
        ):
            raw_no_ow = json.dumps(
                {
                    "toolCall": {
                        "name": "call_mcp_tool",
                        "args": {
                            "ServerName": "multiplayer_multiplayer",
                            "ToolName": "party_poll",
                            "Arguments": no_overwrite_args,
                        },
                    }
                }
            )
            proc = subprocess.run(
                [sys.executable, str(agy_hook)],
                input=raw_no_ow,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            self.assertEqual(json.loads(proc.stdout), {"decision": "ask"})

        # Secret alongside stringified IDs still fails closed (no overwrite bypass)
        secret_with_str_id = json.dumps(
            {
                "toolCall": {
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "multiplayer_multiplayer",
                        "ToolName": "party_send",
                        "Arguments": {"party_id": "2162678961511450", "body": f"leak {secret_tok}"},
                    },
                }
            }
        )
        proc = subprocess.run(
            [sys.executable, str(agy_hook)],
            input=secret_with_str_id,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["decision"], "deny")
        self.assertNotIn("overwrite", out)

    def test_hermes_cli_entrypoint_shared_read_cursor_and_json_safe_redaction(self) -> None:
        # 1. Non-greedy URL fragment redaction preserves surrounding JSON quotes
        raw_json = '{"share_url":"https://multiplayer.tech/p/i/42#SECRET999","ok":true}'
        redacted = redact_url_fragments(raw_json)
        self.assertEqual(json.loads(redacted)["share_url"], "https://multiplayer.tech/p/i/42#[REDACTED]")
        self.assertEqual(json.loads(redacted)["ok"], True)

        # 2. _cli_entrypoint prints output and returns int (not tuple)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = hermes._cli_entrypoint(SimpleNamespace(action="setup", write=False, binary="mp-outpost"))
        self.assertIs(type(rc), int)
        self.assertEqual(rc, 0)
        self.assertIn("hermes mcp add multiplayer -- mp-outpost mcp", buf.getvalue())

        # 3. register(ctx) makes pre_llm_call opt-in by default and shares cursor across /party-read
        registered_hooks: dict[str, object] = {}
        registered_cmds: dict[str, object] = {}

        class _Ctx:
            def register_hook(self, name: str, fn: object) -> None:
                registered_hooks[name] = fn

            def register_command(self, name: str, fn: object, **_kw: object) -> None:
                registered_cmds[name] = fn

            def register_cli_command(self, _n: str, _h: str, _s: object, fn: object) -> None:
                self.cli_fn = fn

        ctx = _Ctx()
        hermes.register(ctx)
        self.assertIs(ctx.cli_fn, hermes._cli_entrypoint)
        self.assertIsNone(registered_hooks["pre_llm_call"]())  # disabled unless env opted in
        self.assertIn("party-chat", registered_cmds)
        self.assertIn("party-listen", registered_cmds)

        # 4. P0/P1 Hermes regressions: #fragment refused on detect_secret_kind & join argv;
        #    UnreadNotificationHook seeds from head even with explicit party_id & recovers on 4040.
        self.assertEqual(
            hermes.detect_secret_kind("join https://clank.party/i/42#SUPERSECRET12345"),
            "invite_url_fragment",
        )
        self.assertEqual(
            redact_url_fragments("https://staging.example.com/p/i/42#SUPERSECRET"),
            "https://staging.example.com/p/i/42#[REDACTED]",
        )
        code, msg = hermes.handle_cli_command(
            SimpleNamespace(action="join", target="https://clank.party/i/42#SECRET99", json=False)
        )
        self.assertEqual(code, 2)
        self.assertIn("#fragment", msg)

        calls: list[list[str]] = []

        def fake_runner(argv: list[str], _timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            if argv[-2:] == ["party", "list"]:
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps({"daemon_epoch": 9, "parties": [{"party_id": 42, "next_seq": 15}]}), ""
                )
            if "read" in argv:
                return subprocess.CompletedProcess(argv, 1, "", "daemon error (code=4040): party 42 is not active")
            return subprocess.CompletedProcess(argv, 0, "{}", "")

        hook = hermes.UnreadNotificationHook(party_id=42, seed_from_head=True, runner=fake_runner, enabled=True)
        self.assertIsNone(hook())  # seeds from head (next_seq=15) without replaying history!
        self.assertEqual(hook.cursor.after_seq, 15)
        self.assertIsNone(hook())  # hits 4040 -> resets cursor for re-discovery instead of stalling forever
        self.assertIsNone(hook.cursor)

    def test_detached_phux_party_chat_launchers_across_all_hosts(self) -> None:
        """Verify detached phux window creation, reuse, stale cleanup, and secret refusal across all hosts."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            state_file = tmp_path / "phux_state.json"
            state_file.write_text(json.dumps({"sessions": []}), encoding="utf-8")
            fake_phux = tmp_path / "fake-phux"
            fake_phux.write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent(
                    f"""
                    import json, sys
                    from pathlib import Path
                    state_path = Path({str(state_file)!r})
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    args = sys.argv[1:]
                    if args == ["ls", "--json"]:
                        host_sessions = [{{"name": s["name"], "active_terminal": "@42"}} for s in state["sessions"] if s.get("exec", {{}}).get("running", 0) > 0]
                        print(json.dumps({{"schema_version": 4, "sessions": state["sessions"], "hosts": [{{"local": True, "sessions": host_sessions}}]}}))
                    elif len(args) >= 5 and args[:3] == ["new", "--json", "-s"] and "--" in args:
                        sess = args[3]
                        state["sessions"].append({{"name": sess, "exec": {{"running": 1, "starting": 0}}}})
                        state_path.write_text(json.dumps(state), encoding="utf-8")
                        print(json.dumps({{"schema_version": 1, "session": sess, "terminal_id": 42, "argv": args}}))
                    elif args[:2] == ["kill", "--yes"]:
                        sess = args[2]
                        state["sessions"] = [s for s in state["sessions"] if s["name"] != sess]
                        state_path.write_text(json.dumps(state), encoding="utf-8")
                        print("killed")
                    else:
                        sys.stderr.write(f"unexpected fake-phux args: {{args!r}}\\n")
                        sys.exit(2)
                    """
                ),
                encoding="utf-8",
            )
            fake_phux.chmod(fake_phux.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            # 1. Hermes launcher: fresh create -> @42 -> reuse -> refuse secret/#fragment
            from hermes.chat_launcher import launch_detached_chat as hermes_launch

            res1 = hermes_launch(phux_binary=str(fake_phux))
            self.assertTrue(res1["ok"])
            self.assertEqual(res1["backend"], "phux")
            self.assertFalse(res1["reused"])
            self.assertEqual(res1["pane_id"], "@42")
            self.assertEqual(res1["attach_cmd"], "phux attach multiplayer-chat")
            self.assertEqual(res1["native_cmd"], "phux native attach @42")

            res2 = hermes_launch(phux_binary=str(fake_phux))
            self.assertTrue(res2["ok"])
            self.assertTrue(res2["reused"])
            self.assertEqual(res2["pane_id"], "@42")
            self.assertEqual(res2["native_cmd"], "phux native attach @42")

            with self.assertRaises(ValueError):
                hermes_launch(target="https://clank.party/i/1#SECRETFRAG", phux_binary=str(fake_phux))
            with self.assertRaises(ValueError):
                hermes_launch(target="mpinv1_" + ("A" * 44), phux_binary=str(fake_phux))

            # Reset to stale 0-running session for JS host tests
            state_file.write_text(
                json.dumps({"sessions": [{"name": "multiplayer-chat", "exec": {"running": 0, "starting": 0}}]}),
                encoding="utf-8",
            )

            # 2. Pi (ctrl+shift+p shortcut + /party-chat), OpenClaw (/party-chat), OpenCode TUI (ctrl+shift+p + /party-chat)
            node_script = textwrap.dedent(
                f"""
                import assert from "node:assert/strict";
                import piExt from "./adapters/pi/index.ts";
                import openclawPlugin from "./adapters/openclaw/index.ts";
                import opencodeTui from "./adapters/opencode/src/tui.ts";

                process.env.PHUX_BIN = {str(fake_phux)!r};

                // Pi shortcut + /party-chat (cleans stale 0-running session and spawns fresh @42)
                const piShortcuts = new Map();
                const piCmds = new Map();
                piExt({{
                  registerCommand(n, s) {{ piCmds.set(n, s); }},
                  registerShortcut(k, s) {{ piShortcuts.set(k, s); }},
                }});
                assert.ok(piShortcuts.has("ctrl+shift+p"), "Pi must register ctrl+shift+p shortcut");
                assert.ok(piCmds.has("party-chat"), "Pi must register /party-chat");
                const piNotes = [];
                const piStatuses = [];
                await piShortcuts.get("ctrl+shift+p").handler({{
                  ui: {{
                    notify(msg, lvl) {{ piNotes.push([lvl, msg]); }},
                    setStatus(k, v) {{ piStatuses.push([k, v]); }},
                  }},
                }});
                assert.ok(piNotes.some(([, m]) => m.includes("phux attach multiplayer-chat") && m.includes("@42")));
                assert.ok(piStatuses.some(([k, v]) => k === "multiplayer" && v.includes("phux attach multiplayer-chat")));

                // OpenClaw /party-chat reuses running session
                const ocCmds = new Map();
                openclawPlugin.register({{
                  registerTool() {{}},
                  registerCommand(c) {{ ocCmds.set(c.name, c); }},
                }});
                assert.ok(ocCmds.has("party-chat"));
                const ocOut = await ocCmds.get("party-chat").handler({{ args: "" }});
                assert.ok(ocOut.text.includes("already running") && ocOut.text.includes("phux attach multiplayer-chat"));

                // OpenCode TUI plugin registers global ctrl+alt+m (/party menu), /party-chat, /party-say, /party-read, /party-status via ui.slot({{ append: "app" }})
                const layers = [];
                const toasts = [];
                const alerts = [];
                const slots = [];
                opencodeTui.setup({{
                  keymap: {{ layer(factory) {{ layers.push(factory()); }} }},
                  ui: {{
                    toast: {{ show(t) {{ toasts.push(t); }} }},
                    dialog: {{
                      async select() {{ return "chat"; }},
                      async prompt() {{ return "hello from prompt"; }},
                      async alert(a) {{ alerts.push(a); }},
                    }},
                    slot(spec) {{ slots.push(spec); spec.render(); }},
                  }},
                }});
                assert.equal(slots.length, 1);
                assert.equal(slots[0].append, "app");
                assert.equal(layers[0].mode, "global");
                const menuCmd = layers[0].commands.find((c) => c.id === "multiplayer.menu");
                assert.equal(menuCmd.bind, "ctrl+alt+m");
                assert.equal(menuCmd.palette, true);
                assert.equal(menuCmd.slash.name, "party");
                const chatCmd = layers[0].commands.find((c) => c.id === "multiplayer.chat");
                assert.equal(chatCmd.palette, true);
                assert.equal(chatCmd.slash.name, "party-chat");
                assert.ok(layers[0].commands.some((c) => c.id === "multiplayer.say" && c.slash.name === "party-say"));
                assert.ok(layers[0].commands.some((c) => c.id === "multiplayer.read" && c.slash.name === "party-read"));
                assert.ok(layers[0].commands.some((c) => c.id === "multiplayer.status" && c.slash.name === "party-status"));
                await menuCmd.run("");
                assert.ok(toasts.some((t) => t.variant === "success" && t.message.includes("phux attach multiplayer-chat") && t.message.includes("@42")));

                // Verify /party-say refuses secrets before spawning mp-outpost
                const sayCmd = layers[0].commands.find((c) => c.id === "multiplayer.say");
                await sayCmd.run("mpinv1_" + "A".repeat(44));
                assert.ok(toasts.some((t) => t.variant === "error" && t.message.includes("forbidden secret")));

                console.log("ALL_PHUX_LAUNCHERS_OK");
                """
            )
            proc = subprocess.run(
                ["node", "--input-type=module", "-e", node_script],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
            self.assertIn("ALL_PHUX_LAUNCHERS_OK", proc.stdout)

            # 3. Antigravity IDE / VS Code extension syntax check
            vs_check = subprocess.run(
                ["node", "--check", str(REPO_ROOT / "adapters" / "vscode-antigravity" / "extension.js")],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(vs_check.returncode, 0, msg=vs_check.stderr)

    def test_hermes_inline_party_chat_and_party_say(self) -> None:
        """Verify Hermes /party-chat --inline watcher (zero-token feed, echo filter, 4040 recovery) and /party-say."""
        import threading
        import time
        from hermes import InlinePartyWatcher, _make_slash_handler

        emitted: list[str] = []
        emitted_event = threading.Event()
        wait_calls: list[list[str]] = []
        say_calls: list[list[str]] = []

        def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "list" in argv:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps({"daemon_epoch": 9, "parties": [{"party_id": 777, "next_seq": 10}]}),
                    "",
                )
            if "status" in argv:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps({"handle": "antimeme", "device_id": 500, "control_ws_connected": True}),
                    "",
                )
            if "say" in argv:
                say_calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 0, json.dumps({"ok": True}), "")
            return subprocess.CompletedProcess(argv, 1, "", "unexpected")

        class FakeProc:
            def __init__(self, stdout: str, stderr: str = "", rc: int = 0) -> None:
                self._stdout = stdout
                self._stderr = stderr
                self.returncode: int | None = rc
                self._terminated = False

            def poll(self) -> int | None:
                return self.returncode

            def terminate(self) -> None:
                self._terminated = True

            def kill(self) -> None:
                self._terminated = True

            def wait(self, timeout: float | None = None) -> int:
                return self.returncode or 0

            def communicate(self, timeout: float | None = None) -> tuple[str, str]:
                if self._terminated:
                    return "", ""
                return self._stdout, self._stderr

        call_idx = 0

        def fake_popen(argv: list[str], **_kwargs: Any) -> FakeProc:
            nonlocal call_idx
            wait_calls.append(list(argv))
            call_idx += 1
            if call_idx == 1:
                payload = {
                    "daemon_epoch": 9,
                    "next_seq": 13,
                    "events": [
                        # Own non-browser echo -> must be filtered out
                        {
                            "event_seq": 11,
                            "kind": "chat",
                            "sender_handle": "antimeme",
                            "sender_device_id": 500,
                            "text": "my own echo",
                        },
                        # Remote peer message with ANSI escape + #fragment -> sanitized & redacted
                        {
                            "event_seq": 12,
                            "kind": "chat",
                            "sender_handle": "phall",
                            "sender_device_id": 901,
                            "text": "\x1b[31mhi\x1b[0m https://clank.party/i/abc#SECRET1234",
                        },
                        # Browser message even under own device_id -> must NOT be skipped and tagged [browser]
                        {
                            "event_seq": 13,
                            "kind": "chat",
                            "sender_handle": "antimeme",
                            "sender_device_id": 500,
                            "is_browser": True,
                            "text": "from web tab",
                        },
                    ],
                }
                return FakeProc(json.dumps(payload), "", 0)
            if call_idx == 2:
                return FakeProc("", "code=4040 party is not active", 1)
            time.sleep(0.05)
            return FakeProc(json.dumps({"daemon_epoch": 9, "next_seq": 13, "events": []}), "", 0)

        def on_emit(line: str) -> None:
            emitted.append(line)
            if len(emitted) >= 2:
                emitted_event.set()

        watcher = InlinePartyWatcher(
            outpost_binary="mp-outpost",
            emit_fn=on_emit,
            popen_factory=fake_popen,
            run_factory=fake_run,
            idle_backoff_s=0.05,
        )
        chat_handler = _make_slash_handler("chat", shared_inline_watcher=watcher)

        start_msg = chat_handler("--inline")
        self.assertIn("Inline party feed started for party #777", start_msg)
        self.assertIn("seq=10", start_msg)
        self.assertTrue(emitted_event.wait(timeout=3.0), f"expected 2 emitted lines, got {emitted!r}")

        status_msg = chat_handler("--inline status")
        self.assertIn("Inline party feed: ON", status_msg)

        stop_msg = chat_handler("--inline off")
        self.assertIn("Stopped inline party feed", stop_msg)
        self.assertFalse(watcher.is_running)

        # Verify own echo filtered, ANSI/fragment cleaned, browser message kept & tagged
        self.assertEqual(len(emitted), 2)
        self.assertIn("@phall", emitted[0])
        self.assertNotIn("\x1b", emitted[0])
        self.assertNotIn("SECRET1234", emitted[0])
        self.assertIn("#[REDACTED]", emitted[0])
        self.assertIn("@antimeme [browser]", emitted[1])
        self.assertIn("from web tab", emitted[1])
        self.assertTrue(any("--after-seq" in c and "10" in c for c in wait_calls))

        # Test /party-say send, secret refusal, and bare flag refusal
        def sync_runner(argv: list[str], _timeout: float) -> subprocess.CompletedProcess[str]:
            return fake_run(argv)

        say_handler = _make_slash_handler("say", runner=sync_runner)
        self.assertIn("Sent to party #777", say_handler("hello team"))
        self.assertEqual(len(say_calls), 1)
        self.assertIn("hello team", say_calls[0])

        refused_secret = say_handler("leak mpinv1_" + ("A" * 44))
        self.assertIn("forbidden secret", refused_secret)
        self.assertEqual(len(say_calls), 1)

        refused_flag = say_handler("--scope")
        self.assertIn("ambiguous", refused_flag.lower())
        self.assertEqual(len(say_calls), 1)

    def test_opencode_tui_native_dialogs(self) -> None:
        """Verify OpenCode v2 TUI /party menu, /party-say prompt, /party-read, /party-status, friends & listen dialogs."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            say_log = tmp_path / "say_log.json"
            fake_outpost = tmp_path / "fake-mp-outpost"
            fake_outpost.write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent(
                    f"""
                    import json, sys
                    from pathlib import Path
                    args = sys.argv[1:]
                    if args[:1] == ["--json"]:
                        args = args[1:]
                    if args == ["party", "list"]:
                        print(json.dumps({{"daemon_epoch": 5, "parties": [{{"party_id": 888, "member_count": 3, "next_seq": 20, "relay_policy": "allow_relays"}}]}}))
                    elif args == ["party", "status"]:
                        print(json.dumps({{"handle": "antimeme", "control_ws_connected": True, "api_authority": "api.multiplayer.tech", "local_relay_policy": "allow_relays", "dual_host_churn_alert": False}}))
                    elif args[:2] == ["party", "read"]:
                        print(json.dumps({{"events": [
                            {{"event_seq": 19, "kind": "chat", "sender_handle": "phall", "text": "status update https://clank.party/i/x#SECRET999"}},
                            {{"event_seq": 20, "kind": "chat", "sender_handle": "antimeme", "is_browser": True, "text": "web ping"}}
                        ]}}))
                    elif args[:2] == ["party", "say"]:
                        Path({str(say_log)!r}).write_text(json.dumps(args), encoding="utf-8")
                        print(json.dumps({{"ok": True}}))
                    elif args == ["friends"]:
                        print(json.dumps({{"friends": [{{"handle": "phall", "presence": "online", "state": "friend", "joinable": True}}], "pending_invites": []}}))
                    elif args == ["listen", "status"]:
                        print(json.dumps({{"profile": "default", "enabled": True, "scope": "self-only", "require_e2ee": True, "allow_browser": False, "nick": "mac"}}))
                    else:
                        sys.stderr.write(f"unexpected args: {{args!r}}\\n")
                        sys.exit(2)
                    """
                ),
                encoding="utf-8",
            )
            fake_outpost.chmod(fake_outpost.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            node_script = textwrap.dedent(
                f"""
                import assert from "node:assert/strict";
                import opencodeTui from "./adapters/opencode/src/tui.ts";

                process.env.MP_OUTPOST_BIN = {str(fake_outpost)!r};

                const layers = [];
                const toasts = [];
                const alerts = [];
                let nextSelect = "friends";
                opencodeTui.setup({{
                  keymap: {{ layer(factory) {{ layers.push(factory()); }} }},
                  ui: {{
                    toast: {{ show(t) {{ toasts.push(t); }} }},
                    dialog: {{
                      async select() {{ return nextSelect; }},
                      async prompt() {{ return "hello from opencode dialog"; }},
                      async alert(a) {{ alerts.push(a); }},
                    }},
                    slot(spec) {{ spec.render(); }},
                  }},
                }});

                const cmds = Object.fromEntries(layers[0].commands.map((c) => [c.id, c]));

                // 1. /party-read shows sanitized UNTRUSTED EXTERNAL DATA with [browser] tag and redacted #fragment
                await cmds["multiplayer.read"].run();
                assert.ok(alerts.some((a) => a.message.includes("UNTRUSTED EXTERNAL DATA") && a.message.includes("@phall") && a.message.includes("#[REDACTED]") && !a.message.includes("SECRET999") && a.message.includes("@antimeme [browser]")));

                // 2. /party-status shows handle + active party
                await cmds["multiplayer.status"].run();
                assert.ok(alerts.some((a) => a.title === "Multiplayer Status" && a.message.includes("@antimeme") && a.message.includes("#888")));

                // 3. /party-say with empty input uses dialog.prompt and posts
                await cmds["multiplayer.say"].run("");
                assert.ok(toasts.some((t) => t.variant === "success" && t.message.includes("#888")));

                // 4. /party menu -> friends and listen
                nextSelect = "friends";
                await cmds["multiplayer.menu"].run();
                assert.ok(alerts.some((a) => a.title.includes("Friends") && a.message.includes("@phall") && a.message.includes("joinable")));

                nextSelect = "listen";
                await cmds["multiplayer.menu"].run();
                assert.ok(alerts.some((a) => a.title.includes("Listen") && a.message.includes("Enabled: ON")));

                console.log("OPENCODE_TUI_DIALOGS_OK");
                """
            )
            proc = subprocess.run(
                ["node", "--input-type=module", "-e", node_script],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
            self.assertIn("OPENCODE_TUI_DIALOGS_OK", proc.stdout)
            posted = json.loads(say_log.read_text(encoding="utf-8"))
            self.assertIn("hello from opencode dialog", posted)

    def test_opencode_tui_live_party_panel_and_feed_store(self) -> None:
        """Verify OpenCode v2 /party-panel, PartyFeedStore live streaming, echo filter, 4040 recovery, and SIGTERM stop."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            state_file = tmp_path / "state.json"
            term_marker = tmp_path / "sigterm_hit.txt"
            state_file.write_text(json.dumps({"party_id": 777, "wait_calls": 0}), encoding="utf-8")
            fake_outpost = tmp_path / "fake-mp-outpost"
            fake_outpost.write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent(
                    f"""
                    import json, signal, sys, time
                    from pathlib import Path
                    state_path = Path({str(state_file)!r})
                    term_path = Path({str(term_marker)!r})
                    def _on_term(_sig, _frame):
                        term_path.write_text("SIGTERM", encoding="utf-8")
                        sys.exit(0)
                    signal.signal(signal.SIGTERM, _on_term)
                    args = sys.argv[1:]
                    if args[:1] == ["--json"]:
                        args = args[1:]
                    st = json.loads(state_path.read_text(encoding="utf-8"))
                    if args == ["party", "status"]:
                        print(json.dumps({{"handle": "antimeme", "device_id": 500, "control_ws_connected": True}}))
                    elif args == ["party", "list"]:
                        pid = st["party_id"]
                        print(json.dumps({{"daemon_epoch": 11, "parties": [{{"party_id": pid, "member_count": 3, "next_seq": 20, "relay_policy": "allow_relays"}}]}}))
                    elif args[:2] == ["party", "read"]:
                        pid = int(args[2])
                        if pid == 777:
                            print(json.dumps({{"daemon_epoch": 11, "next_seq": 20, "events": [
                                {{"event_seq": 18, "kind": "chat", "sender_handle": "antimeme", "sender_device_id": 500, "text": "own non-browser echo"}},
                                {{"event_seq": 19, "kind": "chat", "sender_handle": "phall", "sender_device_id": 901, "text": "\\x1b[31mhi\\x1b[0m \\u202ebidi\\u202c https://clank.party/i/abc#SECRET1234"}},
                                {{"event_seq": 20, "kind": "chat", "sender_handle": "antimeme", "sender_device_id": 500, "is_browser": True, "text": "web tab msg"}}
                            ]}}))
                        else:
                            print(json.dumps({{"daemon_epoch": 12, "next_seq": 2, "events": [
                                {{"event_seq": 2, "kind": "chat", "sender_handle": "spongebob", "sender_device_id": 777, "text": "new room hello"}}
                            ]}}))
                    elif args[:2] == ["party", "wait"]:
                        st["wait_calls"] += 1
                        if st["wait_calls"] == 1:
                            st["party_id"] = 888
                            state_path.write_text(json.dumps(st), encoding="utf-8")
                            sys.stderr.write("code=4040 party is not active\\n")
                            sys.exit(1)
                        state_path.write_text(json.dumps(st), encoding="utf-8")
                        time.sleep(20)
                        print(json.dumps({{"daemon_epoch": 12, "next_seq": 2, "events": []}}))
                    else:
                        sys.stderr.write(f"unexpected args: {{args!r}}\\n")
                        sys.exit(2)
                    """
                ),
                encoding="utf-8",
            )
            fake_outpost.chmod(fake_outpost.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            node_script = textwrap.dedent(
                f"""
                import assert from "node:assert/strict";
                import opencodeTui, {{ PartyFeedStore, PARTY_PANEL_NAME }} from "./adapters/opencode/src/tui.ts";

                process.env.MP_OUTPOST_BIN = {str(fake_outpost)!r};

                // 1. PartyFeedStore lifecycle: idle before start, seed+filter+sanitize, 4040 switch, immediate SIGTERM stop
                const store = new PartyFeedStore({{ idleBackoffMs: 50 }});
                assert.equal(store.isRunning(), false);
                store.start();
                assert.equal(store.isRunning(), true);

                let sawFirstRoom = false;
                let sawSwitchedRoom = false;
                const deadline = Date.now() + 8000;
                while (Date.now() < deadline && !sawSwitchedRoom) {{
                  const snap = store.getSnapshot();
                  if (snap.partyId === 777 && snap.messages.length >= 2) {{
                    sawFirstRoom = true;
                    assert.ok(!snap.messages.some((m) => m.body.includes("own non-browser echo")), "must filter own non-browser echo");
                    const remote = snap.messages.find((m) => m.handle === "@phall");
                    assert.ok(remote, "must keep remote peer message");
                    assert.ok(!remote.body.includes("\\x1b") && !remote.body.includes("[31m") && !remote.body.includes("\\u202e"));
                    assert.ok(!remote.body.includes("SECRET1234") && remote.body.includes("#[REDACTED]"));
                    const web = snap.messages.find((m) => m.isBrowser);
                    assert.ok(web && web.handle === "@antimeme" && web.body.includes("web tab msg"));
                  }}
                  if (snap.partyId === 888 && snap.messages.some((m) => m.body.includes("new room hello"))) {{
                    sawSwitchedRoom = true;
                  }}
                  if (!sawSwitchedRoom) await new Promise((r) => setTimeout(r, 40));
                }}
                assert.ok(sawSwitchedRoom, "PartyFeedStore must recover from code=4040 and switch to #888");
                // Give second wait child a moment to spawn before stopping
                await new Promise((r) => setTimeout(r, 120));
                const t0 = Date.now();
                store.stop();
                assert.equal(store.isRunning(), false);
                assert.ok(Date.now() - t0 < 500, "stop() must return immediately");
                await new Promise((r) => setTimeout(r, 150));

                // 2. /party-panel command with mocked ui.panel & cleanup
                let openPanel = undefined;
                const panelCalls = [];
                const toasts = [];
                const alerts = [];
                const layers = [];
                const cleanup = opencodeTui.setup({{
                  keymap: {{ layer(factory) {{ layers.push(factory()); }} }},
                  ui: {{
                    toast: {{ show(t) {{ toasts.push(t); }} }},
                    dialog: {{ async alert(a) {{ alerts.push(a); }} }},
                    panel: {{
                      open(name, opts) {{ openPanel = {{ name, presentation: opts?.presentation ?? "panel" }}; panelCalls.push(["open", name, opts]); return true; }},
                      close() {{ openPanel = undefined; panelCalls.push(["close"]); }},
                      current() {{ return openPanel; }},
                    }},
                    slot(spec) {{ spec.render(); }},
                  }},
                }});

                assert.equal(opencodeTui.id, "antimeme.multiplayer");
                const panelCmd = layers[0].commands.find((c) => c.id === "multiplayer.panel");
                assert.ok(panelCmd && panelCmd.slash.name === "party-panel" && panelCmd.slash.aliases.includes("mp-panel") && panelCmd.palette === true);

                await panelCmd.run("on");
                assert.equal(openPanel?.name, PARTY_PANEL_NAME);
                assert.equal(openPanel?.presentation, "panel");

                await panelCmd.run("status");
                assert.ok(alerts.some((a) => a.message.includes("Panel: OPEN")));

                await panelCmd.run("full");
                assert.equal(openPanel?.presentation, "fullscreen");

                await panelCmd.run("sidebar");
                assert.ok(toasts.some((t) => t.message.toLowerCase().includes("sidebar")));

                await panelCmd.run("off");
                assert.equal(openPanel, undefined);

                if (typeof cleanup === "function") cleanup();

                // 3. Minimal context without ui.panel/ui.router falls back cleanly to dialog.alert
                const minAlerts = [];
                const minLayers = [];
                const minCleanup = opencodeTui.setup({{
                  keymap: {{ layer(factory) {{ minLayers.push(factory()); }} }},
                  ui: {{
                    toast: {{ show() {{}} }},
                    dialog: {{ async alert(a) {{ minAlerts.push(a); }} }},
                    slot(spec) {{ spec.render(); }},
                  }},
                }});
                const minPanelCmd = minLayers[0].commands.find((c) => c.id === "multiplayer.panel");
                await minPanelCmd.run("on");
                assert.ok(minAlerts.some((a) => a.message.includes("UNTRUSTED EXTERNAL DATA")));
                if (typeof minCleanup === "function") minCleanup();

                console.log("OPENCODE_LIVE_PANEL_OK");
                """
            )
            proc = subprocess.run(
                ["node", "--input-type=module", "-e", node_script],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
            self.assertIn("OPENCODE_LIVE_PANEL_OK", proc.stdout)
            self.assertTrue(term_marker.is_file(), "expected SIGTERM marker on blocked party wait child")

    def test_pi_native_party_panels_and_live_watcher(self) -> None:
        """Verify Pi docked widget (/party-panel), interactive overlay (/party-overlay, ctrl+shift+m, /party-chat --inline), and live PartyFeedWatcher."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            state_file = tmp_path / "state.json"
            say_log = tmp_path / "say_log.json"
            state_file.write_text(json.dumps({"party_id": 777, "wait_calls": 0}), encoding="utf-8")
            fake_outpost = tmp_path / "fake-mp-outpost"
            fake_outpost.write_text(
                f"#!{sys.executable}\n"
                + textwrap.dedent(
                    f"""
                    import json, sys, time
                    from pathlib import Path
                    state_path = Path({str(state_file)!r})
                    say_path = Path({str(say_log)!r})
                    args = sys.argv[1:]
                    if args[:1] == ["--json"]:
                        args = args[1:]
                    st = json.loads(state_path.read_text(encoding="utf-8"))
                    if args == ["party", "status"]:
                        print(json.dumps({{"handle": "antimeme", "device_id": 500, "control_ws_connected": True}}))
                    elif args == ["party", "list"]:
                        pid = st["party_id"]
                        print(json.dumps({{"daemon_epoch": 11, "parties": [{{"party_id": pid, "member_count": 3, "next_seq": 20, "relay_policy": "allow_relays"}}]}}))
                    elif args[:2] == ["party", "read"]:
                        pid = int(args[2])
                        if pid == 777:
                            print(json.dumps({{"daemon_epoch": 11, "next_seq": 20, "events": [
                                {{"event_seq": 18, "kind": "chat", "sender_handle": "antimeme", "sender_device_id": 500, "body": "own echo"}},
                                {{"event_seq": 19, "kind": "chat", "sender_handle": "phall", "sender_device_id": 901, "body": "\\x1b[31mhi\\x1b[0m https://clank.party/i/abc#SECRET1234"}},
                                {{"event_seq": 20, "kind": "chat", "sender_handle": "antimeme", "sender_device_id": 500, "is_browser": True, "body": "web tab msg"}}
                            ]}}))
                        else:
                            print(json.dumps({{"daemon_epoch": 12, "next_seq": 2, "events": [
                                {{"event_seq": 2, "kind": "agent_card", "sender_handle": "spongebob", "sender_device_id": 777, "card": {{"title": "Build", "status": "done", "summary": "all green"}}}}
                            ]}}))
                    elif args[:2] == ["party", "wait"]:
                        st["wait_calls"] += 1
                        if st["wait_calls"] == 1:
                            st["party_id"] = 888
                            state_path.write_text(json.dumps(st), encoding="utf-8")
                            sys.stderr.write("code=4040 party is not active\\n")
                            sys.exit(1)
                        state_path.write_text(json.dumps(st), encoding="utf-8")
                        time.sleep(20)
                        print(json.dumps({{"daemon_epoch": 12, "next_seq": 2, "events": []}}))
                    elif args[:2] == ["party", "say"]:
                        existing = json.loads(say_path.read_text(encoding="utf-8")) if say_path.is_file() else []
                        existing.append(args)
                        say_path.write_text(json.dumps(existing), encoding="utf-8")
                        print(json.dumps({{"ok": True}}))
                    else:
                        sys.stderr.write(f"unexpected args: {{args!r}}\\n")
                        sys.exit(2)
                    """
                ),
                encoding="utf-8",
            )
            fake_outpost.chmod(fake_outpost.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            node_script = textwrap.dedent(
                f"""
                import assert from "node:assert/strict";
                import piExt, {{ PartyFeedWatcher, visibleWidth }} from "./adapters/pi/index.ts";

                process.env.MP_OUTPOST_BIN = {str(fake_outpost)!r};

                const cmds = new Map();
                const shortcuts = new Map();
                const events = new Map();
                piExt({{
                  registerCommand(n, s) {{ cmds.set(n, s); }},
                  registerShortcut(k, s) {{ shortcuts.set(k, s); }},
                  registerTool() {{}},
                  on(ev, h) {{ events.set(ev, h); }},
                }});

                assert.ok(cmds.has("party-panel"), "Pi must register /party-panel");
                assert.ok(cmds.has("party-overlay"), "Pi must register /party-overlay");
                assert.ok(shortcuts.has("ctrl+shift+m"), "Pi must register ctrl+shift+m");
                assert.ok(events.has("session_shutdown"), "Pi must register session_shutdown");

                const widgets = new Map();
                const statuses = new Map();
                const notes = [];
                let renderCount = 0;
                const fakeTui = {{ requestRender() {{ renderCount += 1; }}, terminal: {{ rows: 30 }} }};
                const fakeTheme = {{ fg: (_c, t) => `\\x1b[36m${{t}}\\x1b[0m`, bold: (t) => `\\x1b[1m${{t}}\\x1b[0m` }};

                const ctx = {{
                  ui: {{
                    notify(m, lvl) {{ notes.push([lvl, m]); }},
                    setStatus(k, v) {{ statuses.set(k, v); }},
                    setWidget(k, content, opts) {{ widgets.set(k, {{ content, opts }}); }},
                    async custom(factory, opts) {{
                      assert.equal(opts?.overlay, true);
                      let closed = false;
                      const comp = await factory(fakeTui, fakeTheme, {{}}, () => {{ closed = true; }});
                      for (const w of [24, 50, 80, 120]) {{
                        const lines = comp.render(w);
                        assert.ok(lines.length > 0);
                        for (const line of lines) {{
                          assert.ok(visibleWidth(line) <= w, `overlay line width ${{visibleWidth(line)}} > ${{w}}`);
                        }}
                      }}
                      const joined = comp.render(80).join("\\n");
                      assert.ok(joined.includes("UNTRUSTED EXTERNAL DATA"));

                      // Pre-exec secret refusal inside overlay composer (must NOT close or call party say)
                      comp.handleInput("mpinv1_" + "A".repeat(44));
                      comp.handleInput("\\r");
                      assert.equal(closed, false);
                      assert.ok(comp.render(80).join("\\n").toLowerCase().includes("secret"));

                      // Clear with Ctrl+U, type valid message, Enter to send
                      comp.handleInput("\\x15");
                      comp.handleInput("hello from pi overlay");
                      comp.handleInput("\\r");
                      await new Promise((r) => setTimeout(r, 250));
                      assert.equal(closed, false);

                      // Scroll with Up / Down / mouse wheel and close with Esc
                      comp.handleInput("\\x1b[A");
                      comp.handleInput("\\x1b[<64;10;10M");
                      comp.handleInput("\\x1b");
                      assert.equal(closed, true);
                      comp.dispose?.();
                    }},
                  }},
                }};

                // 1. Docked panel /party-panel below -> renders strictly within width & recovers 4040 -> #888
                await cmds.get("party-panel").handler("below", ctx);
                const wEntry = widgets.get("multiplayer-chat");
                assert.equal(wEntry?.opts?.placement, "belowEditor");
                const widgetComp = typeof wEntry.content === "function" ? wEntry.content(fakeTui, fakeTheme) : null;
                assert.ok(widgetComp, "expected widget component factory");

                const deadline = Date.now() + 8000;
                let sawCard = false;
                while (Date.now() < deadline && !sawCard) {{
                  const text = widgetComp.render(80).join("\\n");
                  if (text.includes("#888") && text.includes("Build")) sawCard = true;
                  else await new Promise((r) => setTimeout(r, 50));
                }}
                assert.ok(sawCard, "docked widget must recover from 4040 and render new room #888 agent_card");
                assert.ok(renderCount > 0, "expected tui.requestRender() calls");
                for (const w of [12, 40, 80, 120]) {{
                  for (const line of widgetComp.render(w)) {{
                    assert.ok(visibleWidth(line) <= w, `widget line width ${{visibleWidth(line)}} > ${{w}}`);
                  }}
                }}

                // 2. Interactive overlay via /party-overlay
                await cmds.get("party-overlay").handler("", ctx);

                // 3. Clean unmount on session_shutdown
                await events.get("session_shutdown")({{}}, ctx);
                assert.equal(widgets.get("multiplayer-chat")?.content, undefined);

                console.log("PI_NATIVE_PANELS_OK");
                """
            )
            proc = subprocess.run(
                ["node", "--input-type=module", "-e", node_script],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}")
            self.assertIn("PI_NATIVE_PANELS_OK", proc.stdout)
            posted = json.loads(say_log.read_text(encoding="utf-8"))
            self.assertEqual(len(posted), 1, f"secret must be refused; only 1 valid say expected, got {posted!r}")
            self.assertIn("hello from pi overlay", posted[0])


if __name__ == "__main__":
    unittest.main()
