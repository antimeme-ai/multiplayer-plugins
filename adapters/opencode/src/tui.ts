/**
 * OpenCode TUI plugin (`@opencode/plugin/tui` contract) for multiplayer.tech.
 *
 * Adds:
 * - `/party` (alias `/mp`, global shortcut `ctrl+alt+m`, Command Palette) opening a
 *   native `context.ui.dialog.select` Multiplayer quick menu.
 * - `/party-chat [target]` (alias `/mp-chat`) launching or reusing `mp-outpost chat`
 *   in a detached `phux` window (`tmux` / `omarchy-launch-tui` fallback).
 * - `/party-say [message]` (alias `/mp-say`) sending a secret-checked message inline
 *   or via native `context.ui.dialog.prompt`.
 * - `/party-read` (alias `/mp-read`) showing the latest sanitized party messages in
 *   native `context.ui.dialog.alert` (clearly tagged UNTRUSTED EXTERNAL DATA).
 * - `/party-status` (alias `/mp-status`) showing live `@handle`, active party, and
 *   daemon connection posture.
 *
 * Zero `console.*` calls and zero external runtime dependencies.
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { detectForbiddenSecret } from "./security.ts";

const DEFAULT_SESSION = "multiplayer-chat";
const SAFE_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_TARGET_RE = /^@?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const URL_FRAGMENT_RE =
  /((?:https?:\/\/)?(?:(?:www\.)?(?:clank\.party|multiplayer\.tech|mp\.gg)\/[^\s#"']+?|[^\s#"']+?\/(?:p\/)?i\/[A-Za-z0-9_-]+))#[A-Za-z0-9_-]+/gi;
const AMBIGUOUS_SAY_FLAGS = new Set([
  "--scope",
  "--to-device",
  "--json",
  "--state-dir",
  "--help",
  "-h",
  "--version",
  "-V",
]);

export interface OpenCodeTuiToast {
  show(options: {
    title?: string;
    message: string;
    variant?: "info" | "success" | "warning" | "error";
    duration?: number;
  }): void;
}

export interface OpenCodeTuiDialog {
  alert?(options: { title: string; message: string }): Promise<void>;
  confirm?(options: { title: string; message: string; label?: string }): Promise<boolean | undefined>;
  prompt?(options: {
    title: string;
    description?: string;
    placeholder?: string;
    value?: string;
  }): Promise<string | undefined>;
  select?(options: {
    title: string;
    placeholder?: string;
    options: ReadonlyArray<{
      title: string;
      description?: string;
      value: string;
      disabled?: boolean;
    }>;
    current?: string;
  }): Promise<string | undefined>;
  clear?(): void;
  set?(options: { size?: "small" | "medium" | "large"; centered?: boolean }): void;
}

export interface OpenCodeTuiKeymapCommand {
  readonly id?: string;
  readonly title?: string;
  readonly description?: string;
  readonly group?: string;
  readonly bind?: false | string;
  readonly palette?: true;
  readonly slash?: { readonly name: string; readonly aliases?: string[]; readonly arguments?: true };
  readonly suggested?: boolean | (() => boolean);
  readonly run: (input?: string) => void | false | Promise<void>;
}

export interface OpenCodeTuiContext {
  readonly keymap: {
    layer(factory: () => { readonly mode?: string; readonly commands?: readonly OpenCodeTuiKeymapCommand[] }): void;
  };
  readonly ui: {
    readonly toast: OpenCodeTuiToast;
    readonly dialog?: OpenCodeTuiDialog;
    readonly slot?: (spec: { readonly append?: string; readonly prepend?: string; readonly render: () => unknown }) => void;
  };
}

export interface DetachedChatLaunchResult {
  ok: boolean;
  backend: "phux" | "tmux" | "omarchy-launch-tui" | "manual";
  session: string;
  paneId?: string;
  reused: boolean;
  attachCmd: string;
  nativeCmd?: string;
  message: string;
}

function redactUrlFragments(text: string): string {
  return text.replace(URL_FRAGMENT_RE, "$1#[REDACTED]");
}

function sanitizePeerText(raw: string): string {
  let out = "";
  for (const ch of raw) {
    if (ch === "\n" || ch === "\t") {
      out += ch;
      continue;
    }
    const cp = ch.codePointAt(0) ?? 0;
    if (
      cp <= 0x1f ||
      cp === 0x7f ||
      (cp >= 0x80 && cp <= 0x9f) ||
      cp === 0x2028 ||
      cp === 0x2029 ||
      cp === 0x061c ||
      cp === 0x200e ||
      cp === 0x200f ||
      cp === 0xfeff ||
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069) ||
      (cp >= 0x200b && cp <= 0x200d) ||
      (cp >= 0xe0000 && cp <= 0xe007f)
    ) {
      continue;
    }
    out += ch;
  }
  return out;
}

function sanitizeSingleLine(raw: string): string {
  return sanitizePeerText(raw).replace(/[\n\t]+/g, " ").replace(/\s+/g, " ").trim();
}

async function execCapture(
  binary: string,
  args: string[],
  timeoutMs = 10_000,
): Promise<{ code: number; stdout: string; stderr: string; notFound?: boolean }> {
  return await new Promise((resolve) => {
    let settled = false;
    const child = spawn(binary, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    const outChunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill("SIGTERM");
      } catch {
        // ignore
      }
      resolve({ code: 124, stdout: "", stderr: "timed out" });
    }, timeoutMs);
    child.stdout.on("data", (c: Buffer) => outChunks.push(c));
    child.stderr.on("data", (c: Buffer) => errChunks.push(c));
    child.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: err.code === "ENOENT" ? 127 : 1, stdout: "", stderr: err.message, notFound: err.code === "ENOENT" });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(outChunks).toString("utf8").trim(),
        stderr: Buffer.concat(errChunks).toString("utf8").trim(),
      });
    });
  });
}

function resolveBinaryPath(binary: string): string {
  if (!binary || binary.includes("/") || binary.includes("\\")) return binary;
  const searchDirs = [
    ...(process.env.PATH ? process.env.PATH.split(path.delimiter) : []),
    path.join(os.homedir(), ".local", "bin"),
    path.join(os.homedir(), ".cargo", "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
  ];
  for (const dir of searchDirs) {
    if (!dir) continue;
    const cand = path.join(dir, binary);
    try {
      fs.accessSync(cand, fs.constants.X_OK);
      if (fs.statSync(cand).isFile()) return cand;
    } catch {
      // continue
    }
  }
  return binary;
}

function formatTerminalAddress(val: unknown): string | undefined {
  if (typeof val === "number" && Number.isInteger(val) && val > 0) return `@${val}`;
  if (typeof val === "string") {
    const cleaned = val.trim();
    if (!cleaned) return undefined;
    if (/^\d+$/.test(cleaned)) return `@${cleaned}`;
    return cleaned;
  }
  return undefined;
}

function extractPaneId(payload: unknown): string | undefined {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  const obj = payload as Record<string, unknown>;
  if ("terminal_id" in obj) {
    const addr = formatTerminalAddress(obj.terminal_id);
    if (addr) return addr;
  }
  for (const k of ["terminal", "pane", "pane_id", "id"]) {
    const addr = formatTerminalAddress(obj[k]);
    if (addr) return addr;
  }
  for (const k of ["pane", "terminal", "seed", "result"]) {
    const nested = extractPaneId(obj[k]);
    if (nested) return nested;
  }
  return undefined;
}

function extractActiveTerminal(lsData: unknown, session: string): string | undefined {
  if (!lsData || typeof lsData !== "object" || Array.isArray(lsData)) return undefined;
  const hosts = (lsData as { hosts?: unknown[] }).hosts;
  if (!Array.isArray(hosts)) return undefined;
  for (const host of hosts) {
    if (!host || typeof host !== "object") continue;
    const sessions = (host as { sessions?: unknown[] }).sessions;
    if (!Array.isArray(sessions)) continue;
    for (const s of sessions) {
      if (s && typeof s === "object" && (s as { name?: unknown }).name === session) {
        const addr = formatTerminalAddress((s as { active_terminal?: unknown }).active_terminal);
        if (addr) return addr;
      }
    }
  }
  return undefined;
}

async function runOutpostJson(
  subArgs: string[],
  timeoutMs = 8_000,
): Promise<{ ok: true; data: Record<string, unknown> } | { ok: false; error: string }> {
  const bin = resolveBinaryPath(process.env.MP_OUTPOST_BIN?.trim() || "mp-outpost");
  const res = await execCapture(bin, ["--json", ...subArgs], timeoutMs);
  if (res.notFound) {
    return { ok: false, error: `mp-outpost binary '${bin}' not found on PATH.` };
  }
  if (res.code !== 0 || !res.stdout) {
    const msg = redactUrlFragments(res.stderr || res.stdout || `mp-outpost exited with status ${res.code}`);
    return { ok: false, error: msg };
  }
  try {
    const parsed = JSON.parse(res.stdout) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "Unexpected JSON response from mp-outpost." };
    }
    return { ok: true, data: parsed as Record<string, unknown> };
  } catch {
    return { ok: false, error: "Invalid JSON output from mp-outpost." };
  }
}

async function showAlertOrToast(
  context: OpenCodeTuiContext,
  title: string,
  message: string,
  variant: "info" | "success" | "warning" | "error" = "info",
): Promise<void> {
  if (typeof context.ui?.dialog?.alert === "function") {
    await context.ui.dialog.alert({ title, message });
    return;
  }
  context.ui.toast.show({ title, message, variant, duration: 7000 });
}

function extractEventBody(ev: Record<string, unknown>): string {
  for (const key of ["text", "body", "message"]) {
    const val = ev[key];
    if (typeof val === "string" && val.trim()) return val;
  }
  const payload = ev.payload;
  if (typeof payload === "string" && payload.trim()) return payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    const p = payload as Record<string, unknown>;
    if (p.type === "agent_card" || "title" in p) {
      const title = typeof p.title === "string" ? p.title.trim() : "";
      const summary = typeof p.summary === "string" ? p.summary.trim() : "";
      const status = typeof p.status === "string" ? p.status.trim() : "";
      const tag = status ? `[${status}] ` : "";
      if (title && summary) return `card: ${tag}${title} — ${summary}`;
      if (title || summary) return `card: ${tag}${title || summary}`;
    }
    try {
      return JSON.stringify(payload);
    } catch {
      return "";
    }
  }
  return "";
}

async function getActiveParty(): Promise<
  { ok: true; partyId: number; nextSeq: number; memberCount: number; relayPolicy: string } | { ok: false; error: string }
> {
  const listed = await runOutpostJson(["party", "list"]);
  if (!listed.ok) return listed;
  const parties = Array.isArray(listed.data.parties) ? listed.data.parties : [];
  const first = parties[0] as Record<string, unknown> | undefined;
  if (!first || typeof first.party_id !== "number") {
    return { ok: false, error: "No active multiplayer party found. Open or join one via mp-outpost first." };
  }
  return {
    ok: true,
    partyId: first.party_id,
    nextSeq: typeof first.next_seq === "number" ? first.next_seq : 0,
    memberCount: typeof first.member_count === "number" ? first.member_count : 0,
    relayPolicy: typeof first.relay_policy === "string" ? first.relay_policy : "unknown",
  };
}

export async function launchDetachedPartyChat(options?: {
  target?: string;
  session?: string;
  outpostBinary?: string;
  phuxBinary?: string;
  tmuxBinary?: string;
  omarchyTuiBinary?: string;
}): Promise<DetachedChatLaunchResult> {
  const session = (options?.session ?? DEFAULT_SESSION).trim();
  if (!SAFE_SESSION_RE.test(session)) {
    throw new Error(`Invalid session name '${session}'.`);
  }
  let cleanTarget: string | undefined;
  if (options?.target?.trim()) {
    const raw = options.target.trim();
    if (raw.startsWith("-")) throw new Error("Refused chat target: value cannot start with '-'.");
    if (raw.includes("#")) {
      throw new Error("Refused #fragment invite URL on argv: redeem fragment links directly via `mp-outpost join`.");
    }
    const secret = detectForbiddenSecret(raw);
    if (secret !== null) throw new Error(`Refused chat target: detected forbidden secret material (${secret}).`);
    if (!SAFE_TARGET_RE.test(raw)) throw new Error("Chat target must be a @handle, room code, or numeric party ID.");
    cleanTarget = raw;
  }

  const resolvedOutpost = resolveBinaryPath(
    options?.outpostBinary?.trim() || process.env.MP_OUTPOST_BIN?.trim() || "mp-outpost",
  );
  const outpostCmd = [resolvedOutpost, "chat", ...(cleanTarget ? [cleanTarget] : [])];
  const phuxBin = resolveBinaryPath(options?.phuxBinary ?? process.env.PHUX_BIN?.trim() ?? "phux");
  const lsRes = await execCapture(phuxBin, ["ls", "--json"]);
  if (!lsRes.notFound) {
    let existingFound = false;
    let existingRunning = false;
    let existingTerminal: string | undefined;
    if (lsRes.code === 0 && lsRes.stdout) {
      try {
        const parsed = JSON.parse(lsRes.stdout) as {
          sessions?: Array<{ name?: string; exec?: { running?: number; starting?: number } }>;
        };
        const found = parsed.sessions?.find((s) => s?.name === session);
        if (found) {
          existingFound = true;
          existingRunning = Number(found.exec?.running ?? 0) + Number(found.exec?.starting ?? 0) > 0;
          if (existingRunning) existingTerminal = extractActiveTerminal(parsed, session);
        }
      } catch {
        // ignore
      }
    }
    if (existingRunning) {
      const nativeCmd = existingTerminal ? `phux native attach ${existingTerminal}` : undefined;
      return {
        ok: true,
        backend: "phux",
        session,
        ...(existingTerminal ? { paneId: existingTerminal } : {}),
        reused: true,
        attachCmd: `phux attach ${session}`,
        ...(nativeCmd ? { nativeCmd } : {}),
        message: `Party chat running in detached phux '${session}'${existingTerminal ? ` (${existingTerminal})` : ""}. Grab: phux attach ${session}${nativeCmd ? ` | window: ${nativeCmd}` : ""}`,
      };
    }
    if (existingFound) await execCapture(phuxBin, ["kill", "--yes", session]);
    const created = await execCapture(phuxBin, ["new", "--json", "-s", session, "--", ...outpostCmd], 15_000);
    if (created.code === 0) {
      let paneId: string | undefined;
      if (created.stdout) {
        try {
          paneId = extractPaneId(JSON.parse(created.stdout));
        } catch {
          // ignore
        }
      }
      const nativeCmd = paneId ? `phux native attach ${paneId}` : undefined;
      return {
        ok: true,
        backend: "phux",
        session,
        ...(paneId ? { paneId } : {}),
        reused: false,
        attachCmd: `phux attach ${session}`,
        ...(nativeCmd ? { nativeCmd } : {}),
        message: `Started detached phux chat '${session}'${paneId ? ` (${paneId})` : ""}. Grab: phux attach ${session}${nativeCmd ? ` | window: ${nativeCmd}` : ""}`,
      };
    }
    if (created.stdout.includes("spawn_failed") || created.stderr.includes("spawn_failed")) {
      await execCapture(phuxBin, ["kill", "--yes", session]);
    }
  }

  const tmuxBin = options?.tmuxBinary ?? "tmux";
  const hasTmux = await execCapture(tmuxBin, ["has-session", "-t", session], 5_000);
  if (!hasTmux.notFound) {
    if (hasTmux.code === 0) {
      return {
        ok: true,
        backend: "tmux",
        session,
        reused: true,
        attachCmd: `tmux attach -t ${session}`,
        message: `Party chat running in detached tmux '${session}'. Grab: tmux attach -t ${session}`,
      };
    }
    const created = await execCapture(tmuxBin, ["new-session", "-d", "-s", session, "--", ...outpostCmd]);
    if (created.code === 0) {
      return {
        ok: true,
        backend: "tmux",
        session,
        reused: false,
        attachCmd: `tmux attach -t ${session}`,
        message: `Started detached tmux chat '${session}'. Grab: tmux attach -t ${session}`,
      };
    }
  }

  const omarchyBin = options?.omarchyTuiBinary ?? "omarchy-launch-tui";
  const hasOmarchy = await execCapture("which", [omarchyBin], 3_000);
  if (hasOmarchy.code === 0) {
    const child = spawn(omarchyBin, outpostCmd, { shell: false, detached: true, stdio: "ignore" });
    child.unref();
    return {
      ok: true,
      backend: "omarchy-launch-tui",
      session,
      reused: false,
      attachCmd: outpostCmd.join(" "),
      message: "Launched mp-outpost chat in a native Omarchy TUI window.",
    };
  }

  return {
    ok: false,
    backend: "manual",
    session,
    reused: false,
    attachCmd: outpostCmd.join(" "),
    message: `Run in another terminal: ${outpostCmd.join(" ")}`,
  };
}

async function runOpenChat(context: OpenCodeTuiContext, target?: string): Promise<void> {
  try {
    const res = await launchDetachedPartyChat({ target: target?.trim() || undefined });
    context.ui.toast.show({
      title: "Multiplayer Party Chat",
      message: res.message,
      variant: res.ok ? "success" : "warning",
      duration: 6000,
    });
  } catch (err) {
    context.ui.toast.show({
      title: "Multiplayer Party Chat",
      message: (err as Error).message,
      variant: "error",
      duration: 6000,
    });
  }
}

async function runPartySay(context: OpenCodeTuiContext, rawInput?: string): Promise<void> {
  let body = rawInput?.trim() ?? "";
  if (!body) {
    if (typeof context.ui?.dialog?.prompt !== "function") {
      context.ui.toast.show({
        title: "Multiplayer Say",
        message: "Usage: /party-say <message>",
        variant: "warning",
        duration: 5000,
      });
      return;
    }
    const prompted = await context.ui.dialog.prompt({
      title: "Send Party Message",
      description: "Posts directly to your active multiplayer.tech party (secret-checked before sending).",
      placeholder: "Type a message to the party...",
    });
    if (!prompted?.trim()) return;
    body = prompted.trim();
  }

  if (AMBIGUOUS_SAY_FLAGS.has(body) || (body.startsWith("--") && !body.includes(" "))) {
    context.ui.toast.show({
      title: "Multiplayer Say",
      message: "Refused message: bare CLI option flag is ambiguous.",
      variant: "error",
      duration: 6000,
    });
    return;
  }

  const secretKind = detectForbiddenSecret(body, { allowInviteFragment: false });
  if (secretKind !== null) {
    context.ui.toast.show({
      title: "Multiplayer Say — Refused",
      message: `Refused outbound message: detected forbidden secret material (${secretKind}).`,
      variant: "error",
      duration: 7000,
    });
    return;
  }

  const active = await getActiveParty();
  if (!active.ok) {
    context.ui.toast.show({
      title: "Multiplayer Say",
      message: active.error,
      variant: "warning",
      duration: 6000,
    });
    return;
  }

  const sent = await runOutpostJson(["party", "say", String(active.partyId), "--scope", "party/main", body]);
  if (!sent.ok) {
    context.ui.toast.show({
      title: "Multiplayer Say",
      message: sent.error,
      variant: "error",
      duration: 6000,
    });
    return;
  }

  context.ui.toast.show({
    title: "Multiplayer Say",
    message: `Sent message to party #${active.partyId}.`,
    variant: "success",
    duration: 4000,
  });
}

async function runPartyRead(context: OpenCodeTuiContext): Promise<void> {
  const active = await getActiveParty();
  if (!active.ok) {
    await showAlertOrToast(context, "Party Messages", active.error, "warning");
    return;
  }

  const afterSeq = Math.max(0, active.nextSeq - 15);
  const res = await runOutpostJson([
    "party",
    "read",
    String(active.partyId),
    "--after-seq",
    String(afterSeq),
    "--limit",
    "15",
  ]);
  if (!res.ok) {
    await showAlertOrToast(context, "Party Messages", res.error, "error");
    return;
  }

  const events = Array.isArray(res.data.events) ? res.data.events : [];
  const lines: string[] = [];
  for (const raw of events) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const ev = raw as Record<string, unknown>;
    const kind = String(ev.kind ?? "unknown");
    if (kind === "membership_changed" || kind === "system") continue;
    const body = redactUrlFragments(sanitizePeerText(extractEventBody(ev))).trim();
    if (!body) continue;
    const handle = sanitizeSingleLine(String(ev.sender_handle ?? ev.from ?? "peer")) || "peer";
    const client = sanitizeSingleLine(String(ev.sender_client ?? ev.client ?? "")).toLowerCase();
    const isBrowser = Boolean(ev.is_browser) || client === "web" || client === "browser";
    const seq = typeof ev.event_seq === "number" ? ev.event_seq : typeof ev.seq === "number" ? ev.seq : 0;
    const atHandle = handle.startsWith("@") ? handle : `@${handle}`;
    const originTag = isBrowser ? " [browser]" : "";
    lines.push(`#${seq} ${atHandle}${originTag}: ${body}`);
  }

  const message =
    lines.length > 0
      ? [
          `Party #${active.partyId} — latest ${lines.length} message(s) (UNTRUSTED EXTERNAL DATA):`,
          "",
          ...lines,
        ].join("\n")
      : `No recent chat messages in party #${active.partyId}.`;

  await showAlertOrToast(context, `Party #${active.partyId} Messages`, message, "info");
}

async function runPartyStatus(context: OpenCodeTuiContext): Promise<void> {
  const [statusRes, listRes] = await Promise.all([
    runOutpostJson(["party", "status"]),
    runOutpostJson(["party", "list"]),
  ]);
  if (!statusRes.ok) {
    await showAlertOrToast(context, "Multiplayer Status", statusRes.error, "error");
    return;
  }

  const st = statusRes.data;
  const handle = sanitizeSingleLine(String(st.handle ?? "signed-out"));
  const online = Boolean(st.control_ws_connected);
  const parties = listRes.ok && Array.isArray(listRes.data.parties) ? listRes.data.parties : [];
  const firstParty = parties[0] as Record<string, unknown> | undefined;

  const lines = [
    `Handle: @${handle} · ${online ? "Online" : "Offline"}`,
    `API: ${sanitizeSingleLine(String(st.api_authority ?? "api.multiplayer.tech"))}`,
    `Relay policy: ${sanitizeSingleLine(String(st.local_relay_policy ?? "unknown"))}`,
  ];
  if (firstParty && typeof firstParty.party_id === "number") {
    const members = typeof firstParty.member_count === "number" ? firstParty.member_count : "?";
    const nextSeq = typeof firstParty.next_seq === "number" ? firstParty.next_seq : 0;
    lines.push(`Active party: #${firstParty.party_id} (${members} live, seq=${nextSeq})`);
  } else {
    lines.push("Active party: none");
  }
  if (st.dual_host_churn_alert) {
    lines.push("WARNING: dual_host_churn_alert=true");
  }

  await showAlertOrToast(context, "Multiplayer Status", lines.join("\n"), online ? "info" : "warning");
}

async function runPartyFriends(context: OpenCodeTuiContext): Promise<void> {
  const res = await runOutpostJson(["friends"]);
  if (!res.ok) {
    await showAlertOrToast(context, "Multiplayer Friends", res.error, "error");
    return;
  }

  const friends = Array.isArray(res.data.friends) ? res.data.friends : [];
  const invites = Array.isArray(res.data.pending_invites) ? res.data.pending_invites : [];
  const lines: string[] = [];

  if (friends.length > 0) {
    lines.push(`Friends (${friends.length}):`);
    for (const raw of friends) {
      if (!raw || typeof raw !== "object") continue;
      const f = raw as Record<string, unknown>;
      const handle = sanitizeSingleLine(String(f.handle ?? "unknown"));
      const presence = sanitizeSingleLine(String(f.presence ?? "offline"));
      const state = sanitizeSingleLine(String(f.state ?? "friend"));
      const stateTag = state !== "friend" ? ` [${state}]` : "";
      const joinTag = f.joinable ? " · joinable" : "";
      lines.push(`  @${handle} · ${presence}${stateTag}${joinTag}`);
    }
  } else {
    lines.push("Friends: none yet");
  }

  if (invites.length > 0) {
    lines.push("", `Pending invites (${invites.length}):`);
    for (const raw of invites) {
      if (!raw || typeof raw !== "object") continue;
      const inv = raw as Record<string, unknown>;
      const from = sanitizeSingleLine(String(inv.from_handle ?? inv.sender_handle ?? "unknown"));
      lines.push(`  from @${from}`);
    }
  } else {
    lines.push("", "Pending invites: none");
  }

  await showAlertOrToast(context, "Multiplayer Friends & Invites", lines.join("\n"), "info");
}

async function runPartyListenStatus(context: OpenCodeTuiContext): Promise<void> {
  const res = await runOutpostJson(["listen", "status"]);
  if (!res.ok) {
    await showAlertOrToast(context, "Multiplayer Listen Profile", res.error, "error");
    return;
  }
  const d = res.data;
  const lines = [
    `Profile: ${sanitizeSingleLine(String(d.profile ?? "default"))}`,
    `Enabled: ${d.enabled ? "ON" : "OFF"}`,
    `Scope: ${sanitizeSingleLine(String(d.scope ?? "unknown"))}`,
    `Require E2EE: ${d.require_e2ee ? "yes" : "no"} · Allow browser: ${d.allow_browser ? "yes" : "no"}`,
    `Nick: ${sanitizeSingleLine(String(d.nick ?? ""))}`,
  ];
  await showAlertOrToast(context, "Multiplayer Listen Profile", lines.join("\n"), "info");
}

async function runPartyMenu(context: OpenCodeTuiContext): Promise<void> {
  if (typeof context.ui?.dialog?.select !== "function") {
    await runOpenChat(context);
    return;
  }

  const choice = await context.ui.dialog.select({
    title: "Multiplayer (multiplayer.tech)",
    placeholder: "Choose a Multiplayer action...",
    options: [
      {
        title: "Open Party Chat (detached phux window)",
        description: "Start or reuse detached mp-outpost chat via phux/tmux/Omarchy",
        value: "chat",
      },
      {
        title: "Send Message to Party",
        description: "Compose a secret-checked message to the active party",
        value: "say",
      },
      {
        title: "Read Recent Party Messages",
        description: "Show the latest 15 sanitized party messages",
        value: "read",
      },
      {
        title: "Party Status & Active Room",
        description: "Inspect signed-in @handle, daemon status, and active party",
        value: "status",
      },
      {
        title: "Friends & Pending Invites",
        description: "View online presence, friend requests, and party invites",
        value: "friends",
      },
      {
        title: "Listen Profile Status",
        description: "Inspect current mp-outpost listen profile settings",
        value: "listen",
      },
    ],
  });

  switch (choice) {
    case "chat":
      await runOpenChat(context);
      break;
    case "say":
      await runPartySay(context);
      break;
    case "read":
      await runPartyRead(context);
      break;
    case "status":
      await runPartyStatus(context);
      break;
    case "friends":
      await runPartyFriends(context);
      break;
    case "listen":
      await runPartyListenStatus(context);
      break;
    default:
      break;
  }
}

const tuiPlugin = {
  id: "antimeme-ai.multiplayer",
  setup(context: OpenCodeTuiContext): void {
    const registerLayer = () => {
      context.keymap.layer(() => ({
        mode: "global",
        commands: [
          {
            id: "multiplayer.menu",
            title: "Multiplayer Party Menu",
            description: "Open quick Multiplayer menu (chat, say, read, status, friends, listen)",
            group: "Multiplayer",
            bind: "ctrl+alt+m",
            palette: true,
            slash: { name: "party", aliases: ["mp"] },
            suggested: true,
            async run() {
              await runPartyMenu(context);
            },
          },
          {
            id: "multiplayer.chat",
            title: "Open Multiplayer Party Chat",
            description: "Launch mp-outpost chat in a detached phux window (tmux/Omarchy fallback)",
            group: "Multiplayer",
            palette: true,
            slash: { name: "party-chat", aliases: ["mp-chat"], arguments: true },
            suggested: true,
            async run(input?: string) {
              await runOpenChat(context, input);
            },
          },
          {
            id: "multiplayer.say",
            title: "Send Multiplayer Party Message",
            description: "Send a secret-checked message to the active party (or open prompt)",
            group: "Multiplayer",
            palette: true,
            slash: { name: "party-say", aliases: ["mp-say"], arguments: true },
            async run(input?: string) {
              await runPartySay(context, input);
            },
          },
          {
            id: "multiplayer.read",
            title: "Read Recent Party Messages",
            description: "View the latest 15 sanitized messages in the active party",
            group: "Multiplayer",
            palette: true,
            slash: { name: "party-read", aliases: ["mp-read"] },
            async run() {
              await runPartyRead(context);
            },
          },
          {
            id: "multiplayer.status",
            title: "Multiplayer Party Status",
            description: "Show signed-in @handle, connection posture, and active party",
            group: "Multiplayer",
            palette: true,
            slash: { name: "party-status", aliases: ["mp-status"] },
            async run() {
              await runPartyStatus(context);
            },
          },
        ],
      }));
      return null;
    };

    if (typeof context.ui?.slot === "function") {
      context.ui.slot({
        append: "app",
        render: registerLayer,
      });
    } else {
      registerLayer();
    }
  },
};

export default tuiPlugin;
