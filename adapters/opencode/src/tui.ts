/**
 * OpenCode TUI plugin (`@opencode/plugin/tui` contract) for multiplayer.tech.
 *
 * Adds:
 * - `/party` (alias `/mp`, global shortcut `ctrl+alt+m`, Command Palette) opening a
 *   native `context.ui.dialog.select` Multiplayer quick menu.
 * - `/party-panel [on|off|full|sidebar|status]` (alias `/mp-panel`) opening a live
 *   native OpenCode v2.3.2 Party Chat display panel (`session.panel` + `ui.router`
 *   fallback on home screen, collapsible `sidebar.content` live feed, and a compact
 *   `prompt.footer.status` indicator while active).
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
import { detectForbiddenSecret } from "./security.ts";
import {
  PartyFeedStore,
  execCapture,
  parsePartyEvent,
  redactUrlFragments,
  resolveBinaryPath,
  runOutpostJson,
  sanitizeSingleLine,
  type PartyChatMessage,
  type PartyFeedSnapshot,
} from "./party-feed.ts";

export { PartyFeedStore } from "./party-feed.ts";
export type { PartyChatMessage, PartyFeedSnapshot, PartyFeedStatus } from "./party-feed.ts";

export const PARTY_PANEL_NAME = "multiplayer.party";

const DEFAULT_SESSION = "multiplayer-chat";
const SAFE_SESSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_TARGET_RE = /^@?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
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

export interface OpenCodeTuiPanelInput {
  readonly name: string;
  readonly sessionID?: string;
  readonly width?: number;
  readonly presentation?: "panel" | "fullscreen";
  readonly focused?: boolean;
  readonly focus?: () => void;
  readonly close?: () => void;
  readonly toggleFullscreen?: () => void;
}

export interface OpenCodeTuiPanelApi {
  open(name: string, options?: { presentation?: "panel" | "fullscreen" }): boolean;
  close(): void;
  current(): { readonly name: string; readonly sessionID: string } | undefined;
}

export interface OpenCodeTuiRoute {
  readonly type: "home" | "session" | "plugin";
  readonly sessionID?: string;
  readonly id?: string;
  readonly name?: string;
  readonly data?: Record<string, unknown>;
}

export interface OpenCodeTuiRouterApi {
  register(spec: { readonly name: string; readonly render: (args: { data?: Record<string, unknown> }) => unknown }): () => void;
  navigate(route: OpenCodeTuiRoute): void;
  current(): OpenCodeTuiRoute;
}

export interface OpenCodeTuiTheme {
  readonly text?: {
    readonly base?: string;
    readonly muted?: string;
    readonly feedback?: {
      readonly success?: { readonly base?: string };
      readonly warning?: { readonly base?: string };
      readonly error?: { readonly base?: string };
      readonly info?: { readonly base?: string };
    };
  };
  readonly background?: {
    readonly base?: string;
    readonly raised?: {
      readonly base?: string;
      readonly high?: string;
    };
  };
  readonly border?: { readonly base?: string };
  readonly hue?: {
    readonly accent?: Record<number, string>;
    readonly interactive?: Record<number, string>;
  };
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
  readonly enabled?: () => boolean;
  readonly run: (input?: string) => void | false | Promise<void>;
}

export interface OpenCodeTuiContext {
  readonly theme?: OpenCodeTuiTheme;
  readonly keymap: {
    layer(factory: () => { readonly mode?: string; readonly commands?: readonly OpenCodeTuiKeymapCommand[] }): void;
  };
  readonly ui: {
    readonly toast: OpenCodeTuiToast;
    readonly dialog?: OpenCodeTuiDialog;
    readonly panel?: OpenCodeTuiPanelApi;
    readonly router?: OpenCodeTuiRouterApi;
    readonly slot?: (spec: {
      readonly append?: string;
      readonly prepend?: string;
      readonly render: (input?: Record<string, unknown>) => unknown;
    }) => void | (() => void);
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

interface SolidRuntime {
  createSignal<T>(value: T): [() => T, (next: T | ((prev: T) => T)) => T];
  createEffect(fn: () => void): void;
  onCleanup(fn: () => void): void;
  Show: unknown;
  For: unknown;
}

interface OpenTuiRuntime {
  createElement(tag: string): Record<string, unknown>;
  createTextNode(value: string): unknown;
  createComponent(comp: unknown, props: Record<string, unknown>): unknown;
  insert(parent: unknown, accessor: unknown, marker?: unknown): void;
  insertNode(parent: unknown, node: unknown, anchor?: unknown): void;
  setProp(node: unknown, key: string, value: unknown, prev?: unknown): unknown;
  effect(fn: (prev?: unknown) => unknown, init?: unknown): void;
  use?(fn: (el: unknown, accessor: () => unknown) => void, el: unknown, accessor?: () => unknown): void;
}

interface LoadedOpenTuiRuntime {
  solid: SolidRuntime;
  opentui: OpenTuiRuntime;
}

interface ScrollboxLike {
  scrollBy?(delta: number): void;
  scrollTo?(offset: number): void;
  scrollHeight?: number;
  viewport?: { height?: number };
}

interface PanelUiState {
  panelOpen: boolean;
  sidebarOpen: boolean;
  sidebarExpanded: boolean;
  nativeRuntimeLoaded: boolean;
  returnRoute?: OpenCodeTuiRoute;
}

let cachedRuntimePromise: Promise<LoadedOpenTuiRuntime | null> | null = null;

/**
 * Dynamically load OpenCode v2.3.2's bundled SolidJS + OpenTUI runtime modules.
 *
 * Inside OpenCode v2.3.2 (Bun + `bun-plugin-opentui-runtime-modules`), literal
 * `import("solid-js")` and `import("@opentui/solid")` are rewritten to OpenCode's
 * shared reactive host modules. In plain Node or non-OpenCode Bun test harnesses,
 * the imports fail cleanly and resolve to `null`.
 */
function loadOpenTuiRuntime(): Promise<LoadedOpenTuiRuntime | null> {
  if (cachedRuntimePromise !== null) return cachedRuntimePromise;
  cachedRuntimePromise = (async () => {
    try {
      // Use literal import() calls so OpenCode's regex rewriter intercepts them.
      const [solidMod, opentuiMod] = await Promise.all([
        import("solid-js") as Promise<Record<string, unknown>>,
        import("@opentui/solid") as Promise<Record<string, unknown>>,
      ]);
      if (
        typeof solidMod?.createSignal !== "function" ||
        typeof solidMod?.onCleanup !== "function" ||
        typeof opentuiMod?.createElement !== "function" ||
        typeof opentuiMod?.insert !== "function" ||
        typeof opentuiMod?.setProp !== "function"
      ) {
        return null;
      }
      return {
        solid: solidMod as unknown as SolidRuntime,
        opentui: opentuiMod as unknown as OpenTuiRuntime,
      };
    } catch {
      return null;
    }
  })();
  return cachedRuntimePromise;
}

function themeColors(theme?: OpenCodeTuiTheme) {
  return {
    bg: theme?.background?.base ?? "#121212",
    bgRaised: theme?.background?.raised?.base ?? "#1c1c1c",
    bgHighlight: theme?.background?.raised?.high ?? "#262626",
    fg: theme?.text?.base ?? "#e5e5e5",
    muted: theme?.text?.muted ?? "#8a8a8a",
    success: theme?.text?.feedback?.success?.base ?? "#4ade80",
    warning: theme?.text?.feedback?.warning?.base ?? "#facc15",
    error: theme?.text?.feedback?.error?.base ?? "#f87171",
    info: theme?.text?.feedback?.info?.base ?? "#60a5fa",
    accent: theme?.hue?.accent?.[500] ?? theme?.text?.feedback?.info?.base ?? "#60a5fa",
    interactive: theme?.hue?.interactive?.[200] ?? theme?.text?.feedback?.info?.base ?? "#93c5fd",
    border: theme?.border?.base ?? "#3f3f46",
  };
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
    const parsed = parsePartyEvent(raw, { filterOwnEcho: false });
    if (!parsed.message) continue;
    const m = parsed.message;
    const originTag = m.isBrowser ? " [browser]" : "";
    const cardTag = m.isCard ? "card: " : "";
    lines.push(`#${m.seq} ${m.handle}${originTag}: ${cardTag}${m.body}`);
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

class PartyPanelController {
  readonly feed: PartyFeedStore;
  private readonly context: OpenCodeTuiContext;
  private state: PanelUiState = {
    panelOpen: false,
    sidebarOpen: false,
    sidebarExpanded: true,
    nativeRuntimeLoaded: false,
  };
  private uiListeners = new Set<(state: PanelUiState) => void>();

  constructor(context: OpenCodeTuiContext, feed?: PartyFeedStore) {
    this.context = context;
    this.feed = feed ?? new PartyFeedStore();
  }

  getState(): PanelUiState {
    return this.state;
  }

  subscribeUi(listener: (state: PanelUiState) => void): () => void {
    this.uiListeners.add(listener);
    return () => {
      this.uiListeners.delete(listener);
    };
  }

  private emitUi(patch: Partial<PanelUiState>): void {
    this.state = { ...this.state, ...patch };
    for (const listener of [...this.uiListeners]) {
      try {
        listener(this.state);
      } catch {
        // ignore
      }
    }
  }

  markNativeRuntimeLoaded(): void {
    this.emitUi({ nativeRuntimeLoaded: true });
  }

  private syncFeedLifecycle(): void {
    if (this.state.panelOpen || this.state.sidebarOpen) {
      this.feed.start();
    } else {
      this.feed.stop();
    }
  }

  isPanelActiveInHost(): boolean {
    const panelCur = this.context.ui?.panel?.current?.();
    if (panelCur?.name === PARTY_PANEL_NAME) return true;
    const routeCur = this.context.ui?.router?.current?.();
    if (routeCur?.type === "plugin" && routeCur.name === PARTY_PANEL_NAME) return true;
    return this.state.panelOpen;
  }

  notifyPanelMounted(focused = true): void {
    this.emitUi({ panelOpen: true });
    this.feed.setPanelFocused(focused);
    this.syncFeedLifecycle();
  }

  notifyPanelUnmounted(): void {
    this.feed.setPanelFocused(false);
    // Only mark closed if host no longer has our panel or plugin route active.
    const panelCur = this.context.ui?.panel?.current?.();
    const routeCur = this.context.ui?.router?.current?.();
    const stillHostOpen =
      panelCur?.name === PARTY_PANEL_NAME ||
      (routeCur?.type === "plugin" && routeCur.name === PARTY_PANEL_NAME);
    if (!stillHostOpen) {
      this.emitUi({ panelOpen: false });
      this.syncFeedLifecycle();
    }
  }

  async openPanel(presentation: "panel" | "fullscreen" = "panel"): Promise<boolean> {
    this.context.ui?.dialog?.clear?.();
    const panelApi = this.context.ui?.panel;
    const routerApi = this.context.ui?.router;

    if (panelApi && typeof panelApi.open === "function") {
      const opened = panelApi.open(PARTY_PANEL_NAME, { presentation });
      if (opened) {
        this.emitUi({ panelOpen: true });
        this.feed.setPanelFocused(true);
        this.syncFeedLifecycle();
        return true;
      }
    }

    if (routerApi && typeof routerApi.navigate === "function") {
      const cur = typeof routerApi.current === "function" ? routerApi.current() : { type: "home" as const };
      const returnRoute: OpenCodeTuiRoute =
        cur.type === "session" && cur.sessionID
          ? { type: "session", sessionID: cur.sessionID }
          : cur.type === "plugin" && cur.name && cur.name !== PARTY_PANEL_NAME
            ? { type: "plugin", id: cur.id, name: cur.name, ...(cur.data ? { data: { ...cur.data } } : {}) }
            : { type: "home" };
      this.emitUi({ panelOpen: true, returnRoute });
      this.feed.setPanelFocused(true);
      this.syncFeedLifecycle();
      routerApi.navigate({
        type: "plugin",
        name: PARTY_PANEL_NAME,
        data: { sessionID: cur.type === "session" ? cur.sessionID : undefined, returnRoute },
      });
      return true;
    }

    return false;
  }

  closePanel(stopSidebar = false): void {
    const panelApi = this.context.ui?.panel;
    const routerApi = this.context.ui?.router;

    if (panelApi?.current?.()?.name === PARTY_PANEL_NAME) {
      panelApi.close();
    }
    const curRoute = routerApi?.current?.();
    if (curRoute?.type === "plugin" && curRoute.name === PARTY_PANEL_NAME) {
      routerApi?.navigate(this.state.returnRoute ?? { type: "home" });
    }

    this.feed.setPanelFocused(false);
    this.emitUi({
      panelOpen: false,
      ...(stopSidebar ? { sidebarOpen: false } : {}),
    });
    this.syncFeedLifecycle();
  }

  toggleSidebar(): boolean {
    const next = !this.state.sidebarOpen;
    this.emitUi({ sidebarOpen: next, sidebarExpanded: true });
    this.syncFeedLifecycle();
    return next;
  }

  toggleSidebarExpanded(): void {
    this.emitUi({ sidebarExpanded: !this.state.sidebarExpanded });
  }

  async handlePanelCommand(rawInput?: string): Promise<void> {
    const arg = (rawInput ?? "").trim().toLowerCase();

    if (arg === "status") {
      const snap = this.feed.getSnapshot();
      const lines = [
        `Panel: ${this.isPanelActiveInHost() ? "OPEN" : "CLOSED"} · Sidebar feed: ${this.state.sidebarOpen ? "ON" : "OFF"}`,
        `Feed loop: ${snap.running ? snap.status.toUpperCase() : "IDLE (0 background processes)"}`,
        snap.partyId !== undefined
          ? `Active party: #${snap.partyId} (${snap.memberCount} live, seq=${snap.cursorSeq}, buffered=${snap.messages.length})`
          : "Active party: none discovered",
      ];
      if (snap.lastError) lines.push(`Last error: ${redactUrlFragments(snap.lastError)}`);
      await showAlertOrToast(this.context, "Multiplayer Party Panel", lines.join("\n"), "info");
      return;
    }

    if (arg === "sidebar") {
      const enabled = this.toggleSidebar();
      this.context.ui.toast.show({
        title: "Multiplayer Party Sidebar",
        message: enabled
          ? "Live Party Chat sidebar feed enabled (bounded party wait)."
          : "Live Party Chat sidebar feed stopped.",
        variant: "info",
        duration: 4000,
      });
      return;
    }

    if (arg === "off" || arg === "close" || arg === "hide" || arg === "stop") {
      this.closePanel(true);
      this.context.ui.toast.show({
        title: "Multiplayer Party Panel",
        message: "Closed Party Chat panel and stopped background feed.",
        variant: "info",
        duration: 3500,
      });
      return;
    }

    if (arg === "on" || arg === "open" || arg === "show" || arg === "full" || arg === "fullscreen") {
      const presentation = arg === "full" || arg === "fullscreen" ? "fullscreen" : "panel";
      const opened = await this.openPanel(presentation);
      if (!opened) {
        await runPartyRead(this.context);
      }
      return;
    }

    if (arg === "" || arg === "toggle") {
      if (this.isPanelActiveInHost()) {
        this.closePanel(false);
        this.context.ui.toast.show({
          title: "Multiplayer Party Panel",
          message: this.state.sidebarOpen
            ? "Closed Party Chat panel (sidebar feed still active)."
            : "Closed Party Chat panel.",
          variant: "info",
          duration: 3000,
        });
        return;
      }
      const opened = await this.openPanel("panel");
      if (!opened) {
        await runPartyRead(this.context);
      }
      return;
    }

    this.context.ui.toast.show({
      title: "Multiplayer Party Panel",
      message: "Usage: /party-panel [on|off|full|sidebar|status]",
      variant: "warning",
      duration: 5000,
    });
  }

  dispose(): void {
    this.closePanel(true);
    this.uiListeners.clear();
  }
}

function statusDotColor(status: PartyFeedSnapshot["status"], colors: ReturnType<typeof themeColors>): string {
  switch (status) {
    case "live":
      return colors.success;
    case "connecting":
    case "reconnecting":
      return colors.warning;
    case "error":
      return colors.error;
    default:
      return colors.muted;
  }
}

function statusLabel(snap: PartyFeedSnapshot): string {
  switch (snap.status) {
    case "live":
      return snap.partyId !== undefined
        ? `Live · #${snap.partyId} · ${snap.memberCount} online · seq ${snap.cursorSeq}`
        : "Live";
    case "connecting":
      return "Connecting to active party…";
    case "reconnecting":
      return snap.lastError ? `Reconnecting (${snap.lastError})` : "Reconnecting…";
    case "no_party":
      return "No active party — join via /party or mp-outpost";
    case "error":
      return snap.lastError ? `Error: ${snap.lastError}` : "Feed error";
    default:
      return "Idle";
  }
}

function buildPartyPanelView(
  rt: LoadedOpenTuiRuntime,
  context: OpenCodeTuiContext,
  controller: PartyPanelController,
  options: {
    panel?: OpenCodeTuiPanelInput;
    onClose: () => void;
    fullscreenOverlay?: boolean;
  },
): unknown {
  const { solid, opentui: ui } = rt;
  const [snap, setSnap] = solid.createSignal<PartyFeedSnapshot>(controller.feed.getSnapshot());
  const [uiState, setUiState] = solid.createSignal<PanelUiState>(controller.getState());
  const unsubFeed = controller.feed.subscribe((next) => setSnap(next));
  const unsubUi = controller.subscribeUi((next) => setUiState(next));

  let scrollRef: ScrollboxLike | undefined;

  controller.notifyPanelMounted(options.panel?.focused ?? true);

  solid.createEffect(() => {
    const focused = options.panel ? options.panel.focused === true : true;
    controller.feed.setPanelFocused(focused);
  });

  solid.onCleanup(() => {
    unsubFeed();
    unsubUi();
    controller.notifyPanelUnmounted();
  });

  const scrollByLines = (delta: number) => {
    scrollRef?.scrollBy?.(delta);
  };

  // Register panel-scoped key bindings (active while focused, matching opencode.diffs).
  if (typeof context.keymap?.layer === "function") {
    context.keymap.layer(() => ({
      commands: [
        {
          id: "multiplayer.panel.say",
          title: "Send party message",
          group: "Multiplayer",
          bind: "s",
          run() {
            void runPartySay(context);
          },
        },
        {
          id: "multiplayer.panel.refresh",
          title: "Refresh party feed",
          group: "Multiplayer",
          bind: "r",
          run() {
            controller.feed.refresh();
          },
        },
        {
          id: "multiplayer.panel.down",
          title: "Scroll party chat down",
          group: "Multiplayer",
          bind: "j",
          run() {
            scrollByLines(3);
          },
        },
        {
          id: "multiplayer.panel.up",
          title: "Scroll party chat up",
          group: "Multiplayer",
          bind: "k",
          run() {
            scrollByLines(-3);
          },
        },
        {
          id: "multiplayer.panel.top",
          title: "Scroll to top of party chat",
          group: "Multiplayer",
          bind: "g",
          run() {
            scrollRef?.scrollTo?.(0);
          },
        },
        {
          id: "multiplayer.panel.bottom",
          title: "Scroll to latest party message",
          group: "Multiplayer",
          bind: "G",
          run() {
            if (scrollRef && typeof scrollRef.scrollHeight === "number") {
              scrollRef.scrollTo?.(scrollRef.scrollHeight);
            }
          },
        },
        {
          id: "multiplayer.panel.fullscreen",
          title: "Toggle party panel fullscreen",
          group: "Multiplayer",
          bind: "f",
          enabled: () => typeof options.panel?.toggleFullscreen === "function",
          run() {
            options.panel?.toggleFullscreen?.();
          },
        },
        {
          id: "multiplayer.panel.close",
          title: "Close party chat panel",
          group: "Multiplayer",
          bind: "q",
          run() {
            options.onClose();
          },
        },
        {
          id: "multiplayer.panel.escape",
          title: "Close party chat panel",
          group: "Multiplayer",
          bind: "escape",
          run() {
            options.onClose();
          },
        },
      ],
    }));
  }

  const root = ui.createElement("box");
  ui.setProp(root, "width", "100%");
  ui.setProp(root, "height", "100%");
  ui.setProp(root, "flexDirection", "column");
  if (options.fullscreenOverlay) {
    ui.setProp(root, "position", "absolute");
    ui.setProp(root, "zIndex", 2500);
    ui.setProp(root, "left", 0);
    ui.setProp(root, "top", 0);
  }
  ui.effect(() => {
    const c = themeColors(context.theme);
    const isSidePanel = options.panel?.presentation === "panel";
    ui.setProp(root, "backgroundColor", isSidePanel ? c.bgRaised : c.bg);
  });

  // Header bar
  const header = ui.createElement("box");
  ui.setProp(header, "flexDirection", "row");
  ui.setProp(header, "justifyContent", "space-between");
  ui.setProp(header, "paddingLeft", 2);
  ui.setProp(header, "paddingRight", 2);
  ui.setProp(header, "paddingTop", 1);
  ui.setProp(header, "paddingBottom", 1);
  ui.setProp(header, "gap", 1);
  ui.setProp(header, "flexShrink", 0);
  ui.setProp(header, "border", ["bottom"]);
  ui.effect(() => ui.setProp(header, "borderColor", themeColors(context.theme).border));

  const headerLeft = ui.createElement("box");
  ui.setProp(headerLeft, "flexDirection", "row");
  ui.setProp(headerLeft, "gap", 1);
  ui.setProp(headerLeft, "flexGrow", 1);
  ui.setProp(headerLeft, "minWidth", 0);

  const statusDot = ui.createElement("text");
  ui.setProp(statusDot, "flexShrink", 0);
  ui.setProp(statusDot, "wrapMode", "none");
  ui.insertNode(statusDot, ui.createTextNode("●"));
  ui.effect(() => ui.setProp(statusDot, "fg", statusDotColor(snap().status, themeColors(context.theme))));

  const titleText = ui.createElement("text");
  ui.setProp(titleText, "flexShrink", 0);
  ui.setProp(titleText, "wrapMode", "none");
  const titleBold = ui.createElement("b");
  ui.insertNode(titleText, titleBold);
  ui.insert(titleBold, () => {
    const s = snap();
    return s.partyId !== undefined ? `Party #${s.partyId}` : "Multiplayer Party";
  });
  ui.effect(() => ui.setProp(titleText, "fg", themeColors(context.theme).fg));

  const metaText = ui.createElement("text");
  ui.setProp(metaText, "flexGrow", 1);
  ui.setProp(metaText, "minWidth", 0);
  ui.setProp(metaText, "wrapMode", "none");
  ui.setProp(metaText, "truncate", true);
  ui.insert(metaText, () => {
    const s = snap();
    const parts: string[] = [];
    if (s.handle) parts.push(s.handle);
    if (s.partyId !== undefined && s.memberCount > 0) parts.push(`${s.memberCount} live`);
    return parts.length > 0 ? `· ${parts.join(" · ")}` : "";
  });
  ui.effect(() => ui.setProp(metaText, "fg", themeColors(context.theme).muted));

  ui.insertNode(headerLeft, statusDot);
  ui.insertNode(headerLeft, titleText);
  ui.insertNode(headerLeft, metaText);

  const headerActions = ui.createElement("box");
  ui.setProp(headerActions, "flexDirection", "row");
  ui.setProp(headerActions, "gap", 1);
  ui.setProp(headerActions, "flexShrink", 0);

  const makeActionLink = (label: () => string, onClick: () => void, accent = false) => {
    const t = ui.createElement("text");
    ui.setProp(t, "selectable", false);
    ui.setProp(t, "flexShrink", 0);
    ui.setProp(t, "wrapMode", "none");
    ui.setProp(t, "onMouseUp", () => onClick());
    ui.insert(t, label);
    ui.effect(() => {
      const c = themeColors(context.theme);
      ui.setProp(t, "fg", accent ? c.interactive : c.muted);
    });
    return t;
  };

  ui.insertNode(
    headerActions,
    makeActionLink(() => "[say]", () => void runPartySay(context), true),
  );
  if (typeof options.panel?.toggleFullscreen === "function") {
    ui.insertNode(
      headerActions,
      makeActionLink(
        () => (options.panel?.presentation === "fullscreen" ? "[split]" : "[full]"),
        () => options.panel?.toggleFullscreen?.(),
      ),
    );
  }
  ui.insertNode(
    headerActions,
    makeActionLink(() => "[×]", () => options.onClose()),
  );

  ui.insertNode(header, headerLeft);
  ui.insertNode(header, headerActions);

  // Provenance / hint sub-header
  const banner = ui.createElement("box");
  ui.setProp(banner, "paddingLeft", 2);
  ui.setProp(banner, "paddingRight", 2);
  ui.setProp(banner, "paddingTop", 0);
  ui.setProp(banner, "paddingBottom", 1);
  ui.setProp(banner, "flexShrink", 0);
  const bannerText = ui.createElement("text");
  ui.setProp(bannerText, "wrapMode", "none");
  ui.setProp(bannerText, "truncate", true);
  ui.insert(bannerText, () => {
    const s = snap();
    return s.gapNotice
      ? `UNTRUSTED EXTERNAL DATA · ${s.gapNotice}`
      : "UNTRUSTED EXTERNAL DATA · [s] say  [r] refresh  [j/k] scroll  [q/esc] close";
  });
  ui.effect(() => {
    const c = themeColors(context.theme);
    ui.setProp(bannerText, "fg", snap().gapNotice ? c.warning : c.muted);
  });
  ui.insertNode(banner, bannerText);

  // Scrollable message feed
  const scrollbox = ui.createElement("scrollbox");
  ui.setProp(scrollbox, "id", "multiplayer-party-scroll");
  ui.setProp(scrollbox, "flexGrow", 1);
  ui.setProp(scrollbox, "minHeight", 0);
  ui.setProp(scrollbox, "minWidth", 0);
  ui.setProp(scrollbox, "stickyScroll", true);
  ui.setProp(scrollbox, "stickyStart", "bottom");
  ui.setProp(scrollbox, "horizontalScrollbarOptions", { visible: false });
  if (typeof ui.use === "function") {
    ui.use((el: unknown) => {
      scrollRef = el as ScrollboxLike;
    }, scrollbox);
  } else {
    scrollRef = scrollbox as unknown as ScrollboxLike;
  }

  const listContainer = ui.createElement("box");
  ui.setProp(listContainer, "flexDirection", "column");
  ui.setProp(listContainer, "paddingLeft", 2);
  ui.setProp(listContainer, "paddingRight", 2);
  ui.setProp(listContainer, "gap", 1);

  // Empty / loading / error placeholder when 0 messages
  ui.insert(
    listContainer,
    ui.createComponent(solid.Show, {
      get when() {
        return snap().messages.length === 0;
      },
      get children() {
        const emptyBox = ui.createElement("box");
        ui.setProp(emptyBox, "paddingTop", 1);
        const emptyText = ui.createElement("text");
        ui.setProp(emptyText, "wrapMode", "word");
        ui.insert(emptyText, () => {
          const s = snap();
          if (s.status === "connecting") return "Connecting to active multiplayer.tech party…";
          if (s.status === "no_party") return "No active multiplayer party. Join a party via mp-outpost or /party.";
          if (s.status === "error" || s.lastError) return `Feed error: ${s.lastError ?? "unable to reach mp-outpost"}`;
          return "No recent chat messages yet. Press [s] or run /party-say to send one.";
        });
        ui.effect(() => {
          const c = themeColors(context.theme);
          const s = snap();
          ui.setProp(emptyText, "fg", s.status === "error" ? c.error : c.muted);
        });
        ui.insertNode(emptyBox, emptyText);
        return emptyBox;
      },
    }),
  );

  // Message list
  ui.insert(
    listContainer,
    ui.createComponent(solid.For, {
      get each() {
        return snap().messages;
      },
      children: (msg: PartyChatMessage) => {
        const row = ui.createElement("box");
        ui.setProp(row, "flexDirection", "column");
        ui.setProp(row, "flexShrink", 0);

        const metaRow = ui.createElement("box");
        ui.setProp(metaRow, "flexDirection", "row");
        ui.setProp(metaRow, "gap", 1);

        const seqText = ui.createElement("text");
        ui.setProp(seqText, "flexShrink", 0);
        ui.setProp(seqText, "wrapMode", "none");
        ui.insertNode(seqText, ui.createTextNode(`#${msg.seq}`));
        ui.effect(() => ui.setProp(seqText, "fg", themeColors(context.theme).muted));

        const handleText = ui.createElement("text");
        ui.setProp(handleText, "flexShrink", 0);
        ui.setProp(handleText, "wrapMode", "none");
        const handleBold = ui.createElement("b");
        ui.insertNode(handleText, handleBold);
        ui.insertNode(handleBold, ui.createTextNode(msg.handle));
        ui.effect(() => {
          const c = themeColors(context.theme);
          ui.setProp(handleText, "fg", msg.isBrowser ? c.warning : msg.isOwn ? c.success : c.accent);
        });

        ui.insertNode(metaRow, seqText);
        ui.insertNode(metaRow, handleText);

        if (msg.isBrowser) {
          const browserBadge = ui.createElement("text");
          ui.setProp(browserBadge, "flexShrink", 0);
          ui.setProp(browserBadge, "wrapMode", "none");
          ui.insertNode(browserBadge, ui.createTextNode("[browser]"));
          ui.effect(() => ui.setProp(browserBadge, "fg", themeColors(context.theme).warning));
          ui.insertNode(metaRow, browserBadge);
        }

        if (msg.isCard) {
          const cardBadge = ui.createElement("text");
          ui.setProp(cardBadge, "flexShrink", 0);
          ui.setProp(cardBadge, "wrapMode", "none");
          ui.insertNode(cardBadge, ui.createTextNode("[card]"));
          ui.effect(() => ui.setProp(cardBadge, "fg", themeColors(context.theme).info));
          ui.insertNode(metaRow, cardBadge);
        }

        if (msg.timestamp) {
          const tsText = ui.createElement("text");
          ui.setProp(tsText, "flexShrink", 0);
          ui.setProp(tsText, "wrapMode", "none");
          ui.insertNode(tsText, ui.createTextNode(msg.timestamp));
          ui.effect(() => ui.setProp(tsText, "fg", themeColors(context.theme).muted));
          ui.insertNode(metaRow, tsText);
        }

        const bodyText = ui.createElement("text");
        ui.setProp(bodyText, "wrapMode", "word");
        ui.setProp(bodyText, "paddingLeft", 2);
        ui.insertNode(bodyText, ui.createTextNode(msg.body));
        ui.effect(() => ui.setProp(bodyText, "fg", themeColors(context.theme).fg));

        ui.insertNode(row, metaRow);
        ui.insertNode(row, bodyText);
        return row;
      },
    }),
  );

  ui.insertNode(scrollbox, listContainer);

  // Footer bar
  const footer = ui.createElement("box");
  ui.setProp(footer, "flexDirection", "row");
  ui.setProp(footer, "justifyContent", "space-between");
  ui.setProp(footer, "paddingLeft", 2);
  ui.setProp(footer, "paddingRight", 2);
  ui.setProp(footer, "paddingTop", 1);
  ui.setProp(footer, "paddingBottom", 1);
  ui.setProp(footer, "gap", 1);
  ui.setProp(footer, "flexShrink", 0);
  ui.setProp(footer, "border", ["top"]);
  ui.effect(() => ui.setProp(footer, "borderColor", themeColors(context.theme).border));

  const footerStatus = ui.createElement("text");
  ui.setProp(footerStatus, "flexGrow", 1);
  ui.setProp(footerStatus, "minWidth", 0);
  ui.setProp(footerStatus, "wrapMode", "none");
  ui.setProp(footerStatus, "truncate", true);
  ui.insert(footerStatus, () => {
    const s = snap();
    return `${statusLabel(s)} · ${s.messages.length} msg${s.messages.length === 1 ? "" : "s"}`;
  });
  ui.effect(() => {
    const c = themeColors(context.theme);
    const s = snap();
    ui.setProp(footerStatus, "fg", s.status === "error" ? c.error : c.muted);
  });

  const footerActions = ui.createElement("box");
  ui.setProp(footerActions, "flexDirection", "row");
  ui.setProp(footerActions, "gap", 1);
  ui.setProp(footerActions, "flexShrink", 0);
  ui.insertNode(
    footerActions,
    makeActionLink(() => "[refresh]", () => controller.feed.refresh()),
  );
  ui.insertNode(
    footerActions,
    makeActionLink(
      () => (uiState().sidebarOpen ? "[sidebar:on]" : "[sidebar:off]"),
      () => {
        controller.toggleSidebar();
      },
    ),
  );

  ui.insertNode(footer, footerStatus);
  ui.insertNode(footer, footerActions);

  ui.insertNode(root, header);
  ui.insertNode(root, banner);
  ui.insertNode(root, scrollbox);
  ui.insertNode(root, footer);

  return root;
}

function buildSidebarWidget(
  rt: LoadedOpenTuiRuntime,
  context: OpenCodeTuiContext,
  controller: PartyPanelController,
): unknown {
  const { solid, opentui: ui } = rt;
  const [snap, setSnap] = solid.createSignal<PartyFeedSnapshot>(controller.feed.getSnapshot());
  const [uiState, setUiState] = solid.createSignal<PanelUiState>(controller.getState());
  const unsubFeed = controller.feed.subscribe((next) => setSnap(next));
  const unsubUi = controller.subscribeUi((next) => setUiState(next));
  solid.onCleanup(() => {
    unsubFeed();
    unsubUi();
  });

  return ui.createComponent(solid.Show, {
    get when() {
      return uiState().sidebarOpen;
    },
    get children() {
      const container = ui.createElement("box");
      ui.setProp(container, "flexDirection", "column");
      ui.setProp(container, "flexShrink", 0);
      ui.setProp(container, "gap", 0);

      // Collapsible section header matching opencode.sidebar.mcp
      const headerRow = ui.createElement("box");
      ui.setProp(headerRow, "flexDirection", "row");
      ui.setProp(headerRow, "gap", 1);
      ui.setProp(headerRow, "onMouseDown", () => controller.toggleSidebarExpanded());

      const chevron = ui.createElement("text");
      ui.setProp(chevron, "flexShrink", 0);
      ui.insert(chevron, () => (uiState().sidebarExpanded ? "▼" : "▶"));
      ui.effect(() => ui.setProp(chevron, "fg", themeColors(context.theme).fg));

      const dot = ui.createElement("text");
      ui.setProp(dot, "flexShrink", 0);
      ui.insertNode(dot, ui.createTextNode("●"));
      ui.effect(() => ui.setProp(dot, "fg", statusDotColor(snap().status, themeColors(context.theme))));

      const heading = ui.createElement("text");
      ui.setProp(heading, "flexGrow", 1);
      ui.setProp(heading, "minWidth", 0);
      ui.setProp(heading, "wrapMode", "none");
      ui.setProp(heading, "truncate", true);
      const headingBold = ui.createElement("b");
      ui.insertNode(heading, headingBold);
      ui.insertNode(headingBold, ui.createTextNode("Party Chat"));
      const countSpan = ui.createElement("span");
      ui.insert(countSpan, () => {
        const s = snap();
        return s.partyId !== undefined ? ` (#${s.partyId})` : "";
      });
      ui.effect(() => ui.setProp(countSpan, "style", { fg: themeColors(context.theme).muted }));
      ui.insertNode(heading, countSpan);
      ui.effect(() => ui.setProp(heading, "fg", themeColors(context.theme).fg));

      ui.insertNode(headerRow, chevron);
      ui.insertNode(headerRow, dot);
      ui.insertNode(headerRow, heading);
      ui.insertNode(container, headerRow);

      // Body when expanded
      ui.insert(
        container,
        ui.createComponent(solid.Show, {
          get when() {
            return uiState().sidebarExpanded;
          },
          get children() {
            const body = ui.createElement("box");
            ui.setProp(body, "flexDirection", "column");
            ui.setProp(body, "paddingLeft", 2);
            ui.setProp(body, "gap", 0);

            const note = ui.createElement("text");
            ui.setProp(note, "wrapMode", "none");
            ui.setProp(note, "truncate", true);
            ui.insert(note, () => {
              const s = snap();
              if (s.status === "connecting") return "Connecting…";
              if (s.status === "no_party") return "No active party";
              if (s.status === "error") return s.lastError ?? "Feed error";
              return `UNTRUSTED DATA · seq ${s.cursorSeq}`;
            });
            ui.effect(() => {
              const c = themeColors(context.theme);
              ui.setProp(note, "fg", snap().status === "error" ? c.error : c.muted);
            });
            ui.insertNode(body, note);

            ui.insert(
              body,
              ui.createComponent(solid.For, {
                get each() {
                  return snap().messages.slice(-8);
                },
                children: (msg: PartyChatMessage) => {
                  const line = ui.createElement("text");
                  ui.setProp(line, "wrapMode", "none");
                  ui.setProp(line, "truncate", true);
                  const singleLineBody = sanitizeSingleLine(msg.body);
                  const tag = msg.isBrowser ? " [web]" : "";
                  ui.insertNode(line, ui.createTextNode(`${msg.handle}${tag}: ${singleLineBody}`));
                  ui.effect(() => {
                    const c = themeColors(context.theme);
                    ui.setProp(line, "fg", msg.isBrowser ? c.warning : c.fg);
                  });
                  return line;
                },
              }),
            );

            const actions = ui.createElement("box");
            ui.setProp(actions, "flexDirection", "row");
            ui.setProp(actions, "gap", 1);

            const mkBtn = (label: string, onClick: () => void, accent = false) => {
              const t = ui.createElement("text");
              ui.setProp(t, "selectable", false);
              ui.setProp(t, "wrapMode", "none");
              ui.setProp(t, "onMouseUp", onClick);
              ui.insertNode(t, ui.createTextNode(label));
              ui.effect(() => {
                const c = themeColors(context.theme);
                ui.setProp(t, "fg", accent ? c.interactive : c.muted);
              });
              return t;
            };

            ui.insertNode(
              actions,
              mkBtn("[panel]", () => void controller.openPanel("panel"), true),
            );
            ui.insertNode(
              actions,
              mkBtn("[say]", () => void runPartySay(context)),
            );
            ui.insertNode(
              actions,
              mkBtn("[stop]", () => controller.toggleSidebar()),
            );
            ui.insertNode(body, actions);
            return body;
          },
        }),
      );

      return container;
    },
  });
}

function buildFooterStatusIndicator(
  rt: LoadedOpenTuiRuntime,
  context: OpenCodeTuiContext,
  controller: PartyPanelController,
): unknown {
  const { solid, opentui: ui } = rt;
  const [snap, setSnap] = solid.createSignal<PartyFeedSnapshot>(controller.feed.getSnapshot());
  const unsubFeed = controller.feed.subscribe((next) => setSnap(next));
  solid.onCleanup(() => unsubFeed());

  return ui.createComponent(solid.Show, {
    get when() {
      return snap().running;
    },
    get children() {
      const box = ui.createElement("box");
      ui.setProp(box, "flexShrink", 0);
      ui.setProp(box, "flexDirection", "row");
      ui.setProp(box, "gap", 1);
      ui.setProp(box, "onMouseUp", () => void controller.handlePanelCommand("toggle"));

      const dot = ui.createElement("text");
      ui.setProp(dot, "flexShrink", 0);
      ui.setProp(dot, "wrapMode", "none");
      ui.insertNode(dot, ui.createTextNode("●"));
      ui.effect(() => ui.setProp(dot, "fg", statusDotColor(snap().status, themeColors(context.theme))));

      const label = ui.createElement("text");
      ui.setProp(label, "flexShrink", 0);
      ui.setProp(label, "wrapMode", "none");
      ui.insert(label, () => {
        const s = snap();
        const base = s.partyId !== undefined ? `party #${s.partyId}` : "party";
        return s.unreadCount > 0 ? `${base} (${s.unreadCount} new)` : base;
      });
      ui.effect(() => {
        const c = themeColors(context.theme);
        const s = snap();
        ui.setProp(label, "fg", s.unreadCount > 0 ? c.interactive : c.muted);
      });

      ui.insertNode(box, dot);
      ui.insertNode(box, label);
      return box;
    },
  });
}

async function mountNativePanelSlots(
  context: OpenCodeTuiContext,
  controller: PartyPanelController,
  isDisposed: () => boolean,
  cleanups: Array<() => void>,
): Promise<void> {
  const rt = await loadOpenTuiRuntime();
  if (!rt || isDisposed()) return;
  if (typeof context.ui?.slot !== "function") return;

  controller.markNativeRuntimeLoaded();

  // 1. Full-height live session.panel slot
  const unsubPanelSlot = context.ui.slot({
    append: "session.panel",
    render(rawInput) {
      const panelInput = (rawInput ?? {}) as unknown as OpenCodeTuiPanelInput;
      return rt.opentui.createComponent(rt.solid.Show, {
        get when() {
          return panelInput.name === PARTY_PANEL_NAME;
        },
        get children() {
          return buildPartyPanelView(rt, context, controller, {
            panel: panelInput,
            onClose: () => {
              if (typeof panelInput.close === "function") {
                panelInput.close();
              } else {
                controller.closePanel(false);
              }
            },
          });
        },
      });
    },
  });
  if (typeof unsubPanelSlot === "function") cleanups.push(unsubPanelSlot);

  // 2. Fallback standalone plugin route when opened from OpenCode's "home" screen
  if (typeof context.ui?.router?.register === "function") {
    try {
      const unsubRoute = context.ui.router.register({
        name: PARTY_PANEL_NAME,
        render({ data }) {
          const returnRoute = (data?.returnRoute as OpenCodeTuiRoute | undefined) ?? { type: "home" };
          return buildPartyPanelView(rt, context, controller, {
            fullscreenOverlay: true,
            onClose: () => {
              controller.closePanel(false);
              context.ui.router?.navigate(returnRoute);
            },
          });
        },
      });
      if (typeof unsubRoute === "function") cleanups.push(unsubRoute);
    } catch {
      // ignore if route already registered
    }
  }

  // 3. Collapsible live sidebar.content widget
  const unsubSidebarSlot = context.ui.slot({
    append: "sidebar.content",
    render() {
      return buildSidebarWidget(rt, context, controller);
    },
  });
  if (typeof unsubSidebarSlot === "function") cleanups.push(unsubSidebarSlot);

  // 4. Compact prompt.footer.status live indicator (only visible while feed runs)
  const unsubFooterSlot = context.ui.slot({
    append: "prompt.footer.status",
    render() {
      return buildFooterStatusIndicator(rt, context, controller);
    },
  });
  if (typeof unsubFooterSlot === "function") cleanups.push(unsubFooterSlot);
}

async function runPartyMenu(context: OpenCodeTuiContext, controller: PartyPanelController): Promise<void> {
  if (typeof context.ui?.dialog?.select !== "function") {
    await runOpenChat(context);
    return;
  }

  const panelOpen = controller.isPanelActiveInHost();
  const sidebarOpen = controller.getState().sidebarOpen;

  const choice = await context.ui.dialog.select({
    title: "Multiplayer (multiplayer.tech)",
    placeholder: "Choose a Multiplayer action...",
    options: [
      {
        title: panelOpen ? "Close Live Party Chat Panel" : "Open Live Party Chat Panel (native)",
        description: panelOpen
          ? "Close the live OpenCode party chat panel"
          : "Display live party chat natively inside OpenCode (session panel)",
        value: "panel",
      },
      {
        title: sidebarOpen ? "Stop Sidebar Party Feed" : "Toggle Live Sidebar Party Feed",
        description: sidebarOpen
          ? "Hide sidebar feed and stop background party wait"
          : "Show a compact live party feed in the OpenCode session sidebar",
        value: "sidebar",
      },
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
    case "panel":
      await controller.handlePanelCommand("toggle");
      break;
    case "sidebar":
      await controller.handlePanelCommand("sidebar");
      break;
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
  id: "antimeme.multiplayer",
  setup(context: OpenCodeTuiContext): () => void {
    let disposed = false;
    const cleanups: Array<() => void> = [];
    const controller = new PartyPanelController(context);

    const registerLayer = () => {
      context.keymap.layer(() => ({
        mode: "global",
        commands: [
          {
            id: "multiplayer.menu",
            title: "Multiplayer Party Menu",
            description: "Open quick Multiplayer menu (panel, sidebar, chat, say, read, status, friends, listen)",
            group: "Multiplayer",
            bind: "ctrl+alt+m",
            palette: true,
            slash: { name: "party", aliases: ["mp"] },
            suggested: true,
            async run() {
              await runPartyMenu(context, controller);
            },
          },
          {
            id: "multiplayer.panel",
            title: "Toggle Multiplayer Party Chat Panel",
            description: "Show or hide the native live Party Chat display panel (args: on|off|full|sidebar|status)",
            group: "Multiplayer",
            palette: true,
            slash: { name: "party-panel", aliases: ["mp-panel"], arguments: true },
            suggested: true,
            async run(input?: string) {
              await controller.handlePanelCommand(input);
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
      const unsubApp = context.ui.slot({
        append: "app",
        render: registerLayer,
      });
      if (typeof unsubApp === "function") cleanups.push(unsubApp);
      void mountNativePanelSlots(context, controller, () => disposed, cleanups);
    } else {
      registerLayer();
    }

    return () => {
      disposed = true;
      controller.dispose();
      for (const fn of cleanups.splice(0).reverse()) {
        try {
          fn();
        } catch {
          // ignore cleanup errors
        }
      }
    };
  },
};

export default tuiPlugin;
