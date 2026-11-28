/**
 * Live background `PartyFeedStore` and sanitization helpers for OpenCode TUI.
 *
 * Runs a bounded `mp-outpost --json party wait` loop ONLY while started (panel
 * or sidebar visible), seeded with the latest ~12 messages via `party read`.
 *
 * Security & operational guarantees:
 * - Zero `console.*` calls and zero external runtime dependencies.
 * - Full ANSI/OSC escape stripping + C0/C1/BiDi/zero-width/tag-char removal.
 * - Invite URL `#fragment` redaction before storing or displaying text.
 * - Own non-browser device echo filtering (`sender_device_id === ownDeviceId`),
 *   while preserving `is_browser=true` / `sender_client="web"|"browser"` messages
 *   and marking them `[browser]`.
 * - Automatic `code=4040` / inactive-party recovery (re-queries `party list`).
 * - Immediate `SIGTERM` termination of any in-flight `party wait` child on
 *   `stop()` or process exit.
 */

import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const URL_FRAGMENT_RE =
  /((?:https?:\/\/)?(?:(?:www\.)?(?:clank\.party|multiplayer\.tech|mp\.gg)\/[^\s#"']+?|[^\s#"']+?\/(?:p\/)?i\/[A-Za-z0-9_-]+))#[A-Za-z0-9_-]+/gi;

// CSI, OSC, DCS/PM/APC, and 2-byte ESC sequences.
const ANSI_ESCAPE_RE =
  // eslint-disable-next-line no-control-regex
  /\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\|\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])/g;

const DEFAULT_WAIT_TIMEOUT_MS = 25_000;
const MAX_WAIT_TIMEOUT_MS = 45_000;
const DEFAULT_SEED_LIMIT = 12;
const DEFAULT_MAX_MESSAGES = 100;
const DEFAULT_IDLE_BACKOFF_MS = 1_500;

export interface PartyChatMessage {
  readonly seq: number;
  readonly handle: string;
  readonly isBrowser: boolean;
  readonly isCard: boolean;
  readonly isOwn: boolean;
  readonly body: string;
  readonly timestamp?: string;
}

export type PartyFeedStatus = "idle" | "connecting" | "live" | "reconnecting" | "no_party" | "error";

export interface PartyFeedSnapshot {
  readonly running: boolean;
  readonly status: PartyFeedStatus;
  readonly partyId?: number;
  readonly handle?: string;
  readonly ownDeviceId?: string;
  readonly memberCount: number;
  readonly relayPolicy?: string;
  readonly cursorSeq: number;
  readonly daemonEpoch: number;
  readonly messages: readonly PartyChatMessage[];
  readonly unreadCount: number;
  readonly gapNotice?: string;
  readonly lastError?: string;
  readonly updatedAt: number;
}

export interface PartyFeedStoreOptions {
  outpostBinary?: string;
  waitTimeoutMs?: number;
  seedLimit?: number;
  maxMessages?: number;
  idleBackoffMs?: number;
}

export function redactUrlFragments(text: string): string {
  return text.replace(URL_FRAGMENT_RE, "$1#[REDACTED]");
}

export function stripAnsiEscapes(text: string): string {
  return text.replace(ANSI_ESCAPE_RE, "");
}

export function sanitizePeerText(raw: string): string {
  const withoutAnsi = stripAnsiEscapes(raw);
  let out = "";
  for (const ch of withoutAnsi) {
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

export function sanitizeSingleLine(raw: string): string {
  return sanitizePeerText(raw).replace(/[\n\t]+/g, " ").replace(/\s+/g, " ").trim();
}

export function resolveBinaryPath(binary: string): string {
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

export async function execCapture(
  binary: string,
  args: string[],
  timeoutMs = 10_000,
  onSpawn?: (child: ChildProcess) => void,
): Promise<{ code: number; stdout: string; stderr: string; notFound?: boolean; aborted?: boolean }> {
  return await new Promise((resolve) => {
    let settled = false;
    const child = spawn(binary, args, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    onSpawn?.(child);
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
    if (typeof timer.unref === "function") timer.unref();

    child.stdout?.on("data", (c: Buffer) => outChunks.push(c));
    child.stderr?.on("data", (c: Buffer) => errChunks.push(c));
    child.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code: err.code === "ENOENT" ? 127 : 1,
        stdout: "",
        stderr: err.message,
        notFound: err.code === "ENOENT",
      });
    });
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code: code ?? (signal ? 143 : 1),
        stdout: Buffer.concat(outChunks).toString("utf8").trim(),
        stderr: Buffer.concat(errChunks).toString("utf8").trim(),
        aborted: signal === "SIGTERM" || signal === "SIGKILL",
      });
    });
  });
}

export async function runOutpostJson(
  subArgs: string[],
  timeoutMs = 8_000,
  options?: { outpostBinary?: string; onSpawn?: (child: ChildProcess) => void },
): Promise<
  { ok: true; data: Record<string, unknown> } | { ok: false; error: string; aborted?: boolean; code?: number }
> {
  const bin = resolveBinaryPath(options?.outpostBinary?.trim() || process.env.MP_OUTPOST_BIN?.trim() || "mp-outpost");
  const res = await execCapture(bin, ["--json", ...subArgs], timeoutMs, options?.onSpawn);
  if (res.aborted) {
    return { ok: false, error: "aborted", aborted: true, code: res.code };
  }
  if (res.notFound) {
    return { ok: false, error: `mp-outpost binary '${bin}' not found on PATH.`, code: res.code };
  }
  if (res.code !== 0 || !res.stdout) {
    const msg = redactUrlFragments(
      sanitizeSingleLine(res.stderr || res.stdout || `mp-outpost exited with status ${res.code}`),
    );
    return { ok: false, error: msg, code: res.code };
  }
  try {
    const parsed = JSON.parse(res.stdout) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "Unexpected JSON response from mp-outpost.", code: res.code };
    }
    return { ok: true, data: parsed as Record<string, unknown> };
  } catch {
    return { ok: false, error: "Invalid JSON output from mp-outpost.", code: res.code };
  }
}

export function extractEventBody(ev: Record<string, unknown>): { body: string; isCard: boolean } {
  for (const key of ["text", "body", "message"]) {
    const val = ev[key];
    if (typeof val === "string" && val.trim()) return { body: val, isCard: false };
  }
  const payload = ev.payload;
  if (typeof payload === "string" && payload.trim()) return { body: payload, isCard: false };
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    const p = payload as Record<string, unknown>;
    if (p.type === "agent_card" || "title" in p) {
      const title = typeof p.title === "string" ? p.title.trim() : "";
      const summary = typeof p.summary === "string" ? p.summary.trim() : "";
      const status = typeof p.status === "string" ? p.status.trim() : "";
      const tag = status ? `[${status}] ` : "";
      if (title && summary) return { body: `${tag}${title} — ${summary}`, isCard: true };
      if (title || summary) return { body: `${tag}${title || summary}`, isCard: true };
    }
    try {
      return { body: JSON.stringify(payload), isCard: false };
    } catch {
      return { body: "", isCard: false };
    }
  }
  return { body: "", isCard: false };
}

function normalizeDeviceId(val: unknown): string | undefined {
  if (typeof val === "number" && Number.isFinite(val) && val > 0) return String(Math.trunc(val));
  if (typeof val === "string") {
    const cleaned = val.trim();
    if (cleaned && cleaned !== "0") return cleaned;
  }
  return undefined;
}

function formatEventTimestamp(ev: Record<string, unknown>): string | undefined {
  const raw = ev.created_at ?? ev.timestamp ?? ev.sent_at ?? ev.ts;
  let d: Date | undefined;
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) {
    d = new Date(raw > 1e12 ? raw : raw * 1000);
  } else if (typeof raw === "string" && raw.trim()) {
    const parsed = Date.parse(raw.trim());
    if (!Number.isNaN(parsed)) d = new Date(parsed);
  }
  if (!d || Number.isNaN(d.getTime())) return undefined;
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

export function parsePartyEvent(
  raw: unknown,
  options?: { ownDeviceId?: string; ownHandle?: string; filterOwnEcho?: boolean },
): { seq: number; message?: PartyChatMessage } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { seq: 0 };
  const ev = raw as Record<string, unknown>;
  const seq =
    typeof ev.event_seq === "number"
      ? ev.event_seq
      : typeof ev.seq === "number"
        ? ev.seq
        : 0;
  const kind = String(ev.kind ?? "unknown");
  if (kind === "membership_changed" || kind === "system") return { seq };

  const senderClient = sanitizeSingleLine(String(ev.sender_client ?? ev.client ?? "")).toLowerCase();
  const isBrowser = Boolean(ev.is_browser) || senderClient === "web" || senderClient === "browser";
  const senderDeviceId = normalizeDeviceId(ev.sender_device_id);
  const ownDeviceId = options?.ownDeviceId;

  if (options?.filterOwnEcho !== false && !isBrowser && ownDeviceId && senderDeviceId && senderDeviceId === ownDeviceId) {
    return { seq };
  }

  const extracted = extractEventBody(ev);
  const body = redactUrlFragments(sanitizePeerText(extracted.body)).trim();
  if (!body) return { seq };

  const rawHandle = sanitizeSingleLine(String(ev.sender_handle ?? ev.from ?? "peer")) || "peer";
  const handle = rawHandle.startsWith("@") ? rawHandle : `@${rawHandle}`;
  const ownHandleNorm = options?.ownHandle ? (options.ownHandle.startsWith("@") ? options.ownHandle : `@${options.ownHandle}`) : undefined;
  const isOwn = Boolean(!isBrowser && ownHandleNorm && handle.toLowerCase() === ownHandleNorm.toLowerCase());

  return {
    seq,
    message: {
      seq,
      handle,
      isBrowser,
      isCard: extracted.isCard || kind === "agent_card",
      isOwn,
      body,
      timestamp: formatEventTimestamp(ev),
    },
  };
}

function isPartyInactiveError(errText: string): boolean {
  const lower = errText.toLowerCase();
  return (
    lower.includes("code=4040") ||
    lower.includes("is not active") ||
    lower.includes("no active party") ||
    lower.includes("party_not_found") ||
    lower.includes("not a member")
  );
}

export class PartyFeedStore {
  private readonly outpostBinary?: string;
  private readonly waitTimeoutMs: number;
  private readonly seedLimit: number;
  private readonly maxMessages: number;
  private readonly idleBackoffMs: number;

  private listeners = new Set<(snapshot: PartyFeedSnapshot) => void>();
  private generation = 0;
  private activeChild: ChildProcess | null = null;
  private sleepTimer: ReturnType<typeof setTimeout> | null = null;
  private sleepResolve: (() => void) | null = null;
  private loopPromise: Promise<void> | null = null;
  private readonly onProcessExit: () => void;
  private exitHookAttached = false;
  private panelFocused = false;

  private snapshot: PartyFeedSnapshot = {
    running: false,
    status: "idle",
    memberCount: 0,
    cursorSeq: 0,
    daemonEpoch: 0,
    messages: [],
    unreadCount: 0,
    updatedAt: Date.now(),
  };

  constructor(options?: PartyFeedStoreOptions) {
    this.outpostBinary = options?.outpostBinary;
    const rawWait = options?.waitTimeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS;
    this.waitTimeoutMs = Math.max(1_000, Math.min(MAX_WAIT_TIMEOUT_MS, Math.trunc(rawWait)));
    this.seedLimit = Math.max(1, Math.min(50, Math.trunc(options?.seedLimit ?? DEFAULT_SEED_LIMIT)));
    this.maxMessages = Math.max(20, Math.min(500, Math.trunc(options?.maxMessages ?? DEFAULT_MAX_MESSAGES)));
    this.idleBackoffMs = Math.max(50, Math.trunc(options?.idleBackoffMs ?? DEFAULT_IDLE_BACKOFF_MS));
    this.onProcessExit = () => {
      this.terminateActiveChild();
    };
  }

  getSnapshot(): PartyFeedSnapshot {
    return this.snapshot;
  }

  isRunning(): boolean {
    return this.snapshot.running;
  }

  subscribe(listener: (snapshot: PartyFeedSnapshot) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  setPanelFocused(focused: boolean): void {
    this.panelFocused = focused;
    if (focused && this.snapshot.unreadCount > 0) {
      this.patch({ unreadCount: 0 });
    }
  }

  clearUnread(): void {
    if (this.snapshot.unreadCount > 0) {
      this.patch({ unreadCount: 0 });
    }
  }

  start(): void {
    if (this.snapshot.running) return;
    const gen = ++this.generation;
    this.attachExitHook();
    this.patch({
      running: true,
      status: "connecting",
      lastError: undefined,
      gapNotice: undefined,
    });
    this.loopPromise = this.runLoop(gen).finally(() => {
      if (this.generation === gen && this.snapshot.running) {
        this.patch({ running: false, status: "idle" });
      }
      this.loopPromise = null;
    });
  }

  stop(): void {
    this.generation += 1;
    this.clearSleep();
    this.terminateActiveChild();
    this.detachExitHook();
    if (this.snapshot.running || this.snapshot.status !== "idle") {
      this.patch({
        running: false,
        status: "idle",
        lastError: undefined,
      });
    }
  }

  refresh(): void {
    if (!this.snapshot.running) {
      this.start();
      return;
    }
    // Restart the loop cleanly to re-discover active party & re-seed latest messages.
    const prevMessages = this.snapshot.messages;
    this.stop();
    this.patch({ messages: prevMessages });
    this.start();
  }

  private attachExitHook(): void {
    if (this.exitHookAttached) return;
    this.exitHookAttached = true;
    process.once("exit", this.onProcessExit);
  }

  private detachExitHook(): void {
    if (!this.exitHookAttached) return;
    this.exitHookAttached = false;
    process.removeListener("exit", this.onProcessExit);
  }

  private terminateActiveChild(): void {
    const child = this.activeChild;
    this.activeChild = null;
    if (!child) return;
    try {
      child.kill("SIGTERM");
    } catch {
      // ignore
    }
  }

  private clearSleep(): void {
    if (this.sleepTimer !== null) {
      clearTimeout(this.sleepTimer);
      this.sleepTimer = null;
    }
    if (this.sleepResolve) {
      const resolve = this.sleepResolve;
      this.sleepResolve = null;
      resolve();
    }
  }

  private async sleepBackoff(gen: number, ms = this.idleBackoffMs): Promise<void> {
    if (this.generation !== gen) return;
    await new Promise<void>((resolve) => {
      this.sleepResolve = resolve;
      const timer = setTimeout(() => {
        this.sleepTimer = null;
        this.sleepResolve = null;
        resolve();
      }, ms);
      if (typeof timer.unref === "function") timer.unref();
      this.sleepTimer = timer;
    });
  }

  private patch(update: Partial<PartyFeedSnapshot>): void {
    this.snapshot = {
      ...this.snapshot,
      ...update,
      updatedAt: Date.now(),
    };
    for (const listener of [...this.listeners]) {
      try {
        listener(this.snapshot);
      } catch {
        // never let a subscriber break the feed loop
      }
    }
  }

  private mergeMessages(
    existing: readonly PartyChatMessage[],
    incoming: readonly PartyChatMessage[],
  ): { merged: PartyChatMessage[]; addedCount: number } {
    if (incoming.length === 0) return { merged: [...existing], addedCount: 0 };
    const seenSeqs = new Set<number>();
    const merged: PartyChatMessage[] = [];
    for (const m of existing) {
      if (m.seq > 0) seenSeqs.add(m.seq);
      merged.push(m);
    }
    let addedCount = 0;
    for (const m of incoming) {
      if (m.seq > 0 && seenSeqs.has(m.seq)) continue;
      if (m.seq > 0) seenSeqs.add(m.seq);
      merged.push(m);
      addedCount += 1;
    }
    merged.sort((a, b) => a.seq - b.seq);
    if (merged.length > this.maxMessages) {
      merged.splice(0, merged.length - this.maxMessages);
    }
    return { merged, addedCount };
  }

  private async discoverAndSeed(gen: number): Promise<boolean> {
    const [statusRes, listRes] = await Promise.all([
      runOutpostJson(["party", "status"], 8_000, {
        outpostBinary: this.outpostBinary,
        onSpawn: (c) => {
          if (this.generation !== gen) {
            try {
              c.kill("SIGTERM");
            } catch {
              // ignore
            }
          }
        },
      }),
      runOutpostJson(["party", "list"], 8_000, {
        outpostBinary: this.outpostBinary,
        onSpawn: (c) => {
          if (this.generation !== gen) {
            try {
              c.kill("SIGTERM");
            } catch {
              // ignore
            }
          }
        },
      }),
    ]);

    if (this.generation !== gen) return false;

    let ownDeviceId = this.snapshot.ownDeviceId;
    let handle = this.snapshot.handle;
    if (statusRes.ok) {
      ownDeviceId = normalizeDeviceId(statusRes.data.device_id) ?? ownDeviceId;
      const h = sanitizeSingleLine(String(statusRes.data.handle ?? ""));
      if (h) handle = h.startsWith("@") ? h : `@${h}`;
    }

    if (!listRes.ok) {
      this.patch({
        status: "error",
        handle,
        ownDeviceId,
        lastError: listRes.error,
      });
      return false;
    }

    const daemonEpoch = typeof listRes.data.daemon_epoch === "number" ? listRes.data.daemon_epoch : 0;
    const parties = Array.isArray(listRes.data.parties) ? listRes.data.parties : [];
    const first = parties[0] as Record<string, unknown> | undefined;
    if (!first || typeof first.party_id !== "number") {
      this.patch({
        status: "no_party",
        partyId: undefined,
        handle,
        ownDeviceId,
        memberCount: 0,
        cursorSeq: 0,
        daemonEpoch,
        lastError: undefined,
      });
      return false;
    }

    const partyId = first.party_id;
    const nextSeq = typeof first.next_seq === "number" ? first.next_seq : 0;
    const memberCount = typeof first.member_count === "number" ? first.member_count : 0;
    const relayPolicy = typeof first.relay_policy === "string" ? sanitizeSingleLine(first.relay_policy) : undefined;
    const switchedParty = this.snapshot.partyId !== undefined && this.snapshot.partyId !== partyId;

    // Seed with latest ~12 messages via `party read`
    const seedAfter = Math.max(0, nextSeq - this.seedLimit);
    const readRes = await runOutpostJson(
      ["party", "read", String(partyId), "--after-seq", String(seedAfter), "--limit", String(this.seedLimit)],
      8_000,
      {
        outpostBinary: this.outpostBinary,
        onSpawn: (c) => {
          if (this.generation !== gen) {
            try {
              c.kill("SIGTERM");
            } catch {
              // ignore
            }
          }
        },
      },
    );

    if (this.generation !== gen) return false;

    let cursorSeq = nextSeq;
    let seedEpoch = daemonEpoch;
    const seeded: PartyChatMessage[] = [];
    if (readRes.ok) {
      if (typeof readRes.data.daemon_epoch === "number" && readRes.data.daemon_epoch > 0) {
        seedEpoch = readRes.data.daemon_epoch;
      }
      if (typeof readRes.data.next_seq === "number" && readRes.data.next_seq > cursorSeq) {
        cursorSeq = readRes.data.next_seq;
      }
      const events = Array.isArray(readRes.data.events) ? readRes.data.events : [];
      for (const raw of events) {
        const parsed = parsePartyEvent(raw, { ownDeviceId, ownHandle: handle, filterOwnEcho: true });
        if (parsed.seq > cursorSeq) cursorSeq = parsed.seq;
        if (parsed.message) seeded.push(parsed.message);
      }
    }

    const baseMessages = switchedParty ? [] : this.snapshot.messages;
    const { merged } = this.mergeMessages(baseMessages, seeded);

    this.patch({
      status: "live",
      partyId,
      handle,
      ownDeviceId,
      memberCount,
      relayPolicy,
      cursorSeq,
      daemonEpoch: seedEpoch,
      messages: merged,
      unreadCount: switchedParty ? 0 : this.snapshot.unreadCount,
      lastError: undefined,
      gapNotice: undefined,
    });
    return true;
  }

  private async runLoop(gen: number): Promise<void> {
    while (this.generation === gen) {
      if (this.snapshot.partyId === undefined) {
        const ok = await this.discoverAndSeed(gen);
        if (this.generation !== gen) break;
        if (!ok) {
          await this.sleepBackoff(gen);
          continue;
        }
      }

      const partyId = this.snapshot.partyId;
      if (partyId === undefined) continue;

      const waitArgs = [
        "party",
        "wait",
        String(partyId),
        "--after-seq",
        String(this.snapshot.cursorSeq),
        "--timeout-ms",
        String(this.waitTimeoutMs),
      ];
      if (this.snapshot.daemonEpoch > 0) {
        waitArgs.push("--cursor-epoch", String(this.snapshot.daemonEpoch));
      }

      const res = await runOutpostJson(waitArgs, this.waitTimeoutMs + 10_000, {
        outpostBinary: this.outpostBinary,
        onSpawn: (child) => {
          if (this.generation !== gen) {
            try {
              child.kill("SIGTERM");
            } catch {
              // ignore
            }
            return;
          }
          this.activeChild = child;
        },
      });
      this.activeChild = null;

      if (this.generation !== gen) break;

      if (!res.ok) {
        if (res.aborted) break;
        if (isPartyInactiveError(res.error)) {
          // Party switched or closed (e.g., code=4040): reset partyId and re-discover immediately after brief pause.
          this.patch({
            status: "reconnecting",
            partyId: undefined,
            cursorSeq: 0,
            daemonEpoch: 0,
            lastError: res.error,
          });
          await this.sleepBackoff(gen, Math.min(this.idleBackoffMs, 500));
          continue;
        }
        this.patch({
          status: "reconnecting",
          lastError: res.error,
        });
        await this.sleepBackoff(gen);
        continue;
      }

      const data = res.data;
      const newEpoch =
        typeof data.daemon_epoch === "number" && data.daemon_epoch > 0
          ? data.daemon_epoch
          : this.snapshot.daemonEpoch;
      const cursorReset = Boolean(data.cursor_reset);
      const gapPossible = Boolean(data.gap_possible);
      const events = Array.isArray(data.events) ? data.events : [];

      let nextCursor = cursorReset ? 0 : this.snapshot.cursorSeq;
      const incoming: PartyChatMessage[] = [];
      for (const raw of events) {
        const parsed = parsePartyEvent(raw, {
          ownDeviceId: this.snapshot.ownDeviceId,
          ownHandle: this.snapshot.handle,
          filterOwnEcho: true,
        });
        if (parsed.seq > nextCursor) nextCursor = parsed.seq;
        if (parsed.message) incoming.push(parsed.message);
      }
      if (typeof data.next_seq === "number" && data.next_seq > nextCursor) {
        nextCursor = data.next_seq;
      }

      const { merged, addedCount } = this.mergeMessages(this.snapshot.messages, incoming);
      const unreadCount = this.panelFocused ? 0 : this.snapshot.unreadCount + addedCount;

      this.patch({
        status: "live",
        daemonEpoch: newEpoch,
        cursorSeq: nextCursor,
        messages: merged,
        unreadCount,
        lastError: undefined,
        gapNotice:
          cursorReset || gapPossible
            ? "Cursor reset detected — some intermediate messages may have been missed."
            : this.snapshot.gapNotice,
      });
    }
  }
}
