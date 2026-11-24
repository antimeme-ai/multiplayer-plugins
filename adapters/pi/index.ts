/**
 * Pi Coding Agent extension for multiplayer.tech (`mp-outpost`).
 *
 * Uses `execFile` exclusively (zero shell interpolation), refuses outbound secret
 * material (including zero-width/fullwidth/hyphen obfuscation) and flag injection
 * before spawning any subprocess, sanitizes all peer metadata, and wraps every
 * remote peer event kind (including `chat_message`, `agent_card`, `control_notice`,
 * `bridge_envelope`, and `membership_changed`) in per-response CSPRNG nonce fences
 * matching `outpost-core/src/fence.rs`.
 */

import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const RECOVERY_KEY_DOMAIN_SEP = Buffer.from("mp-recovery-v1:", "utf8");
const MAX_RECOVERY_WINDOW_TOKENS = 16;
const MAX_RECOVERY_WINDOW_SPAN = 160;
const RECOVERY_SEPS = new Set([..."-_.,/:| \t\r\n\f\v"]);

const CROCKFORD_MAP: Readonly<Record<string, number>> = {
  "0": 0, O: 0, o: 0,
  "1": 1, I: 1, i: 1, L: 1, l: 1,
  "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
  A: 10, a: 10, B: 11, b: 11, C: 12, c: 12, D: 13, d: 13,
  E: 14, e: 14, F: 15, f: 15, G: 16, g: 16, H: 17, h: 17,
  J: 18, j: 18, K: 19, k: 19, M: 20, m: 20, N: 21, n: 21,
  P: 22, p: 22, Q: 23, q: 23, R: 24, r: 24, S: 25, s: 25,
  T: 26, t: 26, V: 27, v: 27, W: 28, w: 28, X: 29, x: 29,
  Y: 30, y: 30, Z: 31, z: 31,
};

const SECRET_PATTERNS: ReadonlyArray<{ kind: string; re: RegExp }> = [
  { kind: "invite_token", re: /(?:^|[^a-zA-Z0-9])mpinv1_[A-Za-z0-9_-]{43,}/i },
  { kind: "party_invite", re: /(?:^|[^a-zA-Z0-9])mppi1_[0-9]+_[A-Za-z0-9_-]{43,}/i },
  { kind: "device_link_token", re: /(?:^|[^a-zA-Z0-9])mpdl1_[A-Za-z0-9_-]{43,}/i },
  { kind: "private_key_pem", re: /-----BEGIN [A-Z0-9 -]{0,48}(?:PRIVATE|RECOVERY|SECRET) KEY-----/i },
  { kind: "recovery_file", re: /"format"\s*:\s*"mpkey"|MPKEY1|"kdf"\s*:\s*"argon2id"[\s\S]{0,256}"ciphertext"/i },
  {
    kind: "device_credential",
    re: /["']?(?:device_secret|device_cwt|root_key_hex|root_secret)["']?\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{16,}/i,
  },
];

function normalizeForSecretScan(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 0x00ad || (cp >= 0x200b && cp <= 0x200f) || cp === 0x2060 || cp === 0xfeff) {
      continue;
    }
    if (cp >= 0xff01 && cp <= 0xff5e) {
      out += String.fromCodePoint(cp - 0xff01 + 0x21);
    } else if ((cp >= 0x2010 && cp <= 0x2015) || cp === 0x2212) {
      out += "-";
    } else if (cp === 0x3000) {
      out += " ";
    } else {
      out += ch;
    }
  }
  return out;
}

function verifyUnprefixedRecoveryWindow(syms: number[]): boolean {
  if (syms.length !== 55 || (syms[54] & 0x07) !== 0) {
    return false;
  }
  if (new Set(syms).size <= 1) {
    return false;
  }
  const payload = Buffer.alloc(34);
  let outIdx = 0;
  let bitBuf = 0;
  let bitLen = 0;
  for (const val of syms) {
    bitBuf = (bitBuf << 5) | val;
    bitLen += 5;
    while (bitLen >= 8) {
      bitLen -= 8;
      payload[outIdx++] = (bitBuf >> bitLen) & 0xff;
    }
  }
  if (outIdx !== 34 || bitLen !== 3 || (bitBuf & 0x07) !== 0) {
    return false;
  }
  const digest = createHash("sha256")
    .update(RECOVERY_KEY_DOMAIN_SEP)
    .update(payload.subarray(0, 32))
    .digest();
  return payload[32] === digest[0] && payload[33] === digest[1];
}

function containsRecoveryKey(norm: string): boolean {
  const lower = norm.toLowerCase();
  let start = 0;
  while (true) {
    const idx = lower.indexOf("mprk1_", start);
    if (idx < 0) break;
    start = idx + 6;
    const win = norm.slice(start, start + 256);
    if (!win || win[0] === " " || win[0] === "\t") continue;
    const vals: number[] = [];
    for (const ch of win) {
      const val = CROCKFORD_MAP[ch];
      if (val !== undefined) {
        vals.push(val);
        if (vals.length >= 40 && new Set(vals.slice(0, 40)).size >= 2) {
          return true;
        }
        if (vals.length >= 55) break;
      } else if (RECOVERY_SEPS.has(ch)) {
        continue;
      } else {
        break;
      }
    }
  }

  let i = 0;
  while (i < norm.length) {
    if (CROCKFORD_MAP[norm[i]] === undefined || (i > 0 && CROCKFORD_MAP[norm[i - 1]] !== undefined)) {
      i += 1;
      continue;
    }
    const syms: Array<{ val: number; pos: number; startB: boolean; endB: boolean }> = [];
    let j = i;
    let atBoundary = true;
    while (j < norm.length) {
      const ch = norm[j];
      const val = CROCKFORD_MAP[ch];
      if (val !== undefined) {
        syms.push({ val, pos: j, startB: atBoundary, endB: false });
        atBoundary = false;
        j += 1;
      } else if (RECOVERY_SEPS.has(ch)) {
        if (syms.length > 0) syms[syms.length - 1].endB = true;
        atBoundary = true;
        j += 1;
      } else {
        break;
      }
    }
    if (syms.length > 0) syms[syms.length - 1].endB = true;
    if (syms.length >= 55) {
      for (let k = 0; k <= syms.length - 55; k++) {
        const first = syms[k];
        const last = syms[k + 54];
        if (!first.startB || !last.endB) continue;
        if (last.pos - first.pos > MAX_RECOVERY_WINDOW_SPAN) continue;
        let tokenStarts = 0;
        for (let m = k; m < k + 55; m++) {
          if (syms[m].startB) tokenStarts += 1;
        }
        if (tokenStarts > MAX_RECOVERY_WINDOW_TOKENS) continue;
        if (verifyUnprefixedRecoveryWindow(syms.slice(k, k + 55).map((s) => s.val))) {
          return true;
        }
      }
    }
    i = j + 1;
  }
  return false;
}

export function detectForbiddenSecret(text: string): string | null {
  const norm = normalizeForSecretScan(text);
  const candidates = norm === text ? [text] : [text, norm];
  for (const candidate of candidates) {
    for (const { kind, re } of SECRET_PATTERNS) {
      if (re.test(candidate)) {
        return kind;
      }
    }
  }
  if (containsRecoveryKey(norm)) {
    return "recovery_key";
  }
  return null;
}

export function validateSafePositionalArg(label: string, raw: string): { value?: string; error?: string } {
  const cleaned = raw.trim();
  if (!cleaned) {
    return { error: `Missing ${label}.` };
  }
  if (cleaned.startsWith("-")) {
    return { error: `Refused ${label}: value cannot start with '-'.` };
  }
  const secretKind = detectForbiddenSecret(cleaned);
  if (secretKind !== null) {
    return { error: `Refused ${label}: detected forbidden secret material (${secretKind}).` };
  }
  return { value: cleaned };
}

export function sanitizePeerText(raw: string): string {
  let out = "";
  for (const ch of raw) {
    const cp = ch.codePointAt(0) ?? 0;
    if (ch === "\n" || ch === "\t") {
      out += ch;
      continue;
    }
    if (
      cp <= 0x1f ||
      cp === 0x7f ||
      (cp >= 0x80 && cp <= 0x9f) ||
      cp === 0x2028 ||
      cp === 0x2029 ||
      cp === 0x061c ||
      cp === 0x200e ||
      cp === 0x200f ||
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069) ||
      (cp >= 0x200b && cp <= 0x200d) ||
      cp === 0xfeff ||
      (cp >= 0xe0000 && cp <= 0xe007f)
    ) {
      continue;
    }
    out += ch;
  }
  return out;
}

function breakAngleRuns(input: string): string {
  return input.replace(/<{3,}|>{3,}/g, (match) => match.split("").join(" "));
}

export function fencePeerText(raw: string): string {
  const nonce = randomBytes(8).toString("hex");
  const clean = sanitizePeerText(raw);
  const redacted = clean.replace(new RegExp(nonce, "gi"), "[redacted-nonce]");
  const safe = breakAngleRuns(redacted);
  return (
    `<<<BLACKBIRD_UNTRUSTED_PEER_DATA_BEGIN_${nonce}>>>\n` +
    `${safe}\n` +
    `<<<BLACKBIRD_UNTRUSTED_PEER_DATA_END_${nonce}>>>`
  );
}

export interface OutpostPartyEvent {
  event_seq?: number;
  seq?: number;
  kind: string;
  sender_handle?: string;
  from?: string;
  sender_account_id?: number;
  room_scope?: string;
  body?: unknown;
  card?: unknown;
  text?: string;
  payload_b64?: string;
  summary?: string;
}

export function formatPartyEvent(ev: OutpostPartyEvent): string {
  const seq = Number.isSafeInteger(ev.event_seq)
    ? ev.event_seq
    : Number.isSafeInteger(ev.seq)
      ? ev.seq
      : 0;
  const kind = sanitizePeerText(String(ev.kind ?? "unknown"));
  const handle = sanitizePeerText(String(ev.sender_handle ?? ev.from ?? "system"));
  const accountId = Number.isSafeInteger(ev.sender_account_id) ? ev.sender_account_id : 0;
  const header = `[seq=${seq} kind=${kind} from=${handle}(${accountId})]`;

  let payloadRaw: string;
  if (ev.kind === "chat_message" || ev.kind === "chat") {
    payloadRaw = String(ev.body ?? "");
  } else if (ev.kind === "agent_card") {
    const scope = sanitizePeerText(String(ev.room_scope ?? ""));
    const rawCard =
      ev.body !== undefined && ev.body !== null
        ? typeof ev.body === "string"
          ? ev.body
          : JSON.stringify(ev.body)
        : ev.card !== undefined && ev.card !== null
          ? typeof ev.card === "string"
            ? ev.card
            : JSON.stringify(ev.card)
          : JSON.stringify(ev);
    payloadRaw = scope ? `scope: ${scope}\n${rawCard}` : rawCard;
  } else if (ev.kind === "control_notice") {
    payloadRaw = String(ev.text ?? "");
  } else if (ev.kind === "bridge_envelope") {
    const scope = sanitizePeerText(String(ev.room_scope ?? ""));
    payloadRaw = `scope: ${scope}\npayload_b64: ${String(ev.payload_b64 ?? "")}`;
  } else if (ev.kind === "membership_changed" || ev.kind === "system") {
    payloadRaw = String(ev.summary ?? ev.body ?? "");
  } else {
    payloadRaw = JSON.stringify(ev);
  }

  return `${header}\n${fencePeerText(payloadRaw)}`;
}

async function runOutpostJson(args: string[], timeoutMs = 15_000): Promise<unknown> {
  const { stdout } = await execFileAsync("mp-outpost", ["--json", ...args], {
    timeout: timeoutMs,
    maxBuffer: 2 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}

export interface PiCommandContext {
  notify: (message: string, level?: "info" | "warning" | "error") => void;
}

export interface PiExtensionAPI {
  registerCommand: (
    name: string,
    spec: {
      description: string;
      handler: (args: string, ctx: PiCommandContext) => Promise<void>;
    },
  ) => void;
  on?: (
    event: string,
    handler: (ctx: PiCommandContext) => Promise<void> | void,
  ) => void;
}

export default function multiplayerExtension(pi: PiExtensionAPI): void {
  pi.on?.("session_start", async (ctx) => {
    try {
      const status = (await runOutpostJson(["party", "status"], 5_000)) as {
        active_party_id?: number;
      };
      if (status.active_party_id) {
        ctx.notify(
          `multiplayer.tech active party #${status.active_party_id} (use /party-status or /party)`,
          "info",
        );
      }
    } catch {
      // mp-outpost daemon not running or binary not installed yet; stay quiet.
    }
  });

  pi.registerCommand("party-status", {
    description: "Show local mp-outpost status and active mp2 party summary",
    async handler(_args, ctx) {
      try {
        const status = await runOutpostJson(["party", "status"]);
        ctx.notify(JSON.stringify(status, null, 2), "info");
      } catch (err) {
        ctx.notify(`mp-outpost status failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("party-invite", {
    description: "Create/reuse an mp2 party room and optionally ring @handle: /party-invite [@handle]",
    async handler(rawArgs, ctx) {
      const args = ["invite"];
      if (rawArgs.trim()) {
        const checked = validateSafePositionalArg("handle", rawArgs);
        if (checked.error) {
          ctx.notify(checked.error, "error");
          return;
        }
        args.push(checked.value!);
      }
      try {
        const resp = await runOutpostJson(args);
        ctx.notify(JSON.stringify(resp, null, 2), "info");
      } catch (err) {
        ctx.notify(`mp-outpost invite failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("party-join", {
    description: "Join by @handle, room code, share URL, or blank to accept latest invite: /party-join [target]",
    async handler(rawArgs, ctx) {
      const args = ["join"];
      if (rawArgs.trim()) {
        const checked = validateSafePositionalArg("target", rawArgs);
        if (checked.error) {
          ctx.notify(checked.error, "error");
          return;
        }
        args.push(checked.value!);
      }
      try {
        const resp = await runOutpostJson(args);
        ctx.notify(JSON.stringify(resp, null, 2), "info");
      } catch (err) {
        ctx.notify(`mp-outpost join failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("party-leave", {
    description: "Leave the active multiplayer.tech party room: /party-leave [party_id]",
    async handler(rawArgs, ctx) {
      const args = ["leave"];
      if (rawArgs.trim()) {
        const partyId = Number(rawArgs.trim());
        if (!Number.isSafeInteger(partyId) || partyId <= 0) {
          ctx.notify("Usage: /party-leave [party_id]", "warning");
          return;
        }
        args.push(String(partyId));
      }
      try {
        const resp = await runOutpostJson(args);
        ctx.notify(JSON.stringify(resp, null, 2), "info");
      } catch (err) {
        ctx.notify(`mp-outpost leave failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("friend-add", {
    description: "Send or accept a friend request by handle: /friend-add @handle",
    async handler(rawArgs, ctx) {
      const checked = validateSafePositionalArg("handle", rawArgs);
      if (checked.error) {
        ctx.notify(checked.error, "error");
        return;
      }
      try {
        const resp = await runOutpostJson(["add", checked.value!]);
        ctx.notify(JSON.stringify(resp, null, 2), "info");
      } catch (err) {
        ctx.notify(`mp-outpost add failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("friends", {
    description: "List multiplayer.tech friends, live presence, and pending invites",
    async handler(_args, ctx) {
      try {
        const resp = await runOutpostJson(["friends"]).catch(async (err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          if (msg.toLowerCase().includes("unknown subcommand")) {
            return await runOutpostJson(["friend", "list"]);
          }
          throw err;
        });
        ctx.notify(JSON.stringify(resp, null, 2), "info");
      } catch (err) {
        ctx.notify(`mp-outpost friends failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("party", {
    description: "List active multiplayer.tech party and recent fenced messages",
    async handler(rawArgs, ctx) {
      try {
        const list = (await runOutpostJson(["party", "list"])) as {
          parties?: Array<{ party_id: number; member_count: number; next_seq: number }>;
        };
        const parties = list.parties ?? [];
        if (parties.length === 0) {
          ctx.notify("No active multiplayer.tech party.", "info");
          return;
        }
        const partyId = rawArgs.trim() ? Number(rawArgs.trim()) : parties[0].party_id;
        if (!Number.isSafeInteger(partyId) || partyId <= 0) {
          ctx.notify("Usage: /party [party_id]", "warning");
          return;
        }
        const poll = (await runOutpostJson([
          "party",
          "read",
          String(partyId),
          "--after-seq",
          "0",
          "--limit",
          "20",
        ])) as {
          events?: OutpostPartyEvent[];
        };
        const lines = (poll.events ?? []).map((ev) => formatPartyEvent(ev));
        ctx.notify(lines.length ? lines.join("\n\n") : `Party #${partyId}: no events.`, "info");
      } catch (err) {
        ctx.notify(`mp-outpost party read failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("party-say", {
    description: "Send a chat message to the active mp2 party: /party-say <party_id> <message>",
    async handler(rawArgs, ctx) {
      const trimmed = rawArgs.trim();
      const splitIdx = trimmed.search(/\s+/);
      if (splitIdx <= 0) {
        ctx.notify("Usage: /party-say <party_id> <message>", "warning");
        return;
      }
      const partyId = Number(trimmed.slice(0, splitIdx));
      const body = trimmed.slice(splitIdx).trim();
      if (!Number.isSafeInteger(partyId) || partyId <= 0 || !body) {
        ctx.notify("Usage: /party-say <party_id> <message>", "warning");
        return;
      }
      if (body === "--scope" || body === "--to-device") {
        ctx.notify("Refused ambiguous flag-only message body.", "error");
        return;
      }
      const secretKind = detectForbiddenSecret(body);
      if (secretKind !== null) {
        ctx.notify(
          `Refused outbound message: detected forbidden secret material (${secretKind}).`,
          "error",
        );
        return;
      }
      try {
        const resp = await runOutpostJson([
          "party",
          "say",
          String(partyId),
          "--scope",
          "party/main",
          body,
        ]);
        ctx.notify(`Sent to party #${partyId}: ${JSON.stringify(resp)}`, "info");
      } catch (err) {
        ctx.notify(`mp-outpost party say failed: ${(err as Error).message}`, "error");
      }
    },
  });
}
