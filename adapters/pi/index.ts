/**
 * Pi Coding Agent extension for multiplayer.tech (`mp-outpost`).
 *
 * Uses `execFile` exclusively (zero shell interpolation), refuses outbound secret
 * material before spawning any subprocess, and wraps remote peer output in
 * per-response CSPRNG nonce fences matching `outpost-core/src/fence.rs`.
 */

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const SECRET_PATTERNS: ReadonlyArray<{ kind: string; re: RegExp }> = [
  { kind: "invite_token", re: /(?:^|[^a-zA-Z0-9])mpinv1_[A-Za-z0-9_-]{43,}/i },
  { kind: "party_invite", re: /(?:^|[^a-zA-Z0-9])mppi1_[0-9]+_[A-Za-z0-9_-]{43,}/i },
  { kind: "device_link_token", re: /(?:^|[^a-zA-Z0-9])mpdl1_[A-Za-z0-9_-]{43,}/i },
  { kind: "recovery_key", re: /mprk1_[A-Za-z0-9\-_]{32,}/i },
  { kind: "private_key_pem", re: /-----BEGIN [A-Z0-9 -]{0,48}(?:PRIVATE|RECOVERY|SECRET) KEY-----/i },
  { kind: "mpkey_backup", re: /"format"\s*:\s*"mpkey"|MPKEY1/i },
];

export function detectForbiddenSecret(text: string): string | null {
  for (const { kind, re } of SECRET_PATTERNS) {
    if (re.test(text)) {
      return kind;
    }
  }
  return null;
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
    description: "Show local mp-outpost status and active party summary",
    async handler(_args, ctx) {
      try {
        const status = await runOutpostJson(["party", "status"]);
        ctx.notify(JSON.stringify(status, null, 2), "info");
      } catch (err) {
        ctx.notify(`mp-outpost status failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("party", {
    description: "List active multiplayer.tech party and recent messages",
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
          events?: Array<{
            event_seq: number;
            kind: string;
            sender_handle?: string;
            sender_account_id?: number;
            body?: string;
          }>;
        };
        const lines = (poll.events ?? []).map((ev) => {
          const header = `[seq=${ev.event_seq} kind=${ev.kind} from=${ev.sender_handle ?? "system"}(${ev.sender_account_id ?? 0})]`;
          return ev.body ? `${header}\n${fencePeerText(ev.body)}` : header;
        });
        ctx.notify(lines.length ? lines.join("\n\n") : `Party #${partyId}: no events.`, "info");
      } catch (err) {
        ctx.notify(`mp-outpost party read failed: ${(err as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("party-say", {
    description: "Send an E2EE P2P chat message: /party-say <party_id> <message>",
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
