/**
 * Provenance fencing, #fragment URL redaction, strict base64 decoding,
 * and pre-exec secret refusal matching mp-outpost v0.7.0 (`outpost-core/src/fence.rs`).
 */

import { createHash, randomBytes } from "node:crypto";

const RECOVERY_KEY_DOMAIN_SEP = Buffer.from("mp-recovery-v1:", "utf8");
const MAX_RECOVERY_WINDOW_TOKENS = 16;
const MAX_RECOVERY_WINDOW_SPAN = 160;
const MAX_SCAN_DEPTH = 8;
const RECOVERY_SEPS = new Set([..."-_.,/:| \t\r\n\f\v"]);

const CREDENTIAL_KEYS = new Set([
  "device_secret",
  "device_cwt",
  "root_key_hex",
  "root_secret",
  "private_key",
  "recovery_key",
]);

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
  { kind: "invite_token", re: /(?:^|[^a-zA-Z0-9])(?:mpcs1_|mpguest1_)[A-Za-z0-9_-]{16,}/i },
  { kind: "device_link_token", re: /(?:^|[^a-zA-Z0-9])mpdl1_[A-Za-z0-9_-]{43,}/i },
  {
    kind: "private_key_pem",
    re: /-----(?:BEGIN|END) [A-Z0-9 -]{0,48}(?:PRIVATE|RECOVERY|SECRET) KEY-----/i,
  },
  {
    kind: "recovery_file",
    re: /"format"\s*:\s*"mpkey"|MPKEY1|TVBLRVkxAA|"kdf"\s*:\s*"argon2id"[\s\S]{0,256}"ciphertext"/i,
  },
  {
    kind: "device_credential",
    re: /["']?(?:device_secret|device_cwt|root_key_hex|root_secret)["']?\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{16,}/i,
  },
];

const URL_FRAGMENT_RE =
  /((?:https?:\/\/)?(?:(?:www\.)?(?:clank\.party|multiplayer\.tech|mp\.gg)\/[^\s#"']+?|[^\s#"']+\/(?:p\/)?i\/[A-Za-z0-9_-]+))#[A-Za-z0-9_-]+/gi;

const INVITE_FRAGMENT_TEST_RE =
  /(?:https?:\/\/)?(?:(?:www\.)?(?:clank\.party|multiplayer\.tech|mp\.gg)\/[^\s#"']+|[^\s#"']+\/(?:p\/)?i\/[A-Za-z0-9_-]+)#[^\s"']{8,}/i;

const STRICT_B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

export function redactUrlFragments(text: string): string {
  return text.replace(URL_FRAGMENT_RE, "$1#[REDACTED]");
}

export function decodeStrictBase64(raw: string): Buffer {
  const compact = raw.replace(/\s+/g, "");
  if (!compact || compact.length % 4 !== 0 || !STRICT_B64_RE.test(compact)) {
    throw new Error("payload_b64 is not valid canonical base64");
  }
  const buf = Buffer.from(compact, "base64");
  if (buf.toString("base64") !== compact) {
    throw new Error("payload_b64 contains non-canonical base64 padding or bits");
  }
  return buf;
}

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
  if (syms.length !== 55 || (syms[54] & 0x07) !== 0 || new Set(syms).size <= 1) {
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

export function detectForbiddenSecret(
  text: string,
  options?: { allowInviteFragment?: boolean },
): string | null {
  const norm = normalizeForSecretScan(text);
  const candidates = norm === text ? [text] : [text, norm];
  for (const candidate of candidates) {
    for (const { kind, re } of SECRET_PATTERNS) {
      if (re.test(candidate)) {
        return kind;
      }
    }
    if (!options?.allowInviteFragment && INVITE_FRAGMENT_TEST_RE.test(candidate)) {
      return "invite_url_fragment";
    }
  }
  if (containsRecoveryKey(norm)) {
    return "recovery_key";
  }
  return null;
}

export function detectForbiddenSecretInBytes(buf: Buffer): string | null {
  if (buf.subarray(0, 7).equals(Buffer.from("MPKEY1\0", "latin1"))) {
    return "recovery_file";
  }
  return detectForbiddenSecret(buf.toString("utf8"), { allowInviteFragment: false });
}

export function scanValueForSecrets(
  value: unknown,
  options?: { toolName?: string; keyName?: string; depth?: number },
): string | null {
  const depth = options?.depth ?? 0;
  if (depth > MAX_SCAN_DEPTH) return "nesting_depth_exceeded";
  if (value === null || value === undefined) return null;

  const toolName = options?.toolName ?? "";
  const keyName = options?.keyName ?? "";
  const allowInviteFragment = toolName === "party_join" && keyName === "target";

  if (typeof value === "string") {
    if (CREDENTIAL_KEYS.has(keyName.toLowerCase()) && value.trim().length >= 16) {
      return "device_credential";
    }
    const hit = detectForbiddenSecret(value, { allowInviteFragment });
    if (hit !== null) return hit;
    if (keyName === "payload_b64") {
      try {
        return detectForbiddenSecretInBytes(decodeStrictBase64(value));
      } catch {
        return null;
      }
    }
    return null;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = scanValueForSecrets(item, { toolName, keyName, depth: depth + 1 });
      if (hit !== null) return hit;
    }
    return null;
  }
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const kHit = detectForbiddenSecret(k, { allowInviteFragment: false });
      if (kHit !== null) return kHit;
      const vHit = scanValueForSecrets(v, { toolName, keyName: k, depth: depth + 1 });
      if (vHit !== null) return vHit;
    }
  }
  return null;
}

export function validateSafePositionalArg(
  label: string,
  raw: string,
  options?: { allowInviteFragment?: boolean },
): { value?: string; error?: string } {
  const cleaned = raw.trim();
  if (!cleaned) {
    return { error: `Missing ${label}.` };
  }
  if (cleaned.startsWith("-")) {
    return { error: `Refused ${label}: value cannot start with '-'.` };
  }
  const secretKind = detectForbiddenSecret(cleaned, options);
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

export function sanitizeSingleLine(raw: string): string {
  return sanitizePeerText(raw).replace(/[\n\t]+/g, " ").replace(/\s+/g, " ").trim();
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
  sender_device_id?: number;
  sender_client?: string;
  client?: string;
  is_browser?: boolean;
  is_historical_catchup?: boolean;
  room_scope?: string;
  body?: unknown;
  card?: unknown;
  text?: string;
  payload_b64?: string;
  summary?: string;
}

export function isBrowserOriginEvent(ev: OutpostPartyEvent): boolean {
  if (ev.is_browser === true) return true;
  const client = String(ev.sender_client ?? ev.client ?? "").trim().toLowerCase();
  return client === "web" || client === "browser";
}

function tryDecodeAgentCardFromB64(b64: string): string | null {
  if (!b64) return null;
  try {
    const parsed = JSON.parse(decodeStrictBase64(b64).toString("utf8"));
    if (
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      typeof (parsed as Record<string, unknown>).title === "string" &&
      typeof (parsed as Record<string, unknown>).summary === "string"
    ) {
      return JSON.stringify(parsed);
    }
  } catch {
    // Opaque non-JSON or non-card envelope.
  }
  return null;
}

export function formatPartyEvent(ev: OutpostPartyEvent): string {
  const seq = Number.isSafeInteger(ev.event_seq)
    ? ev.event_seq
    : Number.isSafeInteger(ev.seq)
      ? ev.seq
      : 0;
  const kind = sanitizeSingleLine(String(ev.kind ?? "unknown"));
  const handle = sanitizeSingleLine(String(ev.sender_handle ?? ev.from ?? "system"));
  const accountId = Number.isSafeInteger(ev.sender_account_id) ? ev.sender_account_id : 0;
  const deviceId = Number.isSafeInteger(ev.sender_device_id) && (ev.sender_device_id as number) > 0
    ? ev.sender_device_id
    : 0;
  const deviceTag = deviceId > 0 ? ` device=${deviceId}` : "";
  const browserTag = isBrowserOriginEvent(ev) ? " origin=browser" : "";
  const catchupTag =
    ev.is_historical_catchup === true
      ? " historical_catchup=true"
      : ev.is_historical_catchup === false
        ? " historical_catchup=false"
        : " replay_provenance=unknown";
  const header = `[seq=${seq} kind=${kind} from=${handle}(${accountId})${deviceTag}${browserTag}${catchupTag}]`;

  let payloadRaw: string;
  if (ev.kind === "chat_message" || ev.kind === "chat") {
    payloadRaw = String(ev.body ?? "");
  } else if (ev.kind === "agent_card") {
    const scope = sanitizeSingleLine(String(ev.room_scope ?? ""));
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
    const scope = sanitizeSingleLine(String(ev.room_scope ?? ""));
    const rawB64 = String(ev.payload_b64 ?? "");
    const decodedCard = tryDecodeAgentCardFromB64(rawB64);
    if (decodedCard !== null) {
      payloadRaw = scope ? `scope: ${scope}\nagent_card: ${decodedCard}` : `agent_card: ${decodedCard}`;
    } else {
      payloadRaw = `scope: ${scope}\npayload_b64: ${rawB64}`;
    }
  } else if (ev.kind === "membership_changed" || ev.kind === "system") {
    payloadRaw = String(ev.summary ?? ev.body ?? "");
  } else {
    payloadRaw = JSON.stringify(ev);
  }

  return `${header}\n${fencePeerText(payloadRaw)}`;
}

export interface OutpostInboxDrop {
  drop_id?: number;
  sender_handle?: string;
  sender_account_id?: number;
  sender_device_id?: number;
  safety_number?: string;
  created_at_ms?: number;
  expires_at_ms?: number;
  body?: string;
}

export function formatInboxDrop(drop: OutpostInboxDrop): string {
  const dropId = Number.isSafeInteger(drop.drop_id) ? drop.drop_id : 0;
  const handle = sanitizeSingleLine(String(drop.sender_handle ?? "unknown"));
  const accountId = Number.isSafeInteger(drop.sender_account_id) ? drop.sender_account_id : 0;
  const deviceTag =
    Number.isSafeInteger(drop.sender_device_id) && (drop.sender_device_id as number) > 0
      ? ` device=${drop.sender_device_id}`
      : "";
  return `[drop_id=${dropId} from=${handle}(${accountId})${deviceTag} untrusted_remote=true]\n${fencePeerText(String(drop.body ?? ""))}`;
}
