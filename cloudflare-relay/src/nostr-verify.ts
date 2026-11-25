import { schnorr } from "@noble/curves/secp256k1";

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface NostrFilter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  "#p"?: string[];
  "#e"?: string[];
  since?: number;
  until?: number;
  limit?: number;
}

export interface VerifyResult {
  ok: boolean;
  reason: string;
}

const HEX_64_RE = /^[a-f0-9]{64}$/;
const HEX_128_RE = /^[a-f0-9]{128}$/;
const MAX_CONTENT_BYTES = 65536;
const MAX_CLOCK_SKEW_SEC = 300;
const MAX_TAGS = 32;

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) {
      throw new Error("Invalid hex character");
    }
    out[i] = b;
  }
  return out;
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy);
  return bytesToHex(new Uint8Array(digest));
}

export async function computeEventId(evt: Pick<NostrEvent, "pubkey" | "created_at" | "kind" | "tags" | "content">): Promise<string> {
  const serialized = JSON.stringify([0, evt.pubkey, evt.created_at, evt.kind, evt.tags, evt.content]);
  return sha256Hex(serialized);
}

export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function verifyNostrEvent(
  evt: unknown,
  nowSec: number = Math.floor(Date.now() / 1000)
): Promise<VerifyResult> {
  if (!evt || typeof evt !== "object") {
    return { ok: false, reason: "invalid: event must be an object" };
  }

  const e = evt as Partial<NostrEvent>;
  if (typeof e.id !== "string" || !HEX_64_RE.test(e.id)) {
    return { ok: false, reason: "invalid: malformed event id" };
  }
  if (typeof e.pubkey !== "string" || !HEX_64_RE.test(e.pubkey)) {
    return { ok: false, reason: "invalid: malformed pubkey" };
  }
  if (typeof e.sig !== "string" || !HEX_128_RE.test(e.sig)) {
    return { ok: false, reason: "invalid: malformed signature" };
  }
  if (typeof e.created_at !== "number" || !Number.isInteger(e.created_at)) {
    return { ok: false, reason: "invalid: created_at must be an integer" };
  }
  if (Math.abs(nowSec - e.created_at) > MAX_CLOCK_SKEW_SEC) {
    return { ok: false, reason: "invalid: created_at outside 300s window" };
  }
  if (typeof e.kind !== "number" || !Number.isInteger(e.kind)) {
    return { ok: false, reason: "invalid: kind must be an integer" };
  }
  // Ephemeral-only blind relay (NIP-01 ephemeral range 20000..29999)
  if (e.kind < 20000 || e.kind > 29999) {
    return { ok: false, reason: "blocked: only ephemeral events (20000-29999) accepted" };
  }
  if (typeof e.content !== "string") {
    return { ok: false, reason: "invalid: content must be string" };
  }
  if (new TextEncoder().encode(e.content).byteLength > MAX_CONTENT_BYTES) {
    return { ok: false, reason: "invalid: content exceeds 64 KiB" };
  }
  if (!Array.isArray(e.tags) || e.tags.length > MAX_TAGS) {
    return { ok: false, reason: "invalid: malformed tags" };
  }
  for (const tag of e.tags) {
    if (!Array.isArray(tag) || tag.length > 16 || tag.some((item) => typeof item !== "string")) {
      return { ok: false, reason: "invalid: tag elements must be strings" };
    }
  }

  const expectedId = await computeEventId({
    pubkey: e.pubkey,
    created_at: e.created_at,
    kind: e.kind,
    tags: e.tags,
    content: e.content,
  });

  if (expectedId !== e.id) {
    return { ok: false, reason: "invalid: id does not match canonical hash" };
  }

  try {
    const valid = schnorr.verify(hexToBytes(e.sig), hexToBytes(e.id), hexToBytes(e.pubkey));
    if (!valid) {
      return { ok: false, reason: "invalid: schnorr signature verification failed" };
    }
  } catch {
    return { ok: false, reason: "invalid: schnorr verification threw" };
  }

  return { ok: true, reason: "" };
}

export function matchesFilter(evt: NostrEvent, filter: NostrFilter): boolean {
  if (!filter || typeof filter !== "object") return false;
  if (filter.ids && !filter.ids.includes(evt.id)) return false;
  if (filter.authors && !filter.authors.includes(evt.pubkey)) return false;
  if (filter.kinds && !filter.kinds.includes(evt.kind)) return false;
  if (typeof filter.since === "number" && evt.created_at < filter.since) return false;
  if (typeof filter.until === "number" && evt.created_at > filter.until) return false;

  if (filter["#p"] && filter["#p"].length > 0) {
    const hasP = evt.tags.some((t) => t.length >= 2 && t[0] === "p" && filter["#p"]!.includes(t[1]));
    if (!hasP) return false;
  }
  if (filter["#e"] && filter["#e"].length > 0) {
    const hasE = evt.tags.some((t) => t.length >= 2 && t[0] === "e" && filter["#e"]!.includes(t[1]));
    if (!hasE) return false;
  }
  return true;
}

export function matchesFilters(evt: NostrEvent, filters: NostrFilter[]): boolean {
  return filters.some((f) => matchesFilter(evt, f));
}
