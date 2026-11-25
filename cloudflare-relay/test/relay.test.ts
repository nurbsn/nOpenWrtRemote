import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { schnorr } from "@noble/curves/secp256k1";
import {
  bytesToHex,
  computeEventId,
  constantTimeEqualHex,
  hexToBytes,
  matchesFilters,
  type NostrEvent,
  sha256Hex,
  verifyNostrEvent,
} from "../src/nostr-verify.ts";

async function createSignedEvent(
  privHex: string,
  overrides: Partial<Omit<NostrEvent, "id" | "pubkey" | "sig">> = {}
): Promise<NostrEvent> {
  const privBytes = hexToBytes(privHex);
  const pubkey = bytesToHex(schnorr.getPublicKey(privBytes));
  const now = Math.floor(Date.now() / 1000);
  const base = {
    pubkey,
    created_at: overrides.created_at ?? now,
    kind: overrides.kind ?? 24135,
    tags: overrides.tags ?? [["p", "a".repeat(64)]],
    content: overrides.content ?? "v2_encrypted_payload_test",
  };
  const id = await computeEventId(base);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), privBytes));
  return { id, ...base, sig };
}

describe("nostr-verify", () => {
  const privHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

  it("verifies valid BIP-340 signed ephemeral event", async () => {
    const evt = await createSignedEvent(privHex);
    const res = await verifyNostrEvent(evt);
    assert.equal(res.ok, true);
  });

  it("rejects tampered event content", async () => {
    const evt = await createSignedEvent(privHex);
    evt.content = "tampered";
    const res = await verifyNostrEvent(evt);
    assert.equal(res.ok, false);
    assert.ok(res.reason.includes("hash"));
  });

  it("rejects non-ephemeral event kinds", async () => {
    const evt = await createSignedEvent(privHex, { kind: 1 });
    const res = await verifyNostrEvent(evt);
    assert.equal(res.ok, false);
    assert.ok(res.reason.includes("ephemeral"));
  });

  it("rejects stale timestamp outside 300s window", async () => {
    const now = 1_764_090_000;
    const evt = await createSignedEvent(privHex, { created_at: now - 400 });
    const res = await verifyNostrEvent(evt, now);
    assert.equal(res.ok, false);
    assert.ok(res.reason.includes("300s"));
  });

  it("rejects oversized content (> 64 KiB)", async () => {
    const evt = await createSignedEvent(privHex, { content: "x".repeat(65537) });
    const res = await verifyNostrEvent(evt);
    assert.equal(res.ok, false);
    assert.ok(res.reason.includes("64 KiB"));
  });

  it("matches #p tag and kind filters accurately", async () => {
    const targetPub = "b".repeat(64);
    const evt = await createSignedEvent(privHex, { kind: 24136, tags: [["p", targetPub]] });
    assert.equal(matchesFilters(evt, [{ kinds: [24136], "#p": [targetPub] }]), true);
    assert.equal(matchesFilters(evt, [{ kinds: [24135], "#p": [targetPub] }]), false);
    assert.equal(matchesFilters(evt, [{ kinds: [24136], "#p": ["c".repeat(64)] }]), false);
  });

  it("computes SHA-256 token hash and constant-time equality", async () => {
    const token = "ab".repeat(32);
    const hashA = await sha256Hex(token);
    const hashB = await sha256Hex(token);
    assert.equal(hashA.length, 64);
    assert.equal(constantTimeEqualHex(hashA, hashB), true);
    assert.equal(constantTimeEqualHex(hashA, "0".repeat(64)), false);
  });
});
