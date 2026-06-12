/**
 * Fleet Auth — API key management
 * Keys use format: fleet_sk_<key_id>.<secret>
 * Stored as SHA-256 hash in D1; KV mirror for hot-path lookups.
 */

import type { ApiKeyRecord, KeyRecord, FleetAuthEnv } from "./types";

const KEY_ID_LENGTH = 8;
const SECRET_BYTES = 32;
const KEY_PREFIX = "fleet_sk_";

// ── helpers ──────────────────────────────────────────────────────────

/** Base32 alphabet (lowercase, no padding) for key IDs */
const BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567";

function randomBase32(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += BASE32_CHARS[bytes[i] % BASE32_CHARS.length];
  }
  return out;
}

function randomBase64url(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function kvKey(keyId: string): string {
  return `auth:key:${keyId}`;
}

function recordToKvValue(rec: ApiKeyRecord): KeyRecord {
  return {
    h: rec.key_hash,
    s: JSON.parse(rec.scopes),
    st: rec.status,
    exp: rec.expires_at,
    o: rec.owner,
  };
}

// ── public API ───────────────────────────────────────────────────────

export interface CreateKeyResult {
  /** The full API key (only shown once) */
  key: string;
  /** The public key ID */
  keyId: string;
}

/**
 * Generate a new API key, store its hash in D1, and mirror to KV.
 * Returns the full key string — this is the only time it's available.
 */
export async function generateApiKey(
  env: FleetAuthEnv,
  options: {
    name: string;
    owner: string;
    scopes: string[];
    expiresIn?: number; // ms from now, undefined = no expiry
  },
): Promise<CreateKeyResult> {
  const keyId = randomBase32(KEY_ID_LENGTH);
  const secret = randomBase64url(SECRET_BYTES);
  const fullKey = `${KEY_PREFIX}${keyId}.${secret}`;

  const hash = await sha256Hex(secret);
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO api_keys (key_id, key_hash, name, owner, scopes, status, created_at, expires_at, last_used_at, rotated_from)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL)`,
  )
    .bind(
      keyId,
      hash,
      options.name,
      options.owner,
      JSON.stringify(options.scopes),
      now,
      options.expiresIn ? now + options.expiresIn : null,
    )
    .run();

  // Mirror to KV (best-effort)
  if (env.AUTH_KV) {
    const rec: KeyRecord = {
      h: hash,
      s: options.scopes,
      st: "active",
      exp: options.expiresIn ? now + options.expiresIn : null,
      o: options.owner,
    };
    await env.AUTH_KV.put(kvKey(keyId), JSON.stringify(rec));
  }

  return { key: fullKey, keyId };
}

/**
 * Validate an API key string.
 * Tries KV first (hot path), falls back to D1.
 * Returns the key ID and scopes if valid, or null.
 */
export async function validateApiKey(
  token: string,
  env: FleetAuthEnv,
): Promise<{ keyId: string; scopes: string[]; owner: string } | null> {
  const match = token.match(/^fleet_sk_([a-z2-7]{8})\.(.+)$/);
  if (!match) return null;

  const keyId = match[1];
  const secret = match[2];
  const hash = await sha256Hex(secret);

  // Try KV first (1–3ms warm)
  if (env.AUTH_KV) {
    const kvRec = await env.AUTH_KV.get<KeyRecord>(kvKey(keyId), "json");
    if (kvRec) {
      if (kvRec.st !== "active" && kvRec.st !== "rotating") return null;
      if (kvRec.exp && Date.now() > kvRec.exp) return null;
      if (kvRec.h !== hash) return null;
      return { keyId, scopes: kvRec.s, owner: kvRec.o };
    }
  }

  // Fallback to D1
  const dbRec = await env.DB.prepare(
    `SELECT key_id, key_hash, scopes, status, expires_at, owner FROM api_keys WHERE key_id = ?`,
  )
    .bind(keyId)
    .first<ApiKeyRecord>();

  if (!dbRec) return null;
  if (dbRec.status !== "active" && dbRec.status !== "rotating") return null;
  if (dbRec.expires_at && Date.now() > dbRec.expires_at) return null;
  if (dbRec.key_hash !== hash) return null;

  return {
    keyId,
    scopes: JSON.parse(dbRec.scopes),
    owner: dbRec.owner,
  };
}

/**
 * Rotate an API key — creates a new key and marks the old one as rotating.
 * During the grace period (specified by expiresIn), both keys are valid.
 */
export async function rotateApiKey(
  env: FleetAuthEnv,
  oldKeyId: string,
  options: {
    gracePeriodMs: number; // e.g. 7 * 24 * 60 * 60 * 1000 for 7 days
  },
): Promise<CreateKeyResult | null> {
  // Fetch old key record
  const oldRec = await env.DB.prepare(
    `SELECT * FROM api_keys WHERE key_id = ? AND status = 'active'`,
  )
    .bind(oldKeyId)
    .first<ApiKeyRecord>();

  if (!oldRec) return null;

  const now = Date.now();
  const scopes = JSON.parse(oldRec.scopes);

  // Create new key
  const result = await generateApiKey(env, {
    name: oldRec.name,
    owner: oldRec.owner,
    scopes,
  });

  // Mark old key as rotating with grace period
  await env.DB.prepare(
    `UPDATE api_keys SET status = 'rotating', expires_at = ?, rotated_from = ? WHERE key_id = ?`,
  )
    .bind(now + options.gracePeriodMs, oldKeyId, oldKeyId)
    .run();

  // Update KV mirror for old key
  if (env.AUTH_KV) {
    const kvRec: KeyRecord = {
      h: oldRec.key_hash,
      s: scopes,
      st: "rotating",
      exp: now + options.gracePeriodMs,
      o: oldRec.owner,
    };
    await env.AUTH_KV.put(kvKey(oldKeyId), JSON.stringify(kvRec));
  }

  // Update new key record with rotated_from
  await env.DB.prepare(
    `UPDATE api_keys SET rotated_from = ? WHERE key_id = ?`,
  )
    .bind(oldKeyId, result.keyId)
    .run();

  return result;
}

/**
 * Immediately revoke an API key.
 * Removes from KV and marks as revoked in D1.
 */
export async function revokeApiKey(
  env: FleetAuthEnv,
  keyId: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE api_keys SET status = 'revoked' WHERE key_id = ?`,
  )
    .bind(keyId)
    .run();

  // Delete KV mirror immediately
  if (env.AUTH_KV) {
    await env.AUTH_KV.delete(kvKey(keyId));
  }

  return result.meta.changes > 0;
}
