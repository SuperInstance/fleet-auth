/**
 * Fleet Auth — JWT utilities using Web Crypto API
 * HS256 signing and verification, sub-5ms target.
 */

import type { JWTPayload } from "./types";

const JWT_TTL_SECONDS = 15 * 60; // 15 minutes
const ALGORITHM = "HS256";

// ── helpers ──────────────────────────────────────────────────────────

function base64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(s: string): string {
  let padded = s.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4) padded += "=";
  return atob(padded);
}

function textToBuffer(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    textToBuffer(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

// ── public API ───────────────────────────────────────────────────────

/**
 * Sign a payload into a JWT string.
 */
export async function sign(
  payload: Omit<JWTPayload, "iat" | "exp">,
  secret: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const full: JWTPayload = { ...payload, iat: now, exp: now + JWT_TTL_SECONDS };

  const header = base64url(textToBuffer(JSON.stringify({ alg: ALGORITHM, typ: "JWT", kid: payload.kid })));
  const body = base64url(textToBuffer(JSON.stringify(full)));
  const signingInput = `${header}.${body}`;

  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, textToBuffer(signingInput));

  return `${signingInput}.${base64url(sig)}`;
}

/**
 * Verify a JWT against one or more secrets (supports rotation).
 * Returns the decoded payload if valid, or null.
 */
export async function verify(
  token: string,
  secrets: { current: string; previous?: string },
): Promise<JWTPayload | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerB64, bodyB64, sigB64] = parts;
  const signingInput = `${headerB64}.${bodyB64}`;

  // Decode header to get kid
  let kid: string | undefined;
  try {
    const headerJson = JSON.parse(base64urlDecode(headerB64));
    kid = headerJson.kid;
  } catch {
    return null;
  }

  // Decode signature
  const sigStr = base64urlDecode(sigB64);
  const sigBuf = new Uint8Array(sigStr.length);
  for (let i = 0; i < sigStr.length; i++) sigBuf[i] = sigStr.charCodeAt(i);

  // Try current secret first, then previous
  const candidates = [secrets.current, secrets.previous].filter(
    (s): s is string => !!s,
  );

  for (const secret of candidates) {
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      textToBuffer(signingInput),
      sigBuf,
    );
    if (valid) {
      try {
        const payload: JWTPayload = JSON.parse(base64urlDecode(bodyB64));
        if (payload.exp && Date.now() / 1000 > payload.exp) return null;
        return payload;
      } catch {
        return null;
      }
    }
  }

  return null;
}

/**
 * Decode a JWT payload without verifying the signature.
 * Useful for inspection / debugging only — never trust the result for auth.
 */
export function decode(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    return JSON.parse(base64urlDecode(parts[1]));
  } catch {
    return null;
  }
}

/**
 * Check if a JWT is close to expiry and should be renewed.
 * Returns true if the token expires within `withinSeconds` seconds.
 */
export function shouldRenew(token: string, withinSeconds = 120): boolean {
  const payload = decode(token);
  if (!payload) return true;
  return payload.exp - Date.now() / 1000 < withinSeconds;
}
