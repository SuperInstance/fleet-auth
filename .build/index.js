"use strict";
(() => {
  var __defProp = Object.defineProperty;
  var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

  // src/keys.ts
  var KEY_ID_LENGTH = 8;
  var SECRET_BYTES = 32;
  var KEY_PREFIX = "fleet_sk_";
  var BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567";
  function randomBase32(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    let out = "";
    for (let i = 0; i < length; i++) {
      out += BASE32_CHARS[bytes[i] % BASE32_CHARS.length];
    }
    return out;
  }
  __name(randomBase32, "randomBase32");
  function randomBase64url(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  __name(randomBase64url, "randomBase64url");
  async function sha256Hex(input) {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(input)
    );
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  __name(sha256Hex, "sha256Hex");
  function kvKey(keyId) {
    return `auth:key:${keyId}`;
  }
  __name(kvKey, "kvKey");
  async function generateApiKey(env, options) {
    const keyId = randomBase32(KEY_ID_LENGTH);
    const secret = randomBase64url(SECRET_BYTES);
    const fullKey = `${KEY_PREFIX}${keyId}.${secret}`;
    const hash = await sha256Hex(secret);
    const now = Date.now();
    await env.DB.prepare(
      `INSERT INTO api_keys (key_id, key_hash, name, owner, scopes, status, created_at, expires_at, last_used_at, rotated_from)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL)`
    ).bind(
      keyId,
      hash,
      options.name,
      options.owner,
      JSON.stringify(options.scopes),
      now,
      options.expiresIn ? now + options.expiresIn : null
    ).run();
    if (env.AUTH_KV) {
      const rec = {
        h: hash,
        s: options.scopes,
        st: "active",
        exp: options.expiresIn ? now + options.expiresIn : null,
        o: options.owner
      };
      await env.AUTH_KV.put(kvKey(keyId), JSON.stringify(rec));
    }
    return { key: fullKey, keyId };
  }
  __name(generateApiKey, "generateApiKey");
  async function validateApiKey(token, env) {
    const match = token.match(/^fleet_sk_([a-z2-7]{8})\.(.+)$/);
    if (!match) return null;
    const keyId = match[1];
    const secret = match[2];
    const hash = await sha256Hex(secret);
    if (env.AUTH_KV) {
      const kvRec = await env.AUTH_KV.get(kvKey(keyId), "json");
      if (kvRec) {
        if (kvRec.st !== "active" && kvRec.st !== "rotating") return null;
        if (kvRec.exp && Date.now() > kvRec.exp) return null;
        if (kvRec.h !== hash) return null;
        return { keyId, scopes: kvRec.s, owner: kvRec.o };
      }
    }
    const dbRec = await env.DB.prepare(
      `SELECT key_id, key_hash, scopes, status, expires_at, owner FROM api_keys WHERE key_id = ?`
    ).bind(keyId).first();
    if (!dbRec) return null;
    if (dbRec.status !== "active" && dbRec.status !== "rotating") return null;
    if (dbRec.expires_at && Date.now() > dbRec.expires_at) return null;
    if (dbRec.key_hash !== hash) return null;
    return {
      keyId,
      scopes: JSON.parse(dbRec.scopes),
      owner: dbRec.owner
    };
  }
  __name(validateApiKey, "validateApiKey");
  async function rotateApiKey(env, oldKeyId, options) {
    const oldRec = await env.DB.prepare(
      `SELECT * FROM api_keys WHERE key_id = ? AND status = 'active'`
    ).bind(oldKeyId).first();
    if (!oldRec) return null;
    const now = Date.now();
    const scopes = JSON.parse(oldRec.scopes);
    const result = await generateApiKey(env, {
      name: oldRec.name,
      owner: oldRec.owner,
      scopes
    });
    await env.DB.prepare(
      `UPDATE api_keys SET status = 'rotating', expires_at = ?, rotated_from = ? WHERE key_id = ?`
    ).bind(now + options.gracePeriodMs, oldKeyId, oldKeyId).run();
    if (env.AUTH_KV) {
      const kvRec = {
        h: oldRec.key_hash,
        s: scopes,
        st: "rotating",
        exp: now + options.gracePeriodMs,
        o: oldRec.owner
      };
      await env.AUTH_KV.put(kvKey(oldKeyId), JSON.stringify(kvRec));
    }
    await env.DB.prepare(
      `UPDATE api_keys SET rotated_from = ? WHERE key_id = ?`
    ).bind(oldKeyId, result.keyId).run();
    return result;
  }
  __name(rotateApiKey, "rotateApiKey");
  async function revokeApiKey(env, keyId) {
    const result = await env.DB.prepare(
      `UPDATE api_keys SET status = 'revoked' WHERE key_id = ?`
    ).bind(keyId).run();
    if (env.AUTH_KV) {
      await env.AUTH_KV.delete(kvKey(keyId));
    }
    return result.meta.changes > 0;
  }
  __name(revokeApiKey, "revokeApiKey");

  // src/jwt.ts
  var JWT_TTL_SECONDS = 15 * 60;
  var ALGORITHM = "HS256";
  function base64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  __name(base64url, "base64url");
  function base64urlDecode(s) {
    let padded = s.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    return atob(padded);
  }
  __name(base64urlDecode, "base64urlDecode");
  function textToBuffer(text) {
    return new TextEncoder().encode(text);
  }
  __name(textToBuffer, "textToBuffer");
  async function hmacKey(secret) {
    return crypto.subtle.importKey(
      "raw",
      textToBuffer(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  }
  __name(hmacKey, "hmacKey");
  async function sign(payload, secret) {
    const now = Math.floor(Date.now() / 1e3);
    const full = { ...payload, iat: now, exp: now + JWT_TTL_SECONDS };
    const header = base64url(textToBuffer(JSON.stringify({ alg: ALGORITHM, typ: "JWT", kid: payload.kid })));
    const body = base64url(textToBuffer(JSON.stringify(full)));
    const signingInput = `${header}.${body}`;
    const key = await hmacKey(secret);
    const sig = await crypto.subtle.sign("HMAC", key, textToBuffer(signingInput));
    return `${signingInput}.${base64url(sig)}`;
  }
  __name(sign, "sign");
  async function verify(token, secrets) {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [headerB64, bodyB64, sigB64] = parts;
    const signingInput = `${headerB64}.${bodyB64}`;
    let kid;
    try {
      const headerJson = JSON.parse(base64urlDecode(headerB64));
      kid = headerJson.kid;
    } catch {
      return null;
    }
    const sigStr = base64urlDecode(sigB64);
    const sigBuf = new Uint8Array(sigStr.length);
    for (let i = 0; i < sigStr.length; i++) sigBuf[i] = sigStr.charCodeAt(i);
    const candidates = [secrets.current, secrets.previous].filter(
      (s) => !!s
    );
    for (const secret of candidates) {
      const key = await hmacKey(secret);
      const valid = await crypto.subtle.verify(
        "HMAC",
        key,
        textToBuffer(signingInput),
        sigBuf
      );
      if (valid) {
        try {
          const payload = JSON.parse(base64urlDecode(bodyB64));
          if (payload.exp && Date.now() / 1e3 > payload.exp) return null;
          return payload;
        } catch {
          return null;
        }
      }
    }
    return null;
  }
  __name(verify, "verify");
  function decode(token) {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      return JSON.parse(base64urlDecode(parts[1]));
    } catch {
      return null;
    }
  }
  __name(decode, "decode");
  function shouldRenew(token, withinSeconds = 120) {
    const payload = decode(token);
    if (!payload) return true;
    return payload.exp - Date.now() / 1e3 < withinSeconds;
  }
  __name(shouldRenew, "shouldRenew");

  // src/middleware.ts
  function hasScopes(granted, required) {
    if (required.length === 0) return true;
    if (granted.includes("*")) return true;
    for (const req of required) {
      const matched = granted.some((g) => {
        if (g === req) return true;
        const [gVerb, gResource] = g.split(":");
        const [rVerb, rResource] = req.split(":");
        if (gVerb === "*" || gResource === "*") {
          if (gVerb === "*" && gResource === "*") return true;
          if (gVerb === "*" && gResource === rResource) return true;
          if (gVerb === rVerb && gResource === "*") return true;
        }
        return false;
      });
      if (!matched) return false;
    }
    return true;
  }
  __name(hasScopes, "hasScopes");
  function clientIp(req) {
    return req.headers.get("CF-Connecting-IP") ?? "unknown";
  }
  __name(clientIp, "clientIp");
  async function logAudit(env, auth, req, outcome) {
    try {
      await env.DB.prepare(
        `INSERT INTO auth_audit (ts, key_id, worker, path, outcome, ip)
       VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(
        Date.now(),
        auth?.keyId ?? null,
        env.WORKER_NAME ?? "unknown",
        new URL(req.url).pathname,
        outcome,
        clientIp(req)
      ).run();
    } catch {
    }
  }
  __name(logAudit, "logAudit");
  function isServiceBinding(req) {
    const cfInternal = req.headers.get("CF-Connecting-Source") ?? "";
    return cfInternal === "service-binding";
  }
  __name(isServiceBinding, "isServiceBinding");
  function withAuth(requiredScopes, handler, options) {
    const opts = {
      requiredScopes,
      allowServiceBinding: true,
      skipAudit: false,
      ...options
    };
    return async (req, env, ctx) => {
      if (opts.allowServiceBinding && isServiceBinding(req)) {
        const auth2 = {
          keyId: "service-binding",
          scopes: ["*"],
          via: "service-binding"
        };
        if (!opts.skipAudit) {
          ctx.waitUntil(logAudit(env, auth2, req, "ok"));
        }
        return handler(req, env, ctx, auth2);
      }
      const authHeader = req.headers.get("Authorization") ?? "";
      const token = authHeader.replace(/^Bearer\s+/i, "").trim();
      if (!token) {
        if (!opts.skipAudit) {
          ctx.waitUntil(logAudit(env, null, req, "malformed"));
        }
        return new Response(JSON.stringify({ error: "missing authorization" }), {
          status: 401,
          headers: { "Content-Type": "application/json", "WWW-Authenticate": 'Bearer realm="fleet"' }
        });
      }
      let auth = null;
      if (token.startsWith("fleet_sk_")) {
        const result = await validateApiKey(token, env);
        if (result) {
          auth = {
            keyId: result.keyId,
            scopes: result.scopes,
            via: "api-key"
          };
        }
      } else if (token.split(".").length === 3) {
        const payload = await verify(token, {
          current: env.JWT_SECRET_CURRENT,
          previous: env.JWT_SECRET_PREVIOUS
        });
        if (payload) {
          auth = {
            keyId: payload.sub,
            scopes: payload.scopes,
            via: "jwt"
          };
        }
      }
      if (!auth) {
        if (!opts.skipAudit) {
          ctx.waitUntil(logAudit(env, null, req, "invalid"));
        }
        return new Response(JSON.stringify({ error: "invalid credentials" }), {
          status: 401,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (!hasScopes(auth.scopes, opts.requiredScopes ?? [])) {
        if (!opts.skipAudit) {
          ctx.waitUntil(logAudit(env, auth, req, "scope_denied"));
        }
        return new Response(JSON.stringify({ error: "insufficient scopes", required: opts.requiredScopes }), {
          status: 403,
          headers: { "Content-Type": "application/json" }
        });
      }
      if (!opts.skipAudit) {
        ctx.waitUntil(logAudit(env, auth, req, "ok"));
      }
      return handler(req, env, ctx, auth);
    };
  }
  __name(withAuth, "withAuth");
})();
//# sourceMappingURL=index.js.map
