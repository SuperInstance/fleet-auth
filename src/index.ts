/**
 * Fleet Auth — Cloudflare Worker
 * ES module format with D1 + KV bindings.
 */

import { withAuth } from "./middleware";
import { generateApiKey, validateApiKey, rotateApiKey, revokeApiKey, sha256Hex } from "./keys";
import { sign, verify, decode, shouldRenew } from "./jwt";
import type { FleetAuthEnv, AuthContext } from "./types";

// ── Helpers ──────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function methodNotAllowed(): Response {
  return json({ error: "method not allowed" }, 405);
}

// ── Routes ───────────────────────────────────────────────────────────

async function handleHealth(_req: Request, _env: FleetAuthEnv): Promise<Response> {
  return json({ status: "ok", service: "fleet-auth" });
}

/** POST /api/keys — generate a new API key */
async function handleCreateKey(req: Request, env: FleetAuthEnv, _ctx: ExecutionContext, auth: AuthContext): Promise<Response> {
  if (req.method !== "POST") return methodNotAllowed();
  const body = await req.json<{ name?: string; owner?: string; scopes?: string[] }>().catch(() => ({}));
  const result = await generateApiKey(
    { name: body.name ?? "unnamed", owner: body.owner ?? auth.keyId, scopes: body.scopes ?? ["read"] },
    env,
  );
  return json(result, 201);
}

/** POST /api/keys/:keyId/rotate — rotate an API key */
async function handleRotateKey(req: Request, env: FleetAuthEnv, _ctx: ExecutionContext, auth: AuthContext): Promise<Response> {
  if (req.method !== "POST") return methodNotAllowed();
  const url = new URL(req.url);
  const keyId = url.pathname.split("/")[3]; // /api/keys/:keyId/rotate
  if (!keyId) return json({ error: "missing keyId" }, 400);
  const result = await rotateApiKey(keyId, env);
  return json(result);
}

/** DELETE /api/keys/:keyId — revoke an API key */
async function handleRevokeKey(req: Request, env: FleetAuthEnv, _ctx: ExecutionContext, _auth: AuthContext): Promise<Response> {
  if (req.method !== "DELETE") return methodNotAllowed();
  const url = new URL(req.url);
  const keyId = url.pathname.split("/")[3]; // /api/keys/:keyId
  if (!keyId) return json({ error: "missing keyId" }, 400);
  await revokeApiKey(keyId, env);
  return json({ ok: true, revoked: keyId });
}

/** POST /api/tokens/verify — verify a JWT */
async function handleVerifyToken(req: Request, env: FleetAuthEnv): Promise<Response> {
  if (req.method !== "POST") return methodNotAllowed();
  const body = await req.json<{ token?: string }>().catch(() => ({}));
  if (!body.token) return json({ error: "missing token" }, 400);
  const payload = await verify(body.token, {
    current: env.JWT_SECRET_CURRENT,
    previous: env.JWT_SECRET_PREVIOUS,
  });
  if (!payload) return json({ valid: false }, 401);
  return json({ valid: true, payload });
}

/** POST /api/tokens/sign — issue a JWT */
async function handleSignToken(req: Request, env: FleetAuthEnv, _ctx: ExecutionContext, auth: AuthContext): Promise<Response> {
  if (req.method !== "POST") return methodNotAllowed();
  const body = await req.json<{ sub?: string; scopes?: string[]; expiresIn?: number }>().catch(() => ({}));
  const token = await sign(
    {
      iss: "fleet-auth",
      sub: body.sub ?? auth.keyId,
      aud: "fleet",
      scopes: body.scopes ?? auth.scopes,
    },
    env.JWT_SECRET_CURRENT,
    body.expiresIn ?? 3600,
  );
  return json({ token });
}

// ── Router ───────────────────────────────────────────────────────────

export default {
  async fetch(req: Request, env: FleetAuthEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    // Health check (unauthenticated)
    if (path === "/health" || path === "/") {
      return handleHealth(req, env);
    }

    // Token verification (accepts token in body, not Bearer)
    if (path === "/api/tokens/verify") {
      return handleVerifyToken(req, env);
    }

    // Key management — requires admin:keys scope
    if (path === "/api/keys" && req.method === "POST") {
      return withAuth(["admin:keys"], handleCreateKey)(req, env, ctx);
    }
    if (path.match(/^\/api\/keys\/[^/]+\/rotate$/)) {
      return withAuth(["admin:keys"], handleRotateKey)(req, env, ctx);
    }
    if (path.match(/^\/api\/keys\/[^/]+$/) && req.method === "DELETE") {
      return withAuth(["admin:keys"], handleRevokeKey)(req, env, ctx);
    }

    // Token signing
    if (path === "/api/tokens/sign") {
      return withAuth(["admin:tokens"], handleSignToken)(req, env, ctx);
    }

    // Re-export library info
    if (path === "/api/info") {
      return json({
        service: "fleet-auth",
        endpoints: [
          "GET  /health",
          "POST /api/keys",
          "POST /api/keys/:keyId/rotate",
          "DELETE /api/keys/:keyId",
          "POST /api/tokens/verify",
          "POST /api/tokens/sign",
        ],
      });
    }

    return json({ error: "not found" }, 404);
  },
};

// Re-export library functions for consumers
export { withAuth, hasScopes } from "./middleware";
export { generateApiKey, validateApiKey, rotateApiKey, revokeApiKey, sha256Hex } from "./keys";
export { sign, verify, decode, shouldRenew } from "./jwt";
export type {
  AuthenticatedRequest,
  AuthContext,
  ApiKeyRecord,
  KeyRecord,
  JWTPayload,
  AuthOptions,
  FleetAuthEnv,
} from "./types";
