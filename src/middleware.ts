/**
 * Fleet Auth — Core authentication middleware
 *
 * Usage:
 *   export default {
 *     fetch: withAuth(["read:vector"], async (req, env, ctx, auth) => {
 *       return Response.json({ ok: true, scopes: auth.scopes });
 *     }),
 *   };
 */

import type { AuthContext, AuthOptions, FleetAuthEnv } from "./types";
import { validateApiKey } from "./keys";
import { verify as verifyJwt } from "./jwt";

// ── scope matching ───────────────────────────────────────────────────

/**
 * Check if granted scopes satisfy all required scopes.
 * Supports wildcards: "*" matches everything, "read:*" matches "read:vector", etc.
 */
export function hasScopes(granted: string[], required: string[]): boolean {
  if (required.length === 0) return true;
  if (granted.includes("*")) return true;

  for (const req of required) {
    const matched = granted.some((g) => {
      if (g === req) return true;
      // Wildcard on either side: "read:*" matches "read:vector"
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

// ── audit logging ────────────────────────────────────────────────────

function clientIp(req: Request): string {
  return req.headers.get("CF-Connecting-IP") ?? "unknown";
}

async function logAudit(
  env: FleetAuthEnv,
  auth: AuthContext | null,
  req: Request,
  outcome: "ok" | "invalid" | "expired" | "revoked" | "scope_denied" | "malformed",
): Promise<void> {
  try {
    await env.DB.prepare(
      `INSERT INTO auth_audit (ts, key_id, worker, path, outcome, ip)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        Date.now(),
        auth?.keyId ?? null,
        env.WORKER_NAME ?? "unknown",
        new URL(req.url).pathname,
        outcome,
        clientIp(req),
      )
      .run();
  } catch {
    // Audit logging must never fail the request
  }
}

// ── service binding detection ────────────────────────────────────────

/**
 * Detect if the request came through a Cloudflare service binding.
 * Service bindings are guaranteed authentic by the runtime — no token needed.
 */
function isServiceBinding(req: Request): boolean {
  // Cloudflare sets this header on internally-routed requests
  const cfInternal = req.headers.get("CF-Connecting-Source") ?? "";
  return cfInternal === "service-binding";
}

// ── middleware ───────────────────────────────────────────────────────

type AuthedHandler = (
  req: Request,
  env: FleetAuthEnv,
  ctx: ExecutionContext,
  auth: AuthContext,
) => Promise<Response>;

/**
 * Wrap a fetch handler with authentication.
 *
 * @param requiredScopes - Scopes required (or single string for convenience)
 * @param handler - Your handler, receiving an additional AuthContext parameter
 * @param options - Optional auth configuration
 */
export function withAuth(
  requiredScopes: string[],
  handler: AuthedHandler,
  options?: AuthOptions,
): (req: Request, env: FleetAuthEnv, ctx: ExecutionContext) => Promise<Response> {
  const opts: AuthOptions = {
    requiredScopes,
    allowServiceBinding: true,
    skipAudit: false,
    ...options,
  };

  return async (req: Request, env: FleetAuthEnv, ctx: ExecutionContext): Promise<Response> => {
    // 1. Service binding — trust implicitly
    if (opts.allowServiceBinding && isServiceBinding(req)) {
      const auth: AuthContext = {
        keyId: "service-binding",
        scopes: ["*"],
        via: "service-binding",
      };
      if (!opts.skipAudit) {
        ctx.waitUntil(logAudit(env, auth, req, "ok"));
      }
      return handler(req, env, ctx, auth);
    }

    // 2. Extract token from Authorization header
    const authHeader = req.headers.get("Authorization") ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();

    if (!token) {
      if (!opts.skipAudit) {
        ctx.waitUntil(logAudit(env, null, req, "malformed"));
      }
      return new Response(JSON.stringify({ error: "missing authorization" }), {
        status: 401,
        headers: { "Content-Type": "application/json", "WWW-Authenticate": 'Bearer realm="fleet"' },
      });
    }

    // 3. Dispatch by token shape
    let auth: AuthContext | null = null;

    if (token.startsWith("fleet_sk_")) {
      // API key path — KV/D1 lookup + SHA-256 comparison
      const result = await validateApiKey(token, env);
      if (result) {
        auth = {
          keyId: result.keyId,
          scopes: result.scopes,
          via: "api-key",
        };
      }
    } else if (token.split(".").length === 3) {
      // JWT path — pure CPU verification
      const payload = await verifyJwt(token, {
        current: env.JWT_SECRET_CURRENT,
        previous: env.JWT_SECRET_PREVIOUS,
      });
      if (payload) {
        auth = {
          keyId: payload.sub,
          scopes: payload.scopes,
          via: "jwt",
        };
      }
    }

    // 4. Auth failed
    if (!auth) {
      if (!opts.skipAudit) {
        ctx.waitUntil(logAudit(env, null, req, "invalid"));
      }
      return new Response(JSON.stringify({ error: "invalid credentials" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 5. Scope check
    if (!hasScopes(auth.scopes, opts.requiredScopes ?? [])) {
      if (!opts.skipAudit) {
        ctx.waitUntil(logAudit(env, auth, req, "scope_denied"));
      }
      return new Response(JSON.stringify({ error: "insufficient scopes", required: opts.requiredScopes }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 6. Success — audit off the critical path
    if (!opts.skipAudit) {
      ctx.waitUntil(logAudit(env, auth, req, "ok"));
    }

    return handler(req, env, ctx, auth);
  };
}
