# fleet-auth

**Authentication middleware for the SuperInstance fleet — API keys, JWTs, and service bindings, purpose-built for Cloudflare Workers.**

Every fleet worker needs to answer the same question: *who is calling, and are they allowed to?* This crate answers it. It provides a single `withAuth()` middleware that handles API keys (`fleet_sk_...`), HS256 JWTs, and Cloudflare service-binding detection — so your worker handler only sees authenticated requests with granted scopes.

## Why This Exists

The SuperInstance fleet has 20+ Cloudflare Workers communicating over HTTP. Every worker needs auth, but every worker shouldn't reimplement it. `fleet-auth` is the shared authentication layer that:

1. **Validates credentials** — API keys (hashed, stored in D1, mirrored to KV) and JWTs (signed with rotating secrets)
2. **Enforces scopes** — fine-grained permissions like `read:vector`, `write:fishinglog`, or wildcard `*`
3. **Audits every request** — logs auth outcomes to D1 without blocking the response
4. **Detects service bindings** — Cloudflare-internal requests are trusted automatically (the runtime guarantees authenticity)

The design targets **sub-5ms auth overhead**. KV lookups for API keys hit in 1–3ms. JWT verification is pure CPU (no I/O). Service binding detection is a single header check.

## Architecture

```
                        Incoming Request
                              │
                    ┌─────────▼─────────┐
                    │   withAuth()      │
                    │   middleware      │
                    └─────────┬─────────┘
                              │
                  ┌───────────▼───────────┐
                  │ Service binding?      │──── Yes ──► Trust (CF runtime guarantees auth)
                  │ (CF-Connecting-Source)│
                  └───────────┬───────────┘
                              │ No
                  ┌───────────▼───────────┐
                  │ Extract Bearer token  │
                  └───────────┬───────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────▼──────┐  ┌────▼─────┐  ┌──────▼──────┐
    │ fleet_sk_...   │  │ JWT      │  │ Unknown     │
    │ (API key path) │  │ (3-part) │  │             │
    └─────────┬──────┘  └────┬─────┘  └──────┬──────┘
              │               │               │
    ┌─────────▼──────┐  ┌────▼─────┐          │
    │ KV lookup      │  │ HS256    │          │
    │ (fallback D1)  │  │ verify   │          │
    │ SHA-256 compare│  │ (rotate) │          │
    └─────────┬──────┘  └────┬─────┘          │
              │               │               │
              └───────┬───────┘       ┌────────▼────────┐
                      │               │ 401 Unauthorized │
              ┌───────▼───────┐       └─────────────────┘
              │ Scope check   │
              │ (wildcard ok) │
              └───────┬───────┘
                      │
           ┌──────────▼──────────┐
           │ Your handler(req,   │
           │ env, ctx, auth)     │
           └─────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Dual auth (API key + JWT) | API keys for long-lived service accounts; JWTs for short-lived user sessions |
| SHA-256 hashed keys | Never store plaintext secrets. Keys are hashed on creation, compared by hash on validation. |
| KV mirror + D1 source of truth | KV for hot-path latency (1–3ms); D1 for durability and complex queries |
| JWT secret rotation | `JWT_SECRET_CURRENT` + `JWT_SECRET_PREVIOUS` enables zero-downtime key rotation |
| Audit to D1 (non-blocking) | `ctx.waitUntil()` ensures audit logging never blocks the response |
| Service binding trust | CF runtime authenticates internal requests — no token needed |

## Quick Start

### Install as a dependency

```bash
# In your Cloudflare Worker project
cp -r ../fleet-auth/src/auth ./src/auth
# Or import directly if published
```

### Protect an endpoint

```typescript
import { withAuth } from "./auth/middleware";

export default {
  fetch: withAuth(["read:vector"], async (req, env, ctx, auth) => {
    // auth.keyId  — who's calling
    // auth.scopes — what they can do
    // auth.via    — "api-key" | "jwt" | "service-binding"
    return Response.json({ ok: true, you: auth.keyId });
  }),
};
```

### Generate an API key

```typescript
import { generateApiKey } from "./auth/keys";

const result = await generateApiKey(env, {
  name: "fleet-scanner-service",
  owner: "ci-pipeline",
  scopes: ["read:vector", "read:fleet"],
  expiresIn: 30 * 24 * 60 * 60 * 1000, // 30 days
});

console.log("Key (save this — shown once):", result.key);
console.log("Key ID:", result.keyId);
// Key format: fleet_sk_<8-char-base32-id>.<44-char-base64url-secret>
```

### Create a JWT

```typescript
import { sign } from "./auth/jwt";

const token = await sign(
  {
    iss: "fleet-auth",
    sub: "user-123",
    aud: "fleet-vector-api",
    scopes: ["read:vector", "write:fishinglog"],
    kid: "key-1",
  },
  env.JWT_SECRET_CURRENT,
);
// token is a standard HS256 JWT, expires in 15 minutes
```

## API Reference

### Middleware

#### `withAuth(requiredScopes, handler, options?)`

Wrap a Workers fetch handler with authentication.

```typescript
withAuth(
  ["read:vector", "write:fishinglog"],  // all must be present
  async (req, env, ctx, auth) => { /* your handler */ },
  { allowServiceBinding: true, skipAudit: false }
);
```

#### `hasScopes(granted, required)`

Check scope satisfaction. Supports wildcards:

- `"*"` matches everything
- `"read:*"` matches `"read:vector"`, `"read:fleet"`, etc.

### API Key Management

| Function | Description |
|----------|-------------|
| `generateApiKey(env, options)` | Create key, store hash in D1, mirror to KV. Returns full key (once!). |
| `validateApiKey(token, env)` | KV-first lookup, D1 fallback. SHA-256 comparison. |
| `rotateApiKey(env, oldKeyId, options)` | Create replacement key. Old key stays valid during grace period. |
| `revokeApiKey(env, keyId)` | Immediate revocation. Deletes from KV, marks revoked in D1. |

### JWT Utilities

| Function | Description |
|----------|-------------|
| `sign(payload, secret)` | Sign a JWT with HS256. 15-minute TTL. |
| `verify(token, secrets)` | Verify against current + previous secrets (rotation support). |
| `decode(token)` | Decode without verifying (debugging only). |
| `shouldRenew(token, withinSeconds?)` | Check if token expires soon. Default: within 120s. |

## API Key Format

```
fleet_sk_abcdefghij.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
         │       │ ──────────────────────────────────────────────
         │       │              32-byte random secret (base64url)
         │       └── 8-char base32 key ID (used for lookup)
         └── prefix
```

The **key ID** (`abcdefghij`) is the public identifier. It's used for KV lookups, D1 queries, and audit logs. The **secret** is the private half — it's stored as a SHA-256 hash, never in plaintext. When you validate, you hash the submitted secret and compare.

This is the same pattern as Stripe API keys (`sk_live_...`) and GitHub tokens (`ghp_...`).

## Scopes

Scopes follow the `verb:resource` pattern:

| Scope | Description |
|-------|-------------|
| `read:vector` | Read vector embeddings |
| `write:fishinglog` | Write fishing log entries |
| `read:fleet` | Read fleet status |
| `*` | Full access (service bindings get this) |
| `read:*` | Read access to all resources |

## Env Bindings

Your Worker needs these bindings in `wrangler.toml`:

```toml
[[d1_databases]]
binding = "DB"
database_name = "fleet-auth-db"
database_id = "your-database-id"

[[kv_namespaces]]
binding = "AUTH_KV"
id = "your-kv-namespace-id"

[vars]
WORKER_NAME = "your-worker-name"

# Set via `wrangler secret put`:
# JWT_SECRET_CURRENT — current signing secret
# JWT_SECRET_PREVIOUS — previous secret (for rotation)
```

### D1 Schema

The `api_keys` and `auth_audit` tables must exist. Deploy from [fleet-events-db](https://github.com/SuperInstance/fleet-events-db) migrations:

```sql
-- api_keys table
CREATE TABLE api_keys (
  key_id TEXT PRIMARY KEY,
  key_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  owner TEXT NOT NULL,
  scopes TEXT NOT NULL,      -- JSON array
  status TEXT NOT NULL,       -- 'active', 'rotating', 'revoked'
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  last_used_at INTEGER,
  rotated_from TEXT
);

-- auth_audit table
CREATE TABLE auth_audit (
  ts INTEGER NOT NULL,
  key_id TEXT,
  worker TEXT NOT NULL,
  path TEXT NOT NULL,
  outcome TEXT NOT NULL,     -- 'ok', 'invalid', 'expired', 'revoked', 'scope_denied', 'malformed'
  ip TEXT
);
```

## JWT Rotation

Zero-downtime secret rotation:

1. Set `JWT_SECRET_PREVIOUS = current_secret`
2. Set `JWT_SECRET_CURRENT = new_secret`
3. Tokens signed with the old secret still validate (via `PREVIOUS`)
4. New tokens are signed with the new secret
5. After all old tokens expire (15 minutes), remove `JWT_SECRET_PREVIOUS`

## Conservation Law Connection

Every authenticated request follows the fleet's conservation law (γ + η = C):

- **One request in** → **one audit record out** (no request goes unlogged)
- **One API key created** → **one hash stored** (no duplication)
- **One JWT issued** → **one JWT verifiable** (no drift)

The audit trail is append-only, like the fleet's event sourcing in [fleet-events-db](https://github.com/SuperInstance/fleet-events-db). Auth events are first-class fleet events.

## Related

- [fleet-events-db](https://github.com/SuperInstance/fleet-events-db) — D1 schema with `api_keys` and `auth_audit` tables
- [fleet-edge-worker](https://github.com/SuperInstance/fleet-edge-worker) — Edge dispatcher using this auth layer
- [fleet-vector-api](https://github.com/SuperInstance/fleet-vector-api) — Vector search API with scoped access
- [fleet-warden](https://github.com/SuperInstance/fleet-warden) — Disk cleanup daemon (uses API keys for fleet scanning)

## License

MIT
