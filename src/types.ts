/**
 * Fleet Auth — TypeScript types
 */

/** Extended Request with authenticated context */
export interface AuthenticatedRequest extends Request {
  auth: AuthContext;
}

/** Result of successful authentication */
export interface AuthContext {
  /** API key public half (key_id) or JWT sub */
  keyId: string;
  /** Granted scopes (e.g. ["read:vector", "write:fishinglog"]) */
  scopes: string[];
  /** How the request was authenticated */
  via: "api-key" | "jwt" | "service-binding";
}

/** D1 api_keys row */
export interface ApiKeyRecord {
  key_id: string;
  key_hash: string;
  name: string;
  owner: string;
  scopes: string; // JSON array string
  status: "active" | "rotating" | "revoked";
  created_at: number;
  expires_at: number | null;
  last_used_at: number | null;
  rotated_from: string | null;
}

/** KV mirror of a key record (hot-path) */
export interface KeyRecord {
  /** SHA-256 hex hash */
  h: string;
  /** Scopes array */
  s: string[];
  /** Status */
  st: "active" | "rotating" | "revoked";
  /** Expiry epoch ms or null */
  exp: number | null;
  /** Owner */
  o: string;
}

/** JWT payload structure */
export interface JWTPayload {
  iss: string;
  sub: string;
  aud: string;
  scopes: string[];
  exp: number;
  iat: number;
  kid: string;
}

/** Options for withAuth middleware */
export interface AuthOptions {
  /** Scopes required to access the endpoint (all must be present) */
  requiredScopes?: string[];
  /** Whether to allow service-binding requests (default: true) */
  allowServiceBinding?: boolean;
  /** Whether to skip audit logging (default: false) */
  skipAudit?: boolean;
}

/** Worker env bindings expected by fleet-auth */
export interface FleetAuthEnv {
  /** D1 database for auth tables */
  DB: D1Database;
  /** KV namespace for hot-path key lookups */
  AUTH_KV?: KVNamespace;
  /** Current JWT signing secret */
  JWT_SECRET_CURRENT: string;
  /** Previous JWT signing secret (for rotation) */
  JWT_SECRET_PREVIOUS?: string;
  /** Current internal JWT secret */
  JWT_SECRET_INTERNAL?: string;
  /** Previous internal JWT secret */
  JWT_SECRET_INTERNAL_PREVIOUS?: string;
  /** This worker's name (for audit + aud validation) */
  WORKER_NAME?: string;
}
