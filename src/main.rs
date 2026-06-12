use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
    sub: String,
    role: String,
    exp: u64,
    iat: u64,
}

#[derive(Debug)]
struct AuthResult {
    valid: bool,
    subject: String,
    role: String,
}

struct AuthService {
    secret: Vec<u8>,
}

impl AuthService {
    fn new(secret: &[u8]) -> Self {
        Self { secret: secret.to_vec() }
    }

    fn hash_password(&self, password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&self.secret);
        format!("{:x}", hasher.finalize())
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool {
        self.hash_password(password) == hash
    }

    fn issue_token(&self, claims: &TokenClaims) -> String {
        let payload = serde_json::to_string(claims).unwrap();
        let mut mac = HmacSha256::new_from_slice(&self.secret).unwrap();
        mac.update(payload.as_bytes());
        let sig = mac.finalize().into_bytes();
        format!("{}.{}", hex::encode(payload), hex::encode(sig))
    }

    fn verify_token(&self, token: &str) -> AuthResult {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return AuthResult { valid: false, subject: String::new(), role: String::new() };
        }
        let payload = hex::decode(parts[0]).ok();
        let sig = hex::decode(parts[1]).ok();
        match (payload, sig) {
            (Some(p), Some(s)) => {
                let mut mac = HmacSha256::new_from_slice(&self.secret).unwrap();
                mac.update(&p);
                if let Ok(_) = mac.verify_slice(&s) {
                    if let Ok(claims) = serde_json::from_slice::<TokenClaims>(&p) {
                        return AuthResult { valid: true, subject: claims.sub, role: claims.role };
                    }
                }
                AuthResult { valid: false, subject: String::new(), role: String::new() }
            }
            _ => AuthResult { valid: false, subject: String::new(), role: String::new() },
        }
    }
}

fn main() {
    let auth = AuthService::new(b"fleet-secret-2024");

    let hash = auth.hash_password("admin123");
    println!("Password hash: {}", hash);
    println!("Verify correct: {}", auth.verify_password("admin123", &hash));
    println!("Verify wrong: {}", auth.verify_password("wrong", &hash));
}
