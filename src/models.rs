use serde::{Deserialize, Serialize};

/// JWT Claims
/// https://tools.ietf.org/html/rfc7519#section-4
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    // Registered Claim Names
    iss: Option<String>,
    sub: Option<String>,
    aud: Vec<String>,
    exp: Option<i64>,
    nbf: Option<i64>,
    iat: Option<i64>,
    jti: Option<String>,
    // Private Claim Names?
    email: String,
    // "type" is a strict keyword of Rust
    #[serde(rename(deserialize = "type", serialize = "type"))]
    type_: String,
    identity_nonce: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub enum KeyType {
    RSA,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub enum KeyAlgorithm {
    RS256,
}

/// JWK (RSA/RS256 only)
/// https://tools.ietf.org/html/rfc7517#section-4
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct JWK {
    pub kty: KeyType,
    #[serde(rename(deserialize = "use"))]
    pub use_: Option<String>,
    pub alg: Option<KeyAlgorithm>,
    pub kid: Option<String>,
    // RSA
    pub n: String,
    pub e: String,
}

/// JWK Set
/// https://tools.ietf.org/html/rfc7517#section-5
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct JWKSet {
    pub keys: Vec<JWK>,
}

impl JWKSet {
    /// Returns a JWK with the given kid if it exists.
    /// Otherwise, returns None.
    /// If there multiple keys with the same kid,
    /// there's no guarantee on which one is returned.
    pub fn find(&self, kid: &str) -> Option<&JWK> {
        self.keys.iter().find(|jwk| jwk.kid == Some(kid.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::{JWKSet, KeyAlgorithm, KeyType, JWK};

    #[test]
    fn test_find_jwk_finds_key() {
        let jwk1 = JWK {
            kty: KeyType::RSA,
            use_: Some("sig".to_string()),
            alg: Some(KeyAlgorithm::RS256),
            kid: Some("key1".to_string()),
            n: "x66ZeMvBm8o0qAiKjFsMCVcc34nd".to_string(),
            e: "AQAB".to_string(),
        };
        let jwk2 = JWK {
            kty: KeyType::RSA,
            use_: Some("sig".to_string()),
            alg: Some(KeyAlgorithm::RS256),
            kid: Some("key2".to_string()),
            n: "Yadafddsa8o0qAidfafad1321r8s".to_string(),
            e: "AQAB".to_string(),
        };
        let jwks = JWKSet {
            keys: vec![jwk1.to_owned(), jwk2.to_owned()],
        };
        assert_eq!(jwks.find("key1"), Some(&jwk1));
        assert_eq!(jwks.find("key2"), Some(&jwk2));
    }

    #[test]
    fn test_find_jwk_not_found() {
        let jwk = JWK {
            kty: KeyType::RSA,
            use_: Some("sig".to_string()),
            alg: Some(KeyAlgorithm::RS256),
            kid: Some("key1".to_string()),
            n: "x66ZeMvBm8o0qAiKjFsMCVcc34nd".to_string(),
            e: "AQAB".to_string(),
        };
        let jwks = JWKSet { keys: vec![jwk] };
        assert!(jwks.find("key2").is_none());
    }

    #[test]
    fn test_find_jwk_when_empty() {
        let jwks = JWKSet { keys: vec![] };
        assert!(jwks.find("kid").is_none());
    }
}
