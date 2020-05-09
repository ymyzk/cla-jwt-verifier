use serde::{Deserialize, Serialize};

/// JWT Claims
/// https://tools.ietf.org/html/rfc7519#section-4
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Claims {
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
pub(crate) enum KeyType {
    RSA,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) enum KeyAlgorithm {
    RS256,
}

/// JWK (RSA/RS256 only)
/// https://tools.ietf.org/html/rfc7517#section-4
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct JWK {
    pub(crate) kty: KeyType,
    #[serde(rename(deserialize = "use"))]
    pub(crate) use_: Option<String>,
    pub(crate) alg: Option<KeyAlgorithm>,
    pub(crate) kid: Option<String>,
    // RSA
    pub(crate) n: String,
    pub(crate) e: String,
}

/// JWK Set
/// https://tools.ietf.org/html/rfc7517#section-5
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct JWKSet {
    pub(crate) keys: Vec<JWK>,
}

impl JWKSet {
    pub(crate) fn find(&self, kid: &str) -> Option<&JWK> {
        self.keys.iter().find(|jwk| jwk.kid == Some(kid.into()))
    }
}

