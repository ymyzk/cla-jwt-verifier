#[macro_use]
extern crate log;

use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use warp::http::StatusCode;
use warp::Filter;

/// JWT Claims
/// https://tools.ietf.org/html/rfc7519#section-4
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Claims {
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

#[derive(Clone, Debug, Deserialize)]
enum KeyType {
    RSA,
}

#[derive(Clone, Debug, Deserialize)]
enum KeyAlgorithm {
    RS256,
}

/// JWK (RSA/RS256 only)
/// https://tools.ietf.org/html/rfc7517#section-4
#[derive(Clone, Debug, Deserialize)]
struct JWK {
    kty: KeyType,
    #[serde(rename(deserialize = "use"))]
    use_: Option<String>,
    alg: Option<KeyAlgorithm>,
    kid: Option<String>,
    // RSA
    n: String,
    e: String,
}

/// JWK Set
/// https://tools.ietf.org/html/rfc7517#section-5
#[derive(Clone, Debug, Deserialize)]
struct JWKSet {
    keys: Vec<JWK>,
}

impl JWKSet {
    fn find(&self, kid: &str) -> Option<&JWK> {
        self.keys.iter().find(|jwk| jwk.kid == Some(kid.into()))
    }
}

#[derive(Clone, Debug, Serialize)]
struct ErrorMessage {
    message: String,
}

/// Download JWK Set from a given URL
async fn download_jwks(url: &str) -> Result<JWKSet, Box<dyn std::error::Error>> {
    Ok(reqwest::get(url).await?.json::<JWKSet>().await?)
}

fn verify_token(
    token: &str,
    validation: &jsonwebtoken::Validation,
    jwks: JWKSet,
) -> Result<jsonwebtoken::TokenData<Claims>, Box<dyn std::error::Error>> {
    let header = jsonwebtoken::decode_header(token)?;
    debug!("Decoded header: {:?}", header);

    let kid = header
        .kid
        .ok_or("Failed to get 'kid' from header of JWT.")?;
    let jwk = jwks
        .find(&kid)
        .ok_or(format!("Could not find a key matching with kid = {}", kid))?;
    let rsa_key = jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e);

    Ok(jsonwebtoken::decode::<Claims>(
        &token,
        &rsa_key,
        &validation,
    )?)
}

async fn auth_handle(
    token: String,
    certs_url: String,
    validation: jsonwebtoken::Validation,
) -> Result<impl warp::Reply, warp::Rejection> {
    let jwks = match download_jwks(&certs_url).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(warp::reply::with_status(
                warp::reply::json(&ErrorMessage {
                    message: format!("Failed to get JWK Set: {}", e.to_string()),
                }),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    };
    debug!("JWK Set: {:?}", jwks);
    let decoded = match verify_token(&token, &validation, jwks) {
        Ok(r) => r,
        Err(e) => {
            return Ok(warp::reply::with_status(
                warp::reply::json(&ErrorMessage {
                    message: format!("Failed to validate JWT: {}", e.to_string()),
                }),
                StatusCode::UNAUTHORIZED,
            ))
        }
    };
    println!("Decoded JWT: {:?}", decoded);
    Ok(warp::reply::with_status(
        warp::reply::json(&decoded.claims),
        StatusCode::OK,
    ))
}

fn get_filters(
    certs_url: String,
    validation: jsonwebtoken::Validation,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let auth = warp::path("auth")
        .and(warp::get())
        // This header is required
        .and(warp::header::<String>("Cf-Access-Jwt-Assertion"))
        .and(warp::any().map(move || certs_url.clone()))
        .and(warp::any().map(move || validation.clone()))
        .and_then(auth_handle);
    let hello = warp::path!("hello" / String)
        .and(warp::get())
        .map(|name| format!("Hello, {}!", name));
    auth.or(hello)
}

#[tokio::main]
async fn main() {
    // Init logger
    env_logger::init();
    info!("starting up");

    // Load configuration
    let mut settings = config::Config::default();
    settings.set_default("listen", "127.0.0.1:3030").unwrap();
    // Add in settings from the environment (with a prefix of APP)
    // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
    settings
        .merge(config::Environment::with_prefix("APP"))
        .unwrap();
    debug!(
        "Configuration: {:?}",
        settings
            .clone()
            .try_into::<HashMap<String, String>>()
            .unwrap()
    );

    // Prepare warp filters
    let listen = settings.get_str("listen").unwrap();
    let certs_url = settings
        .get_str("certs_url")
        .expect("APP_CERTS_URL is required");
    let audience_str = settings.get_str("audiences").unwrap();
    let audiences: Vec<&str> = audience_str.split(",").map(|s| s.trim()).collect();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&audiences);
    let routes = get_filters(certs_url.to_string(), validation);
    let addr: std::net::SocketAddr = listen
        .parse()
        .expect(&format!("Failed to parse '{}' as SocketAddr", listen));

    // Start serving
    warp::serve(routes).run(addr).await
}

#[cfg(test)]
mod tests {
    use warp::http::StatusCode;
    use warp::test::request;

    #[tokio::test]
    async fn test_root_not_found() {
        let certs_url = "https://sample.cloudflareaccess.com/cdn-cgi/access/certs";
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let routes = super::get_filters(certs_url.to_string(), validation);
        let resp = request().method("GET").path("/").reply(&routes).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_auth_without_header() {
        let certs_url = "https://sample.cloudflareaccess.com/cdn-cgi/access/certs";
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let routes = super::get_filters(certs_url.to_string(), validation);
        let resp = request().method("GET").path("/auth").reply(&routes).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
