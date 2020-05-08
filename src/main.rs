#[macro_use]
extern crate log;

use serde::Deserialize;
use serde::Serialize;
use std::collections::hash_map::{Entry, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use warp::http::StatusCode;
use warp::Filter;

const CACHE_TTL: Duration = Duration::from_secs(300);

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

#[derive(Clone, Debug, Deserialize, PartialEq)]
enum KeyType {
    RSA,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
enum KeyAlgorithm {
    RS256,
}

/// JWK (RSA/RS256 only)
/// https://tools.ietf.org/html/rfc7517#section-4
#[derive(Clone, Debug, Deserialize, PartialEq)]
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
#[derive(Clone, Debug, Deserialize, PartialEq)]
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

type JWKCache = Arc<Mutex<HashMap<String, (Instant, JWKSet)>>>;

fn init_cache() -> JWKCache {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Get JWK Set from a cache or download it from a given URL and store to the cache.
async fn download_jwks_with_cache(
    cache: JWKCache,
    url: &str,
) -> Result<JWKSet, Box<dyn std::error::Error>> {
    let mut cache = cache.lock().await;
    let now = Instant::now();
    let jwks = match cache.entry(url.to_string()) {
        Entry::Vacant(entry) => {
            let jwks = download_jwks(&url).await?;
            entry.insert((now, jwks.to_owned()));
            jwks
        }
        Entry::Occupied(mut entry) => {
            let (ts, jwks) = entry.get();
            if ts.elapsed() < CACHE_TTL {
                jwks.to_owned()
            } else {
                debug!("JWK Set cache has expired");
                let jwks = download_jwks(&url).await?;
                entry.insert((now, jwks.to_owned()));
                jwks
            }
        }
    };
    Ok(jwks)
}

/// Download JWK Set from a given URL
async fn download_jwks(url: &str) -> Result<JWKSet, Box<dyn std::error::Error>> {
    debug!("Downloading JWK Set from {:?}", url);
    Ok(reqwest::get(url).await?.json::<JWKSet>().await?)
}

fn verify_token(
    token: &str,
    validation: &jsonwebtoken::Validation,
    jwks: &JWKSet,
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
    cache: JWKCache,
    certs_url: String,
    validation: jsonwebtoken::Validation,
) -> Result<impl warp::Reply, warp::Rejection> {
    let jwks = match download_jwks_with_cache(cache, &certs_url).await {
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
    let decoded = match verify_token(&token, &validation, &jwks) {
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
    debug!("Decoded JWT: {:?}", decoded);
    Ok(warp::reply::with_status(
        warp::reply::json(&decoded.claims),
        StatusCode::OK,
    ))
}

fn get_filters(
    cache: JWKCache,
    certs_url: String,
    validation: jsonwebtoken::Validation,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let auth = warp::path("auth")
        .and(warp::get())
        // This header is required
        .and(warp::header::<String>("Cf-Access-Jwt-Assertion"))
        .and(warp::any().map(move || cache.clone()))
        .and(warp::any().map(move || certs_url.clone()))
        .and(warp::any().map(move || validation.clone()))
        .and_then(auth_handle);
    // Use auth.or(another_endpoint).with(warp::log("cla_jwt_verifier"))
    // to add additional endpoints
    auth.with(warp::log("cla_jwt_verifier"))
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
    let cache = init_cache();
    let certs_url = settings
        .get_str("certs_url")
        .expect("APP_CERTS_URL is required");
    let audience_str = settings.get_str("audiences").unwrap();
    let audiences: Vec<&str> = audience_str.split(",").map(|s| s.trim()).collect();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&audiences);
    let routes = get_filters(cache, certs_url.to_string(), validation);
    let listen = settings.get_str("listen").unwrap();
    let addr: std::net::SocketAddr = listen
        .parse()
        .expect(&format!("Failed to parse '{}' as SocketAddr", listen));

    // Start serving
    warp::serve(routes).run(addr).await
}

#[cfg(test)]
mod tests {
    use mockito::{mock, server_url};
    use std::path::PathBuf;
    use tokio::fs;
    use warp::http::StatusCode;
    use warp::test::request;

    async fn read_fixture(file: &str) -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/fixtures");
        path.push(file);
        fs::read_to_string(path)
            .await
            .expect("failed to read a test fixture")
    }

    #[tokio::test]
    async fn test_download_jwks_works() {
        let _m = mock("GET", "/cdn-cgi/access/certs")
            .with_status(200)
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(read_fixture("key1_jwks.json").await)
            .create();
        let url = format!("{}/cdn-cgi/access/certs", &server_url());
        let result = super::download_jwks(&url).await;
        let expected = super::JWKSet {
            keys: vec![
                super::JWK {
                    kty: super::KeyType::RSA,
                    use_: Some("sig".to_string()),
                    alg: Some(super::KeyAlgorithm::RS256),
                    kid: Some("key1".to_string()),
                    n: "x66ZeMvBm8o0qAiKjFsMCVcc34nd_vq-68zI1f89P4EfPk2ohRH8KCy8u4ZNV7_CLY3eBeUqB-4avjZ0I-O23H1JjdXMhVvxzu7iNoWnJV2cl1oXv7OTF7MFrcRiI0hqHh8REmseMkngICP0SwVXTcrvuhYfCrdCLENVeNDoI9pRZyvKl2NyKORhG0qBD6iCfbXDJXoN0ZThs28E9uVedeH4z9YYRe_9ld5cwMls6HiFoSYGLU7Lv2HGPH2eYRIcm4fkLXRV6Sv2ca9BcYfT7l__bW2iTq4Uhs7SdV1AKbBiHf1-ac4GyU-82y1Y9W2HtocMz8YmsXdWH0Rg-eaafw".to_string(),
                    e: "AQAB".to_string(),
                }
            ]
        };
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected)
    }

    #[tokio::test]
    async fn test_download_jwks_http_error() {
        let _m = mock("GET", "/cdn-cgi/access/certs")
            .with_status(404)
            .create();
        let url = format!("{}/cdn-cgi/access/certs", &server_url());
        let result = super::download_jwks(&url).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_download_jwks_unsupported_key() {
        let _m = mock("GET", "/cdn-cgi/access/certs")
            .with_status(200)
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(read_fixture("key2_jwks_unsupported.json").await)
            .create();
        let url = format!("{}/cdn-cgi/access/certs", &server_url());
        let result = super::download_jwks(&url).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_root_not_found() {
        let cache = super::init_cache();
        let certs_url = format!("{}/cdn-cgi/access/certs", &server_url());
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let routes = super::get_filters(cache, certs_url.to_string(), validation);
        let resp = request().method("GET").path("/").reply(&routes).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_auth_validates() {
        let _m = mock("GET", "/cdn-cgi/access/certs")
            .with_status(200)
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(read_fixture("key1_jwks.json").await)
            .create();
        let cache = super::init_cache();
        let certs_url = format!("{}/cdn-cgi/access/certs", &server_url());
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&vec!["AUDIENCE1"]);
        let routes = super::get_filters(cache, certs_url.to_string(), validation);
        let jwt = read_fixture("key1_jwt_valid.txt").await;
        let resp = request()
            .method("GET")
            .path("/auth")
            .header("Cf-Access-Jwt-Assertion", jwt.trim_end())
            .reply(&routes)
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body(), r#"{"iss":"https://example.cloudflareaccess.com","sub":"SUBJECT1","aud":["AUDIENCE1"],"exp":4742516436,"nbf":1588916436,"iat":1588916436,"jti":null,"email":"user@example.com","type":"app","identity_nonce":"NONCE1"}"#);
    }

    #[tokio::test]
    async fn test_auth_invalid_audience() {
        let _m = mock("GET", "/cdn-cgi/access/certs")
            .with_status(200)
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(read_fixture("key1_jwks.json").await)
            .create();
        let cache = super::init_cache();
        let certs_url = format!("{}/cdn-cgi/access/certs", &server_url());
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&vec!["INVALID_AUDIENCE"]);
        let routes = super::get_filters(cache, certs_url.to_string(), validation);
        let jwt = read_fixture("key1_jwt_valid.txt").await;
        let resp = request()
            .method("GET")
            .path("/auth")
            .header("Cf-Access-Jwt-Assertion", jwt.trim_end())
            .reply(&routes)
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.body(), r#"{"message":"Failed to validate JWT: InvalidAudience"}"#);
    }

    #[tokio::test]
    async fn test_auth_expired() {
        let _m = mock("GET", "/cdn-cgi/access/certs")
            .with_status(200)
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(read_fixture("key1_jwks.json").await)
            .create();
        let cache = super::init_cache();
        let certs_url = format!("{}/cdn-cgi/access/certs", &server_url());
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&vec!["AUDIENCE1"]);
        let routes = super::get_filters(cache, certs_url.to_string(), validation);
        let jwt = read_fixture("key1_jwt_expired.txt").await;
        let resp = request()
            .method("GET")
            .path("/auth")
            .header("Cf-Access-Jwt-Assertion", jwt.trim_end())
            .reply(&routes)
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.body(), r#"{"message":"Failed to validate JWT: ExpiredSignature"}"#);
    }

    #[tokio::test]
    async fn test_auth_wrong_key() {
        let _m = mock("GET", "/cdn-cgi/access/certs")
            .with_status(200)
            .with_header("content-type", "application/json; charset=utf-8")
            .with_body(read_fixture("key3_jwks.json").await)
            .create();
        let cache = super::init_cache();
        let certs_url = format!("{}/cdn-cgi/access/certs", &server_url());
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&vec!["AUDIENCE1"]);
        let routes = super::get_filters(cache, certs_url.to_string(), validation);
        let jwt = read_fixture("key1_jwt_valid.txt").await;
        let resp = request()
            .method("GET")
            .path("/auth")
            .header("Cf-Access-Jwt-Assertion", jwt.trim_end())
            .reply(&routes)
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.body(), r#"{"message":"Failed to validate JWT: Could not find a key matching with kid = key1"}"#);
    }

    #[tokio::test]
    async fn test_auth_without_header() {
        let cache = super::init_cache();
        let certs_url = format!("{}/cdn-cgi/access/certs", &server_url());
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        let routes = super::get_filters(cache, certs_url.to_string(), validation);
        let resp = request().method("GET").path("/auth").reply(&routes).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
