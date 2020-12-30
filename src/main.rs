extern crate cla_jwt_verifier;

use cla_jwt_verifier::{get_routes, init_cache};
use log::{debug, info};
use std::collections::hash_map::HashMap;

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
    let routes = get_routes(cache, certs_url.to_string(), validation);
    let listen = settings.get_str("listen").unwrap();
    let addr: std::net::SocketAddr = listen
        .parse()
        .expect(&format!("Failed to parse '{}' as SocketAddr", listen));
    // Start serving
    warp::serve(routes).run(addr).await
}
