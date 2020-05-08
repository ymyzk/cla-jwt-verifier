# cla-jwt-verifier
Simple HTTP server to verify JWT issued by [Cloudflare Access](https://teams.cloudflare.com/access/).

## Usage
1. Start cla-jwt-verifier
```shell
APP_CERTS_URL=https://<account>.cloudflareaccess.com/cdn-cgi/access/certs \
APP_AUDIENCES=<audience1>,<audience2> \
RUST_LOG=cla_jwt_verifier=info \
cargo run
```
2. Verify a JWT token
```shell
curl -v -H 'Cf-Access-Jwt-Assertion: <token>' localhost:3030/auth
```
3. cla-jwt-verifier returns HTTP 200 only when the given token is verified.

## Configurations
cla-jwt-verifier reads configurations from environment variables.

- `APP_CERTS_URL` (required)
- `APP_AUDIENCES` (required)
- `APP_LISTEN` (optional)
- `RUST_LOG` (optional)

## Reference
- [Validating JSON Web Tokens - Cloudflare Access](https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/)
