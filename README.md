# cla-jwt-verifier
![CI](https://github.com/ymyzk/cla-jwt-verifier/workflows/CI/badge.svg)

Simple HTTP server for verifying JWT issued by [Cloudflare Access](https://teams.cloudflare.com/access/).

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

## Docker
The Docker image is also available on [Docker Hub](https://hub.docker.com/repository/docker/ymyzk/cla-jwt-verifier).

## Reference
- [Validating JSON Web Tokens - Cloudflare Access](https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/)
