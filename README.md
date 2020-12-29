# cla-jwt-verifier
![CI](https://github.com/ymyzk/cla-jwt-verifier/workflows/CI/badge.svg)

Simple HTTP server for verifying JSON web tokens (JWTs) issued by [Cloudflare Access](https://teams.cloudflare.com/access/).
Works well with Nginx's [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

When we use Cloudflare Access, no one should be able to access our origin servers directly.
To secure origin servers, Cloudflare Access recommends to force all requests to our origin server through Cloudflare's network and validate JWTs.
cla-jwt-verifier provides a solution to implement the latter.
See [How Access works - Cloudflare Access](https://developers.cloudflare.com/access/about/how-access-works/) for more details.

## Usage
1. Start cla-jwt-verifier
```shell
APP_CERTS_URL=https://<account>.cloudflareaccess.com/cdn-cgi/access/certs \
APP_AUDIENCES=<audience1>,<audience2> \
RUST_LOG=cla_jwt_verifier=info \
cargo run
```
2. Verify a JWT token using cla-jwt-verifier. cla-jwt-verifier always get a token from the HTTP header not HTTP Cookie.
```shell
curl -v -H 'Cf-Access-Jwt-Assertion: <token>' localhost:3030/auth
```
3. cla-jwt-verifier returns HTTP 200 only when the given token is verified.

## Integrating with Nginx
cla-jwt-verifier can be integrated with Nginx easily by using [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

Example configuration:
```
location / {
  auth_request /auth;
  ...
}

location = /auth {
  internal;

  proxy_pass http://<cla-jwt-verifier>/auth;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";

  // Optional
  proxy_set_header X-Original-URI $request_uri;
}
```

If you're using [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/) on Kubernetes, integration will be easier.
Run cla-jwt-verifier on Kubernetes and set [global-auth-url](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#global-auth-url) of ConfigMap or [nginx.ingress.kubernetes.io/auth-url](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#external-authentication) annotation depending on where you want to enable authentication (global or ingress).

## Configurations
cla-jwt-verifier reads configurations from environment variables.

- `APP_CERTS_URL` (required)
- `APP_AUDIENCES` (required)
- `APP_LISTEN` (optional)
- `RUST_LOG` (optional)

## Docker
The Docker image is available on [Docker Hub](https://hub.docker.com/repository/docker/ymyzk/cla-jwt-verifier) and
[GitHub](https://github.com/users/ymyzk/packages/container/package/cla-jwt-verifier).

## Reference
- [Validating JSON Web Tokens - Cloudflare Access](https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/)
- [RFC 7517 - JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
