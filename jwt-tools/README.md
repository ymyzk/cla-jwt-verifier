# JWT/JWK Tools for Debugging and Testing
## Generate a public/private key pair
```shell
$ openssl genrsa 2048 > private.pem
$ openssl rsa -in private.pem -pubout -out public.pem
```

## Convert a PEM file to a JWK and a JWK Set
```shell
$ npx pem-jwk ./public.pem | jq '. += {"alg": "RS256", "use": "sig", "kid": "key1"}' > jwk.json
$ npx pem-jwk ./public.pem | jq '. += {"alg": "RS256", "use": "sig", "kid": "key1"}' | jq '{"keys": [.]}' > jwks.json
```

## Sign a JWT using a PEM private key
```shell
$ npm intsall
$ node sign.js
```
