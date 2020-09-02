# Vault Plugin: JWT Backend
![Build Release](https://github.com/quintoandar/vault-plugin-secrets-jwt/workflows/Build%20Release/badge.svg)

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin provides the ability to sign [JSON Web Tokens](https://jwt.io) (JWTs) without ever having the signing keys leave Vault.

It is still under early development and should not be used anywhere.

**Please note**: Hashicorp take Vault's security and their users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting them at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links
    - Vault Website: https://www.vaultproject.io
    - Main Project Github: https://www.github.com/hashicorp/vault
    - Package docs: https://godoc.org/github.com/ian-fox/vault-plugin-secrets-jwt
    - JWT docs: https://jwt.io

## Usage

### Config
Plugin global configurations.

Example
```bash
vault write jwt/config "key_ttl=2s" "jwt_ttl=3s"
```

Options

|key|description|
|---|-----------|
key_ttl|Duration before a key stops signing new tokens and a new one is generated. After this period the public key will still be available to verify JWTs.
jwt_ttl|Duration before a token expires.
set_iat|Whether or not the backend should generate and set the 'iat' claim.
set_jti|Whether or not the backend should generate and set the 'jti' claim.
set_nbf|Whether or not the backend should generate and set the 'nbf' claim.
issuer|Value to set as the 'iss' claim. Claim omitted if empty.


### Claims

Set claims for a given path.

Example

```bash
vault write jwt/claims/test @claims.json
```

Payload Example

```json
{
    "claims": {
        "sub": "Zapp Brannigan"
    }
}
```

Options

|key|description|
|---|-----------|
|claims| Map of custom claims.|

### Sign

Signs an JWt with the claims set on the custom path.

Example
```
vault read jwt/claims/test
```

### JWKS

Exposes the public key on an unauthenticated endpoint.

Example

```bash
curl <vault_addr>/v1/jwt/jwks
```
