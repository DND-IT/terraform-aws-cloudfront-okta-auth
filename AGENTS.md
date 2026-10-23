# AGENTS.md

Instructions for AI coding agents and contributors working in this repository.

## What this repo is

A public Terraform registry module (`tx-pts-dai/cloudfront-okta-auth/aws`) that protects an existing CloudFront distribution with Okta OIDC login. A CloudFront Function checks a signed session cookie on every request; a regional Lambda function behind a function URL handles login, callback and logout on `/_auth/*`.

## Layout

- `main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`: the module. The login function and its SSM parameters live in the caller's region; the CloudFront Function and key value store are global.
- `lambda/auth.mjs`: the login function's OIDC, JWT and cookie logic, zero npm dependencies. `lambda/index.mjs` is its entrypoint and `lambda/config.mjs.tftpl` its only templated file.
- `lambda/gate.js`: the CloudFront Function body (`cloudfront-js-2.0`: no network, no `Buffer`, no timers). `lambda/gate.js.tftpl` prepends the KVS handle, `crypto` and the config and embeds `viewer_request_rewrite`.
- `scripts/put-session-key.sh`: writes the session key into the key value store; the provider has no write-only argument for it.
- `lambda/test/`: `node --test` unit tests; `gate.test.mjs` runs `gate.js` in a `node:vm` context with stand-ins for the CloudFront globals.
- `tests/`: `terraform test` files using `mock_provider "aws"`; they run with no credentials.
- `examples/complete/`: S3 + CloudFront + this module.

## Conventions

- Conventional Commits; releases are cut by semantic-release on `main`. Mark interface changes (removed/renamed variable or output, changed default that alters live infrastructure, raised Terraform floor) as breaking (`feat!:` / `BREAKING CHANGE:`). While the module is `0.x`, `.releaserc.json` maps breaking changes to a MINOR bump; drop that rule when cutting `1.0.0`.
- Do not template `auth.mjs` or `gate.js`; keep shipped handler code byte-identical to what the unit tests exercise.
- The session cookie format (`v1.<exp>.<b64url JSON>.<b64url HMAC>`) is implemented twice, in `auth.mjs` (`signSession`/`verifySession`) and `gate.js`; change both together. Consumers verify it too, so a format change is breaking.
- After changing `gate.js`, check it on the real runtime with `aws cloudfront test-function`; the vm tests cannot catch a feature `cloudfront-js-2.0` lacks.
- Never log or echo tokens, authorization codes or the client secret.
- `okta_client_secret` and the session key are ephemeral and written via `value_wo` (and the key also via the `local-exec` environment); never reference them anywhere else (no locals, outputs or `config.mjs`).
- Run before opening a PR:

```shell
node --test "lambda/test/*.test.mjs"
terraform init -backend=false && terraform validate && terraform test
pre-commit run -a
```
