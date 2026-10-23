import { test } from "node:test";
import assert from "node:assert/strict";
import { signPayload, verifyPayload, verifySession } from "../auth.mjs";
import {
  callbackEvent,
  claims,
  CLIENT_SECRET,
  config,
  cookieValue,
  HOST,
  location,
  loginCookie,
  loginKey,
  makeHandler,
  makeKeyPair,
  NOW_MS,
  SESSION_KEY,
  setCookies,
  signJwt,
  tokenRoute,
} from "./helpers.mjs";

const kp = makeKeyPair();
const nowSeconds = Math.floor(NOW_MS / 1000);

test("successful callback sets a signed session cookie and redirects to the stored path", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1" }));
  const { handler, fetch } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent());

  assert.equal(res.statusCode, 302);
  assert.equal(location(res), "/return?x=1");
  const session = verifySession(SESSION_KEY, cookieValue(res, config.session_cookie), nowSeconds);
  assert.deepEqual(session, { exp: nowSeconds + config.session_ttl_seconds, sub: "user-1", email: "user@example.com" });
  const sessionCookie = setCookies(res).find((c) => c.startsWith(config.session_cookie));
  assert.match(sessionCookie, /Max-Age=28800; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
  assert.equal(cookieValue(res, config.id_token_cookie), idToken);
  assert.match(setCookies(res).find((c) => c.startsWith(config.id_token_cookie)), /Path=\/_auth\//);
  assert.equal(cookieValue(res, config.login_cookie), "");

  const tokenCall = fetch.calls.find((c) => c.url === config.token_endpoint);
  assert.equal(tokenCall.init.method, "POST");
  assert.equal(tokenCall.init.headers.authorization, `Basic ${Buffer.from(`${config.client_id}:${CLIENT_SECRET}`).toString("base64")}`);
  assert.equal(tokenCall.init.headers["content-type"], "application/x-www-form-urlencoded");
  const body = new URLSearchParams(tokenCall.init.body);
  assert.equal(body.get("grant_type"), "authorization_code");
  assert.equal(body.get("code"), "abc");
  assert.equal(body.get("code_verifier"), "verifier1");
  assert.equal(body.get("redirect_uri"), `https://${HOST}/_auth/callback`);
});

test("Okta error parameter yields 403 and clears the login cookie", async () => {
  const { handler, fetch } = makeHandler({ jwk: kp.jwk });
  const res = await handler(callbackEvent({ querystring: "error=access_denied&error_description=User+is+not+assigned&state=state1" }));
  assert.equal(res.statusCode, 403);
  assert.match(res.body, /access_denied: User is not assigned/);
  assert.equal(cookieValue(res, config.login_cookie), "");
  assert.equal(fetch.calls.length, 0);
});

const badRequests = {
  "missing login cookie": { cookie: null },
  "bad cookie signature": { cookie: loginCookie().slice(0, -3) + "abc" },
  "expired login state": { cookie: loginCookie({ t: nowSeconds - 601 }) },
  "state mismatch": { querystring: "code=abc&state=other" },
  "missing state": { querystring: "code=abc" },
  "missing code": { querystring: "state=state1" },
};

for (const [name, opts] of Object.entries(badRequests)) {
  test(`${name} yields 400 without calling Okta`, async () => {
    const { handler, fetch } = makeHandler({ jwk: kp.jwk });
    const res = await handler(callbackEvent(opts));
    assert.equal(res.statusCode, 400);
    assert.equal(cookieValue(res, config.login_cookie), "");
    assert.equal(fetch.calls.length, 0);
  });
}

test("POST to the callback is not allowed", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  assert.equal((await handler(callbackEvent({ method: "POST" }))).statusCode, 405);
});

for (const status of [400, 500]) {
  test(`token endpoint ${status} yields 502`, async () => {
    const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute("", status) });
    const res = await handler(callbackEvent());
    assert.equal(res.statusCode, 502);
    assert.equal(cookieValue(res, config.session_cookie), undefined);
  });
}

test("token endpoint network failure yields 502", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk, routes: { [config.token_endpoint]: new Error("ECONNRESET") } });
  assert.equal((await handler(callbackEvent())).statusCode, 502);
});

test("nonce mismatch yields 401", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "wrong" }));
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent());
  assert.equal(res.statusCode, 401);
  assert.equal(cookieValue(res, config.session_cookie), undefined);
});

test("ID token signed by an unknown key yields 401", async () => {
  const other = makeKeyPair("k1");
  const idToken = signJwt(other.privateKey, claims({ nonce: "nonce1" }));
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  assert.equal((await handler(callbackEvent())).statusCode, 401);
});

test("JWKS unreachable with an empty cache yields 503", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1" }));
  const { handler } = makeHandler({ routes: { ...tokenRoute(idToken), [config.jwks_endpoint]: new Error("ENOTFOUND") } });
  assert.equal((await handler(callbackEvent())).statusCode, 503);
});

test("oversized ID token still signs in but is not kept for logout", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1", groups: Array(200).fill("group-name-that-is-long") }));
  assert.ok(idToken.length > 3900);
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent());
  assert.equal(res.statusCode, 302);
  assert.ok(cookieValue(res, config.session_cookie));
  assert.equal(cookieValue(res, config.id_token_cookie), undefined);
});

test("stored return path is re-validated before redirecting", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1" }));
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken) });
  const res = await handler(callbackEvent({ cookie: loginCookie({ r: "//evil.com" }) }));
  assert.equal(location(res), "/");
});

test("verifyPayload round-trips signPayload", () => {
  assert.deepEqual(verifyPayload(loginKey, signPayload(loginKey, { a: 1 })), { a: 1 });
});
