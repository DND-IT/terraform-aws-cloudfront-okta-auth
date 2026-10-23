import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { b64url, sha256, verifyPayload } from "../auth.mjs";
import { CLIENT_SECRET, config, cookieValue, HOST, location, makeEvent, makeHandler, SESSION_KEY, setCookies } from "./helpers.mjs";

const loginKey = createHmac("sha256", SESSION_KEY).update("login-cookie-v1").digest();

test("login redirects to Okta authorize with PKCE and a signed login cookie", async () => {
  const { handler } = makeHandler();
  const res = await handler(makeEvent({ querystring: `r=${encodeURIComponent("/docs/page?a=1")}` }));
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers["cache-control"], "no-store");

  const url = new URL(location(res));
  assert.equal(`${url.origin}${url.pathname}`, config.authorize_endpoint);
  assert.equal(url.searchParams.get("client_id"), config.client_id);
  assert.equal(url.searchParams.get("redirect_uri"), `https://${HOST}/_auth/callback`);
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("scope"), "openid email profile");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");

  const cookies = setCookies(res);
  assert.equal(cookies.length, 1);
  assert.match(cookies[0], /^__Host-okta_login=.+; Max-Age=600; Path=\/; Secure; HttpOnly; SameSite=Lax$/);

  const login = verifyPayload(loginKey, cookieValue(res, config.login_cookie));
  assert.equal(login.s, url.searchParams.get("state"));
  assert.equal(login.n, url.searchParams.get("nonce"));
  assert.equal(b64url(sha256(login.v)), url.searchParams.get("code_challenge"));
  assert.equal(login.r, "/docs/page?a=1");
});

test("login without a return path returns to the site root", async () => {
  const { handler } = makeHandler();
  const login = verifyPayload(loginKey, cookieValue(await handler(makeEvent()), config.login_cookie));
  assert.equal(login.r, "/");
});

test("login rejects an off-site return path", async () => {
  const { handler } = makeHandler();
  const res = await handler(makeEvent({ querystring: `r=${encodeURIComponent("//evil.com")}` }));
  assert.equal(verifyPayload(loginKey, cookieValue(res, config.login_cookie)).r, "/");
});

test("state and nonce are distinct random values", async () => {
  const { handler } = makeHandler();
  const url = new URL(location(await handler(makeEvent())));
  assert.notEqual(url.searchParams.get("state"), url.searchParams.get("nonce"));
  assert.ok(url.searchParams.get("state").length >= 43);
});

test("tampered login cookie fails verification", async () => {
  const { handler } = makeHandler();
  const value = cookieValue(await handler(makeEvent()), config.login_cookie);
  assert.equal(verifyPayload(loginKey, value.slice(0, -2) + "xx"), null);
  assert.equal(verifyPayload(loginKey, "junk"), null);
});

test("HEAD is redirected like GET, other methods get 405", async () => {
  const { handler } = makeHandler();
  assert.equal((await handler(makeEvent({ method: "HEAD" }))).statusCode, 302);
  const post = await handler(makeEvent({ method: "POST" }));
  assert.equal(post.statusCode, 405);
  assert.equal(post.headers["content-type"], "text/plain; charset=utf-8");
});

test("secret fetch failure is retried on the next request", async () => {
  let attempts = 0;
  const { handler } = makeHandler({
    getSecrets: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("ssm down");
      return { clientSecret: CLIENT_SECRET, sessionKey: SESSION_KEY };
    },
  });
  assert.equal((await handler(makeEvent())).statusCode, 500);
  assert.equal((await handler(makeEvent())).statusCode, 302);
});

test("missing viewer host header is rejected", async () => {
  const { handler } = makeHandler();
  assert.equal((await handler(makeEvent({ host: null }))).statusCode, 400);
});

test("unknown auth paths are 404", async () => {
  const { handler } = makeHandler();
  assert.equal((await handler(makeEvent({ path: "/_auth/other" }))).statusCode, 404);
});
