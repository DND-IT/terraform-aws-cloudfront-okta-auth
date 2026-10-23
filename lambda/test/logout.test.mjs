import { test } from "node:test";
import assert from "node:assert/strict";
import { claims, config, cookieValue, HOST, location, makeEvent, makeHandler, makeKeyPair, setCookies, signJwt } from "./helpers.mjs";

const kp = makeKeyPair();

test("logout clears both cookies and redirects to Okta with id_token_hint", async () => {
  const { handler } = makeHandler();
  const token = signJwt(kp.privateKey, claims());
  const res = await handler(makeEvent({ path: config.logout_path, cookies: [`${config.id_token_cookie}=${token}`] }));
  assert.equal(res.statusCode, 302);
  const url = new URL(location(res));
  assert.equal(`${url.origin}${url.pathname}`, config.logout_endpoint);
  assert.equal(url.searchParams.get("id_token_hint"), token);
  assert.equal(url.searchParams.get("post_logout_redirect_uri"), `https://${HOST}/`);
  assert.equal(cookieValue(res, config.session_cookie), "");
  assert.ok(setCookies(res).includes(`${config.id_token_cookie}=; Max-Age=0; Path=/_auth/; Secure; HttpOnly; SameSite=Lax`));
});

test("logout without an ID token clears the session and returns to the site root", async () => {
  const { handler } = makeHandler();
  const res = await handler(makeEvent({ path: config.logout_path }));
  assert.equal(location(res), "/");
  assert.equal(cookieValue(res, config.session_cookie), "");
});
