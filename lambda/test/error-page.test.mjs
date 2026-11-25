import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { errorPage } from "../auth.mjs";
import { callbackEvent, makeHandler, makeKeyPair } from "./helpers.mjs";

const kp = makeKeyPair();

test("an Okta rejection renders an HTML page with the detail and a way to sign in again", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const res = await handler(
    callbackEvent({
      querystring: "error=access_denied&error_description=User+is+not+assigned+to+the+client+application.&state=state1",
    }),
  );
  assert.equal(res.statusCode, 403);
  assert.equal(res.headers["content-type"], "text/html; charset=utf-8");
  assert.equal(res.headers["cache-control"], "no-store");
  assert.match(res.body, /<h1>Okta did not let you in<\/h1>/);
  assert.match(res.body, /access_denied: User is not assigned to the client application\./);
  assert.match(res.body, /href="\/_auth\/login"/);
});

test("the error description is escaped", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const payload = encodeURIComponent(`<script>alert("x")</script><a href='//evil'>`);
  const res = await handler(callbackEvent({ querystring: `error=access_denied&error_description=${payload}` }));
  assert.doesNotMatch(res.body, /<script>|<a href='/);
  assert.match(res.body, /&#60;script&#62;alert\(&#34;x&#34;\)&#60;\/script&#62;&#60;a href=&#39;\/\/evil&#39;&#62;/);
});

test("the CSP allows the page's own stylesheet and nothing else", () => {
  const res = errorPage(400, "Missing login state", "/_auth/login");
  const css = res.body.match(/<style>([\s\S]*?)<\/style>/)[1];
  const hash = createHash("sha256").update(css).digest("base64");
  const csp = res.headers["content-security-policy"];
  assert.match(csp, /default-src 'none'/);
  assert.ok(csp.includes(`style-src 'sha256-${hash}'`));
  assert.doesNotMatch(res.body, /<script/);
});

test("server errors and unknown statuses get generic copy", () => {
  assert.match(errorPage(502, "Token exchange failed", "/_auth/login").body, /<h1>Sign-in is unavailable<\/h1>/);
  assert.match(errorPage(418, "x", "/_auth/login").body, /<h1>Sign-in failed<\/h1>/);
});
