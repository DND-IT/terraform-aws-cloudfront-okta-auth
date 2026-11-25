import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { errorPageCsp, renderErrorPage } from "../auth.mjs";
import { callbackEvent, makeEvent, makeHandler, makeKeyPair } from "./helpers.mjs";

const kp = makeKeyPair();

function styleHash(html) {
  const css = html.match(/<style>([\s\S]*?)<\/style>/)[1];
  return `'sha256-${createHash("sha256").update(css).digest("base64")}'`;
}

test("an Okta rejection renders the default page with the detail and a way to sign in again", async () => {
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
  assert.doesNotMatch(res.body, /\{\{/);
});

test("the error description is escaped", async () => {
  const { handler } = makeHandler({ jwk: kp.jwk });
  const payload = encodeURIComponent(`<script>alert("x")</script><a href='//evil'>{{title}}`);
  const res = await handler(callbackEvent({ querystring: `error=access_denied&error_description=${payload}` }));
  assert.doesNotMatch(res.body, /<script>|<a href='/);
  assert.match(res.body, /&#60;script&#62;alert\(&#34;x&#34;\)&#60;\/script&#62;&#60;a href=&#39;\/\/evil&#39;&#62;\{\{title\}\}/);
});

test("the CSP allows the default page's own stylesheet and nothing else", async () => {
  const { handler } = makeHandler();
  const res = await handler(makeEvent({ method: "POST" }));
  const csp = res.headers["content-security-policy"];
  assert.match(csp, /default-src 'none'/);
  assert.ok(csp.includes(`style-src ${styleHash(res.body)}`));
  assert.doesNotMatch(res.body, /<script/);
});

test("a custom template replaces the page and gets its own style hash", async () => {
  const template = `<html><head><style>h1{color:red}</style></head><body><h1>{{title}}</h1><p>{{status}} {{hint}} {{message}} {{login_path}} {{other}}</p></body></html>`;
  const { handler } = makeHandler({ overrides: { error_page_template: template } });
  const res = await handler(makeEvent({ method: "POST" }));
  assert.equal(res.statusCode, 405);
  assert.equal(
    res.body,
    "<html><head><style>h1{color:red}</style></head><body><h1>Method not allowed</h1><p>405 Open this address in a browser. Method not allowed /_auth/login {{other}}</p></body></html>",
  );
  assert.ok(res.headers["content-security-policy"].includes(`style-src ${styleHash(template)}`));
});

test("a template without styles gets no style-src", () => {
  assert.doesNotMatch(errorPageCsp("<p>{{message}}</p>"), /style-src/);
});

test("server errors get generic copy and template values are escaped", async () => {
  const { handler } = makeHandler({ getSecrets: async () => { throw new Error("ssm down"); } });
  assert.match((await handler(makeEvent())).body, /<h1>Sign-in is unavailable<\/h1>/);
  assert.equal(renderErrorPage("{{title}}", { title: "<b>" }), "&#60;b&#62;");
});
