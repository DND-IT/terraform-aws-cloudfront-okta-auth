import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { signSession } from "../auth.mjs";
import { NOW_MS, SESSION_KEY } from "./helpers.mjs";

const gateSource = readFileSync(new URL("../gate.js", import.meta.url), "utf8");
const nowSeconds = Math.floor(NOW_MS / 1000);

const CONFIG = {
  auth_prefix: "/_auth/",
  login_path: "/_auth/login",
  session_cookie: "__Host-okta_session",
  session_key_name: "session_key",
  host_header: "x-okta-auth-host",
};

function loadGate({ store = { session_key: SESSION_KEY }, rewrite = "function rewrite(request) { return request; }" } = {}) {
  const kvs = {
    get: async (key) => {
      if (!(key in store)) throw new Error("key not found");
      return store[key];
    },
  };
  const context = { CONFIG, kvs, crypto, Date: { now: () => NOW_MS } };
  vm.runInNewContext(`${rewrite}\n${gateSource}`, context);
  return context.handler;
}

function viewerEvent({ uri = "/page/", method = "GET", cookies = {}, querystring = {}, host = "site.example.com" } = {}) {
  return { request: { method, uri, querystring, headers: { host: { value: host } }, cookies } };
}

function sessionCookie(overrides = {}) {
  return { "__Host-okta_session": { value: signSession(SESSION_KEY, { exp: nowSeconds + 60, sub: "u", ...overrides }) } };
}

test("valid session passes the request through the rewrite", async () => {
  const handler = loadGate({ rewrite: "function rewrite(request) { request.uri = '/docs' + request.uri + 'index.html'; return request; }" });
  const res = await handler(viewerEvent({ cookies: sessionCookie() }));
  assert.equal(res.uri, "/docs/page/index.html");
});

test("missing session redirects to login with the requested path", async () => {
  const handler = loadGate();
  const res = await handler(viewerEvent({ uri: "/a/b/", querystring: { x: { value: "1" }, flag: { value: "" } } }));
  assert.equal(res.statusCode, 302);
  assert.equal(res.headers.location.value, `/_auth/login?r=${encodeURIComponent("/a/b/?x=1&flag")}`);
  assert.equal(res.headers["cache-control"].value, "no-store");
});

test("repeated query parameters survive the redirect", async () => {
  const handler = loadGate();
  const qs = { t: { value: "a", multiValue: [{ value: "a" }, { value: "b" }] } };
  const res = await handler(viewerEvent({ uri: "/s/", querystring: qs }));
  assert.equal(res.headers.location.value, `/_auth/login?r=${encodeURIComponent("/s/?t=a&t=b")}`);
});

const rejected = {
  expired: () => sessionCookie({ exp: nowSeconds }),
  "signed with another key": () => ({ "__Host-okta_session": { value: signSession("other", { exp: nowSeconds + 60 }) } }),
  "old ID token cookie": () => ({ "__Host-okta_session": { value: "aaa.bbb.ccc" } }),
  tampered: () => {
    const value = signSession(SESSION_KEY, { exp: nowSeconds + 60 }).replace(`.${nowSeconds + 60}.`, `.${nowSeconds + 9999}.`);
    return { "__Host-okta_session": { value } };
  },
};

for (const [name, make] of Object.entries(rejected)) {
  test(`${name} session redirects to login`, async () => {
    const res = await loadGate()(viewerEvent({ cookies: make() }));
    assert.equal(res.statusCode, 302);
  });
}

test("missing key in the store fails closed", async () => {
  const res = await loadGate({ store: {} })(viewerEvent({ cookies: sessionCookie() }));
  assert.equal(res.statusCode, 302);
});

test("non-GET without a session gets 401 instead of a redirect", async () => {
  const res = await loadGate()(viewerEvent({ method: "POST" }));
  assert.equal(res.statusCode, 401);
});

test("auth paths pass through unauthenticated with the viewer host attached", async () => {
  const handler = loadGate({ rewrite: "function rewrite(request) { throw new Error('rewrite must not run'); }" });
  for (const uri of ["/_auth/login", "/_auth/callback", "/_auth"]) {
    const res = await handler(viewerEvent({ uri }));
    assert.equal(res.uri, uri);
    assert.equal(res.headers["x-okta-auth-host"].value, "site.example.com");
  }
});
