import { test } from "node:test";
import assert from "node:assert/strict";
import { clearCookie, makeCookie, parseCookies, signSession, verifySession } from "../auth.mjs";

test("parseCookies merges cookie entries and keeps the first duplicate", () => {
  assert.deepEqual(parseCookies(["a=1; b=two", "c=3", "a=ignored"]), { a: "1", b: "two", c: "3" });
});

test("parseCookies tolerates a missing list and malformed parts", () => {
  assert.deepEqual(parseCookies(undefined), {});
  assert.deepEqual(parseCookies(["novalue", "=x", "ok=1"]), { ok: "1" });
});

test("makeCookie sets hardened attributes", () => {
  assert.equal(makeCookie("n", "v", 60), "n=v; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Lax");
  assert.equal(clearCookie("n"), "n=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax");
  assert.equal(clearCookie("n", "/_auth/"), "n=; Max-Age=0; Path=/_auth/; Secure; HttpOnly; SameSite=Lax");
});

test("session round-trips and carries its claims", () => {
  const value = signSession("k", { exp: 2000, sub: "s", email: "e@x" });
  assert.match(value, /^v1\.2000\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.deepEqual(verifySession("k", value, 1000), { exp: 2000, sub: "s", email: "e@x" });
});

test("session is rejected when expired, tampered, signed with another key or malformed", () => {
  const value = signSession("k", { exp: 2000, sub: "s" });
  const [v, exp, body, sig] = value.split(".");
  assert.equal(verifySession("k", value, 2000), null);
  assert.equal(verifySession("other", value, 1000), null);
  assert.equal(verifySession("k", `${v}.9999.${body}.${sig}`, 1000), null);
  assert.equal(verifySession("k", `v2.${exp}.${body}.${sig}`, 1000), null);
  assert.equal(verifySession("k", "a.b.c", 1000), null);
  assert.equal(verifySession("k", undefined, 1000), null);
});
