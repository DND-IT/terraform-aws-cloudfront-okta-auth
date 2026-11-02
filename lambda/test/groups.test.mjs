import { test } from "node:test";
import assert from "node:assert/strict";
import { verifySession } from "../auth.mjs";
import {
  callbackEvent,
  claims,
  config,
  cookieValue,
  location,
  makeEvent,
  makeHandler,
  makeKeyPair,
  NOW_MS,
  SESSION_KEY,
  signJwt,
  tokenRoute,
} from "./helpers.mjs";

const kp = makeKeyPair();
const nowSeconds = Math.floor(NOW_MS / 1000);
const overrides = { groups_table: "user-groups" };

function recorder() {
  const records = [];
  const fn = async (record) => {
    records.push(record);
  };
  fn.records = records;
  return fn;
}

test("login asks Okta for the groups scope when a groups table is set", async () => {
  const { handler } = makeHandler({ overrides });
  const url = new URL(location(await handler(makeEvent())));
  assert.equal(url.searchParams.get("scope"), "openid email profile groups");
});

test("callback records the ID token's groups and keeps them out of the session cookie", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1", email: "User@Example.com", groups: ["Everyone", "App Users"] }));
  const recordGroups = recorder();
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken), recordGroups, overrides });
  const res = await handler(callbackEvent());

  assert.equal(res.statusCode, 302);
  assert.deepEqual(recordGroups.records, [
    {
      email: "user@example.com",
      sub: "user-1",
      groups: ["Everyone", "App Users"],
      updatedAt: new Date(NOW_MS).toISOString(),
    },
  ]);
  const session = verifySession(SESSION_KEY, cookieValue(res, config.session_cookie), nowSeconds);
  assert.deepEqual(Object.keys(session).sort(), ["email", "exp", "sub"]);
});

test("callback records an empty list when the token has no groups claim", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1" }));
  const recordGroups = recorder();
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken), recordGroups, overrides });
  await handler(callbackEvent());
  assert.deepEqual(recordGroups.records[0].groups, []);
});

test("a failed groups write does not block the sign-in", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1", groups: ["Everyone"] }));
  const recordGroups = async () => {
    throw new Error("throttled");
  };
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken), recordGroups, overrides });
  const res = await handler(callbackEvent());
  assert.equal(res.statusCode, 302);
  assert.ok(cookieValue(res, config.session_cookie));
});

test("without a groups table nothing is recorded", async () => {
  const idToken = signJwt(kp.privateKey, claims({ nonce: "nonce1", groups: ["Everyone"] }));
  const recordGroups = recorder();
  const { handler } = makeHandler({ jwk: kp.jwk, routes: tokenRoute(idToken), recordGroups });
  const res = await handler(callbackEvent());
  assert.equal(res.statusCode, 302);
  assert.equal(recordGroups.records.length, 0);
});
