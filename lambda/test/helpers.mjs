import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { b64url, createHandler, signPayload } from "../auth.mjs";

export const config = {
  issuer: "https://acme.okta.com",
  client_id: "0oa123",
  authorize_endpoint: "https://acme.okta.com/oauth2/v1/authorize",
  token_endpoint: "https://acme.okta.com/oauth2/v1/token",
  jwks_endpoint: "https://acme.okta.com/oauth2/v1/keys",
  logout_endpoint: "https://acme.okta.com/oauth2/v1/logout",
  login_path: "/_auth/login",
  callback_path: "/_auth/callback",
  logout_path: "/_auth/logout",
  client_secret_parameter: "/test/okta-client-secret",
  session_key_parameter: "/test/session-key",
  session_cookie: "__Host-okta_session",
  login_cookie: "__Host-okta_login",
  id_token_cookie: "__Secure-okta_id_token",
  session_ttl_seconds: 28800,
  host_header: "x-okta-auth-host",
};

export const CLIENT_SECRET = "s3cret";
export const SESSION_KEY = "session-key-0123456789";
export const HOST = "site.example.com";
export const NOW_MS = 1_800_000_000_000;

export function makeKeyPair(kid = "k1") {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" };
  return { publicKey, privateKey, jwk, kid };
}

export function signJwt(privateKey, payload, header = {}) {
  const h = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "k1", ...header }));
  const p = b64url(JSON.stringify(payload));
  const sig = sign("sha256", Buffer.from(`${h}.${p}`), privateKey).toString("base64url");
  return `${h}.${p}.${sig}`;
}

export function claims(overrides = {}) {
  const nowS = Math.floor(NOW_MS / 1000);
  return {
    iss: config.issuer,
    aud: config.client_id,
    sub: "user-1",
    email: "user@example.com",
    iat: nowS - 10,
    exp: nowS + 3600,
    ...overrides,
  };
}

export function makeEvent({ path = "/_auth/login", querystring = "", method = "GET", host = HOST, cookies = [] } = {}) {
  const headers = { host: "abc.lambda-url.eu-central-1.on.aws" };
  if (host) headers[config.host_header] = host;
  const event = { rawPath: path, rawQueryString: querystring, headers, requestContext: { http: { method } } };
  if (cookies.length > 0) event.cookies = cookies;
  return event;
}

export function fakeFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    calls.push({ url, init });
    const route = routes[url];
    if (!route) throw new Error(`unexpected fetch ${url}`);
    const result = typeof route === "function" ? await route(init) : route;
    if (result instanceof Error) throw result;
    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      json: async () => result.body,
    };
  };
  fn.calls = calls;
  return fn;
}

export function makeHandler({ jwk, routes = {}, now, random, getSecrets } = {}) {
  const clock = { ms: NOW_MS };
  const fetch = fakeFetch({
    [config.jwks_endpoint]: { status: 200, body: { keys: jwk ? [jwk] : [] } },
    ...routes,
  });
  let counter = 0;
  const handler = createHandler(config, {
    fetch,
    now: now || (() => clock.ms),
    random: random || ((n) => Buffer.alloc(n, ++counter)),
    getSecrets: getSecrets || (async () => ({ clientSecret: CLIENT_SECRET, sessionKey: SESSION_KEY })),
  });
  return { handler, fetch, clock };
}

export function setCookies(response) {
  return response.cookies || [];
}

export function cookieValue(response, name) {
  const cookie = setCookies(response).find((c) => c.startsWith(`${name}=`));
  return cookie ? cookie.slice(name.length + 1, cookie.indexOf(";")) : undefined;
}

export function location(response) {
  return response.headers.location;
}

export const loginKey = createHmac("sha256", SESSION_KEY).update("login-cookie-v1").digest();

export function loginCookie(overrides = {}) {
  const t = Math.floor(NOW_MS / 1000) - 5;
  return signPayload(loginKey, { s: "state1", n: "nonce1", v: "verifier1", r: "/return?x=1", t, ...overrides });
}

export function callbackEvent({ querystring = "code=abc&state=state1", cookie = loginCookie(), method = "GET" } = {}) {
  return makeEvent({ path: config.callback_path, querystring, method, cookies: cookie ? [`${config.login_cookie}=${cookie}`] : [] });
}

export function tokenRoute(idToken, status = 200) {
  return { [config.token_endpoint]: { status, body: status === 200 ? { id_token: idToken, token_type: "Bearer" } : { error: "invalid_grant" } } };
}
