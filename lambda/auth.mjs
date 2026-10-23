import {
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify as cryptoVerify,
} from "node:crypto";

const JWKS_TTL_MS = 60 * 60 * 1000;
const JWKS_MISS_INTERVAL_MS = 60 * 1000;
const JWKS_FETCH_TIMEOUT_MS = 3000;
const TOKEN_FETCH_TIMEOUT_MS = 5000;
const LOGIN_MAX_AGE_S = 600;
const MAX_TOKEN_LENGTH = 3900;
const MAX_RETURN_TO_LENGTH = 2048;
const AUTH_PREFIX = "/_auth/";
const SCOPE = "openid email profile";
const SESSION_VERSION = "v1";

export class AuthError extends Error {
  constructor(status, message, cookies = []) {
    super(message);
    this.status = status;
    this.cookies = cookies;
  }
}

export class TokenError extends Error {}

export function b64url(data) {
  return Buffer.from(data).toString("base64url");
}

export function sha256(data) {
  return createHash("sha256").update(data).digest();
}

export function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

export function parseCookies(cookieList) {
  const cookies = {};
  for (const entry of cookieList || []) {
    for (const part of entry.split(";")) {
      const trimmed = part.trim();
      const idx = trimmed.indexOf("=");
      if (idx <= 0) continue;
      const name = trimmed.slice(0, idx).trim();
      const value = trimmed.slice(idx + 1).trim();
      if (!(name in cookies)) cookies[name] = value;
    }
  }
  return cookies;
}

export function makeCookie(name, value, maxAge, path = "/") {
  return `${name}=${value}; Max-Age=${maxAge}; Path=${path}; Secure; HttpOnly; SameSite=Lax`;
}

export function clearCookie(name, path = "/") {
  return makeCookie(name, "", 0, path);
}

export function safeReturnTo(path) {
  if (typeof path !== "string" || path.length === 0 || path.length > MAX_RETURN_TO_LENGTH) return "/";
  if (!path.startsWith("/") || path.startsWith("//") || path.startsWith("/\\")) return "/";
  if (/[\\\x00-\x1f\x7f]/.test(path)) return "/";
  if (path === AUTH_PREFIX.slice(0, -1) || path.startsWith(AUTH_PREFIX)) return "/";
  return path;
}

export function signPayload(key, payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = createHmac("sha256", key).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export function verifyPayload(key, value) {
  if (typeof value !== "string") return null;
  const idx = value.indexOf(".");
  if (idx <= 0) return null;
  const body = value.slice(0, idx);
  const sig = value.slice(idx + 1);
  const expected = createHmac("sha256", key).update(body).digest("base64url");
  if (!safeEqual(sig, expected)) return null;
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export function signSession(key, { exp, ...claims }) {
  const signed = `${SESSION_VERSION}.${exp}.${b64url(JSON.stringify(claims))}`;
  return `${signed}.${createHmac("sha256", key).update(signed).digest("base64url")}`;
}

export function verifySession(key, value, nowSeconds) {
  if (typeof value !== "string") return null;
  const parts = value.split(".");
  if (parts.length !== 4 || parts[0] !== SESSION_VERSION) return null;
  const expected = createHmac("sha256", key).update(parts.slice(0, 3).join(".")).digest("base64url");
  if (!safeEqual(parts[3], expected)) return null;
  const exp = Number(parts[1]);
  if (!Number.isInteger(exp) || exp <= nowSeconds) return null;
  try {
    return { exp, ...JSON.parse(Buffer.from(parts[2], "base64url").toString("utf8")) };
  } catch {
    return null;
  }
}

function decodeJson(segment) {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  } catch {
    throw new TokenError("malformed token segment");
  }
}

export async function verifyJwt({ token, getKey, issuer, clientId, nonce, nowSeconds }) {
  if (typeof token !== "string") throw new TokenError("token missing");
  const parts = token.split(".");
  if (parts.length !== 3) throw new TokenError("token must have three segments");
  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);
  if (header.alg !== "RS256") throw new TokenError("unsupported alg");
  if (typeof header.kid !== "string" || header.kid.length === 0) throw new TokenError("kid missing");
  const key = await getKey(header.kid);
  if (!key) throw new TokenError("unknown kid");
  const ok = cryptoVerify(
    "sha256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    key,
    Buffer.from(parts[2], "base64url"),
  );
  if (!ok) throw new TokenError("bad signature");
  if (payload.iss !== issuer) throw new TokenError("iss mismatch");
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(clientId)) throw new TokenError("aud mismatch");
  if (typeof payload.exp !== "number" || payload.exp <= nowSeconds - 30) throw new TokenError("token expired");
  if (typeof payload.iat === "number" && payload.iat > nowSeconds + 300) throw new TokenError("iat in the future");
  if (nonce !== undefined && !safeEqual(payload.nonce || "", nonce)) throw new TokenError("nonce mismatch");
  return { header, payload };
}

export function redirect(location, cookies = []) {
  return { statusCode: 302, headers: { location, "cache-control": "no-store" }, cookies };
}

export function textResponse(status, message, cookies = []) {
  return {
    statusCode: status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    cookies,
    body: message,
  };
}

async function fetchSecretsFromSsm(config) {
  const { SSMClient, GetParametersCommand } = await import("@aws-sdk/client-ssm");
  const client = new SSMClient({});
  const out = await client.send(
    new GetParametersCommand({
      Names: [config.client_secret_parameter, config.session_key_parameter],
      WithDecryption: true,
    }),
  );
  const values = Object.fromEntries((out.Parameters || []).map((p) => [p.Name, p.Value]));
  const clientSecret = values[config.client_secret_parameter];
  const sessionKey = values[config.session_key_parameter];
  if (!clientSecret || !sessionKey) throw new Error("SSM parameters missing");
  return { clientSecret, sessionKey };
}

export function createHandler(config, deps = {}) {
  const fetchFn = deps.fetch || globalThis.fetch;
  const now = deps.now || (() => Date.now());
  const random = deps.random || ((n) => randomBytes(n));
  const getSecrets = deps.getSecrets || (() => fetchSecretsFromSsm(config));

  let secretsPromise = null;
  const jwks = { keys: new Map(), fetchedAt: 0, missAt: 0 };

  function secrets() {
    if (!secretsPromise) {
      secretsPromise = getSecrets()
        .then(({ clientSecret, sessionKey }) => ({
          clientSecret,
          sessionKey,
          loginKey: createHmac("sha256", sessionKey).update("login-cookie-v1").digest(),
        }))
        .catch((err) => {
          secretsPromise = null;
          throw err;
        });
    }
    return secretsPromise;
  }

  async function fetchJwks() {
    const res = await fetchFn(config.jwks_endpoint, { signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`JWKS fetch returned ${res.status}`);
    const body = await res.json();
    const keys = new Map();
    for (const jwk of body.keys || []) {
      if (jwk.kty === "RSA" && typeof jwk.kid === "string") {
        keys.set(jwk.kid, createPublicKey({ key: jwk, format: "jwk" }));
      }
    }
    jwks.keys = keys;
    jwks.fetchedAt = now();
  }

  async function getKey(kid) {
    const t = now();
    if (jwks.fetchedAt === 0 || t - jwks.fetchedAt > JWKS_TTL_MS) {
      try {
        await fetchJwks();
      } catch (err) {
        if (jwks.keys.size === 0) throw new AuthError(503, "Authentication service unavailable");
        console.error("JWKS refresh failed, using cached keys: " + err.message);
      }
    }
    if (jwks.keys.has(kid)) return jwks.keys.get(kid);
    if (t - jwks.missAt > JWKS_MISS_INTERVAL_MS) {
      jwks.missAt = t;
      try {
        await fetchJwks();
      } catch (err) {
        console.error("JWKS refresh for unknown kid failed: " + err.message);
      }
    }
    return jwks.keys.get(kid) || null;
  }

  function nowSeconds() {
    return Math.floor(now() / 1000);
  }

  function callbackUri(host) {
    return `https://${host}${config.callback_path}`;
  }

  async function startLogin(method, host, query) {
    if (method !== "GET" && method !== "HEAD") throw new AuthError(405, "Method not allowed");
    const state = b64url(random(32));
    const nonce = b64url(random(32));
    const verifier = b64url(random(32));
    const returnTo = safeReturnTo(query.get("r"));
    const { loginKey } = await secrets();
    const loginCookie = signPayload(loginKey, { s: state, n: nonce, v: verifier, r: returnTo, t: nowSeconds() });
    const params = new URLSearchParams({
      client_id: config.client_id,
      redirect_uri: callbackUri(host),
      response_type: "code",
      scope: SCOPE,
      state,
      nonce,
      code_challenge: b64url(sha256(verifier)),
      code_challenge_method: "S256",
    });
    return redirect(`${config.authorize_endpoint}?${params}`, [
      makeCookie(config.login_cookie, loginCookie, LOGIN_MAX_AGE_S),
    ]);
  }

  async function exchangeCode({ code, verifier, host }) {
    const { clientSecret } = await secrets();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUri(host),
      code_verifier: verifier,
    });
    let res;
    try {
      res = await fetchFn(config.token_endpoint, {
        method: "POST",
        headers: {
          authorization: `Basic ${Buffer.from(`${config.client_id}:${clientSecret}`).toString("base64")}`,
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: body.toString(),
        signal: AbortSignal.timeout(TOKEN_FETCH_TIMEOUT_MS),
      });
    } catch (err) {
      console.error("token endpoint unreachable: " + err.message);
      throw new AuthError(502, "Token exchange failed");
    }
    if (!res.ok) {
      console.error(`token endpoint returned ${res.status}`);
      throw new AuthError(502, "Token exchange failed");
    }
    const json = await res.json();
    if (typeof json.id_token !== "string") {
      console.error("token endpoint response has no id_token");
      throw new AuthError(502, "Token exchange failed");
    }
    return json.id_token;
  }

  async function handleCallback(method, host, query, cookies) {
    if (method !== "GET") throw new AuthError(405, "Method not allowed");
    const clearLogin = clearCookie(config.login_cookie);
    if (query.has("error")) {
      const detail = `${query.get("error")}: ${query.get("error_description") || ""}`.slice(0, 200);
      throw new AuthError(403, `Okta rejected the login (${detail})`, [clearLogin]);
    }
    const raw = cookies[config.login_cookie];
    if (!raw) throw new AuthError(400, "Missing login state", [clearLogin]);
    const { loginKey, sessionKey } = await secrets();
    const login = verifyPayload(loginKey, raw);
    if (!login) throw new AuthError(400, "Invalid login state", [clearLogin]);
    if (typeof login.t !== "number" || nowSeconds() - login.t > LOGIN_MAX_AGE_S) {
      throw new AuthError(400, "Login state expired", [clearLogin]);
    }
    const state = query.get("state");
    if (!state || !safeEqual(state, login.s)) throw new AuthError(400, "State mismatch", [clearLogin]);
    const code = query.get("code");
    if (!code) throw new AuthError(400, "Missing authorization code", [clearLogin]);

    const idToken = await exchangeCode({ code, verifier: login.v, host });
    let payload;
    try {
      ({ payload } = await verifyJwt({
        token: idToken,
        getKey,
        issuer: config.issuer,
        clientId: config.client_id,
        nonce: login.n,
        nowSeconds: nowSeconds(),
      }));
    } catch (err) {
      if (err instanceof TokenError) {
        console.error("id_token rejected: " + err.message);
        throw new AuthError(401, "Invalid ID token", [clearLogin]);
      }
      throw err;
    }
    const ttl = config.session_ttl_seconds;
    const session = signSession(sessionKey, { exp: nowSeconds() + ttl, sub: payload.sub, email: payload.email });
    const setCookies = [makeCookie(config.session_cookie, session, ttl), clearLogin];
    if (idToken.length <= MAX_TOKEN_LENGTH) {
      setCookies.push(makeCookie(config.id_token_cookie, idToken, ttl, AUTH_PREFIX));
    }
    return redirect(safeReturnTo(login.r), setCookies);
  }

  function handleLogout(host, cookies) {
    const clear = [clearCookie(config.session_cookie), clearCookie(config.id_token_cookie, AUTH_PREFIX)];
    const token = cookies[config.id_token_cookie];
    if (!token) return redirect("/", clear);
    const params = new URLSearchParams({
      id_token_hint: token,
      post_logout_redirect_uri: `https://${host}/`,
    });
    return redirect(`${config.logout_endpoint}?${params}`, clear);
  }

  async function route(event) {
    const headers = event.headers || {};
    const host = headers[config.host_header];
    if (!host) throw new AuthError(400, "Missing viewer host");
    const method = event.requestContext.http.method;
    const query = new URLSearchParams(event.rawQueryString || "");
    const cookies = parseCookies(event.cookies);
    if (event.rawPath === config.login_path) return startLogin(method, host, query);
    if (event.rawPath === config.callback_path) return handleCallback(method, host, query, cookies);
    if (event.rawPath === config.logout_path) return handleLogout(host, cookies);
    throw new AuthError(404, "Not found");
  }

  return async function handler(event) {
    try {
      return await route(event);
    } catch (err) {
      if (err instanceof AuthError) return textResponse(err.status, err.message, err.cookies);
      console.error("unhandled auth error: " + (err && err.message));
      return textResponse(500, "Authentication error");
    }
  };
}
