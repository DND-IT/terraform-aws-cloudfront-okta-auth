function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function sessionIsValid(cookie) {
  if (!cookie) return false;
  var parts = cookie.value.split(".");
  if (parts.length !== 4 || parts[0] !== "v1") return false;
  var exp = Number(parts[1]);
  if (!(exp > Date.now() / 1000)) return false;
  var key;
  try {
    key = await kvs.get(CONFIG.session_key_name);
  } catch (e) {
    return false;
  }
  var expected = crypto.createHmac("sha256", key).update(parts[0] + "." + parts[1] + "." + parts[2]).digest("base64url");
  return constantTimeEqual(expected, parts[3]);
}

function requestPath(request) {
  var pairs = [];
  var qs = request.querystring || {};
  for (var name in qs) {
    var entries = qs[name].multiValue || [qs[name]];
    for (var i = 0; i < entries.length; i++) {
      pairs.push(entries[i].value === "" ? name : name + "=" + entries[i].value);
    }
  }
  return pairs.length > 0 ? request.uri + "?" + pairs.join("&") : request.uri;
}

async function handler(event) {
  var request = event.request;
  if (request.uri === CONFIG.auth_prefix.slice(0, -1) || request.uri.startsWith(CONFIG.auth_prefix)) {
    request.headers[CONFIG.host_header] = { value: request.headers.host ? request.headers.host.value : "" };
    return request;
  }
  if (await sessionIsValid(request.cookies[CONFIG.session_cookie])) return rewrite(request);
  if (request.method !== "GET" && request.method !== "HEAD") {
    return {
      statusCode: 401,
      statusDescription: "Unauthorized",
      headers: { "cache-control": { value: "no-store" }, "content-type": { value: "text/plain; charset=utf-8" } },
      body: "Authentication required",
    };
  }
  return {
    statusCode: 302,
    statusDescription: "Found",
    headers: {
      "cache-control": { value: "no-store" },
      location: { value: CONFIG.login_path + "?r=" + encodeURIComponent(requestPath(request)) },
    },
  };
}
