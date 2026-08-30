/**
 * DarkHub — security.js
 * Rate limiting, CORS enforcement, anti-bypass and request validation.
 * All protections run before any route handler is reached.
 */

// ─── Constants ───────────────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_SEC = 60;
const RATE_LIMIT_MAX_REQUESTS = 30;
const RATE_LIMIT_LOADER_MAX = 10; // stricter for the loader endpoint
const BLOCKED_BODY = "You are not welcome in this area.";

// Expected User-Agent prefix for the Luau hub loader
// The real fingerprint also includes a rolling segment validated in loader.js
const LOADER_UA_PREFIX = "DarkHub/1.0 RobloxGameClient";

// ─── CORS ────────────────────────────────────────────────────────────────────

/**
 * Returns the CORS headers for a given request.
 * Only allows requests from the configured frontend origin and the Worker itself.
 */
export function getCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = [
    env.FRONTEND_ORIGIN,
    env.WORKER_ORIGIN,
  ];

  if (allowed.some((o) => origin === o)) {
    return {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers":
        "Content-Type, Authorization, X-Hub-Signature, X-Hub-Nonce",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    };
  }

  // Unknown origin: return no CORS header → browser blocks the request
  return {
    "Vary": "Origin",
  };
}

/**
 * Handles OPTIONS preflight requests.
 */
export function handleCORS(request, env) {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(request, env),
  });
}

// ─── Rate Limiting ───────────────────────────────────────────────────────────

/**
 * Returns the real connecting IP, preferring Cloudflare's trusted header.
 */
export function getClientIP(request) {
  // CF-Connecting-IP is set by Cloudflare infrastructure, not spoofable
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Real-IP") ||
    "unknown"
  );
}

/**
 * Enforces rate limiting per IP using KV with a sliding window counter.
 * Returns a 429 Response if the limit is exceeded, otherwise null.
 */
export async function checkRateLimit(request, env, isLoader = false) {
  const ip = getClientIP(request);
  const max = isLoader ? RATE_LIMIT_LOADER_MAX : RATE_LIMIT_MAX_REQUESTS;
  const key = `rl:${isLoader ? "loader" : "api"}:${ip}`;

  const current = await env.RATELIMIT_KV.get(key);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= max) {
    return blocked(429, "Rate limit exceeded. Try again later.");
  }

  // Increment counter — first request sets TTL for the window
  await env.RATELIMIT_KV.put(key, String(count + 1), {
    expirationTtl: RATE_LIMIT_WINDOW_SEC,
  });

  return null;
}

// ─── JWT Utilities ───────────────────────────────────────────────────────────

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64urlEncode(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64urlDecode(str) {
  const padded = str + "===".slice((str.length + 3) % 4);
  return Uint8Array.from(atob(padded.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0)
  );
}

/**
 * Signs and returns a JWT HS256 token.
 */
export async function signJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = b64urlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = b64urlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  const sigB64 = b64urlEncode(new Uint8Array(sig));

  return `${data}.${sigB64}`;
}

/**
 * Verifies a JWT HS256 token. Returns the payload if valid, throws otherwise.
 */
export async function verifyJWT(token, secret) {
  if (!token || typeof token !== "string") throw new Error("Missing token");

  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed token");

  const [headerB64, payloadB64, sigB64] = parts;
  const data = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const sigBytes = b64urlDecode(sigB64);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes,
    encoder.encode(data)
  );

  if (!valid) throw new Error("Invalid signature");

  const payload = JSON.parse(decoder.decode(b64urlDecode(payloadB64)));

  if (payload.exp && Date.now() / 1000 > payload.exp) {
    throw new Error("Token expired");
  }

  return payload;
}

/**
 * Extracts and verifies the Bearer JWT from the Authorization header.
 * Returns the payload or a 403 Response.
 */
export async function requireAdminJWT(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token) return blocked(403);

  try {
    const payload = await verifyJWT(token, env.JWT_SECRET);

    // Must be the configured admin account
    if (payload.login !== env.ADMIN_GITHUB_LOGIN) return blocked(403);

    return payload;
  } catch {
    return blocked(403);
  }
}

// ─── HMAC Signature (for Hub Loader) ─────────────────────────────────────────

/**
 * Verifies the Hub HMAC-SHA256 signature sent by the Luau loader.
 * signature = HMAC-SHA256(HUB_HMAC_SECRET, nonce + placeId + windowTs)
 */
export async function verifyHubSignature(
  signature,
  nonce,
  placeId,
  env
) {
  const windowTs = Math.floor(Date.now() / 30000); // 30-second window

  // Accept current and previous window to handle clock drift
  for (const ts of [windowTs, windowTs - 1]) {
    const message = `${nonce}:${placeId}:${ts}`;
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.HUB_HMAC_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
    const expected = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (timingSafeEqual(expected, signature)) return true;
  }

  return false;
}

/**
 * Derives a per-request XOR keystream using HMAC-SHA256.
 * Used to encrypt the script payload before sending to the Luau hub.
 */
export async function deriveXorKey(nonce, placeId, env) {
  const message = `xor:${nonce}:${placeId}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.HUB_HMAC_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return new Uint8Array(sig); // 32-byte key
}

/**
 * XORs a string against a Uint8Array key (repeating key as needed).
 */
export function xorEncrypt(plaintext, key) {
  const data = encoder.encode(plaintext);
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ key[i % key.length];
  }
  return result;
}

// ─── AES-GCM for KV Storage ──────────────────────────────────────────────────

/**
 * Encrypts plaintext using AES-256-GCM with the AES_ENCRYPTION_KEY secret.
 * Returns base64-encoded IV + ciphertext.
 */
export async function aesEncrypt(plaintext, env) {
  const keyBytes = encoder.encode(env.AES_ENCRYPTION_KEY.slice(0, 32).padEnd(32, "0"));
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(plaintext)
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypts an AES-256-GCM ciphertext (base64 IV + cipher) using the stored key.
 */
export async function aesDecrypt(encoded, env) {
  const combined = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const keyBytes = encoder.encode(env.AES_ENCRYPTION_KEY.slice(0, 32).padEnd(32, "0"));
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return decoder.decode(plain);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Constant-time string comparison to prevent timing attacks.
 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Returns the standard "blocked" response with no information leakage.
 */
export function blocked(status = 403, message = BLOCKED_BODY) {
  return new Response(message, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}

/**
 * Returns a JSON response with CORS headers.
 */
export function jsonResponse(data, status = 200, corsHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders,
    },
  });
}

/**
 * Validates that the request User-Agent starts with the expected Hub prefix.
 * Does NOT fully validate — full validation happens in loader.js via HMAC.
 */
export function isHubUserAgent(request) {
  const ua = request.headers.get("User-Agent") || "";
  return ua.startsWith(LOADER_UA_PREFIX);
}

/**
 * Generates a cryptographically random hex string of the given byte length.
 */
export function randomHex(bytes = 16) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
