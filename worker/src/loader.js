/**
 * DarkHub — loader.js
 * Secure script delivery endpoint for the Luau Hub.
 *
 * Security layers:
 *  1. User-Agent must start with the expected prefix
 *  2. HMAC-SHA256 signature validated (30-second rolling window)
 *  3. Nonce must be unused (one-time use, stored in KV for 60s)
 *  4. PlaceId must have an enabled script
 *  5. Script is XOR-encrypted with a per-request key before transmission
 *  6. Analytics counter is incremented server-side (no code injection)
 *
 * The raw script source NEVER leaves this Worker in plaintext.
 */

import {
  blocked,
  jsonResponse,
  isHubUserAgent,
  verifyHubSignature,
  deriveXorKey,
  xorEncrypt,
  checkRateLimit,
  randomHex,
} from "./security.js";
import { getScriptByPlaceId } from "./scripts.js";
import { incrementExecution } from "./analytics.js";

// ─── Check endpoint (game supported?) ─────────────────────────────────────────

/**
 * POST /api/loader/check
 * Lightweight endpoint: tells the hub whether a game is supported,
 * without sending the script. Used for the "not supported" early abort.
 *
 * Body: { placeId, nonce, signature }
 */
export async function handleLoaderCheck(request, env) {
  // Validate User-Agent first
  if (!isHubUserAgent(request)) return blocked();

  // Rate limit (stricter)
  const rl = await checkRateLimit(request, env, true);
  if (rl) return rl;

  let body;
  try {
    body = await request.json();
  } catch {
    return blocked();
  }

  const { placeId, nonce, signature } = body || {};
  if (!placeId || !nonce || !signature) return blocked();

  // Validate HMAC signature
  const sigValid = await verifyHubSignature(signature, nonce, String(placeId), env);
  if (!sigValid) return blocked();

  // Check if game is supported (no analytics increment here)
  const script = await getScriptByPlaceId(String(placeId), env);

  return new Response(
    JSON.stringify({ supported: Boolean(script) }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

// ─── Main loader endpoint ─────────────────────────────────────────────────────

/**
 * POST /api/loader
 * Full script delivery with XOR encryption.
 *
 * Body: { placeId, nonce, signature, jobHash }
 * Response: { payload: "<hex-encoded XOR-encrypted script>", keyHint: "<hex nonce>" }
 */
export async function handleLoader(request, env, ctx) {
  // ── Layer 1: User-Agent check ──
  if (!isHubUserAgent(request)) return blocked();

  // ── Layer 2: Rate limit (strict) ──
  const rl = await checkRateLimit(request, env, true);
  if (rl) return rl;

  // ── Layer 3: Parse body ──
  let body;
  try {
    body = await request.json();
  } catch {
    return blocked();
  }

  const { placeId, nonce, signature, jobHash } = body || {};

  if (
    !placeId || !nonce || !signature ||
    typeof placeId !== "string" ||
    typeof nonce !== "string" ||
    typeof signature !== "string" ||
    !/^\d+$/.test(placeId) ||
    !/^[0-9a-f]{16,64}$/.test(nonce) ||
    !/^[0-9a-f]{32,128}$/.test(signature)
  ) {
    return blocked();
  }

  // ── Layer 4: HMAC signature validation ──
  const sigValid = await verifyHubSignature(signature, nonce, placeId, env);
  if (!sigValid) return blocked();

  // ── Layer 5: One-time nonce (replay attack prevention) ──
  const nonceKey = `nonce:${nonce}`;
  const nonceUsed = await env.NONCES_KV.get(nonceKey);
  if (nonceUsed) return blocked(); // Replay detected

  // Mark nonce as used (expires after 60 seconds)
  await env.NONCES_KV.put(nonceKey, "1", { expirationTtl: 60 });

  // ── Layer 6: Script lookup ──
  const result = await getScriptByPlaceId(placeId, env);
  if (!result) return blocked(404, "Game not supported.");

  const { source } = result;

  // ── Layer 7: XOR encrypt for transport ──
  // Key is derived from: HMAC(HUB_HMAC_SECRET, "xor:" + nonce + ":" + placeId)
  const xorKey = await deriveXorKey(nonce, placeId, env);
  const encrypted = xorEncrypt(source, xorKey);

  // Convert to hex string for JSON transport
  const payload = Array.from(encrypted)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // ── Layer 8: Increment analytics (non-blocking) ──
  // Use ctx.waitUntil so analytics don't delay the response
  ctx.waitUntil(incrementExecution(placeId, env));

  // Respond — no raw source, no key, no sensitive data
  return new Response(
    JSON.stringify({ payload, ok: true }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }
  );
}
