/**
 * DarkHub — auth.js
 * GitHub OAuth 2.0 flow + JWT session management.
 * Only the configured ADMIN_GITHUB_LOGIN account receives a valid JWT.
 */

import {
  signJWT,
  verifyJWT,
  blocked,
  jsonResponse,
  getCorsHeaders,
  randomHex,
} from "./security.js";

const GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL = "https://api.github.com/user";
const JWT_EXPIRY_SEC = 60 * 60 * 24; // 24 hours
const STATE_TTL_SEC = 300; // 5 minutes for OAuth state nonce

// ─── Step 1: Redirect to GitHub ───────────────────────────────────────────────

/**
 * GET /api/auth/github
 * Generates a random state nonce, stores it in KV, and redirects to GitHub.
 */
export async function handleGithubAuth(request, env) {
  const state = randomHex(16);

  // Store state nonce in KV with short TTL (prevents CSRF)
  await env.SESSIONS_KV.put(`oauth_state:${state}`, "1", {
    expirationTtl: STATE_TTL_SEC,
  });

  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: env.OAUTH_CALLBACK_URL,
    scope: "read:user",
    state,
  });

  return Response.redirect(`${GITHUB_AUTH_URL}?${params}`, 302);
}

// ─── Step 2: Handle GitHub Callback ──────────────────────────────────────────

/**
 * GET /api/auth/callback
 * Exchanges the OAuth code for a GitHub access token, fetches user info,
 * verifies the account is the configured admin, and issues a signed JWT.
 */
export async function handleGithubCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  // Validate CSRF state
  if (!code || !state) return blocked(400, "Missing OAuth parameters.");

  const storedState = await env.SESSIONS_KV.get(`oauth_state:${state}`);
  if (!storedState) return blocked(403, "Invalid or expired OAuth state.");

  // Consume the state (one-time use)
  await env.SESSIONS_KV.delete(`oauth_state:${state}`);

  // Exchange code for access token
  let accessToken;
  try {
    const tokenRes = await fetch(GITHUB_TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: env.OAUTH_CALLBACK_URL,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error("No access token");
    accessToken = tokenData.access_token;
  } catch {
    return blocked(502, "Failed to obtain GitHub access token.");
  }

  // Fetch GitHub user profile
  let user;
  try {
    const userRes = await fetch(GITHUB_USER_URL, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "User-Agent": "DarkHub-Server/1.0",
        Accept: "application/vnd.github+json",
      },
    });
    user = await userRes.json();
    if (!user.login) throw new Error("No user login");
  } catch {
    return blocked(502, "Failed to fetch GitHub user info.");
  }

  // ── CRITICAL: verify this is the admin account ──
  if (user.login !== env.ADMIN_GITHUB_LOGIN) {
    // Silently reject non-admin accounts
    return blocked(403);
  }

  // Issue JWT
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: String(user.id),
    login: user.login,
    avatar: user.avatar_url,
    name: user.name || user.login,
    iat: now,
    exp: now + JWT_EXPIRY_SEC,
    jti: randomHex(8), // unique token ID
  };

  const jwt = await signJWT(payload, env.JWT_SECRET);

  // Return JSON with token — the frontend callback page will pick this up
  return jsonResponse({ token: jwt, user: { login: user.login, name: payload.name, avatar: payload.avatar } });
}

// ─── Session Info ─────────────────────────────────────────────────────────────

/**
 * GET /api/auth/me
 * Returns the current admin's profile if the JWT is valid.
 */
export async function handleAuthMe(request, env) {
  const cors = getCorsHeaders(request, env);
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token) return blocked(401);

  try {
    const payload = await verifyJWT(token, env.JWT_SECRET);
    if (payload.login !== env.ADMIN_GITHUB_LOGIN) return blocked(403);
    return jsonResponse(
      { login: payload.login, name: payload.name, avatar: payload.avatar, exp: payload.exp },
      200,
      cors
    );
  } catch {
    return blocked(401);
  }
}

/**
 * POST /api/auth/logout
 * Client-side JWT deletion is sufficient; this endpoint exists for completeness.
 */
export async function handleLogout(request, env) {
  const cors = getCorsHeaders(request, env);
  return jsonResponse({ ok: true }, 200, cors);
}
