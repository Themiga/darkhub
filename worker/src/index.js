/**
 * DarkHub — index.js
 * Main Cloudflare Worker entry point.
 * All requests pass through security middleware before reaching any handler.
 */

import { handleGithubAuth, handleGithubCallback, handleAuthMe, handleLogout } from "./auth.js";
import {
  adminListScripts,
  adminGetScript,
  adminCreateScript,
  adminUpdateScript,
  adminDeleteScript,
} from "./scripts.js";
import { adminGetAnalytics } from "./analytics.js";
import { handleLoader, handleLoaderCheck } from "./loader.js";
import {
  blocked,
  handleCORS,
  checkRateLimit,
  getCorsHeaders,
} from "./security.js";

// ─── Main fetch handler ───────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // ── Preflight ──
    if (method === "OPTIONS") return handleCORS(request, env);

    // ── Global rate limit (applied to all non-OPTIONS requests) ──
    // The loader has its own stricter rate limit inside its handler.
    if (!path.startsWith("/api/loader")) {
      const rl = await checkRateLimit(request, env, false);
      if (rl) return rl;
    }

    // ── Route table ──
    try {
      // Auth routes
      if (path === "/api/auth/github" && method === "GET")
        return handleGithubAuth(request, env);

      if (path === "/api/auth/callback" && method === "GET")
        return handleGithubCallback(request, env);

      if (path === "/api/auth/me" && method === "GET")
        return handleAuthMe(request, env);

      if (path === "/api/auth/logout" && method === "POST")
        return handleLogout(request, env);

      // Admin — Scripts
      if (path === "/api/admin/scripts") {
        if (method === "GET") return adminListScripts(request, env);
        if (method === "POST") return adminCreateScript(request, env);
        return blocked(405);
      }

      const scriptMatch = path.match(/^\/api\/admin\/scripts\/([a-f0-9]{16})$/);
      if (scriptMatch) {
        const id = scriptMatch[1];
        if (method === "GET") return adminGetScript(request, env, id);
        if (method === "PUT") return adminUpdateScript(request, env, id);
        if (method === "DELETE") return adminDeleteScript(request, env, id);
        return blocked(405);
      }

      // Admin — Analytics
      if (path === "/api/admin/analytics" && method === "GET")
        return adminGetAnalytics(request, env);

      // Loader (Luau Hub)
      if (path === "/api/loader" && method === "POST")
        return handleLoader(request, env, ctx);

      if (path === "/api/loader/check" && method === "POST")
        return handleLoaderCheck(request, env);

      // Health check (no sensitive data)
      if (path === "/api/health" && method === "GET")
        return new Response(JSON.stringify({ ok: true }), {
          headers: { "Content-Type": "application/json" },
        });

      // ── Catch-all: block everything else ──
      return blocked();
    } catch (err) {
      // Never leak error details to the client
      console.error("Unhandled Worker error:", err);
      return blocked(500, "Internal server error.");
    }
  },
};
