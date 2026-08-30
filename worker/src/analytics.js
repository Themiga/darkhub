/**
 * DarkHub — analytics.js
 * Tracks script execution counts entirely server-side.
 * No code is injected into user scripts — counters live purely in KV.
 */

import { jsonResponse, requireAdminJWT, getCorsHeaders } from "./security.js";

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Returns the UTC date string "YYYY-MM-DD" for today.
 */
function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Increments execution counters for a given placeId.
 * Called internally by loader.js — not a public endpoint.
 */
export async function incrementExecution(placeId, env) {
  const pid = String(placeId);
  const today = todayKey();

  const totalKey = `analytics:total:${pid}`;
  const dailyKey = `analytics:daily:${pid}:${today}`;
  const lastSeenKey = `analytics:lastseen:${pid}`;

  // Read current totals
  const [totalRaw, dailyRaw] = await Promise.all([
    env.ANALYTICS_KV.get(totalKey),
    env.ANALYTICS_KV.get(dailyKey),
  ]);

  const total = totalRaw ? parseInt(totalRaw, 10) : 0;
  const daily = dailyRaw ? parseInt(dailyRaw, 10) : 0;

  // Write updated counts — daily entries expire after 90 days
  await Promise.all([
    env.ANALYTICS_KV.put(totalKey, String(total + 1)),
    env.ANALYTICS_KV.put(dailyKey, String(daily + 1), {
      expirationTtl: 60 * 60 * 24 * 90,
    }),
    env.ANALYTICS_KV.put(lastSeenKey, new Date().toISOString()),
  ]);
}

// ─── Admin endpoints ──────────────────────────────────────────────────────────

/**
 * GET /api/admin/analytics
 * Returns execution statistics for all scripts.
 * Requires: valid admin JWT.
 */
export async function adminGetAnalytics(request, env) {
  const cors = getCorsHeaders(request, env);
  const authResult = await requireAdminJWT(request, env);
  if (authResult instanceof Response) return authResult;

  const url = new URL(request.url);
  const placeId = url.searchParams.get("placeId");

  if (placeId) {
    // Single-script analytics with daily breakdown (last 30 days)
    return await getScriptAnalytics(placeId, env, cors);
  }

  // Summary for all scripts
  return await getSummaryAnalytics(env, cors);
}

async function getScriptAnalytics(placeId, env, cors) {
  const pid = String(placeId);
  const totalKey = `analytics:total:${pid}`;
  const lastSeenKey = `analytics:lastseen:${pid}`;

  const [totalRaw, lastSeen] = await Promise.all([
    env.ANALYTICS_KV.get(totalKey),
    env.ANALYTICS_KV.get(lastSeenKey),
  ]);

  const total = totalRaw ? parseInt(totalRaw, 10) : 0;

  // Collect daily breakdown for last 30 days
  const dailyData = [];
  const now = new Date();
  const dailyFetches = [];

  for (let i = 0; i < 30; i++) {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    dailyFetches.push({
      date: dateStr,
      key: `analytics:daily:${pid}:${dateStr}`,
    });
  }

  const results = await Promise.all(
    dailyFetches.map(async ({ date, key }) => ({
      date,
      count: parseInt((await env.ANALYTICS_KV.get(key)) || "0", 10),
    }))
  );

  return jsonResponse(
    {
      placeId: pid,
      total,
      lastSeen: lastSeen || null,
      daily: results.reverse(), // chronological order
    },
    200,
    cors
  );
}

async function getSummaryAnalytics(env, cors) {
  // List all analytics total keys
  const list = await env.ANALYTICS_KV.list({ prefix: "analytics:total:" });

  const summaries = await Promise.all(
    list.keys.map(async ({ name }) => {
      const pid = name.replace("analytics:total:", "");
      const [totalRaw, lastSeen] = await Promise.all([
        env.ANALYTICS_KV.get(name),
        env.ANALYTICS_KV.get(`analytics:lastseen:${pid}`),
      ]);
      return {
        placeId: pid,
        total: parseInt(totalRaw || "0", 10),
        lastSeen: lastSeen || null,
      };
    })
  );

  // Sort by total executions descending
  summaries.sort((a, b) => b.total - a.total);

  return jsonResponse({ analytics: summaries }, 200, cors);
}
