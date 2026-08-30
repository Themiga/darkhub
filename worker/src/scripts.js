/**
 * DarkHub — scripts.js
 * Admin CRUD for scripts stored in Cloudflare KV.
 * Script source is always stored AES-GCM encrypted — never in plaintext.
 */

import {
  blocked,
  jsonResponse,
  getCorsHeaders,
  requireAdminJWT,
  aesEncrypt,
  aesDecrypt,
  randomHex,
} from "./security.js";

// ─── List ─────────────────────────────────────────────────────────────────────

/**
 * GET /api/admin/scripts
 * Returns metadata for all scripts. Source is NOT included in list responses.
 */
export async function adminListScripts(request, env) {
  const cors = getCorsHeaders(request, env);
  const authResult = await requireAdminJWT(request, env);
  if (authResult instanceof Response) return authResult;

  const list = await env.SCRIPTS_KV.list({ prefix: "script:meta:" });

  const scripts = await Promise.all(
    list.keys.map(async ({ name }) => {
      const raw = await env.SCRIPTS_KV.get(name);
      if (!raw) return null;
      return JSON.parse(raw);
    })
  );

  return jsonResponse(
    { scripts: scripts.filter(Boolean) },
    200,
    cors
  );
}

// ─── Get Single Script (with source for editing) ──────────────────────────────

/**
 * GET /api/admin/scripts/:id
 * Returns full script metadata + decrypted source for the admin editor.
 */
export async function adminGetScript(request, env, id) {
  const cors = getCorsHeaders(request, env);
  const authResult = await requireAdminJWT(request, env);
  if (authResult instanceof Response) return authResult;

  const meta = await env.SCRIPTS_KV.get(`script:meta:${id}`);
  if (!meta) return jsonResponse({ error: "Script not found." }, 404, cors);

  const metaObj = JSON.parse(meta);
  const encryptedSource = await env.SCRIPTS_KV.get(`script:source:${id}`);

  let source = "";
  if (encryptedSource) {
    try {
      source = await aesDecrypt(encryptedSource, env);
    } catch {
      source = "// [Decryption error — re-save the script to fix this]";
    }
  }

  return jsonResponse({ ...metaObj, source }, 200, cors);
}

// ─── Create ──────────────────────────────────────────────────────────────────

/**
 * POST /api/admin/scripts
 * Creates a new script entry. Source is encrypted before storage.
 * Body: { name, placeId, description, source, enabled }
 */
export async function adminCreateScript(request, env) {
  const cors = getCorsHeaders(request, env);
  const authResult = await requireAdminJWT(request, env);
  if (authResult instanceof Response) return authResult;

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body." }, 400, cors);
  }

  const { name, placeId, description = "", source = "", enabled = true } = body;

  if (!name || !placeId || !source) {
    return jsonResponse({ error: "name, placeId, and source are required." }, 400, cors);
  }

  // Validate placeId is numeric
  if (!/^\d+$/.test(String(placeId))) {
    return jsonResponse({ error: "placeId must be numeric." }, 400, cors);
  }

  const id = randomHex(8);
  const now = new Date().toISOString();

  const meta = {
    id,
    name: String(name).slice(0, 100),
    placeId: String(placeId),
    description: String(description).slice(0, 500),
    enabled: Boolean(enabled),
    createdAt: now,
    updatedAt: now,
  };

  // Encrypt source before writing to KV
  const encryptedSource = await aesEncrypt(String(source), env);

  await Promise.all([
    env.SCRIPTS_KV.put(`script:meta:${id}`, JSON.stringify(meta)),
    env.SCRIPTS_KV.put(`script:source:${id}`, encryptedSource),
    // Index by placeId for O(1) lookup from the loader
    env.SCRIPTS_KV.put(`script:byplace:${placeId}`, id),
  ]);

  return jsonResponse({ ok: true, script: meta }, 201, cors);
}

// ─── Update ───────────────────────────────────────────────────────────────────

/**
 * PUT /api/admin/scripts/:id
 * Updates an existing script's metadata and/or source.
 * Body: { name?, placeId?, description?, source?, enabled? }
 */
export async function adminUpdateScript(request, env, id) {
  const cors = getCorsHeaders(request, env);
  const authResult = await requireAdminJWT(request, env);
  if (authResult instanceof Response) return authResult;

  const metaRaw = await env.SCRIPTS_KV.get(`script:meta:${id}`);
  if (!metaRaw) return jsonResponse({ error: "Script not found." }, 404, cors);

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body." }, 400, cors);
  }

  const existing = JSON.parse(metaRaw);
  const oldPlaceId = existing.placeId;

  const updated = {
    ...existing,
    name: body.name !== undefined ? String(body.name).slice(0, 100) : existing.name,
    placeId: body.placeId !== undefined ? String(body.placeId) : existing.placeId,
    description:
      body.description !== undefined
        ? String(body.description).slice(0, 500)
        : existing.description,
    enabled: body.enabled !== undefined ? Boolean(body.enabled) : existing.enabled,
    updatedAt: new Date().toISOString(),
  };

  if (body.placeId !== undefined && !/^\d+$/.test(String(body.placeId))) {
    return jsonResponse({ error: "placeId must be numeric." }, 400, cors);
  }

  const writes = [
    env.SCRIPTS_KV.put(`script:meta:${id}`, JSON.stringify(updated)),
  ];

  // Re-encrypt if source was provided
  if (body.source !== undefined) {
    const encryptedSource = await aesEncrypt(String(body.source), env);
    writes.push(env.SCRIPTS_KV.put(`script:source:${id}`, encryptedSource));
  }

  // Update placeId index if it changed
  if (body.placeId !== undefined && body.placeId !== oldPlaceId) {
    writes.push(env.SCRIPTS_KV.delete(`script:byplace:${oldPlaceId}`));
    writes.push(env.SCRIPTS_KV.put(`script:byplace:${updated.placeId}`, id));
  }

  await Promise.all(writes);

  return jsonResponse({ ok: true, script: updated }, 200, cors);
}

// ─── Delete ───────────────────────────────────────────────────────────────────

/**
 * DELETE /api/admin/scripts/:id
 * Permanently removes a script and its placeId index entry.
 */
export async function adminDeleteScript(request, env, id) {
  const cors = getCorsHeaders(request, env);
  const authResult = await requireAdminJWT(request, env);
  if (authResult instanceof Response) return authResult;

  const metaRaw = await env.SCRIPTS_KV.get(`script:meta:${id}`);
  if (!metaRaw) return jsonResponse({ error: "Script not found." }, 404, cors);

  const meta = JSON.parse(metaRaw);

  await Promise.all([
    env.SCRIPTS_KV.delete(`script:meta:${id}`),
    env.SCRIPTS_KV.delete(`script:source:${id}`),
    env.SCRIPTS_KV.delete(`script:byplace:${meta.placeId}`),
  ]);

  return jsonResponse({ ok: true }, 200, cors);
}

// ─── Internal lookup (used by loader.js) ─────────────────────────────────────

/**
 * Looks up a script by PlaceId and returns its decrypted source.
 * Returns null if no script exists or is disabled.
 */
export async function getScriptByPlaceId(placeId, env) {
  const id = await env.SCRIPTS_KV.get(`script:byplace:${placeId}`);
  if (!id) return null;

  const metaRaw = await env.SCRIPTS_KV.get(`script:meta:${id}`);
  if (!metaRaw) return null;

  const meta = JSON.parse(metaRaw);
  if (!meta.enabled) return null;

  const encryptedSource = await env.SCRIPTS_KV.get(`script:source:${id}`);
  if (!encryptedSource) return null;

  const source = await aesDecrypt(encryptedSource, env);
  return { meta, source };
}
