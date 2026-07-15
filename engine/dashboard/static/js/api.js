/* Thin API client. The dashboard renders what the engine serves — nothing
 * is computed client-side beyond layout. The explicit ?preview=1 mode swaps
 * in local sample responses so the UI can be checked without the engine. */

import * as preview from "./preview-data.js";

export const isPreviewMode =
  new URLSearchParams(window.location.search).get("preview") === "1";

export async function apiGet(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

export async function apiSend(path, method, payload) {
  const response = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

export const getSetup = () => isPreviewMode ? preview.getSetup() : apiGet("/api/setup");
export const getStatus = () => isPreviewMode ? preview.getStatus() : apiGet("/api/status");
export const getClusters = (surfacedOnly) =>
  isPreviewMode ? preview.getClusters(surfacedOnly)
    : apiGet(`/api/clusters${surfacedOnly ? "?surfaced_only=true" : ""}`);
export const getCluster = (id) => isPreviewMode
  ? preview.getCluster(id) : apiGet(`/api/clusters/${encodeURIComponent(id)}`);
export const getTimeline = (id) =>
  isPreviewMode ? preview.getTimeline(id)
    : apiGet(`/api/clusters/${encodeURIComponent(id)}/timeline`);
export const getGraph = (id) =>
  isPreviewMode ? preview.getGraph(id)
    : apiGet(`/api/clusters/${encodeURIComponent(id)}/graph`);
export const getTechniques = (ids) => isPreviewMode
  ? preview.getTechniques(ids)
  : apiGet(`/api/attack/techniques?ids=${encodeURIComponent(ids.join(","))}`);
export const getAiSettings = () => isPreviewMode
  ? preview.getAiSettings() : apiGet("/api/settings/ai");
export const putAiSettings = (settings) => isPreviewMode
  ? preview.putAiSettings(settings) : apiSend("/api/settings/ai", "PUT", settings);
export const putSiemSettings = (settings) =>
  isPreviewMode ? preview.putSiemSettings(settings)
    : apiSend("/api/settings/siem", "PUT", settings);
export const validateAi = (overrides) =>
  isPreviewMode ? preview.validateAi(overrides || {})
    : apiSend("/api/ai/validate", "POST", overrides || {});
export const retriage = (id) =>
  isPreviewMode ? preview.retriage(id)
    : apiSend(`/api/clusters/${encodeURIComponent(id)}/triage`, "POST");
