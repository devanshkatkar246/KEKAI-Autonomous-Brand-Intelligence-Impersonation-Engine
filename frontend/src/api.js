/**
 * api.js — Shared API fetch wrapper for KEIKAI frontend
 *
 * Provides:
 *  - fetchWithTimeout: fetch + AbortController timeout
 *  - apiFetch: timeout + retry (2 attempts, 800ms backoff) for network-level
 *    failures only (TypeError = fetch threw = backend unreachable).
 *    4xx/5xx HTTP responses are NOT retried — they are real server errors.
 *  - Error type tagging: err.isNetworkError = true when backend is unreachable.
 */

const DEFAULT_TIMEOUT_MS = 10000;   // 10 s per attempt
const RETRY_ATTEMPTS     = 2;       // 1 initial + 1 retry
const RETRY_BACKOFF_MS   = 800;

/** Low-level fetch with AbortController timeout. */
export async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } catch (err) {
    // Normalise AbortError and TypeError into a single NetworkError shape
    const networkErr = new Error(
      err.name === 'AbortError'
        ? `Request timed out after ${timeoutMs / 1000}s — backend unreachable.`
        : 'Backend unreachable — could not connect to the API server.'
    );
    networkErr.isNetworkError = true;
    throw networkErr;
  } finally {
    clearTimeout(timer);
  }
}

/** sleep helper */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * apiFetch — drop-in replacement for fetch() with:
 *   - 10 s timeout
 *   - up to RETRY_ATTEMPTS retries with backoff on network-level failures only
 *
 * Usage:
 *   const res = await apiFetch('/api/visual-phishing-status');
 *   const data = await res.json();
 *
 * Throws an Error with .isNetworkError = true when all attempts are exhausted
 * and the backend was never reached.
 */
export async function apiFetch(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  let lastErr;
  for (let attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++) {
    try {
      const response = await fetchWithTimeout(url, options, timeoutMs);
      return response;   // success — hand the Response back to caller
    } catch (err) {
      lastErr = err;
      if (err.isNetworkError && attempt < RETRY_ATTEMPTS) {
        console.warn(`[KEIKAI API] Network failure on attempt ${attempt}/${RETRY_ATTEMPTS} for ${url}. Retrying in ${RETRY_BACKOFF_MS}ms…`);
        await sleep(RETRY_BACKOFF_MS);
      } else {
        // 4xx/5xx (not a NetworkError) or final retry exhausted — stop retrying
        break;
      }
    }
  }
  throw lastErr;
}
