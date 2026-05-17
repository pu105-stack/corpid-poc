/**
 * Session store abstraction
 *
 * - Localhost / non-Vercel : plain in-memory Map (no setup needed)
 * - Vercel deployment      : Vercel KV (Redis), detected via process.env.VERCEL
 *
 * API: get(key), set(key, value), delete(key)
 * All methods are async so callers work the same way in both environments.
 */

const IS_VERCEL = !!process.env.VERCEL && !!process.env.KV_REST_API_URL;

// ---------------------------------------------------------------------------
// In-memory store (localhost)
// ---------------------------------------------------------------------------

class MemoryStore {
  constructor() { this._map = new Map(); }
  async get(key)        { return this._map.get(key) ?? null; }
  async set(key, value) { this._map.set(key, value); }
  async delete(key)     { this._map.delete(key); }
}

// ---------------------------------------------------------------------------
// Vercel KV store (production)
// ---------------------------------------------------------------------------

class KVStore {
  constructor() {
    // Lazy-load so localhost never needs the package installed
    this._kv = require('@vercel/kv').kv;
  }
  async get(key)        { return this._kv.get(key); }
  async set(key, value) { await this._kv.set(key, value, { ex: 600 }); } // 10 min TTL
  async delete(key)     { await this._kv.del(key); }
}

// ---------------------------------------------------------------------------
// Export the right one
// ---------------------------------------------------------------------------

const store = IS_VERCEL ? new KVStore() : new MemoryStore();

if (!IS_VERCEL) {
  console.log('[Session] Using in-memory store (localhost)');
} else {
  console.log('[Session] Using Vercel KV store');
}

module.exports = store;
