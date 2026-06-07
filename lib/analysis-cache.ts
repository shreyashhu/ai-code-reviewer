// ─────────────────────────────────────────────────────────────────────────────
// ANALYSIS CACHE v2
//
// Avoids re-running expensive deterministic engines (security-rules, taint,
// pipeline, semantic-graph, symbolic-execution) on identical code.
//
// Architecture:
//   • In-process LRU cache keyed by SHA-256 content hash (crypto module)
//   • Separate cache layers per engine stage, so a partial cache hit still helps
//   • TTL: 30 minutes (in-process; resets on server restart)
//   • Max entries: 200 per stage (evict LRU when exceeded)
//   • Stats exposed in pipelineMetadata for observability
//
// Enterprise caches should use Redis/Valkey with the same key schema.
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'crypto';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CacheEntry<T> {
  value:     T;
  createdAt: number;
  hits:      number;
}

export interface CacheStats {
  stage:        string;
  size:         number;
  hits:         number;
  misses:       number;
  hitRate:      number;       // 0–1
  evictions:    number;
  savedTokens:  number;       // estimated
}

export interface AnalysisCacheStats {
  totalHits:     number;
  totalMisses:   number;
  hitRate:       number;
  estimatedSavedTokens: number;
  stages:        CacheStats[];
}

// ─── Hash ────────────────────────────────────────────────────────────────────

/**
 * SHA-256 content hash via Node.js crypto module.
 * Collision-resistant — safe for use as a security-tool cache key.
 * Returns a 64-char hex string.
 */
function hashCode(code: string): string {
  return createHash('sha256').update(code, 'utf8').digest('hex');
}

// ─── LRU Store ────────────────────────────────────────────────────────────────

const TTL_MS  = 30 * 60 * 1000; // 30 minutes
const MAX_ENTRIES = 200;
const CACHE_SCHEMA_VERSION = 'sast-project-index-v5';

class LRUCache<T> {
  private store = new Map<string, CacheEntry<T>>();
  hits    = 0;
  misses  = 0;
  evictions = 0;

  get(key: string): T | null {
    const entry = this.store.get(key);
    if (!entry) { this.misses++; return null; }
    if (Date.now() - entry.createdAt > TTL_MS) {
      this.store.delete(key);
      this.misses++;
      return null;
    }
    // LRU: re-insert to move to end
    this.store.delete(key);
    entry.hits++;
    this.store.set(key, entry);
    this.hits++;
    return entry.value;
  }

  set(key: string, value: T): void {
    if (this.store.size >= MAX_ENTRIES) {
      // Evict oldest (first in Map iteration order)
      const oldest = this.store.keys().next().value;
      if (oldest) { this.store.delete(oldest); this.evictions++; }
    }
    this.store.set(key, { value, createdAt: Date.now(), hits: 0 });
  }

  size(): number { return this.store.size; }
}

// ─── Per-stage caches ─────────────────────────────────────────────────────────

// Imported types (inline to avoid circular deps)
type AnyRecord = Record<string, unknown>;

interface StageCache {
  name:         string;
  cache:        LRUCache<AnyRecord>;
  tokenCost:    number;  // approximate tokens saved per hit
}

const STAGES: StageCache[] = [
  { name: 'security-rules',       cache: new LRUCache(), tokenCost: 0     },  // deterministic, no AI
  { name: 'taint-engine',         cache: new LRUCache(), tokenCost: 0     },  // deterministic, no AI
  { name: 'pipeline',             cache: new LRUCache(), tokenCost: 0     },  // deterministic, no AI
  { name: 'semantic-graph',       cache: new LRUCache(), tokenCost: 0     },  // deterministic, no AI
  { name: 'symbolic-execution',   cache: new LRUCache(), tokenCost: 0     },  // deterministic, no AI
  { name: 'consensus-result',     cache: new LRUCache(), tokenCost: 8000  },  // 4 AI roles × 2k tokens
  { name: 'patch-generation',     cache: new LRUCache(), tokenCost: 3000  },  // diff AI call
];

const stageMap = new Map<string, StageCache>(STAGES.map(s => [s.name, s]));

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Returns a cache key for the given code + optional variant tag.
 * Use variant to namespace e.g. the same code at different model settings.
 */
export function cacheKey(code: string, variant = ''): string {
  return `${CACHE_SCHEMA_VERSION}:${hashCode(code)}:${variant}`;
}

export function cacheGet<T extends AnyRecord>(stage: string, key: string): T | null {
  const s = stageMap.get(stage);
  if (!s) return null;
  return s.cache.get(key) as T | null;
}

export function cacheSet<T extends AnyRecord>(stage: string, key: string, value: T): void {
  const s = stageMap.get(stage);
  if (!s) return;
  s.cache.set(key, value as AnyRecord);
}

export function getCacheStats(): AnalysisCacheStats {
  const stages: CacheStats[] = STAGES.map(s => {
    const total = s.cache.hits + s.cache.misses;
    return {
      stage:       s.name,
      size:        s.cache.size(),
      hits:        s.cache.hits,
      misses:      s.cache.misses,
      hitRate:     total > 0 ? s.cache.hits / total : 0,
      evictions:   s.cache.evictions,
      savedTokens: s.cache.hits * s.tokenCost,
    };
  });

  const totalHits    = stages.reduce((n, s) => n + s.hits, 0);
  const totalMisses  = stages.reduce((n, s) => n + s.misses, 0);
  const total        = totalHits + totalMisses;

  return {
    totalHits,
    totalMisses,
    hitRate:               total > 0 ? totalHits / total : 0,
    estimatedSavedTokens:  stages.reduce((n, s) => n + s.savedTokens, 0),
    stages,
  };
}

/**
 * Wraps an expensive function with cache-aside logic.
 * The wrapper is transparent: if the cache has a hit, the fn is never called.
 */
export async function withCache<T extends AnyRecord>(
  stage:   string,
  key:     string,
  fn:      () => Promise<T> | T,
): Promise<{ value: T; cached: boolean }> {
  const hit = cacheGet<T>(stage, key);
  if (hit !== null) return { value: hit, cached: true };
  const value = await fn();
  cacheSet(stage, key, value);
  return { value, cached: false };
}

/**
 * Synchronous variant for deterministic (non-async) engines.
 */
export function withCacheSync<T extends AnyRecord>(
  stage: string,
  key:   string,
  fn:    () => T,
): { value: T; cached: boolean } {
  const hit = cacheGet<T>(stage, key);
  if (hit !== null) return { value: hit, cached: true };
  const value = fn();
  cacheSet(stage, key, value);
  return { value, cached: false };
}
