// ─────────────────────────────────────────────────────────────────────────────
// SECURITY MEMORY REFINEMENT — v1.4
//
// Extends the v1.3 security memory engine with:
//   • Team-approved suppressions (named approver, reason, expiry)
//   • Expiration policies (suppressions expire after configurable TTL)
//   • Confidence drift tracking (confidence trend over successive scans)
//   • Suppression audit log (every applied suppression recorded)
//   • Historical vulnerability timelines (first seen / last seen / resolved)
//
// All additions are backward-compatible with the existing RepoMemory schema.
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ConfidenceSample {
  scanTimestamp: number;
  confidence:    number;
  severity:      'high' | 'medium' | 'low';
}

export interface ConfidenceDrift {
  key:            string;
  title:          string;
  samples:        ConfidenceSample[];
  /** positive = confidence trending up (escalating), negative = down (resolving) */
  trend:          number;
  driftLabel:     'stable' | 'escalating' | 'resolving' | 'volatile';
}

export interface TeamSuppression {
  id:            string;
  titlePattern:  string;
  reason:        string;
  approvedBy:    string;
  approvedAt:    number;
  expiresAt?:    number;    // undefined = never expires
  teamId?:       string;
  ticketRef?:    string;    // e.g. JIRA-1234
}

export interface SuppressionAuditEntry {
  suppressionId: string;
  issueTitle:    string;
  issueSeverity: string;
  appliedAt:     number;
  expiresAt:     number | null;
  approvedBy:    string;
  scanCount:     number;
}

export interface VulnTimeline {
  key:          string;
  title:        string;
  category:     string;
  severity:     'high' | 'medium' | 'low';
  firstSeenAt:  number;
  lastSeenAt:   number;
  resolvedAt?:  number;
  seenCount:    number;
  status:       'active' | 'resolved' | 'suppressed';
}

export interface RefinedMemoryStore {
  teamSuppressions:  TeamSuppression[];
  auditLog:          SuppressionAuditEntry[];
  confidenceDrift:   Map<string, ConfidenceDrift>;
  timelines:         Map<string, VulnTimeline>;
}

// ─── Default TTLs ─────────────────────────────────────────────────────────────

const DEFAULT_SUPPRESSION_TTL_DAYS = 90;
const MAX_CONFIDENCE_SAMPLES       = 20;
const DRIFT_VOLATILE_THRESHOLD     = 0.20;  // std dev that triggers 'volatile'
const DRIFT_CHANGE_THRESHOLD       = 0.10;  // linear slope threshold for escalating/resolving

// ─── Persistence path ─────────────────────────────────────────────────────────

const MEMORY_DIR  = join(process.cwd(), '.security-memory');
const REFINE_PATH = join(MEMORY_DIR, 'refined-memory.json');

function ensureDir(): void {
  if (!existsSync(MEMORY_DIR)) mkdirSync(MEMORY_DIR, { recursive: true });
}

function loadStore(): RefinedMemoryStore {
  try {
    if (existsSync(REFINE_PATH)) {
      const raw = JSON.parse(readFileSync(REFINE_PATH, 'utf8'));
      return {
        teamSuppressions: raw.teamSuppressions ?? [],
        auditLog:         raw.auditLog ?? [],
        confidenceDrift:  new Map(Object.entries(raw.confidenceDrift ?? {})),
        timelines:        new Map(Object.entries(raw.timelines ?? {})),
      };
    }
  } catch { /**/ }
  return { teamSuppressions: [], auditLog: [], confidenceDrift: new Map(), timelines: new Map() };
}

function saveStore(store: RefinedMemoryStore): void {
  try {
    ensureDir();
    writeFileSync(REFINE_PATH, JSON.stringify({
      teamSuppressions: store.teamSuppressions,
      auditLog:         store.auditLog,
      confidenceDrift:  Object.fromEntries(store.confidenceDrift),
      timelines:        Object.fromEntries(store.timelines),
    }, null, 2));
  } catch { /**/ }
}

// ─── Core API ─────────────────────────────────────────────────────────────────

export interface MemoryIssue {
  title:      string;
  category:   string;
  severity:   'high' | 'medium' | 'low';
  confidence?: number;
  line?:      number | null;
}

/**
 * Record a batch of issues from the current scan into the refined memory store.
 * Updates timelines, confidence drift, and suppression audit.
 */
export function recordScanIssues(
  issues: MemoryIssue[],
  scanTimestamp = Date.now(),
): void {
  const store = loadStore();
  const now = scanTimestamp;

  for (const issue of issues) {
    const key = `${issue.title.toLowerCase().replace(/\s+/g, '-')}:${issue.category}`;

    // ── Timeline ──────────────────────────────────────────────────────────
    const existing = store.timelines.get(key);
    if (existing) {
      existing.lastSeenAt = now;
      existing.seenCount++;
      existing.status = 'active';
      delete existing.resolvedAt;
    } else {
      store.timelines.set(key, {
        key, title: issue.title, category: issue.category, severity: issue.severity,
        firstSeenAt: now, lastSeenAt: now, seenCount: 1, status: 'active',
      });
    }

    // ── Confidence drift ──────────────────────────────────────────────────
    const conf = issue.confidence ?? 0.75;
    const drift = store.confidenceDrift.get(key) ?? {
      key, title: issue.title, samples: [], trend: 0, driftLabel: 'stable' as const,
    };
    drift.samples.push({ scanTimestamp: now, confidence: conf, severity: issue.severity });
    if (drift.samples.length > MAX_CONFIDENCE_SAMPLES) drift.samples.shift();

    // Compute trend (linear regression slope over samples)
    drift.trend = computeTrend(drift.samples.map(s => s.confidence));
    drift.driftLabel = classifyDrift(drift.samples.map(s => s.confidence), drift.trend);
    store.confidenceDrift.set(key, drift);
  }

  // ── Mark resolved: issues seen before but absent this scan ────────────
  const currentKeys = new Set(issues.map(i =>
    `${i.title.toLowerCase().replace(/\s+/g, '-')}:${i.category}`
  ));
  for (const [key, timeline] of store.timelines) {
    if (!currentKeys.has(key) && timeline.status === 'active') {
      // Only mark resolved if absent for first time
      if (!timeline.resolvedAt) {
        timeline.resolvedAt = now;
        timeline.status = 'resolved';
      }
    }
  }

  saveStore(store);
}

/**
 * Check if a finding should be suppressed by a team-approved suppression.
 * Returns the suppression that matched, or null.
 */
export function checkTeamSuppression(issue: MemoryIssue): TeamSuppression | null {
  const store = loadStore();
  const now = Date.now();

  for (const sup of store.teamSuppressions) {
    // Check expiry
    if (sup.expiresAt && sup.expiresAt < now) continue;
    // Check match (substring or exact)
    if (!issue.title.toLowerCase().includes(sup.titlePattern.toLowerCase())) continue;

    // Record audit entry
    store.auditLog.push({
      suppressionId: sup.id,
      issueTitle:    issue.title,
      issueSeverity: issue.severity,
      appliedAt:     now,
      expiresAt:     sup.expiresAt ?? null,
      approvedBy:    sup.approvedBy,
      scanCount:     1,
    });
    saveStore(store);
    return sup;
  }
  return null;
}

/**
 * Add a new team-approved suppression.
 */
export function addTeamSuppression(
  titlePattern: string,
  reason: string,
  approvedBy: string,
  options: { ticketRef?: string; teamId?: string; ttlDays?: number } = {},
): TeamSuppression {
  const store = loadStore();
  const now   = Date.now();
  const ttl   = options.ttlDays ?? DEFAULT_SUPPRESSION_TTL_DAYS;

  const sup: TeamSuppression = {
    id:            `sup-${now}-${Math.random().toString(36).slice(2, 7)}`,
    titlePattern, reason, approvedBy,
    approvedAt:    now,
    expiresAt:     now + ttl * 24 * 60 * 60 * 1000,
    teamId:        options.teamId,
    ticketRef:     options.ticketRef,
  };
  store.teamSuppressions.push(sup);
  saveStore(store);
  console.log(`[memory-v1.4] Team suppression added: "${titlePattern}" by ${approvedBy} (expires in ${ttl}d)`);
  return sup;
}

/**
 * Purge expired suppressions and return how many were removed.
 */
export function purgeExpiredSuppressions(): number {
  const store = loadStore();
  const now   = Date.now();
  const before = store.teamSuppressions.length;
  store.teamSuppressions = store.teamSuppressions.filter(s => !s.expiresAt || s.expiresAt > now);
  const removed = before - store.teamSuppressions.length;
  if (removed > 0) {
    console.log(`[memory-v1.4] Purged ${removed} expired suppression(s)`);
    saveStore(store);
  }
  return removed;
}

/**
 * Get the confidence drift for a given issue key.
 */
export function getConfidenceDrift(issueKey: string): ConfidenceDrift | null {
  return loadStore().confidenceDrift.get(issueKey) ?? null;
}

/**
 * Get vulnerability timelines, optionally filtered by status.
 */
export function getTimelines(status?: 'active' | 'resolved' | 'suppressed'): VulnTimeline[] {
  const store = loadStore();
  const all = [...store.timelines.values()];
  return status ? all.filter(t => t.status === status) : all;
}

/**
 * Get the suppression audit log.
 */
export function getAuditLog(limit = 100): SuppressionAuditEntry[] {
  return loadStore().auditLog.slice(-limit);
}

/**
 * Get a summary for telemetry.
 */
export function getRefinedMemoryStats(): {
  activeVulns:       number;
  resolvedVulns:     number;
  teamSuppressions:  number;
  expiredCount:      number;
  escalatingDrifts:  number;
  volatileDrifts:    number;
} {
  const store  = loadStore();
  const now    = Date.now();
  const tl     = [...store.timelines.values()];
  const drifts = [...store.confidenceDrift.values()];

  return {
    activeVulns:       tl.filter(t => t.status === 'active').length,
    resolvedVulns:     tl.filter(t => t.status === 'resolved').length,
    teamSuppressions:  store.teamSuppressions.length,
    expiredCount:      store.teamSuppressions.filter(s => s.expiresAt && s.expiresAt < now).length,
    escalatingDrifts:  drifts.filter(d => d.driftLabel === 'escalating').length,
    volatileDrifts:    drifts.filter(d => d.driftLabel === 'volatile').length,
  };
}

// ─── Math helpers ─────────────────────────────────────────────────────────────

function computeTrend(values: number[]): number {
  if (values.length < 2) return 0;
  const n = values.length;
  const xs = values.map((_, i) => i);
  const xMean = xs.reduce((a, b) => a + b, 0) / n;
  const yMean = values.reduce((a, b) => a + b, 0) / n;
  const num = xs.reduce((sum, x, i) => sum + (x - xMean) * (values[i] - yMean), 0);
  const den = xs.reduce((sum, x) => sum + (x - xMean) ** 2, 0);
  return den === 0 ? 0 : num / den;
}

function computeStdDev(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function classifyDrift(values: number[], trend: number): ConfidenceDrift['driftLabel'] {
  const stdDev = computeStdDev(values);
  if (stdDev > DRIFT_VOLATILE_THRESHOLD) return 'volatile';
  if (trend >  DRIFT_CHANGE_THRESHOLD)   return 'escalating';
  if (trend < -DRIFT_CHANGE_THRESHOLD)   return 'resolving';
  return 'stable';
}
