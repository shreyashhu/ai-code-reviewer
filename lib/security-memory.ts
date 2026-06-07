// ─────────────────────────────────────────────────────────────────────────────
// SECURITY MEMORY ENGINE v2
//
// The engine adapts per repository — a huge enterprise feature.
//
// Tracks across scans of the same codebase:
//   • Recurring vulnerability patterns (to escalate persistent issues)
//   • Recurring false positives (to suppress noise automatically)
//   • Developer-approved suppressions (explicit snooze by title + line)
//   • Repo-specific trust patterns (known-safe utility wrappers)
//   • Finding history (trend: new / recurring / resolved)
//
// v2 improvements:
//   • Stable repo fingerprint: REPO_FINGERPRINT env var → import hash fallback
//   • JSON file persistence in .security-memory/ — survives server restarts
//   • High-severity FP gate: high findings require 2× the confirmation count
//     and emit a console warning so they are never silently suppressed
//   • Suppression expiry notifications logged when a TTL has lapsed
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

// ─── Types ────────────────────────────────────────────────────────────────────

export type FindingStatus = 'new' | 'recurring' | 'resolved' | 'suppressed';

export interface MemorizedFinding {
  key:          string;  // normalized title + category
  title:        string;
  category:     string;
  severity:     'high' | 'medium' | 'low';
  seenCount:    number;
  firstSeenAt:  number;
  lastSeenAt:   number;
  /** How many consecutive scans this was absent (0 = still present) */
  absentScans:  number;
  confirmedFP:  boolean;  // explicitly marked false positive
  suppressed:   boolean;  // auto-suppressed after FP threshold
}

export interface ApprovedSuppression {
  titlePattern:  string;  // exact or glob-style
  reason:        string;
  approvedAt:    number;
  approvedBy?:   string;
  expiresAt?:    number;   // optional TTL
}

export interface TrustPattern {
  pattern:       string;   // regex source
  description:   string;
  addedAt:       number;
}

export interface RepoMemory {
  repoFingerprint: string;
  findings:        Map<string, MemorizedFinding>;
  suppressions:    ApprovedSuppression[];
  trustPatterns:   TrustPattern[];
  scanCount:       number;
  lastScannedAt:   number;
}

export interface MemoryApplicationResult {
  issues:          unknown[];
  suppressed:      unknown[];
  escalated:       unknown[];  // recurring high-severity issues
  stats: {
    totalInput:      number;
    suppressed:      number;
    escalated:       number;
    newFindings:     number;
    recurringFindings: number;
    resolvedFindings: number;
  };
}

// ─── Persistence ─────────────────────────────────────────────────────────────

const MEMORY_DIR = join(process.cwd(), '.security-memory');

function memoryPath(fingerprint: string): string {
  return join(MEMORY_DIR, `${fingerprint}.json`);
}

function serializeMemory(mem: RepoMemory): string {
  return JSON.stringify({
    ...mem,
    findings: Array.from(mem.findings.entries()),
  });
}

function deserializeMemory(raw: string): RepoMemory {
  const parsed = JSON.parse(raw);
  return {
    ...parsed,
    findings: new Map(parsed.findings as [string, MemorizedFinding][]),
  };
}

function saveMemory(mem: RepoMemory): void {
  try {
    if (!existsSync(MEMORY_DIR)) mkdirSync(MEMORY_DIR, { recursive: true });
    writeFileSync(memoryPath(mem.repoFingerprint), serializeMemory(mem), 'utf8');
  } catch (e) {
    console.warn('[memory] could not persist memory to disk:', e instanceof Error ? e.message : e);
  }
}

function loadMemory(fingerprint: string): RepoMemory | null {
  try {
    const p = memoryPath(fingerprint);
    if (!existsSync(p)) return null;
    return deserializeMemory(readFileSync(p, 'utf8'));
  } catch (e) {
    console.warn('[memory] could not load persisted memory:', e instanceof Error ? e.message : e);
    return null;
  }
}

// ─── Fingerprinting ───────────────────────────────────────────────────────────

/**
 * Stable repo fingerprint resolution order:
 *   1. REPO_FINGERPRINT env var (set in CI/CD to git remote URL + branch)
 *   2. Import-pattern hash (cheap proxy, resets if imports are reorganized)
 *
 * In a real CI/CD integration set REPO_FINGERPRINT=$(git remote get-url origin):$(git branch --show-current)
 */
export function computeRepoFingerprint(code: string): string {
  // Prefer explicit env var (set in CI to git remote + branch for true stability)
  if (process.env.REPO_FINGERPRINT) return process.env.REPO_FINGERPRINT;

  // Fallback: hash of top-level import patterns
  const imports = (code.match(/(?:import|require)\s*(?:\{[^}]*\}|['"])[^'"]+['"]/g) ?? [])
    .slice(0, 10)
    .join('|');
  let h = 0x811c9dc5;
  for (let i = 0; i < imports.length; i++) {
    h ^= imports.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/\s+at\s+l?\d+/g, '')        // remove line refs
    .replace(/\s+in\s+[a-z_]+\s*\(/g, '') // remove function refs
    .replace(/[^a-z0-9 ]/g, '')
    .replace(/\s+/g, '-')
    .trim();
}

function findingKey(title: string, category: string): string {
  return `${category}::${normalizeTitle(title)}`;
}

// ─── In-memory store ──────────────────────────────────────────────────────────

const _memories = new Map<string, RepoMemory>();

// Auto-suppress after this many confirmed-FP occurrences (low/medium findings)
const FP_AUTO_SUPPRESS_THRESHOLD = 3;
// High-severity findings require 2× confirmations before auto-suppress
const FP_AUTO_SUPPRESS_THRESHOLD_HIGH = 6;

// A finding is "resolved" if absent for this many consecutive scans
const RESOLVED_AFTER_SCANS = 3;

// ─── Memory accessors ─────────────────────────────────────────────────────────

export function getRepoMemory(fingerprint: string): RepoMemory {
  if (!_memories.has(fingerprint)) {
    // Try loading persisted memory from disk first
    const persisted = loadMemory(fingerprint);
    if (persisted) {
      _memories.set(fingerprint, persisted);
    } else {
      _memories.set(fingerprint, {
        repoFingerprint: fingerprint,
        findings:        new Map(),
        suppressions:    [],
        trustPatterns:   [],
        scanCount:       0,
        lastScannedAt:   Date.now(),
      });
    }
  }
  return _memories.get(fingerprint)!;
}

// ─── Suppression check ────────────────────────────────────────────────────────

function isSuppressed(title: string, memory: RepoMemory): string | null {
  const now = Date.now();
  for (const sup of memory.suppressions) {
    if (sup.expiresAt && now > sup.expiresAt) continue;
    const pattern = sup.titlePattern.replace(/\*/g, '.*');
    if (new RegExp(pattern, 'i').test(title)) {
      return `Developer-approved suppression: ${sup.reason}`;
    }
  }
  return null;
}

// ─── Trust pattern check ─────────────────────────────────────────────────────

function matchesTrustPattern(explanation: string, memory: RepoMemory): string | null {
  for (const tp of memory.trustPatterns) {
    try {
      if (new RegExp(tp.pattern, 'i').test(explanation)) {
        return `Repo trust pattern: ${tp.description}`;
      }
    } catch { /* invalid regex */ }
  }
  return null;
}

// ─── Main application ─────────────────────────────────────────────────────────

export interface IssueWithMemory {
  title:       string;
  category:    string;
  severity:    'high' | 'medium' | 'low';
  explanation: string;
  type:        string;
  [key: string]: unknown;
}

export function applySecurityMemory<T extends IssueWithMemory>(
  issues:       T[],
  memory:       RepoMemory,
): MemoryApplicationResult {
  const active:    T[] = [];
  const suppressed: T[] = [];
  const escalated: T[] = [];

  const now = Date.now();
  const seenKeys = new Set<string>();

  // Update scan count
  memory.scanCount++;
  memory.lastScannedAt = now;

  let newCount = 0, recurringCount = 0;

  for (const issue of issues) {
    const key = findingKey(issue.title, issue.category);
    seenKeys.add(key);

    // ── Check developer suppressions ──────────────────────────────────────
    const supReason = isSuppressed(issue.title, memory);
    if (supReason) {
      (issue as Record<string, unknown>)._suppressionReason = supReason;
      suppressed.push(issue);
      continue;
    }

    // ── Check trust patterns ──────────────────────────────────────────────
    const trustReason = matchesTrustPattern(issue.explanation, memory);
    if (trustReason) {
      (issue as Record<string, unknown>)._suppressionReason = trustReason;
      suppressed.push(issue);
      continue;
    }

    // ── Update memory record ──────────────────────────────────────────────
    let record = memory.findings.get(key);
    if (!record) {
      record = {
        key,
        title:       issue.title,
        category:    issue.category,
        severity:    issue.severity,
        seenCount:   0,
        firstSeenAt: now,
        lastSeenAt:  now,
        absentScans: 0,
        confirmedFP: false,
        suppressed:  false,
      };
      memory.findings.set(key, record);
    }
    record.seenCount++;
    record.lastSeenAt  = now;
    record.absentScans = 0;

    // Auto-suppress confirmed FPs — with severity gate for high findings
    if (record.confirmedFP) {
      const threshold = issue.severity === 'high'
        ? FP_AUTO_SUPPRESS_THRESHOLD_HIGH
        : FP_AUTO_SUPPRESS_THRESHOLD;
      if (record.seenCount >= threshold) {
        record.suppressed = true;
        if (issue.severity === 'high') {
          console.warn(
            `[memory] ⚠️  AUTO-SUPPRESSING HIGH-SEVERITY finding after ${record.seenCount} confirmations: "${record.title}". ` +
            `Verify this is a genuine false positive before proceeding.`
          );
        }
        (issue as Record<string, unknown>)._suppressionReason =
          `Auto-suppressed: confirmed false positive (seen ${record.seenCount}x)`;
        suppressed.push(issue);
        continue;
      }
    }

    // ── Status annotation ─────────────────────────────────────────────────
    const isNew       = record.seenCount === 1;
    const isRecurring = record.seenCount > 1;
    (issue as Record<string, unknown>)._memoryStatus = isNew ? 'new' : 'recurring';
    (issue as Record<string, unknown>)._seenCount = record.seenCount;

    if (isNew) newCount++;
    if (isRecurring) {
      recurringCount++;
      // Escalate: recurring high-severity issues get a warning annotation
      if (issue.severity === 'high' && record.seenCount >= 3) {
        (issue as Record<string, unknown>)._escalated = true;
        (issue as Record<string, unknown>)._escalationReason =
          `RECURRING: found in ${record.seenCount} consecutive scans — may be a structural issue`;
        escalated.push(issue);
      }
    }

    active.push(issue);
  }

  // ── Mark absent findings as potentially resolved ───────────────────────
  let resolvedCount = 0;
  for (const [key, record] of memory.findings.entries()) {
    if (!seenKeys.has(key) && !record.suppressed) {
      record.absentScans++;
      if (record.absentScans >= RESOLVED_AFTER_SCANS) {
        resolvedCount++;
        // Keep in memory for trend tracking but log as resolved
        console.log(`[memory] resolved: ${record.title} (absent ${record.absentScans} scans)`);
      }
    }
  }

  // ── Notify on expired suppressions ────────────────────────────────────
  const now2 = Date.now();
  for (const sup of memory.suppressions) {
    if (sup.expiresAt && now2 > sup.expiresAt) {
      console.warn(
        `[memory] ⏰ Suppression TTL expired for pattern "${sup.titlePattern}" ` +
        `(reason: ${sup.reason}). Findings matching this pattern will resurface.`
      );
    }
  }

  // ── Persist to disk so memory survives restarts ────────────────────────
  saveMemory(memory);

  return {
    issues:    active,
    suppressed,
    escalated,
    stats: {
      totalInput:        issues.length,
      suppressed:        suppressed.length,
      escalated:         escalated.length,
      newFindings:       newCount,
      recurringFindings: recurringCount,
      resolvedFindings:  resolvedCount,
    },
  };
}

// ─── Mutation API (for developer feedback loop) ───────────────────────────────

export function markAsFalsePositive(
  fingerprint: string,
  title:       string,
  category:    string,
): void {
  const mem    = getRepoMemory(fingerprint);
  const key    = findingKey(title, category);
  const record = mem.findings.get(key);
  if (record) { record.confirmedFP = true; }
  saveMemory(mem);
}

export function addApprovedSuppression(
  fingerprint:   string,
  titlePattern:  string,
  reason:        string,
  approvedBy?:   string,
  ttlMs?:        number,
): void {
  const mem = getRepoMemory(fingerprint);
  mem.suppressions.push({
    titlePattern,
    reason,
    approvedAt: Date.now(),
    approvedBy,
    expiresAt:  ttlMs ? Date.now() + ttlMs : undefined,
  });
  saveMemory(mem);
}

export function addTrustPattern(
  fingerprint:  string,
  pattern:      string,
  description:  string,
): void {
  const mem = getRepoMemory(fingerprint);
  mem.trustPatterns.push({ pattern, description, addedAt: Date.now() });
  saveMemory(mem);
}

// ─── Stats ────────────────────────────────────────────────────────────────────

export interface MemoryStats {
  reposTracked:   number;
  totalFindings:  number;
  totalFPs:       number;
  totalSuppressed: number;
}

export function getGlobalMemoryStats(): MemoryStats {
  let totalFindings = 0, totalFPs = 0, totalSuppressed = 0;
  for (const mem of _memories.values()) {
    for (const f of mem.findings.values()) {
      totalFindings++;
      if (f.confirmedFP)  totalFPs++;
      if (f.suppressed)   totalSuppressed++;
    }
  }
  return {
    reposTracked:    _memories.size,
    totalFindings,
    totalFPs,
    totalSuppressed,
  };
}
