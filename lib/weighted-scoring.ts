// ─────────────────────────────────────────────────────────────────────────────
// WEIGHTED SCORING ENGINE v7
//
// Replaces the primitive "subtract per finding" scoring with a context-aware
// weighted model that rewards secure patterns and properly adjusts findings.
//
// Factors:
//   • replay-verified    ×1.5  (confirmed exploitable)
//   • dead-code          ×0.0  (unreachable)
//   • internal-only      ×0.2  (not externally accessible)
//   • authenticated      ×0.6  (requires auth — bypasses still count)
//   • admin-only         ×0.4  (admin routes)
//   • duplicate          ×0.1  (same root cause, extra instance)
//   • sanitized          ×0.3  (partial sanitizer present)
//   • production-route   ×1.3  (publicly reachable)
//
// Positive rewards reduce deductions:
//   • parameterized queries
//   • CSP headers
//   • secure headers
//   • zod/joi validation
//   • rate limiting
//   • auth middleware
//   • isolation boundaries
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';
import type { VulnFamily } from './family-clustering';
import type { DecayStats } from './confidence-decay';

// ── Deduction weights (base, modified by context multipliers) ─────────────────
const BASE_DEDUCTIONS: Record<string, Record<string, number>> = {
  bug:        { high: 20, medium: 10, low: 4 },
  risk:       { high: 12, medium:  6, low: 3 },
  suggestion: { high:  2, medium:  2, low: 2 },
};

// ── Context multipliers (same as confidence decay) ────────────────────────────
const CONTEXT_MULTIPLIERS: Record<string, number> = {
  'replay-verified':  1.50,
  'dead-code':        0.00,
  'internal-only':    0.20,
  'authenticated':    0.60,
  'admin-only':       0.40,
  'duplicate':        0.10,
  'sanitized':        0.30,
  'production-route': 1.30,
};

// ── Positive security pattern detectors ───────────────────────────────────────
const POSITIVE_PATTERNS: Array<{ pattern: RegExp; reward: number; label: string }> = [
  // Parameterized queries
  { pattern: /db\.(?:query|execute|run)\s*\([^)]*,\s*\[/,              reward: 5, label: 'parameterized-queries' },
  { pattern: /\.prepare\s*\(/i,                                         reward: 5, label: 'prepared-statements' },
  { pattern: /prisma\.\w+\.(findMany|findFirst|create|update|upsert)/,  reward: 4, label: 'orm-safe-api' },

  // Input validation
  { pattern: /z\.\w+\(\)|\.safeParse\s*\(/,                            reward: 4, label: 'zod-validation' },
  { pattern: /joi\.\w+\(\)|yup\.\w+\(\)/,                              reward: 4, label: 'joi-yup-validation' },
  { pattern: /\.validate\s*\(\s*schema/i,                              reward: 3, label: 'schema-validation' },

  // Security headers
  { pattern: /Content-Security-Policy|csp/i,                           reward: 5, label: 'csp-header' },
  { pattern: /X-Frame-Options|X-Content-Type|Strict-Transport/i,       reward: 3, label: 'security-headers' },
  { pattern: /helmet\s*\(\)|helmet\.contentSecurityPolicy/,            reward: 5, label: 'helmet-middleware' },

  // Rate limiting
  { pattern: /rateLimit|rate-limit|express-rate-limit|throttle/i,      reward: 4, label: 'rate-limiting' },

  // Auth middleware
  { pattern: /requireAuth|isAuthenticated|passport\.authenticate/,      reward: 3, label: 'auth-middleware' },
  { pattern: /jwt\.verify\s*\(/,                                        reward: 3, label: 'jwt-verify' },

  // XSS protection
  { pattern: /DOMPurify\.sanitize/,                                     reward: 4, label: 'dompurify' },
  { pattern: /textContent\s*=|createTextNode/,                          reward: 3, label: 'safe-dom' },

  // CSRF
  { pattern: /csrf|csurf|SameSite/i,                                   reward: 4, label: 'csrf-protection' },

  // Isolation
  { pattern: /Object\.freeze\s*\(/,                                     reward: 2, label: 'prototype-freeze' },
  { pattern: /spawn\s*\([^)]*,\s*\[[^\]]*\]\s*,?\s*\{[^}]*shell\s*:\s*false/, reward: 4, label: 'safe-spawn' },

  // Small-code secure patterns (common in minimal Express apps)
  { pattern: /crypto\.randomBytes\s*\(/,                                reward: 3, label: 'csprng' },
  { pattern: /mime\.lookup\s*\(/,                                        reward: 2, label: 'mime-validation' },
  { pattern: /path\.resolve\s*\([^)]*__dirname/,                        reward: 3, label: 'safe-path-resolve' },
  { pattern: /Object\.keys\s*\(\s*(?:source|input|body)\s*\)/,        reward: 2, label: 'safe-key-iteration' },
  { pattern: /===\s*(?:req\.user\.id|req\.session\.userId)/,              reward: 3, label: 'ownership-check' },
  { pattern: /res\.status\s*\(\s*40[013]/,                              reward: 1, label: 'proper-error-codes' },
  // Python secure patterns
  { pattern: /bcrypt\.checkpw\s*\(|bcrypt\.hashpw\s*\(/,              reward: 5, label: 'python-bcrypt' },
  { pattern: /hmac\.compare_digest\s*\(/,                                reward: 4, label: 'python-timing-safe' },
  { pattern: /cursor\.execute\s*\([^,]+,\s*\(/,                         reward: 5, label: 'python-parameterized-sql' },
  { pattern: /@login_required|current_user\.is_authenticated/,           reward: 3, label: 'python-auth-decorator' },
  { pattern: /shlex\.quote\s*\(|subprocess\.run\s*\(\s*\[/,           reward: 4, label: 'python-safe-subprocess' },
  { pattern: /html\.escape\s*\(/,                                        reward: 3, label: 'python-html-escape' },
  { pattern: /with\s+(?:sqlite3|psycopg2|pymysql)\.connect/,            reward: 3, label: 'python-context-manager-db' },
  { pattern: /os\.environ\.get\s*\(|os\.getenv\s*\(/,                 reward: 3, label: 'python-env-var-config' },
];

export interface WeightedScoreResult {
  score:           number;   // 0–100
  baseDeductions:  number;   // raw deduction before multipliers
  adjustedDeductions: number; // after context multipliers
  positiveRewards: number;   // rewards from secure patterns
  breakdown: Array<{
    title:      string;
    type:       string;
    severity:   string;
    deduction:  number;
    multiplier: number;
    final:      number;
    reason:     string;
  }>;
  securityRewards: Array<{ label: string; reward: number }>;
}

/**
 * Compute a weighted quality score for a set of issues + code.
 * More realistic than simple per-finding deductions.
 */
export function computeWeightedScore(
  issues: Issue[],
  families: VulnFamily[],
  code: string,
  decayStats?: DecayStats,
): WeightedScoreResult {
  let score = 100;
  let baseDeductions   = 0;
  let adjustedDeductions = 0;
  const breakdown: WeightedScoreResult['breakdown'] = [];
  const securityRewards: Array<{ label: string; reward: number }> = [];

  // ── 1. Apply positive rewards first ───────────────────────────────────────
  let totalReward = 0;
  for (const pat of POSITIVE_PATTERNS) {
    if (pat.pattern.test(code)) {
      totalReward += pat.reward;
      securityRewards.push({ label: pat.label, reward: pat.reward });
    }
  }
  // Rewards are stored separately but don't directly inflate score past 100

  // ── 2. Compute per-issue deductions ──────────────────────────────────────
  // Use family data to mark duplicates
  const familyVariantLines = new Set<string>();
  for (const fam of families) {
    if (fam.totalCount > 1) {
      // Mark all non-canonical variants as duplicates
      for (const v of fam.variants) {
        if (v !== fam.canonical) {
          familyVariantLines.add(`${v.line}:${v.title.slice(0, 30)}`);
        }
      }
    }
  }

  for (const issue of issues) {
    const baseDeduction = BASE_DEDUCTIONS[issue.type]?.[issue.severity] ?? 2;
    baseDeductions += baseDeduction;

    // Determine context multiplier
    let multiplier = 1.0;
    let reason     = '';

    const issueKey = `${issue.line}:${issue.title.slice(0, 30)}`;

    // Duplicate variant — severe deduction reduction
    if (familyVariantLines.has(issueKey)) {
      multiplier *= CONTEXT_MULTIPLIERS['duplicate'];
      reason = 'duplicate of family canonical';
    }

    // Exploit verified — increase deduction (confirmed real)
    if (issue.exploitVerified === true) {
      multiplier *= CONTEXT_MULTIPLIERS['replay-verified'];
      reason += reason ? ', replay-verified' : 'replay-verified exploit';
    }

    // Reachability-based modifiers
    const reach = issue.reachability ?? 100;
    if (reach < 10)       { multiplier *= CONTEXT_MULTIPLIERS['dead-code'];       reason += ' dead-code'; }
    else if (reach < 20)  { multiplier *= CONTEXT_MULTIPLIERS['internal-only'];   reason += ' internal-only'; }
    else if (reach < 50)  { multiplier *= CONTEXT_MULTIPLIERS['admin-only'];      reason += ' admin-only'; }
    else if (reach < 70)  { multiplier *= CONTEXT_MULTIPLIERS['authenticated'];   reason += ' auth-required'; }
    else if (reach >= 90) { multiplier *= CONTEXT_MULTIPLIERS['production-route'];reason += ' production-route'; }

    // Sanitizer present (partial)
    if (issue.confidence !== undefined && issue.confidence < 0.5) {
      multiplier *= CONTEXT_MULTIPLIERS['sanitized'];
      reason += ' partially-sanitized';
    }

    const final = Math.round(baseDeduction * multiplier);
    adjustedDeductions += final;
    score -= final;

    breakdown.push({
      title:     issue.title.slice(0, 60),
      type:      issue.type,
      severity:  issue.severity,
      deduction: baseDeduction,
      multiplier: Math.round(multiplier * 100) / 100,
      final,
      reason: reason.trim() || 'standard deduction',
    });
  }

  // ── 3. Apply rewards (reduce deductions, not inflate score) ────────────────
  score = Math.min(100, score + Math.min(totalReward, 20)); // cap rewards at 20pts
  score = Math.max(0, score);

  return {
    score:              Math.round(score),
    baseDeductions:     Math.round(baseDeductions),
    adjustedDeductions: Math.round(adjustedDeductions),
    positiveRewards:    Math.round(totalReward),
    breakdown,
    securityRewards,
  };
}
