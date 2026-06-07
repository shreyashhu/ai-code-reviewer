// ─────────────────────────────────────────────────────────────────────────────
// TRUST MODELING ENGINE v8
//
// Prevents rediscovering safe code forever. Tracks audited sanitizers,
// trusted wrappers, verified utilities, and approved patterns. Issues
// that match trusted patterns are suppressed with a clear explanation.
//
// Architecture:
//   • Trusted sanitizer registry — known-safe implementations
//   • Approved wrapper registry — wrappers that guarantee safety
//   • Framework guarantee registry — framework-level protections
//   • Pattern suppression — issues matching trusted patterns are tagged
//   • Trust score accumulation — code with many trusted patterns scores higher
//
// This prevents:
//   • Re-detecting parameterized queries as SQLi
//   • Flagging DOMPurify-wrapped values as XSS
//   • Re-flagging already-patched issues
//   • Noise from safe ORM API calls
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ── Trusted sanitizer signatures ──────────────────────────────────────────────
// Each entry: pattern that proves safety + what it protects + confidence level
interface TrustedPattern {
  id:         string;
  pattern:    RegExp;
  protects:   string[];   // vuln families this eliminates
  trustScore: number;     // 0.0 (partial) to 1.0 (eliminates risk entirely)
  note:       string;
}

const TRUSTED_SANITIZERS: TrustedPattern[] = [
  // SQL — parameterized queries eliminate SQLi entirely
  {
    id: 'parameterized-query',
    pattern: /db\.(query|execute|run)\s*\([^)]*,\s*\[/,
    protects: ['sql-injection', 'sqli'],
    trustScore: 1.0,
    note: 'Parameterized query: SQL injection impossible regardless of input',
  },
  {
    id: 'prepared-statement',
    pattern: /\.prepare\s*\(/i,
    protects: ['sql-injection', 'sqli'],
    trustScore: 1.0,
    note: 'Prepared statement: SQL injection impossible',
  },
  {
    id: 'orm-safe-api',
    pattern: /prisma\.\w+\.(findMany|findFirst|findUnique|create|update|upsert|delete|createMany|updateMany)\s*\(/,
    protects: ['sql-injection', 'sqli'],
    trustScore: 0.95,
    note: 'Prisma ORM safe API: parameterized by design',
  },
  {
    id: 'sequelize-safe',
    pattern: /sequelize\.\w+\.(findAll|findOne|create|update|destroy)\s*\(/,
    protects: ['sql-injection', 'sqli'],
    trustScore: 0.90,
    note: 'Sequelize ORM safe API: parameterized by default',
  },
  {
    id: 'knex-bindings',
    pattern: /knex\s*\.\s*(?:where|select|insert|update|delete)\s*\(/,
    protects: ['sql-injection', 'sqli'],
    trustScore: 0.90,
    note: 'Knex.js query builder: parameterized bindings',
  },

  // XSS — structural safe alternatives
  {
    id: 'text-content',
    pattern: /\.textContent\s*=|createTextNode\s*\(/,
    protects: ['xss', 'cross-site-scripting'],
    trustScore: 1.0,
    note: 'textContent/createTextNode: XSS impossible (no HTML parsing)',
  },
  {
    id: 'dompurify-full',
    pattern: /DOMPurify\.sanitize\s*\([^)]+,\s*\{[^}]+ALLOWED_TAGS/,
    protects: ['xss', 'cross-site-scripting'],
    trustScore: 0.92,
    note: 'DOMPurify with ALLOWED_TAGS config: XSS highly unlikely',
  },
  {
    id: 'dompurify-basic',
    pattern: /DOMPurify\.sanitize\s*\(/,
    protects: ['xss', 'cross-site-scripting'],
    trustScore: 0.82,
    note: 'DOMPurify.sanitize: safe for most cases, minor config risks',
  },
  {
    id: 'html-encode',
    pattern: /encodeHTML\s*\(|escapeHtml\s*\(|he\.encode\s*\(/,
    protects: ['xss', 'cross-site-scripting'],
    trustScore: 0.90,
    note: 'HTML encoding function: XSS prevented in HTML context',
  },

  // Command injection
  {
    id: 'spawn-no-shell',
    pattern: /spawn\s*\([^)]*,\s*\[[^\]]*\]\s*,?\s*(?:\{[^}]*shell\s*:\s*false[^}]*\})?\s*\)/,
    protects: ['command-injection', 'cmd-injection', 'rce'],
    trustScore: 1.0,
    note: 'spawn() without shell: shell metachar injection impossible',
  },
  {
    id: 'execfile-safe',
    pattern: /execFile\s*\([^)]*,\s*\[[^\]]*\]/,
    protects: ['command-injection', 'cmd-injection'],
    trustScore: 0.95,
    note: 'execFile with array args: command injection prevented',
  },

  // Path traversal
  {
    id: 'path-resolve-guard',
    pattern: /path\.resolve\s*\([^)]*\)[\s\S]{0,150}\.startsWith\s*\(/,
    protects: ['path-traversal', 'directory-traversal'],
    trustScore: 0.95,
    note: 'path.resolve + startsWith guard: traversal blocked',
  },

  // JWT
  {
    id: 'jwt-verify-with-algo',
    pattern: /jwt\.verify\s*\([^)]*,\s*process\.env\.\w+\s*,\s*\{\s*algorithms:/,
    protects: ['jwt', 'jwt-none-alg'],
    trustScore: 1.0,
    note: 'jwt.verify with pinned algorithm: alg:none bypass impossible',
  },
  {
    id: 'jwt-verify-basic',
    pattern: /jwt\.verify\s*\([^)]*,\s*process\.env\./,
    protects: ['jwt'],
    trustScore: 0.88,
    note: 'jwt.verify with env secret: signature verified',
  },

  // Prototype pollution
  {
    id: 'null-prototype',
    pattern: /Object\.create\s*\(\s*null\s*\)/,
    protects: ['prototype-pollution'],
    trustScore: 0.95,
    note: 'Null-prototype object: prototype chain attacks blocked',
  },
  {
    id: 'object-freeze',
    pattern: /Object\.freeze\s*\(/,
    protects: ['prototype-pollution'],
    trustScore: 0.85,
    note: 'Object.freeze: prototype mutation blocked on frozen objects',
  },

  // SSRF
  {
    id: 'url-allowlist',
    pattern: /ALLOWED_HOSTS|allowedDomains|allowedUrls|ALLOWED_ORIGINS/i,
    protects: ['ssrf'],
    trustScore: 0.70,
    note: 'URL allowlist: reduces SSRF scope (not bypass-proof)',
  },

  // Timing
  {
    id: 'timing-safe',
    pattern: /timingSafeEqual|crypto\.timingSafe|safe-compare|slowEquals/,
    protects: ['timing-attack'],
    trustScore: 1.0,
    note: 'Timing-safe comparison: timing attacks blocked',
  },
];

// ── Framework-level guarantees ────────────────────────────────────────────────
interface FrameworkGuarantee {
  id:        string;
  detector:  RegExp;
  eliminates: string[];  // issue categories this framework makes impossible/unlikely
  note:       string;
}

const FRAMEWORK_GUARANTEES: FrameworkGuarantee[] = [
  {
    id:        'react-jsx',
    detector:  /from ['"]react['"]|import React/,
    eliminates: ['xss'],
    note:      'React JSX auto-escapes interpolated values — XSS via template strings only',
  },
  {
    id:        'nextjs-csp',
    detector:  /contentSecurityPolicy|'use server'/,
    eliminates: [],   // CSP reduces but doesn't eliminate XSS
    note:      'Next.js with CSP header: XSS exploitation surface reduced',
  },
  {
    id:        'prisma-orm',
    detector:  /from ['"]@prisma\/client['"]/,
    eliminates: ['sql-injection'],
    note:      'Prisma ORM: all queries are parameterized by design',
  },
  {
    id:        'drizzle-orm',
    detector:  /from ['"]drizzle-orm['"]/,
    eliminates: ['sql-injection'],
    note:      'Drizzle ORM: parameterized queries by design',
  },
];

// ── Trust model result ─────────────────────────────────────────────────────────
export interface TrustModelResult {
  trustedPatterns:     string[];   // patterns found in the code
  frameworkGuarantees: string[];   // framework-level protections
  suppressedIssues:    Issue[];    // issues matching trusted patterns
  activeIssues:        Issue[];    // issues not covered by trust model
  trustScore:          number;     // 0–100: overall code trust level
  stats:               TrustModelStats;
}

export interface TrustModelStats {
  totalInput:           number;
  suppressedCount:      number;
  trustedPatternCount:  number;
  frameworkCount:       number;
}

// ── Classify issue into vuln family for trust matching ────────────────────────
function issueVulnFamily(issue: Issue): string[] {
  const text = `${issue.title} ${issue.explanation}`.toLowerCase();
  const families: string[] = [];
  if (/sql.inject|sqli/.test(text))             families.push('sql-injection', 'sqli');
  if (/xss|cross.site.script/.test(text))       families.push('xss', 'cross-site-scripting');
  if (/command.inject|rce\b/.test(text))        families.push('command-injection', 'cmd-injection', 'rce');
  if (/path.travers|directory.travers/.test(text)) families.push('path-traversal', 'directory-traversal');
  if (/prototype.poll/.test(text))              families.push('prototype-pollution');
  if (/ssrf|server.side.request/.test(text))   families.push('ssrf');
  if (/jwt|json.web.token/.test(text))          families.push('jwt', 'jwt-none-alg');
  if (/timing.attack/.test(text))              families.push('timing-attack');
  return families;
}

/**
 * Apply the trust model to a set of issues.
 * Suppresses issues that are covered by trusted patterns in the code.
 */
export function applyTrustModel(
  issues: Issue[],
  code: string,
): TrustModelResult {
  // 1. Detect trusted patterns in the code
  const trustedPatterns: string[] = [];
  const patternMap = new Map<string, TrustedPattern>();

  for (const pattern of TRUSTED_SANITIZERS) {
    if (pattern.pattern.test(code)) {
      trustedPatterns.push(pattern.id);
      for (const family of pattern.protects) {
        // Map family → highest-trust pattern
        const existing = patternMap.get(family);
        if (!existing || existing.trustScore < pattern.trustScore) {
          patternMap.set(family, pattern);
        }
      }
    }
  }

  // 2. Detect framework guarantees
  const frameworkGuarantees: string[] = [];
  const frameworkEliminates = new Set<string>();
  for (const fg of FRAMEWORK_GUARANTEES) {
    if (fg.detector.test(code)) {
      frameworkGuarantees.push(fg.id);
      for (const vuln of fg.eliminates) frameworkEliminates.add(vuln);
    }
  }

  // 3. Apply suppression
  const suppressedIssues: Issue[] = [];
  const activeIssues: Issue[] = [];

  for (const issue of issues) {
    const families = issueVulnFamily(issue);

    // Check framework eliminates
    const frameworkCovers = families.some(f => frameworkEliminates.has(f));
    if (frameworkCovers) {
      suppressedIssues.push({
        ...issue,
        _trustSuppressed: true,
        _trustReason: `Framework guarantee covers this vulnerability class`,
      } as Issue & Record<string, unknown>);
      continue;
    }

    // Check sanitizer coverage
    const coveringPattern = families.map(f => patternMap.get(f)).filter(Boolean)[0];
    if (coveringPattern && coveringPattern.trustScore >= 0.90) {
      // High-trust pattern covers this issue — suppress
      suppressedIssues.push({
        ...issue,
        _trustSuppressed: true,
        _trustReason: `${coveringPattern.id}: ${coveringPattern.note}`,
      } as Issue & Record<string, unknown>);
      continue;
    }

    if (coveringPattern && coveringPattern.trustScore >= 0.70) {
      // Medium-trust: downgrade severity but keep issue
      const downgraded: Issue = {
        ...issue,
        severity:    issue.severity === 'high' ? 'medium' : issue.severity,
        confidence:  Math.min(issue.confidence ?? 0.75, 0.65),
        explanation: issue.explanation + ` [Trust model: ${coveringPattern.note}]`,
      };
      activeIssues.push(downgraded);
      continue;
    }

    activeIssues.push(issue);
  }

  // 4. Compute trust score
  const patternBonus    = Math.min(30, trustedPatterns.length * 5);
  const frameworkBonus  = Math.min(20, frameworkGuarantees.length * 8);
  const suppressionRate = issues.length > 0 ? (suppressedIssues.length / issues.length) * 30 : 0;
  const trustScore      = Math.min(100, 50 + patternBonus + frameworkBonus + suppressionRate);

  return {
    trustedPatterns,
    frameworkGuarantees,
    suppressedIssues,
    activeIssues,
    trustScore: Math.round(trustScore),
    stats: {
      totalInput:           issues.length,
      suppressedCount:      suppressedIssues.length,
      trustedPatternCount:  trustedPatterns.length,
      frameworkCount:       frameworkGuarantees.length,
    },
  };
}
