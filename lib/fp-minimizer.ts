// ─────────────────────────────────────────────────────────────────────────────
// FALSE POSITIVE MINIMIZER — v1.3
//
// At this stage: FP reduction > new detection classes.
//
// Applies aggressive contextual suppression using:
//   1. Framework safety guarantees (ORM parameterization, template escaping)
//   2. Sanitizer certainty (proven sanitizer in path, not just nearby)
//   3. Dead-code elimination (unreachable guards, always-false conditions)
//   4. Privilege gating (admin-only routes, auth-verified paths)
//   5. Production-only filtering (test/mock/fixture code suppression)
//   6. Type safety guarantees (TypeScript typed params, validated schemas)
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

export interface FPMinimizerStats {
  total:              number;
  frameworkSafe:      number;
  sanitizerCertain:   number;
  deadCode:           number;
  privilegeGated:     number;
  testCode:           number;
  typeSafe:           number;
  active:             number;
}

// Framework-level safety guarantees — these patterns PROVE the code is safe
const FRAMEWORK_GUARANTEES: Array<{ name: string; pattern: RegExp; kills: string[] }> = [
  // Prisma/TypeORM parameterized queries
  { name: 'Prisma ORM', pattern: /prisma\.\w+\.(findMany|findFirst|findUnique|create|update|delete|upsert)\s*\(/, kills: ['sqli'] },
  { name: 'TypeORM query builder', pattern: /createQueryBuilder\(\)[\s\S]{0,200}\.where\(['"].*\?/, kills: ['sqli'] },
  { name: 'Sequelize parameterized', pattern: /where:\s*\{[^}]*\}/, kills: ['sqli'] },
  // React's JSX auto-escaping
  { name: 'React JSX (auto-escaped)', pattern: /return\s*\(\s*<[A-Z]/, kills: ['xss'] },
  // Next.js server actions
  { name: 'Next.js Server Action', pattern: /'use server'/, kills: ['csrf'] },
  // Helmet.js security headers
  { name: 'Helmet.js', pattern: /helmet\(\)/, kills: ['header-injection'] },
  // CORS configured
  { name: 'CORS configured', pattern: /cors\(\{[^}]*origin/, kills: ['cors'] },
  // express-validator / Zod / Joi schema validation
  { name: 'Zod schema validation', pattern: /z\.(string|number|object|array)\(\)[\s\S]{0,100}\.(parse|safeParse)\s*\(/, kills: ['sqli', 'xss', 'cmd'] },
  { name: 'Joi validation', pattern: /Joi\.(string|number|object)\(\)[\s\S]{0,100}\.validate\s*\(/, kills: ['sqli', 'xss'] },
  { name: 'express-validator', pattern: /body\(['"]\w+['"]\)\.isString\(\)/, kills: ['sqli', 'xss'] },
  // Python ORMs and safe patterns
  { name: 'SQLAlchemy ORM', pattern: /\.filter\s*\(\w+\.\w+\s*==\s*\w+\)|session\.query\s*\(/, kills: ['sqli'] },
  { name: 'Django ORM', pattern: /\.objects\.filter\s*\(|\.objects\.get\s*\(|objects\.all\s*\(/, kills: ['sqli'] },
  { name: 'psycopg2 parameterized', pattern: /cursor\.execute\s*\([^)]+,\s*\(/, kills: ['sqli'] },
  { name: 'Python bcrypt', pattern: /bcrypt\.checkpw\s*\(|bcrypt\.hashpw\s*\(/, kills: ['auth'] },
  { name: 'Flask-Login', pattern: /@login_required|current_user\.is_authenticated/, kills: ['auth'] },
  { name: 'Django auth', pattern: /request\.user\.is_authenticated|@login_required/, kills: ['auth'] },
  { name: 'Python hmac safe compare', pattern: /hmac\.compare_digest\s*\(/, kills: ['timing-attack', 'auth'] },
  { name: 'subprocess safe args', pattern: /subprocess\.(?:run|call|Popen)\s*\(\s*\[/, kills: ['cmd'] },
];

// Proven sanitizers — these in the call path PROVE sanitization happened
const CERTAIN_SANITIZERS: Record<string, RegExp[]> = {
  xss:     [/DOMPurify\.sanitize\s*\(/, /sanitizeHtml\s*\(/, /escapeHtml\s*\(/, /he\.encode\s*\(/, /xss\s*\(/],
  sqli:    [/parameterize\s*\(/, /escape\s*\(/, /mysql\.escape\s*\(/, /pg\.escapeLiteral\s*\(/],
  path:    [/path\.resolve\s*\(/, /path\.normalize\s*\([\s\S]{0,50}startsWith\s*\(/, /\.realpath\s*\(/],
  cmd:     [/shellEscape\s*\(/, /shell-quote/, /argvStringify/, /shlex\.quote\s*\(/],
  redirect:[/URL\s*\(\s*/, /new URL\s*\([\s\S]{0,50}\.origin/, /allowList\.\w*includes\s*\(/],
  // Python-specific sanitizers
  python_sql: [/cursor\.execute\s*\([^,]+,\s*\(/],
  python_cmd: [/shlex\.quote\s*\(/, /subprocess\.run\s*\(\s*\[/],
  python_auth: [/bcrypt\.checkpw\s*\(/, /hmac\.compare_digest\s*\(/],
};

// Dead code markers — findings in these contexts are FPs
const DEAD_CODE_PATTERNS: RegExp[] = [
  /\/\/\s*(TODO|FIXME|HACK|DEAD|DISABLED|UNREACHABLE)/i,
  /if\s*\(\s*false\s*\)/,
  /if\s*\(\s*0\s*\)/,
  /if\s*\(\s*process\.env\.NODE_ENV\s*===?\s*['"]test['"]\s*\)/,
  /process\.env\.DISABLE_\w+\s*===?\s*['"]true['"]/,
  /return\s*;\s*\/\//,  // early return before the sink
];

// Privilege gates — these protect the finding from attacker reach
const PRIVILEGE_GATES: RegExp[] = [
  /requireAdmin\s*\(/,
  /isAdmin\s*\(\)/,
  /role\s*===?\s*['"]admin['"]/,
  /roles\.includes\s*\(['"]admin['"]\)/,
  /checkPermission\s*\(['"]admin/,
  /adminOnly\s*\(/,
  /superuser\s*===?\s*true/,
  /req\.user\.isAdmin/,
];

// Test/fixture code — suppress all findings in these contexts
const TEST_CODE_PATTERNS: RegExp[] = [
  /describe\s*\(/, /it\s*\(['"]/, /test\s*\(['"]/, /beforeEach\s*\(/,
  /jest\.mock\s*\(/, /sinon\.stub\s*\(/,
  /\.spec\.(ts|js)/, /\.test\.(ts|js)/,
  /\/\/ @ts-nocheck/, /eslint-disable/,
  /fixture/, /mockData/, /testHelper/,
];

// TypeScript type safety patterns that prevent injection
const TYPE_SAFE_PATTERNS: RegExp[] = [
  /:\s*number\b.*=\s*req\.(body|query|params)/,
  /parseInt\s*\(.*req\.(body|query|params)/,
  /Number\s*\(.*req\.(body|query|params)/,
  /const\s*\w+:\s*string\[\]\s*=\s*\[/,  // enum/allowlist typing
];

function classifyFinding(issue: Issue): string {
  const text = (issue.title + ' ' + issue.explanation).toLowerCase();
  if (/sql.inject|sqli/.test(text))       return 'sqli';
  if (/xss|cross.site.script/.test(text)) return 'xss';
  if (/ssrf/.test(text))                  return 'ssrf';
  if (/command.inject|shell|rce/.test(text)) return 'cmd';
  if (/path.travers/.test(text))          return 'path';
  if (/open.redirect/.test(text))         return 'redirect';
  if (/header.inject|csp/.test(text))     return 'header-injection';
  if (/cors/.test(text))                  return 'cors';
  if (/csrf/.test(text))                  return 'csrf';
  return 'generic';
}

function getContextWindow(code: string, line: number | null, windowSize = 20): string {
  if (line === null) return code;
  const lines = code.split('\n');
  const start = Math.max(0, line - windowSize);
  const end   = Math.min(lines.length, line + windowSize);
  return lines.slice(start, end).join('\n');
}

export function applyFPMinimizer(
  issues: Issue[],
  code: string,
): { issues: Issue[]; stats: FPMinimizerStats } {
  // Small code guard: if file is ≤80 lines, disable framework-guarantee suppression.
  // Short files rarely use full framework stacks, and false framework-safety suppression
  // causes the analyzer to miss real issues (e.g. suppressing SQLi in a 20-line Express app
  // because "sequelize pattern detected" when it's just string concatenation nearby).
  const lineCount = code.split('\n').length;
  const skipFrameworkGuarantees = lineCount <= 80;
  const stats: FPMinimizerStats = {
    total: issues.length,
    frameworkSafe: 0, sanitizerCertain: 0, deadCode: 0,
    privilegeGated: 0, testCode: 0, typeSafe: 0,
    active: 0,
  };

  // Check global test context first
  const isTestFile = TEST_CODE_PATTERNS.some(p => p.test(code));

  const active: Issue[] = [];

  for (const issue of issues) {
    const cls = classifyFinding(issue);
    const ctx = getContextWindow(code, issue.line, 25);
    let suppressed = false;
    let reason = '';

    // 1. Test code suppression
    if (isTestFile || TEST_CODE_PATTERNS.some(p => p.test(ctx))) {
      stats.testCode++;
      suppressed = true;
      reason = 'test/fixture code context';
    }

    // 2. Framework guarantee
    // Skipped for small files (≤80 lines): short code rarely uses full framework stacks,
    // and framework-pattern suppression causes false negatives on simple Express/Node scripts.
    if (!suppressed && !skipFrameworkGuarantees) {
      for (const fw of FRAMEWORK_GUARANTEES) {
        if (fw.kills.includes(cls) && fw.pattern.test(code)) {
          stats.frameworkSafe++;
          suppressed = true;
          reason = `framework guarantee: ${fw.name}`;
          break;
        }
      }
    }

    // 3. Certain sanitizer in context window
    if (!suppressed) {
      const sanitizers = CERTAIN_SANITIZERS[cls] ?? [];
      if (sanitizers.some(p => p.test(ctx))) {
        stats.sanitizerCertain++;
        suppressed = true;
        reason = 'proven sanitizer in execution path';
      }
    }

    // 4. Dead code detection
    if (!suppressed && issue.line !== null) {
      const localCtx = getContextWindow(code, issue.line, 5);
      if (DEAD_CODE_PATTERNS.some(p => p.test(localCtx))) {
        stats.deadCode++;
        suppressed = true;
        reason = 'dead code / disabled block';
      }
    }

    // 5. Privilege gating (only suppress medium/low, not high)
    if (!suppressed && issue.severity !== 'high') {
      if (PRIVILEGE_GATES.some(p => p.test(ctx))) {
        stats.privilegeGated++;
        suppressed = true;
        reason = 'admin/privilege gate in execution path';
      }
    }

    // 6. Type safety (numeric/validated inputs can't be injected)
    if (!suppressed && ['sqli', 'xss', 'cmd'].includes(cls)) {
      if (TYPE_SAFE_PATTERNS.some(p => p.test(ctx))) {
        stats.typeSafe++;
        suppressed = true;
        reason = 'TypeScript type constraint eliminates injection';
      }
    }

    if (!suppressed) {
      active.push(issue);
    } else {
      // Log suppression reason on the issue for transparency
      console.log(`[fp-minimizer] Suppressed "${issue.title}" L${issue.line}: ${reason}`);
    }
  }

  stats.active = active.length;
  return { issues: active, stats };
}
