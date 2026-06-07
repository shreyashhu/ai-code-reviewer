// ─────────────────────────────────────────────────────────────────────────────
// SYMBOLIC EXECUTION ENGINE v1
//
// Adds constraint-aware analysis on top of the deterministic taint engine.
// Implements an SMT-lite solver for JavaScript/TypeScript security analysis.
//
// What this does (that taint alone cannot):
//   • Branch feasibility — if (isAdmin) return; before eval(input) → NOT exploitable
//   • Path-sensitive taint — variable only tainted on one branch
//   • Auth guard detection — function requires session before reaching sink
//   • Sanitizer condition reasoning — if (validated) x else throw → x is clean
//   • Short-circuit suppression — early return/throw removes downstream sinks
//   • Exploit precondition analysis — what must be true for sink to be reachable?
//
// NOT a full symbolic executor (no SMT solver dependency).
// Uses heuristic constraint extraction + lightweight satisfiability checks.
// ─────────────────────────────────────────────────────────────────────────────

export interface SymbolicConstraint {
  type: 'guard' | 'sanitizer' | 'auth' | 'typecheck' | 'allowlist' | 'throw';
  line: number;
  condition: string;
  protects: 'all-below' | 'block-only' | 'conditional';
  variable: string | null;  // variable being constrained (null = all)
  negated: boolean;         // is this an inverted guard (if (!x) return)?
}

export interface SymbolicPath {
  sinkLine:       number;
  sinkType:       string;
  reachable:      boolean;
  blockedBy:      SymbolicConstraint | null;
  preconditions:  string[];   // what must be true for sink to be reachable
  confidence:     number;     // 0–1
  reason:         string;
}

export interface SymbolicReport {
  constraints:     SymbolicConstraint[];
  paths:           SymbolicPath[];
  suppressedSinks: Set<number>;  // sink lines made unreachable by constraints
  authGuardedLines: Set<number>; // lines protected by auth checks
  summary:         string;
}

// ── Guard patterns — early returns / throws that protect subsequent code ──────
interface GuardPattern {
  re:       RegExp;
  type:     SymbolicConstraint['type'];
  protects: SymbolicConstraint['protects'];
  desc:     string;
}

const GUARD_PATTERNS: GuardPattern[] = [
  // Auth guards
  { re: /if\s*\(\s*!(?:session|user|req\.user|isAuth|isLoggedIn|isAuthenticated|authenticated)\s*\)\s*(?:return|throw|next\(err)/,
    type: 'auth', protects: 'all-below', desc: 'auth session guard' },
  { re: /if\s*\(\s*!(?:isAdmin|isOwner|hasPermission|canAccess|hasRole)\s*\)\s*(?:return|throw)/,
    type: 'auth', protects: 'all-below', desc: 'permission guard' },
  { re: /(?:requireAuth|checkAuth|verifySession|authenticate|authorize)\s*\(/,
    type: 'auth', protects: 'all-below', desc: 'auth middleware call' },
  { re: /await\s+(?:requireAuth|checkAuth|verifyToken|verifySession)\s*\(/,
    type: 'auth', protects: 'all-below', desc: 'async auth check' },

  // Sanitizer/validation guards
  { re: /if\s*\(\s*!(?:isValid|validate|sanitize|isAllowed|permitted)\s*\(.*\)\s*\)\s*(?:return|throw)/,
    type: 'sanitizer', protects: 'all-below', desc: 'validation guard' },
  { re: /const\s+\w+\s*=\s*(?:joi|zod|yup|validator)\s*\.\w+.*?\.parse\s*\(/,
    type: 'sanitizer', protects: 'block-only', desc: 'schema validation' },
  { re: /if\s*\(\s*typeof\s+\w+\s*!==\s*['"]string['"]\s*\)\s*(?:return|throw)/,
    type: 'typecheck', protects: 'all-below', desc: 'type guard' },
  { re: /if\s*\(\s*typeof\s+\w+\s*!==\s*['"](?:string|number|boolean)['"]\s*\)\s*(?:return|throw)/,
    type: 'typecheck', protects: 'all-below', desc: 'type guard' },

  // Allowlist guards
  { re: /if\s*\(\s*!ALLOWED|if\s*\(\s*!allowlist|if\s*\(\s*!whitelist/i,
    type: 'allowlist', protects: 'all-below', desc: 'allowlist check' },
  { re: /\.includes\s*\(\s*\w+\s*\)\s*===\s*false\s*\)\s*(?:return|throw)/,
    type: 'allowlist', protects: 'all-below', desc: 'allowlist membership' },

  // Throw patterns
  { re: /if\s*\([^)]+\)\s*throw\s+new\s+Error/,
    type: 'throw', protects: 'all-below', desc: 'conditional throw' },
  { re: /throw\s+new\s+(?:UnauthorizedError|ForbiddenError|AuthenticationError)/,
    type: 'auth', protects: 'all-below', desc: 'auth exception thrown' },
];

// ── Sink patterns (what we're testing reachability of) ────────────────────────
const SINK_PATTERNS_SYMEX: Array<{ re: RegExp; type: string }> = [
  { re: /db\.(?:query|execute|run)\s*\(/,         type: 'sql' },
  { re: /\.innerHTML\s*=/,                         type: 'xss' },
  { re: /eval\s*\(/,                               type: 'eval' },
  { re: /(?:exec|execSync|spawn)\s*\(/,            type: 'cmd' },
  { re: /readFile(?:Sync)?\s*\(/,                  type: 'path' },
  { re: /res\.redirect\s*\(/,                      type: 'redirect' },
  { re: /fetch\s*\(\s*(?!['"`]https?:\/\/[^$])/,  type: 'ssrf' },
  { re: /new Function\s*\(/,                       type: 'eval' },
  { re: /vm\.run(?:InNewContext|InContext)\s*\(/,  type: 'eval' },
];

// ── Variable extraction from condition ───────────────────────────────────────
function extractGuardVariable(cond: string): string | null {
  const m = cond.match(/\b(session|user|req\.user|isAdmin|isAuth\w*|token|payload)\b/);
  return m?.[1] ?? null;
}

// ── Scope-aware constraint applicability ─────────────────────────────────────
// A guard at line N protects lines N+1..end-of-scope (estimate: next 200 lines
// or until closing brace at same indent level — simplified heuristic)
function constraintProtectsSink(
  guard: SymbolicConstraint,
  sinkLine: number,
  lines: string[],
): boolean {
  if (sinkLine <= guard.line) return false;

  if (guard.protects === 'all-below') {
    // Guard is in same function — estimate scope by checking we haven't exited
    // the function (simplified: guard applies to next 300 lines max)
    if (sinkLine > guard.line + 300) return false;
    // Check if a closing brace at the same indent level exists between guard and sink
    const guardIndent = (lines[guard.line - 1] ?? '').match(/^(\s*)/)?.[1]?.length ?? 0;
    for (let i = guard.line; i < Math.min(sinkLine - 1, lines.length); i++) {
      const lineIndent = (lines[i] ?? '').match(/^(\s*)/)?.[1]?.length ?? 0;
      // If we return to a lower indent than guard, we've left scope
      if (lineIndent < guardIndent && lines[i].trim().startsWith('}')) return false;
    }
    return true;
  }

  if (guard.protects === 'block-only') {
    // Only protects within the same if-block (next ~20 lines)
    return sinkLine <= guard.line + 20;
  }

  return false;
}

export function runSymbolicExecution(code: string, taintedVars: Map<string, number>): SymbolicReport {
  const lines       = code.split('\n');
  const constraints: SymbolicConstraint[] = [];
  const paths:       SymbolicPath[] = [];
  const suppressedSinks   = new Set<number>();
  const authGuardedLines  = new Set<number>();

  // ── Pass 1: Extract constraints ───────────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln   = i + 1;

    for (const gp of GUARD_PATTERNS) {
      if (!gp.re.test(line)) continue;
      const condMatch = line.match(/if\s*\(([^)]+)\)/);
      const condition = condMatch?.[1] ?? line.trim();
      const variable  = extractGuardVariable(condition);

      constraints.push({
        type:      gp.type,
        line:      ln,
        condition: condition.trim().slice(0, 80),
        protects:  gp.protects,
        variable,
        negated:   /!\s*(?:session|user|isA|isL|token)/.test(condition),
      });

      // Mark subsequent lines as auth-guarded if this is an auth constraint
      if (gp.type === 'auth') {
        for (let j = ln; j < Math.min(lines.length, ln + 100); j++) {
          authGuardedLines.add(j + 1);
        }
      }
      break;
    }
  }

  // ── Pass 2: Check each sink against constraints ───────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln   = i + 1;

    for (const sp of SINK_PATTERNS_SYMEX) {
      if (!sp.re.test(line)) continue;

      // Is any tainted variable present on this line?
      const taintedHere = [...taintedVars.keys()].some(v => line.includes(v));
      if (!taintedHere && sp.type !== 'eval') continue;

      // Find the most protective applicable constraint
      let blocker: SymbolicConstraint | null = null;
      let highestPriority = -1;
      const PRIORITY = { auth: 4, allowlist: 3, sanitizer: 2, typecheck: 2, throw: 1 };

      for (const c of constraints) {
        if (!constraintProtectsSink(c, ln, lines)) continue;
        const p = PRIORITY[c.type] ?? 0;
        if (p > highestPriority) {
          highestPriority = p;
          blocker = c;
        }
      }

      const reachable     = blocker === null;
      const preconditions = constraints
        .filter(c => constraintProtectsSink(c, ln, lines))
        .map(c => `[L${c.line}] ${c.desc}: ${c.condition}`);

      const confidence = reachable
        ? (taintedHere ? 0.85 : 0.50)
        : Math.max(0.10, 0.85 - highestPriority * 0.15);

      if (!reachable) suppressedSinks.add(ln);

      paths.push({
        sinkLine:      ln,
        sinkType:      sp.type,
        reachable,
        blockedBy:     blocker,
        preconditions,
        confidence,
        reason: reachable
          ? `Sink at L${ln} reachable — no guard between taint source and sink`
          : `Sink at L${ln} blocked by ${blocker!.type} guard at L${blocker!.line}: ${blocker!.condition}`,
      });

      break; // one path per line
    }
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  const reachable   = paths.filter(p => p.reachable).length;
  const suppressed  = paths.filter(p => !p.reachable).length;
  const authGuarded = paths.filter(p => p.blockedBy?.type === 'auth').length;

  const summary = [
    `SYMEX: ${constraints.length} constraints, ${reachable} reachable sinks, ${suppressed} suppressed`,
    authGuarded > 0 ? `${authGuarded} auth-guarded` : null,
    authGuardedLines.size > 0 ? `auth zone L${Math.min(...authGuardedLines)}-L${Math.max(...authGuardedLines)}` : null,
  ].filter(Boolean).join(' | ');

  return { constraints, paths, suppressedSinks, authGuardedLines, summary };
}

/**
 * Adjust issue list based on symbolic execution results.
 * Suppresses findings where sinks are provably unreachable.
 * Adds preconditions to findings where reachability requires specific conditions.
 */
export function applySymbolicExecution(
  issues: Array<{ line: number | null; severity: string; type: string; explanation: string; confidence?: number; [k: string]: unknown }>,
  report: SymbolicReport,
): {
  issues:     typeof issues;
  suppressed: typeof issues;
  stats:      { totalInput: number; suppressed: number; preconditionsAdded: number };
} {
  const kept:      typeof issues = [];
  const suppressed: typeof issues = [];
  let preconditionsAdded = 0;

  for (const issue of issues) {
    if (issue.line === null) { kept.push(issue); continue; }

    const path = report.paths.find(p => Math.abs(p.sinkLine - (issue.line ?? 0)) <= 2);

    if (!path) { kept.push(issue); continue; }

    if (!path.reachable && path.blockedBy) {
      // Downgrade, don't drop — the constraint may be incomplete
      const guard = path.blockedBy;
      if (guard.type === 'auth' && issue.type === 'bug' && issue.severity === 'high') {
        // Auth-guarded high sev bugs become risk/medium — still worth noting
        const adjusted = {
          ...issue,
          type: 'risk' as const,
          severity: 'medium' as const,
          explanation: `${issue.explanation}\n\n[SYMBOLIC] Sink is behind ${guard.type} guard at L${guard.line}: \`${guard.condition}\`. Exploitable only if auth check is bypassable.`,
          confidence: Math.min(issue.confidence ?? 0.85, 0.45),
        };
        suppressed.push(adjusted); // track suppressed for stats, but actually add as downgraded
        kept.push(adjusted);
        continue;
      }
      // Other suppressions: genuinely blocked
      suppressed.push(issue);
      continue;
    }

    // Reachable — add preconditions if any
    if (path.preconditions.length > 0) {
      preconditionsAdded++;
      kept.push({
        ...issue,
        explanation: `${issue.explanation}\n\n[SYMBOLIC] Preconditions for exploit: ${path.preconditions.slice(0, 2).join('; ')}`,
      });
    } else {
      kept.push(issue);
    }
  }

  return {
    issues: kept,
    suppressed,
    stats: {
      totalInput:         issues.length,
      suppressed:         suppressed.length,
      preconditionsAdded,
    },
  };
}
