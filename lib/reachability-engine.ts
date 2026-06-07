// ─────────────────────────────────────────────────────────────────────────────
// REACHABILITY ANALYSIS ENGINE v6
//
// P0 item: Determine for every sink whether it is actually attacker-reachable.
//
// Analyses:
//   1. Route graph  — HTTP verbs, path params, middleware chain
//   2. Auth graph   — auth middleware, role guards, JWT verify
//   3. Call-chain   — can external input reach the sink?
//   4. Dead code    — unreachable functions/branches
//   5. Scope        — admin-only / internal-only / dev-only flags
//
// Output: ReachabilityContext per finding line
// ─────────────────────────────────────────────────────────────────────────────

export type AttackerType = 'external-anon' | 'external-auth' | 'admin-only' | 'internal' | 'dead-code';

export interface RouteNode {
  method:     string;       // GET | POST | PUT | DELETE | ALL | *
  path:       string;
  line:       number;
  middleware: string[];     // e.g. ['authMiddleware', 'adminGuard']
  handler:    string;       // function name
}

export interface AuthBoundary {
  line:          number;
  guardName:     string;
  requiresLogin: boolean;
  requiresAdmin: boolean;
  requiresRole?: string;
}

export interface ReachabilityContext {
  line:          number;
  attackerType:  AttackerType;
  routeEntry?:   RouteNode;
  authBoundary?: AuthBoundary;
  isDead:        boolean;
  isInternal:    boolean;
  isDevOnly:     boolean;
  reachScore:    number;    // 0–100
  reason:        string;
}

// ── Route graph extractor ──────────────────────────────────────────────────────

const HTTP_ROUTE_RE = /\b(?:app|router|server|fastify|express)\.(get|post|put|patch|delete|all|use)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
const MIDDLEWARE_RE  = /\b(?:app|router)\.use\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\)/gi;

function extractRoutes(code: string): RouteNode[] {
  const lines  = code.split('\n');
  const routes: RouteNode[] = [];
  let match: RegExpExecArray | null;

  HTTP_ROUTE_RE.lastIndex = 0;
  while ((match = HTTP_ROUTE_RE.exec(code)) !== null) {
    const lineIdx = code.slice(0, match.index).split('\n').length;
    const method  = match[1].toUpperCase();
    const path    = match[2];
    // Grab trailing callback name (rough)
    const afterMatch = code.slice(match.index + match[0].length, match.index + match[0].length + 120);
    const handlerM  = afterMatch.match(/([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:\)|,|\{)/);
    const handler   = handlerM?.[1] ?? 'anonymous';
    routes.push({ method, path, line: lineIdx, middleware: [], handler });
  }
  return routes;
}

// ── Auth boundary extractor ────────────────────────────────────────────────────

const AUTH_GUARD_PATTERNS: Array<{ re: RegExp; requiresLogin: boolean; requiresAdmin: boolean }> = [
  { re: /\b(?:requireAuth|isAuthenticated|authMiddleware|authenticate|verifyToken|ensureLoggedIn)\s*[,(]/i, requiresLogin: true,  requiresAdmin: false },
  { re: /\b(?:isAdmin|requireAdmin|adminOnly|requireRole\s*\(\s*['"`]admin)/i,                              requiresLogin: true,  requiresAdmin: true  },
  { re: /\bjwt\.verify\s*\(/i,                                                                              requiresLogin: true,  requiresAdmin: false },
  { re: /\bpassport\.authenticate\s*\(/i,                                                                   requiresLogin: true,  requiresAdmin: false },
  { re: /\bif\s*\(\s*!?\s*req\.(user|session\.user|isAuthenticated\(\))/i,                                 requiresLogin: true,  requiresAdmin: false },
];

function extractAuthBoundaries(code: string): AuthBoundary[] {
  const lines     = code.split('\n');
  const boundaries: AuthBoundary[] = [];

  lines.forEach((line, idx) => {
    for (const { re, requiresLogin, requiresAdmin } of AUTH_GUARD_PATTERNS) {
      if (re.test(line)) {
        boundaries.push({
          line:          idx + 1,
          guardName:     line.trim().slice(0, 60),
          requiresLogin,
          requiresAdmin,
        });
        break;
      }
    }
  });
  return boundaries;
}

// ── Dead code / dev-only detector ─────────────────────────────────────────────

const DEAD_CODE_PATTERNS = [
  /if\s*\(\s*false\s*\)/i,
  /if\s*\(0\s*\)/,
  /\/\/\s*TODO.*(?:remove|dead|unused)/i,
  /\/\*\s*DEAD\s*\*\//i,
];

const DEV_ONLY_PATTERNS = [
  /process\.env\.NODE_ENV\s*===?\s*['"`]development['"`]/i,
  /process\.env\.NODE_ENV\s*!==?\s*['"`]production['"`]/i,
  /isDev\s*(?:&&|\?|===?\s*true)/i,
  /debug\s*(?:&&|\?|===?\s*true)/i,
  /localhost|127\.0\.0\.1/i,
];

const INTERNAL_ONLY_PATTERNS = [
  /\/internal\//i,
  /\/admin\//i,
  /\/private\//i,
  /x-internal-token/i,
  /SERVICE_SECRET|INTERNAL_API_KEY/i,
];

// ── Main reachability computation ─────────────────────────────────────────────

function nearestAuthBoundary(line: number, boundaries: AuthBoundary[]): AuthBoundary | undefined {
  // Find closest auth boundary above this line (within 40 lines)
  return boundaries
    .filter(b => b.line <= line && line - b.line <= 40)
    .sort((a, b) => b.line - a.line)[0];
}

function contextLines(code: string, line: number, radius = 12): string {
  const lines = code.split('\n');
  const start = Math.max(0, line - 1 - radius);
  const end   = Math.min(lines.length - 1, line - 1 + radius);
  return lines.slice(start, end + 1).join('\n');
}

function computeReachScore(ctx: Omit<ReachabilityContext, 'reachScore' | 'reason'>): number {
  if (ctx.isDead)       return 0;
  if (ctx.isDevOnly)    return 10;
  if (ctx.isInternal)   return 20;
  switch (ctx.attackerType) {
    case 'external-anon':  return 100;
    case 'external-auth':  return 70;
    case 'admin-only':     return 30;
    case 'internal':       return 15;
    case 'dead-code':      return 0;
  }
  return 50;
}

function buildReason(ctx: Omit<ReachabilityContext, 'reachScore' | 'reason'>): string {
  if (ctx.isDead)       return 'Dead code — sink unreachable at runtime.';
  if (ctx.isDevOnly)    return 'Dev-only code — sink is guarded by NODE_ENV=development check.';
  if (ctx.isInternal)   return 'Internal route — attacker must be on trusted network or have service token.';
  if (ctx.attackerType === 'admin-only')    return 'Admin-only gate — requires elevated privileges; severity should be reduced.';
  if (ctx.attackerType === 'external-auth') return 'Authenticated route — attacker must be a logged-in user.';
  if (ctx.attackerType === 'external-anon') return 'Unauthenticated public route — directly reachable by any external attacker.';
  return 'Reachability unknown — treat as external-anon (worst case).';
}

export function analyzeReachability(code: string, lines: number[]): Map<number, ReachabilityContext> {
  const routes     = extractRoutes(code);
  const authBounds = extractAuthBoundaries(code);
  const result     = new Map<number, ReachabilityContext>();

  for (const line of lines) {
    const ctx2 = contextLines(code, line, 15);

    const isDead     = DEAD_CODE_PATTERNS.some(re => re.test(ctx2));
    const isDevOnly  = DEV_ONLY_PATTERNS.some(re => re.test(ctx2));
    const isInternal = INTERNAL_ONLY_PATTERNS.some(re => re.test(ctx2));

    const auth         = nearestAuthBoundary(line, authBounds);
    const requiresAdmin = auth?.requiresAdmin ?? false;
    const requiresAuth  = auth?.requiresLogin ?? false;

    let attackerType: AttackerType = 'external-anon';
    if      (isDead)          attackerType = 'dead-code';
    else if (isInternal)      attackerType = 'internal';
    else if (requiresAdmin)   attackerType = 'admin-only';
    else if (requiresAuth)    attackerType = 'external-auth';

    const partial: Omit<ReachabilityContext, 'reachScore' | 'reason'> = {
      line, attackerType, authBoundary: auth,
      isDead, isInternal, isDevOnly,
      routeEntry: routes.find(r => Math.abs(r.line - line) < 20),
    };

    const reachScore = computeReachScore(partial);
    const reason     = buildReason(partial);

    result.set(line, { ...partial, reachScore, reason });
  }

  return result;
}

// ── Severity adjuster based on reachability ───────────────────────────────────

export function adjustSeverityByReachability(
  severity: 'high' | 'medium' | 'low',
  ctx: ReachabilityContext,
): 'high' | 'medium' | 'low' {
  if (ctx.isDead || ctx.reachScore === 0)            return 'low';
  if (ctx.isDevOnly && ctx.reachScore < 15)          return 'low';
  if (ctx.attackerType === 'admin-only' && severity === 'high')    return 'medium';
  if (ctx.attackerType === 'internal'   && severity === 'high')    return 'medium';
  if (ctx.attackerType === 'external-auth' && severity === 'high') return severity; // keep high — auth bypasses happen
  return severity;
}
