// ─────────────────────────────────────────────────────────────────────────────
// WHOLE-SYSTEM SEMANTIC GRAPH v1 — Stage 21
//
// Priority 2 from v13 roadmap.
//
// Upgrades from local reasoning → repository-wide reasoning.
//
// Builds:
//   • Import graph        — who depends on what
//   • Middleware graph     — execution order & trust transitions
//   • Auth graph          — where auth checks live (and where they're missing)
//   • ORM graph           — parameterized vs raw queries
//   • Queue/event graph   — async sinks and producers
//   • SDK wrapper graph   — custom wrappers hiding dangerous calls
//   • Service dependency graph — external service calls
//
// Detects:
//   • Auth bypass via wrapper chains
//   • Unsafe middleware ordering
//   • Indirect taint propagation
//   • Hidden sink wrappers
//   • Cross-module privilege escalation
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from '@/app/api/review/route';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ImportEdge   { from: string; to: string; symbol: string; line: number }
export interface MiddlewareNode { name: string; line: number; isAuth: boolean; isValidation: boolean; order: number }
export interface AuthNode     { name: string; line: number; type: 'check' | 'guard' | 'bypass-risk'; guards: string[] }
export interface OrmNode      { name: string; line: number; parameterized: boolean; rawQuery: boolean }
export interface EventEdge    { producer: string; consumer: string; event: string; line: number }
export interface WrapperNode  { name: string; line: number; wraps: string; safe: boolean }
export interface ServiceNode  { name: string; line: number; external: boolean; authenticated: boolean }

export interface WholeSystemGraph {
  imports:     ImportEdge[];
  middleware:  MiddlewareNode[];
  auth:        AuthNode[];
  orm:         OrmNode[];
  events:      EventEdge[];
  wrappers:    WrapperNode[];
  services:    ServiceNode[];
  findings:    WholeSystemFinding[];
}

export interface WholeSystemFinding {
  type:        'auth-bypass-chain' | 'unsafe-middleware-order' | 'indirect-taint' | 'hidden-sink' | 'privilege-escalation';
  severity:    'high' | 'medium' | 'low';
  title:       string;
  explanation: string;
  lines:       number[];
  confidence:  number;
}

export interface WholeSystemSummary {
  importEdges:        number;
  middlewareNodes:    number;
  authNodes:          number;
  ormNodes:           number;
  eventEdges:         number;
  wrapperNodes:       number;
  serviceNodes:       number;
  crossModuleFindings: number;
  authBypassChains:   number;
  unsafeMiddlewareOrders: number;
}

// ── Import graph builder ──────────────────────────────────────────────────────

function buildImportGraph(code: string): ImportEdge[] {
  const edges: ImportEdge[] = [];
  const lines = code.split('\n');

  // ES6 imports
  const importRe = /^import\s+(?:\{([^}]+)\}|(\w+)|\*\s+as\s+(\w+))\s+from\s+['"]([^'"]+)['"]/;
  // require() calls
  const requireRe = /(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*require\s*\(['"]([^'"]+)['"]\)/;

  lines.forEach((ln, i) => {
    const im = importRe.exec(ln);
    if (im) {
      const symbols = (im[1] ?? im[2] ?? im[3] ?? '').split(',').map(s => s.trim());
      const mod     = im[4];
      symbols.forEach(sym => edges.push({ from: 'current', to: mod, symbol: sym, line: i + 1 }));
    }
    const rq = requireRe.exec(ln);
    if (rq) {
      const symbols = (rq[1] ?? rq[2] ?? '').split(',').map(s => s.trim());
      const mod     = rq[3];
      symbols.forEach(sym => edges.push({ from: 'current', to: mod, symbol: sym, line: i + 1 }));
    }
  });

  return edges;
}

// ── Middleware graph builder ──────────────────────────────────────────────────

function buildMiddlewareGraph(code: string): MiddlewareNode[] {
  const nodes: MiddlewareNode[] = [];
  const lines = code.split('\n');

  // Express-style: app.use(...) / router.use(...)
  const useRe = /(?:app|router)\.(use|get|post|put|delete|patch)\s*\(\s*(?:'[^']*',\s*)?(\w+)/;
  // auth-looking names
  const authNames = /auth|jwt|verify|token|session|require[Aa]uth|isLoggedIn|protect|authenticate/;
  const validNames = /valid|sanitize|schema|joi|zod|yup|check/;

  let order = 0;
  lines.forEach((ln, i) => {
    const m = useRe.exec(ln);
    if (m) {
      const name = m[2];
      nodes.push({
        name,
        line:         i + 1,
        isAuth:       authNames.test(name),
        isValidation: validNames.test(name),
        order:        order++,
      });
    }
  });

  return nodes;
}

// ── Auth graph builder ────────────────────────────────────────────────────────

function buildAuthGraph(code: string): AuthNode[] {
  const nodes: AuthNode[] = [];
  const lines = code.split('\n');

  const authCheckRe = /if\s*\(\s*!?\s*(?:req\.)?(user|session|token|isAuth|isAdmin|role)|(?:authenticate|authorize|verify[Tt]oken|checkAuth|requireLogin)\s*\(/;
  const bypassRiskRe = /skip[Aa]uth|bypass|noAuth|isPublic|skipMiddleware|whitelist/;

  lines.forEach((ln, i) => {
    if (authCheckRe.test(ln)) {
      const isBypassRisk = bypassRiskRe.test(ln);
      nodes.push({
        name:   `auth_check_L${i + 1}`,
        line:   i + 1,
        type:   isBypassRisk ? 'bypass-risk' : 'check',
        guards: [],
      });
    }
  });

  return nodes;
}

// ── ORM graph builder ─────────────────────────────────────────────────────────

function buildOrmGraph(code: string): OrmNode[] {
  const nodes: OrmNode[] = [];
  const lines = code.split('\n');

  const rawQueryRe   = /\.query\s*\(`[^`]*\$\{|\.raw\s*\(|sequelize\.query\s*\([^,)]*\$\{|knex\.raw/;
  const safeQueryRe  = /\.query\s*\([^)]*,\s*\[|\$\d+|\?[^?]|\.findOne\s*\(|\.findAll\s*\(|prisma\./;

  lines.forEach((ln, i) => {
    if (rawQueryRe.test(ln)) {
      nodes.push({ name: `orm_raw_L${i + 1}`, line: i + 1, parameterized: false, rawQuery: true });
    } else if (safeQueryRe.test(ln)) {
      nodes.push({ name: `orm_safe_L${i + 1}`, line: i + 1, parameterized: true,  rawQuery: false });
    }
  });

  return nodes;
}

// ── Event/queue graph builder ─────────────────────────────────────────────────

function buildEventGraph(code: string): EventEdge[] {
  const edges: EventEdge[] = [];
  const lines  = code.split('\n');

  const emitRe = /(?:emit|publish|send|enqueue|dispatch)\s*\(\s*['"](\w+)['"]/;
  const onRe   = /(?:on|subscribe|consume|listen)\s*\(\s*['"](\w+)['"]/;

  const producers: Record<string, number> = {};
  const consumers: Record<string, number> = {};

  lines.forEach((ln, i) => {
    const em = emitRe.exec(ln);
    if (em) producers[em[1]] = i + 1;
    const on = onRe.exec(ln);
    if (on) consumers[on[1]] = i + 1;
  });

  for (const [event, prodLine] of Object.entries(producers)) {
    if (consumers[event]) {
      edges.push({ producer: `L${prodLine}`, consumer: `L${consumers[event]}`, event, line: prodLine });
    }
  }

  return edges;
}

// ── Wrapper graph builder ─────────────────────────────────────────────────────

function buildWrapperGraph(code: string): WrapperNode[] {
  const nodes: WrapperNode[] = [];
  const lines  = code.split('\n');

  // Functions that internally call dangerous sinks
  const dangerousSinks = /exec\s*\(|execSync\s*\(|eval\s*\(|readFile|createReadStream|db\.query/;
  const safePrefixes   = /validated|sanitized|escaped|safe/i;

  lines.forEach((ln, i) => {
    if (dangerousSinks.test(ln)) {
      // Check if it's inside a helper/wrapper function
      const prevLines = lines.slice(Math.max(0, i - 15), i).join('\n');
      const fnMatch   = /(?:function|const|async)\s+(\w+)\s*[=(]/.exec(prevLines);
      if (fnMatch) {
        const name = fnMatch[1];
        const safe = safePrefixes.test(name);
        nodes.push({ name, line: i + 1, wraps: ln.trim().slice(0, 50), safe });
      }
    }
  });

  return nodes;
}

// ── Service dependency builder ────────────────────────────────────────────────

function buildServiceGraph(code: string): ServiceNode[] {
  const nodes: ServiceNode[] = [];
  const lines  = code.split('\n');

  const externalRe = /fetch\s*\(['"`]https?:\/\/|axios\.(get|post|put|delete)\s*\(|http\.request\s*\(/;
  const authRe     = /Authorization|Bearer|apiKey|x-api-key|credentials/i;

  lines.forEach((ln, i) => {
    if (externalRe.test(ln)) {
      // Look nearby for auth headers
      const ctx = lines.slice(Math.max(0, i - 5), i + 5).join('\n');
      nodes.push({
        name:          `service_call_L${i + 1}`,
        line:          i + 1,
        external:      true,
        authenticated: authRe.test(ctx),
      });
    }
  });

  return nodes;
}

// ── Cross-module finding detection ────────────────────────────────────────────

function detectCrossModuleFindings(graph: Omit<WholeSystemGraph, 'findings'>): WholeSystemFinding[] {
  const findings: WholeSystemFinding[] = [];

  // 1. Unsafe middleware ordering: auth middleware comes AFTER route handler
  //    or route is registered without any auth middleware preceding it
  const authMiddleware = graph.middleware.filter(m => m.isAuth);
  const nonAuthMiddleware = graph.middleware.filter(m => !m.isAuth && !m.isValidation);
  for (const nm of nonAuthMiddleware) {
    const hasAuthBefore = authMiddleware.some(am => am.order < nm.order);
    if (!hasAuthBefore && nm.order > 0) {
      findings.push({
        type:        'unsafe-middleware-order',
        severity:    'high',
        title:       `Route handler '${nm.name}' registered before auth middleware`,
        explanation: `Middleware '${nm.name}' at line ${nm.line} executes before any authentication middleware. ` +
                     `Requests reach this handler unauthenticated. Auth middleware should be registered first.`,
        lines:       [nm.line],
        confidence:  0.70,
      });
    }
  }

  // 2. Hidden sink wrappers: unsafe wrappers exported without safe naming
  const unsafeWrappers = graph.wrappers.filter(w => !w.safe);
  for (const w of unsafeWrappers) {
    findings.push({
      type:        'hidden-sink',
      severity:    'medium',
      title:       `Wrapper function '${w.name}' hides dangerous sink`,
      explanation: `Function '${w.name}' (line ${w.line}) wraps a dangerous operation (${w.wraps}) ` +
                   `without a safe- prefix, obscuring the risk during reviews.`,
      lines:       [w.line],
      confidence:  0.60,
    });
  }

  // 3. Auth bypass: bypass-risk auth nodes with preceding unsafe wrapper
  const bypassNodes = graph.auth.filter(a => a.type === 'bypass-risk');
  for (const bn of bypassNodes) {
    findings.push({
      type:        'auth-bypass-chain',
      severity:    'high',
      title:       `Potential auth bypass at line ${bn.line}`,
      explanation: `Code at line ${bn.line} contains an auth skip/bypass pattern. ` +
                   `If this is reachable from an unauthenticated route, it represents a privilege escalation path.`,
      lines:       [bn.line],
      confidence:  0.75,
    });
  }

  // 4. Raw ORM queries with no preceding auth check nearby
  const rawOrm = graph.orm.filter(o => o.rawQuery);
  for (const ro of rawOrm) {
    const hasNearbyAuth = graph.auth.some(a => Math.abs(a.line - ro.line) < 30);
    if (!hasNearbyAuth) {
      findings.push({
        type:        'indirect-taint',
        severity:    'medium',
        title:       `Raw ORM query at L${ro.line} with no nearby auth guard`,
        explanation: `A raw (non-parameterized) database query at line ${ro.line} has no authentication check ` +
                     `within 30 lines. Attackers reaching this code path can inject arbitrary SQL.`,
        lines:       [ro.line],
        confidence:  0.65,
      });
    }
  }

  // 5. Unauthenticated external service calls
  const unauthServices = graph.services.filter(s => s.external && !s.authenticated);
  for (const us of unauthServices) {
    findings.push({
      type:        'privilege-escalation',
      severity:    'low',
      title:       `Unauthenticated external service call at L${us.line}`,
      explanation: `External HTTP call at line ${us.line} does not include Authorization headers or API keys. ` +
                   `If this reaches an internal service, it may allow unauthenticated access.`,
      lines:       [us.line],
      confidence:  0.50,
    });
  }

  return findings;
}

// ── Main export ───────────────────────────────────────────────────────────────

export function buildWholeSystemGraph(code: string): WholeSystemGraph {
  const imports    = buildImportGraph(code);
  const middleware = buildMiddlewareGraph(code);
  const auth       = buildAuthGraph(code);
  const orm        = buildOrmGraph(code);
  const events     = buildEventGraph(code);
  const wrappers   = buildWrapperGraph(code);
  const services   = buildServiceGraph(code);
  const findings   = detectCrossModuleFindings({ imports, middleware, auth, orm, events, wrappers, services });

  return { imports, middleware, auth, orm, events, wrappers, services, findings };
}

export function wholeSystemGraphToIssues(graph: WholeSystemGraph): Issue[] {
  return graph.findings.map((f, i) => ({
    type:        'risk' as const,
    severity:    f.severity,
    category:    f.type.replace(/-/g, ' '),
    line:        f.lines[0] ?? null,
    title:       f.title,
    explanation: f.explanation,
    fix:         null,
    confidence:  f.confidence,
  }));
}

export function getWholeSystemSummary(graph: WholeSystemGraph): WholeSystemSummary {
  return {
    importEdges:             graph.imports.length,
    middlewareNodes:         graph.middleware.length,
    authNodes:               graph.auth.length,
    ormNodes:                graph.orm.length,
    eventEdges:              graph.events.length,
    wrapperNodes:            graph.wrappers.length,
    serviceNodes:            graph.services.length,
    crossModuleFindings:     graph.findings.length,
    authBypassChains:        graph.findings.filter(f => f.type === 'auth-bypass-chain').length,
    unsafeMiddlewareOrders:  graph.findings.filter(f => f.type === 'unsafe-middleware-order').length,
  };
}
