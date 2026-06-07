// ─────────────────────────────────────────────────────────────────────────────
// CI/CD DELTA ANALYSIS ENGINE — v1.3
//
// Security delta analysis: find NEW risks introduced vs baseline.
// Optimized for PR review workflows — only what changed matters.
//
// Detects:
//   - New taint sources introduced in this diff
//   - New sinks added without sanitizers
//   - Changed trust boundaries (new routes without auth)
//   - Newly reachable risk paths
//   - Regression: previously-fixed vulnerabilities reintroduced
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

export interface DeltaAnalysisResult {
  mode:              'delta' | 'full';
  newIssues:         Issue[];      // Issues only in current, not baseline
  regressions:       Issue[];      // Issues that were fixed then reintroduced
  resolvedIssues:    Issue[];      // Issues in baseline but not current
  changedSeverity:   Array<{ title: string; was: string; now: string }>;
  newTrustBoundaries: string[];    // New routes/endpoints without auth
  newSinks:          string[];     // New dangerous sinks introduced
  stats: {
    baselineCount:    number;
    currentCount:     number;
    net:              number;
    regressions:      number;
    resolved:         number;
  };
}

// Dangerous sinks that must be monitored when introduced
const DANGEROUS_SINK_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'Raw SQL query',     pattern: /db\.(query|execute)\s*\(`/ },
  { name: 'eval()',            pattern: /eval\s*\(/ },
  { name: 'exec() shell',      pattern: /\bexec\s*\(/ },
  { name: 'innerHTML write',   pattern: /\.innerHTML\s*=/ },
  { name: 'readFile direct',   pattern: /readFile(?:Sync)?\s*\(/ },
  { name: 'fetch(user input)', pattern: /fetch\s*\(\s*(?:req|url|params)/ },
  { name: 'dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML/ },
  { name: 'child_process',     pattern: /require\(['"]child_process['"]\)/ },
];

// Route/endpoint patterns that establish trust boundaries
const ROUTE_PATTERNS: RegExp[] = [
  /app\.(get|post|put|delete|patch)\s*\(['"]([^'"]+)['"]/,
  /router\.(get|post|put|delete|patch)\s*\(['"]([^'"]+)['"]/,
  /\.(get|post|put|delete|patch)\s*\(['"]\/api\//,
];

// Auth middleware patterns
const AUTH_PATTERNS: RegExp[] = [
  /authenticate|requireAuth|isAuthenticated|verifyToken|checkAuth|authMiddleware/,
  /passport\.authenticate/,
  /jwt\.verify/,
  /session\.\w+/,
];

function extractRoutes(code: string): Array<{ route: string; hasAuth: boolean; line: number }> {
  const lines = code.split('\n');
  const routes: Array<{ route: string; hasAuth: boolean; line: number }> = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    for (const pat of ROUTE_PATTERNS) {
      const m = pat.exec(line);
      if (m) {
        // Check surrounding context for auth middleware
        const ctx = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');
        const hasAuth = AUTH_PATTERNS.some(p => p.test(ctx));
        routes.push({ route: m[2] ?? m[0], hasAuth, line: i + 1 });
      }
    }
  }
  return routes;
}

function extractSinks(code: string): string[] {
  const found: string[] = [];
  for (const { name, pattern } of DANGEROUS_SINK_PATTERNS) {
    if (pattern.test(code)) found.push(name);
  }
  return found;
}

function fingerprint(issue: Issue): string {
  return `${issue.type}:${issue.severity}:${issue.title.toLowerCase().slice(0, 40)}`;
}

export function runDeltaAnalysis(
  currentIssues: Issue[],
  currentCode: string,
  baselineIssues?: Issue[],
  baselineCode?: string,
): DeltaAnalysisResult {
  // If no baseline, return full analysis mode
  if (!baselineIssues || !baselineCode) {
    const sinks = extractSinks(currentCode);
    const routes = extractRoutes(currentCode);
    const unauthRoutes = routes.filter(r => !r.hasAuth).map(r => r.route);

    return {
      mode: 'full',
      newIssues: currentIssues,
      regressions: [],
      resolvedIssues: [],
      changedSeverity: [],
      newTrustBoundaries: unauthRoutes,
      newSinks: sinks,
      stats: {
        baselineCount: 0,
        currentCount: currentIssues.length,
        net: currentIssues.length,
        regressions: 0,
        resolved: 0,
      },
    };
  }

  // Delta mode — compare against baseline
  const baselineFingerprints = new Map(baselineIssues.map(i => [fingerprint(i), i]));
  const currentFingerprints  = new Map(currentIssues.map(i => [fingerprint(i), i]));

  // New issues: in current but not baseline
  const newIssues = currentIssues.filter(i => !baselineFingerprints.has(fingerprint(i)));

  // Resolved: in baseline but not current
  const resolvedIssues = baselineIssues.filter(i => !currentFingerprints.has(fingerprint(i)));

  // Regressions: title matches a resolved issue but is back
  // (simplified: if a HIGH issue was resolved and reappeared)
  const regressions = newIssues.filter(ni => {
    const niTitle = ni.title.toLowerCase().slice(0, 30);
    return resolvedIssues.some(ri => ri.title.toLowerCase().slice(0, 30) === niTitle);
  });

  // Severity changes
  const changedSeverity: Array<{ title: string; was: string; now: string }> = [];
  for (const [fp, curr] of currentFingerprints) {
    const base = baselineFingerprints.get(fp);
    if (base && base.severity !== curr.severity) {
      changedSeverity.push({ title: curr.title, was: base.severity, now: curr.severity });
    }
  }

  // New trust boundaries
  const currentRoutes  = extractRoutes(currentCode);
  const baselineRoutes = extractRoutes(baselineCode);
  const baselineRouteSet = new Set(baselineRoutes.map(r => r.route));
  const newUnauthRoutes = currentRoutes
    .filter(r => !r.hasAuth && !baselineRouteSet.has(r.route))
    .map(r => r.route);

  // New sinks introduced
  const baselineSinkSet = new Set(extractSinks(baselineCode));
  const newSinks = extractSinks(currentCode).filter(s => !baselineSinkSet.has(s));

  return {
    mode: 'delta',
    newIssues,
    regressions,
    resolvedIssues,
    changedSeverity,
    newTrustBoundaries: newUnauthRoutes,
    newSinks,
    stats: {
      baselineCount: baselineIssues.length,
      currentCount:  currentIssues.length,
      net:           newIssues.length - resolvedIssues.length,
      regressions:   regressions.length,
      resolved:      resolvedIssues.length,
    },
  };
}
