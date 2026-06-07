// ─────────────────────────────────────────────────────────────────────────────
// DIFFERENTIAL ANALYSIS ENGINE v8
//
// Scalability upgrade: instead of scanning everything, analyzes only changed
// trust surfaces. For incremental reviews (single file or diff context),
// this enables targeted, high-signal analysis.
//
// Architecture:
//   • Change surface detection — identifies what changed in submitted code
//   • Affected sink analysis — finds sinks reachable from changed code
//   • Incremental taint recomputation — only retaints from changed sources
//   • Noise suppression — issues unrelated to changes are deprioritized
//
// In practice (no git diff available):
//   • Analyzes structural novelty — new functions, new routes, new sinks
//   • Identifies high-churn patterns — complex nesting, dynamic constructs
//   • Scores each finding by proximity to changed/novel code
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ── Change surface analysis ───────────────────────────────────────────────────

export interface ChangeSurface {
  newFunctions:     string[];   // function names that appear novel/complex
  newRoutes:        string[];   // new route handlers
  newSinks:         SinkRef[];  // newly-introduced dangerous sinks
  newSources:       SourceRef[];// new untrusted input points
  highRiskLines:    number[];   // line numbers flagged as high-change-risk
  complexityHotspots: number[]; // lines with high cyclomatic complexity
}

export interface SinkRef {
  line:   number;
  kind:   string;
  code:   string;
}

export interface SourceRef {
  line:   number;
  kind:   string;
  var:    string;
}

// ── Sink detectors ────────────────────────────────────────────────────────────
const SINK_DETECTORS: Array<{ kind: string; pattern: RegExp }> = [
  { kind: 'sql',      pattern: /db\.(query|execute|run)\s*\(/                  },
  { kind: 'eval',     pattern: /\beval\s*\(|new Function\s*\(/                  },
  { kind: 'xss',      pattern: /\.innerHTML\s*=|dangerouslySetInnerHTML/        },
  { kind: 'ssrf',     pattern: /fetch\s*\(\s*\w|axios\.(get|post)\s*\(\s*\w/   },
  { kind: 'cmd',      pattern: /exec\s*\(|spawn\s*\(|execSync\s*\(/            },
  { kind: 'path',     pattern: /readFile\s*\(|readFileSync\s*\(|createReadStream/ },
  { kind: 'redirect', pattern: /res\.redirect\s*\(|location\.href\s*=/          },
  { kind: 'proto',    pattern: /\[req\.|Object\.assign\s*\(\s*\w+\s*,\s*req/    },
];

// ── Source detectors ──────────────────────────────────────────────────────────
const SOURCE_DETECTORS: Array<{ kind: string; pattern: RegExp }> = [
  { kind: 'req.body',    pattern: /(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*req\.body/         },
  { kind: 'req.query',   pattern: /(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*req\.query/        },
  { kind: 'req.params',  pattern: /(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*req\.params/       },
  { kind: 'searchParams',pattern: /(?:const|let|var)\s+(\w+)\s*=\s*(?:req\.|request\.).*searchParams\.get/ },
  { kind: 'formData',    pattern: /(?:const|let|var)\s+(\w+)\s*=\s*formData\.get\s*\(/                 },
];

// ── Complexity scoring ────────────────────────────────────────────────────────
function complexityScore(line: string): number {
  let score = 0;
  // Each nesting level adds risk
  score += (line.match(/\bif\b|\belse\b|\bwhile\b|\bfor\b|\btry\b|\bcatch\b/g) ?? []).length * 2;
  // Callbacks and async patterns add complexity
  score += (line.match(/\bthen\b|\basync\b|\bawait\b/g) ?? []).length;
  // Dynamic property access
  score += (line.match(/\[.*?\]/g) ?? []).length;
  // Template literals (potential injection points)
  score += (line.match(/`[^`]*\$\{/g) ?? []).length * 3;
  return score;
}

/**
 * Analyze the change surface of submitted code.
 * Without a real git diff, we identify "novel" structures: new routes,
 * complex functions, newly-introduced sinks and sources.
 */
export function analyzeChangeSurface(code: string): ChangeSurface {
  const lines = code.split('\n');
  const newFunctions: string[] = [];
  const newRoutes: string[] = [];
  const newSinks: SinkRef[] = [];
  const newSources: SourceRef[] = [];
  const highRiskLines: number[] = [];
  const complexityHotspots: number[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln   = i + 1;

    // Detect function definitions
    const fnM = line.match(/(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(/);
    if (fnM) newFunctions.push(fnM[1]);

    const arrowM = line.match(/(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?\(/);
    if (arrowM && /=>/.test(lines.slice(i, i + 3).join(''))) {
      newFunctions.push(arrowM[1]);
    }

    // Detect route definitions
    const routeM = line.match(
      /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/i
    );
    if (routeM) newRoutes.push(`${routeM[1].toUpperCase()} ${routeM[2]}`);

    const nextRouteM = line.match(/export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE)\s*\(/);
    if (nextRouteM) newRoutes.push(nextRouteM[1]);

    // Detect sinks
    for (const { kind, pattern } of SINK_DETECTORS) {
      if (pattern.test(line)) {
        newSinks.push({ line: ln, kind, code: line.trim().slice(0, 80) });
      }
    }

    // Detect sources
    for (const { kind, pattern } of SOURCE_DETECTORS) {
      const m = line.match(pattern);
      if (m) {
        const varName = (m[1] && !m[1].includes(',')) ? m[1] : (m[2] ?? 'input');
        newSources.push({ line: ln, kind, var: varName.trim() });
      }
    }

    // Complexity hotspots
    const complexity = complexityScore(line);
    if (complexity >= 5) complexityHotspots.push(ln);

    // High-risk lines: template literals flowing to sinks
    if (/`[^`]*\$\{/.test(line) && SINK_DETECTORS.some(d => d.pattern.test(line))) {
      highRiskLines.push(ln);
    }
  }

  return {
    newFunctions:       [...new Set(newFunctions)],
    newRoutes:          [...new Set(newRoutes)],
    newSinks:           deduplicateSinks(newSinks),
    newSources,
    highRiskLines:      [...new Set(highRiskLines)],
    complexityHotspots: [...new Set(complexityHotspots)],
  };
}

function deduplicateSinks(sinks: SinkRef[]): SinkRef[] {
  const seen = new Set<string>();
  return sinks.filter(s => {
    const key = `${s.kind}:${s.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ── Differential prioritization ───────────────────────────────────────────────

/**
 * Score each issue by how close it is to the change surface.
 * Issues touching new sinks or high-risk lines get priority boost.
 * Issues far from any detected change surface get deprioritized.
 */
export function prioritizeByChangeSurface(
  issues: Issue[],
  surface: ChangeSurface,
): Issue[] {
  const highRiskSet = new Set(surface.highRiskLines);
  const sinkLines   = new Set(surface.newSinks.map(s => s.line));
  const sourceLines = new Set(surface.newSources.map(s => s.line));

  return issues
    .map(issue => {
      let priority = 0;
      const ln = issue.line ?? -1;

      // Exact line matches
      if (highRiskSet.has(ln))  priority += 30;
      if (sinkLines.has(ln))    priority += 25;
      if (sourceLines.has(ln))  priority += 15;

      // Near a known sink (±3 lines)
      for (const sinkLine of sinkLines) {
        if (Math.abs(ln - sinkLine) <= 3) { priority += 10; break; }
      }

      // On a complexity hotspot
      if (surface.complexityHotspots.includes(ln)) priority += 8;

      return { issue, priority };
    })
    .sort((a, b) => b.priority - a.priority)
    .map(({ issue }) => issue);
}

// ── Surface summary ───────────────────────────────────────────────────────────
export interface ChangeSurfaceSummary {
  functionCount:      number;
  routeCount:         number;
  sinkCount:          number;
  sourceCount:        number;
  highRiskLineCount:  number;
  hotspotCount:       number;
  riskLevel:          'high' | 'medium' | 'low';
}

export function getChangeSurfaceSummary(surface: ChangeSurface): ChangeSurfaceSummary {
  const riskScore =
    surface.newSinks.length * 10 +
    surface.highRiskLines.length * 8 +
    surface.newSources.length * 5 +
    surface.complexityHotspots.length * 3;

  const riskLevel: 'high' | 'medium' | 'low' =
    riskScore >= 30 ? 'high' :
    riskScore >= 10 ? 'medium' : 'low';

  return {
    functionCount:     surface.newFunctions.length,
    routeCount:        surface.newRoutes.length,
    sinkCount:         surface.newSinks.length,
    sourceCount:       surface.newSources.length,
    highRiskLineCount: surface.highRiskLines.length,
    hotspotCount:      surface.complexityHotspots.length,
    riskLevel,
  };
}
