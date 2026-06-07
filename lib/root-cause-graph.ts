// ─────────────────────────────────────────────────────────────────────────────
// ROOT-CAUSE GRAPH ENGINE v5
//
// Solves the #1 trust problem: duplicate findings inflating counts.
//
// Architecture:
//   • Assign each finding a TaintLineageId (source + sink family)
//   • Cluster findings by (vulnFamily × sinkType × sourceZone)
//   • Collapse each cluster into ONE canonical finding
//   • Annotate canonical with variant count + all affected lines
//   • Execution-context modeling: suppress findings where sink is
//     unreachable under attacker control
//
// Result: "22 bugs" → "~9 unique exploit surfaces"
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ── Vulnerability families ────────────────────────────────────────────────────
export type VulnFamily =
  | 'sqli' | 'xss' | 'rce' | 'ssrf' | 'path-traversal'
  | 'cmd-injection' | 'proto-pollution' | 'open-redirect'
  | 'header-injection' | 'mass-assignment' | 'timing-attack'
  | 'jwt-bypass' | 'insecure-deserialize' | 'redos'
  | 'hardcoded-secret' | 'prompt-injection' | 'unknown';

// ── Sink types (what the payload reaches) ────────────────────────────────────
export type SinkType =
  | 'database' | 'dom' | 'shell' | 'filesystem' | 'network'
  | 'process' | 'eval' | 'header' | 'redirect' | 'object-proto'
  | 'auth' | 'deserializer' | 'regex' | 'secret-store' | 'unknown';

// ── Source zones (where attacker input enters) ────────────────────────────────
export type SourceZone =
  | 'http-body' | 'http-query' | 'http-header' | 'http-param'
  | 'env' | 'file' | 'ipc' | 'websocket' | 'graphql' | 'internal';

export interface TaintLineage {
  id:          string;     // canonical key: `${family}:${sink}:${zone}`
  family:      VulnFamily;
  sink:        SinkType;
  sourceZone:  SourceZone;
  confidence:  number;     // 0–100
}

export interface CanonicalVuln {
  id:              string;
  family:          VulnFamily;
  sink:            SinkType;
  sourceZone:      SourceZone;
  // Representative finding (highest confidence)
  canonical:       Issue;
  // All variant findings collapsed into this one
  variants:        Issue[];
  variantCount:    number;
  affectedLines:   number[];
  // Merged confidence: max of variants weighted by count
  confidence:      number;
  exploitability:  number;
  reachability:    number;
  blastRadius:     'critical' | 'high' | 'medium' | 'low';
  // Execution-context suppression
  suppressed:      boolean;
  suppressReason?: string;
}

export interface RootCauseGraph {
  canonicals:      CanonicalVuln[];
  suppressedCount: number;
  collapsedCount:  number;  // how many duplicates were removed
  totalInput:      number;
  uniqueSurfaces:  number;
}

// ── Family classifier ─────────────────────────────────────────────────────────
const FAMILY_PATTERNS: [RegExp, VulnFamily][] = [
  [/sql.{0,20}inject|sqli|sql injection/i,            'sqli'],
  [/xss|cross.site.script|innerhtml|dangerously/i,    'xss'],
  [/rce|remote.code|eval\(|new Function|vm\.run/i,   'rce'],
  [/ssrf|server.side.request|fetch.*url|unvalidated.url/i, 'ssrf'],
  [/path.travers|directory.travers|readfile.*user/i,  'path-traversal'],
  [/command.inject|exec.*user|spawn.*user|shell/i,    'cmd-injection'],
  [/proto.pollut|__proto__|constructor.prototype/i,   'proto-pollution'],
  [/open.redirect|res\.redirect.*user/i,              'open-redirect'],
  [/header.inject|crlf|setHeader.*user/i,             'header-injection'],
  [/mass.assign|Object\.assign.*req\.body|spread.*req\.body/i, 'mass-assignment'],
  [/timing.attack|===.*secret|===.*token|===.*hash/i, 'timing-attack'],
  [/jwt|decode.*token|algorithm.*none/i,              'jwt-bypass'],
  [/deserializ|unserialize/i,                         'insecure-deserialize'],
  [/redos|catastrophic.backtrack|nested.quantif/i,    'redos'],
  [/hardcoded.{0,20}(secret|password|key|token)|api.key.in.code/i, 'hardcoded-secret'],
  [/prompt.inject|ignore.previous|override.instruct/i,'prompt-injection'],
];

function classifyFamily(issue: Issue): VulnFamily {
  const text = `${issue.title} ${issue.explanation} ${issue.category}`;
  for (const [re, family] of FAMILY_PATTERNS) {
    if (re.test(text)) return family;
  }
  return 'unknown';
}

// ── Sink classifier ────────────────────────────────────────────────────────────
const SINK_PATTERNS: [RegExp, SinkType][] = [
  [/sql|db\.|query|database/i,          'database'],
  [/innerhtml|outerhtml|xss|dom|dangerously|document\.write/i, 'dom'],
  [/exec|spawn|shell|command|child_process/i, 'shell'],
  [/readfile|writefile|path\.join|fs\./i, 'filesystem'],
  [/fetch|axios|ssrf|http|request.*url/i, 'network'],
  [/process\.env|process\.exit/i,        'process'],
  [/eval|new Function|vm\.run/i,         'eval'],
  [/setHeader|header.inject|crlf/i,      'header'],
  [/redirect/i,                          'redirect'],
  [/proto|__proto__|prototype/i,         'object-proto'],
  [/jwt|auth|token|session/i,            'auth'],
  [/deserializ|unserialize/i,            'deserializer'],
  [/regex|redos|backtrack/i,             'regex'],
  [/secret|api.key|hardcoded/i,          'secret-store'],
];

function classifySink(issue: Issue): SinkType {
  const text = `${issue.title} ${issue.explanation}`;
  for (const [re, sink] of SINK_PATTERNS) {
    if (re.test(text)) return sink;
  }
  return 'unknown';
}

// ── Source zone classifier ─────────────────────────────────────────────────────
function classifySourceZone(issue: Issue): SourceZone {
  const text = `${issue.explanation} ${issue.exploitChain ?? ''}`;
  if (/req\.body|body\./i.test(text))   return 'http-body';
  if (/req\.query|query\./i.test(text)) return 'http-query';
  if (/req\.headers|header\./i.test(text)) return 'http-header';
  if (/req\.params|params\./i.test(text)) return 'http-param';
  if (/websocket|ws\./i.test(text))     return 'websocket';
  if (/graphql|resolver/i.test(text))   return 'graphql';
  if (/process\.env|env\./i.test(text)) return 'env';
  if (/file|fs\./i.test(text))          return 'file';
  return 'internal';
}

// ── Execution-context suppression rules ───────────────────────────────────────
// Findings that are technically true but NOT exploitable under normal conditions
interface SuppressionRule {
  familyMatch: VulnFamily[];
  pattern:     RegExp;
  reason:      string;
  // Only suppress if confidence is below this threshold
  maxConfidence: number;
}

const SUPPRESSION_RULES: SuppressionRule[] = [
  {
    // vm.runInNewContext is a real finding BUT suppress at medium confidence
    // if there's no taint evidence of attacker-controlled code input
    familyMatch: ['rce'],
    pattern:     /vm\.run|runInNewContext/i,
    reason:      'vm.runInNewContext detected but no attacker-controlled code input confirmed — reduced to risk. Verify attacker reachability before escalating.',
    maxConfidence: 65,
  },
  {
    // Function() constructor without proven tainted argument
    familyMatch: ['rce'],
    pattern:     /Function\(\)/i,
    reason:      'Function() constructor found but no tainted argument confirmed via taint analysis. Flag for manual review.',
    maxConfidence: 60,
  },
  {
    // ReDoS: medium confidence only if user input confirmed to reach regex
    familyMatch: ['redos'],
    pattern:     /redos|backtrack/i,
    reason:      'ReDoS pattern detected but user input reachability to regex not confirmed — may be internal-only.',
    maxConfidence: 55,
  },
];

function checkSuppression(issue: Issue, family: VulnFamily, conf: number): { suppressed: boolean; reason?: string } {
  for (const rule of SUPPRESSION_RULES) {
    if (!rule.familyMatch.includes(family)) continue;
    const text = `${issue.title} ${issue.explanation}`;
    if (!rule.pattern.test(text)) continue;
    if (conf <= rule.maxConfidence) {
      return { suppressed: true, reason: rule.reason };
    }
  }
  return { suppressed: false };
}

// ── Confidence computation ─────────────────────────────────────────────────────
function computeConfidence(issue: Issue): number {
  // Start from issue's own confidence field if present
  let base = typeof issue.confidence === 'number'
    ? (issue.confidence > 1 ? issue.confidence : issue.confidence * 100)
    : 70;

  // Boost for exploit-verified
  if (issue.exploitVerified === true)  base = Math.min(98, base + 15);
  if (issue.exploitVerified === false) base = Math.max(20, base - 25);

  // Boost for exploit chain (proves reasoning)
  if (issue.exploitChain && issue.exploitChain.length > 40) base = Math.min(95, base + 8);

  // Boost for exploit payload (concrete evidence)
  if (issue.exploitPayload && issue.exploitPayload.length > 20) base = Math.min(95, base + 5);

  // Boost for exact line number (not guessed)
  if (issue.line !== null) base = Math.min(95, base + 3);

  // Penalty for vague explanation
  if (issue.explanation.length < 60) base = Math.max(20, base - 15);

  // Penalty for no fix and no rejection reason (uncertain)
  if (!issue.fix && !issue.fixRejectionReason) base = Math.max(20, base - 5);

  return Math.round(Math.min(98, Math.max(10, base)));
}

// ── Exploitability scoring ────────────────────────────────────────────────────
const FAMILY_EXPLOITABILITY: Record<VulnFamily, number> = {
  'rce': 95, 'sqli': 90, 'ssrf': 85, 'cmd-injection': 92,
  'xss': 80, 'path-traversal': 78, 'proto-pollution': 75,
  'jwt-bypass': 88, 'insecure-deserialize': 90, 'open-redirect': 65,
  'header-injection': 60, 'mass-assignment': 72, 'timing-attack': 55,
  'hardcoded-secret': 85, 'redos': 70, 'prompt-injection': 65, 'unknown': 50,
};

const SINK_REACHABILITY: Record<SinkType, number> = {
  'database': 90, 'shell': 92, 'eval': 95, 'network': 85, 'dom': 82,
  'filesystem': 80, 'header': 70, 'redirect': 72, 'object-proto': 75,
  'auth': 88, 'deserializer': 88, 'regex': 65, 'secret-store': 78,
  'process': 60, 'unknown': 50,
};

const BLAST_RADIUS_MAP: Record<VulnFamily, 'critical' | 'high' | 'medium' | 'low'> = {
  'rce': 'critical', 'cmd-injection': 'critical', 'sqli': 'critical',
  'insecure-deserialize': 'critical', 'ssrf': 'high', 'jwt-bypass': 'high',
  'proto-pollution': 'high', 'xss': 'high', 'path-traversal': 'high',
  'hardcoded-secret': 'high', 'mass-assignment': 'medium', 'open-redirect': 'medium',
  'header-injection': 'medium', 'timing-attack': 'medium', 'redos': 'medium',
  'prompt-injection': 'low', 'unknown': 'low',
};

// ── Line grouping (±5 lines = same logical location) ─────────────────────────
function lineGroup(line: number | null): number {
  if (line === null) return -1;
  return Math.floor(line / 5);
}

// ── Main: build root-cause graph ──────────────────────────────────────────────
export function buildRootCauseGraph(issues: Issue[]): RootCauseGraph {
  const totalInput = issues.length;

  // Step 1: classify each finding
  type Classified = {
    issue:      Issue;
    family:     VulnFamily;
    sink:       SinkType;
    sourceZone: SourceZone;
    confidence: number;
    lineage:    string;
  };

  const classified: Classified[] = issues.map(issue => {
    const family     = classifyFamily(issue);
    const sink       = classifySink(issue);
    const sourceZone = classifySourceZone(issue);
    const confidence = computeConfidence(issue);
    // Lineage key: family + sink type + line group
    // This is narrower than full source zone to avoid over-merging
    const lineage = `${family}:${sink}:${lineGroup(issue.line)}`;
    return { issue, family, sink, sourceZone, confidence, lineage };
  });

  // Step 2: cluster by lineage key
  const clusters = new Map<string, Classified[]>();
  for (const c of classified) {
    const existing = clusters.get(c.lineage) ?? [];
    existing.push(c);
    clusters.set(c.lineage, existing);
  }

  // Step 3: collapse each cluster → canonical
  const canonicals: CanonicalVuln[] = [];
  let collapsedCount = 0;
  let suppressedCount = 0;

  for (const [lineageId, group] of clusters) {
    // Sort by confidence desc → pick highest as canonical
    group.sort((a, b) => b.confidence - a.confidence);
    const best      = group[0];
    const variants  = group.slice(1);
    collapsedCount += variants.length;

    const avgConf   = Math.round(group.reduce((s, c) => s + c.confidence, 0) / group.length);
    const maxConf   = best.confidence;
    // Weight toward max but penalize if only 1 finding (less certainty)
    const finalConf = group.length === 1 ? Math.max(40, maxConf - 5) : Math.min(98, maxConf + Math.min(5, variants.length * 2));

    const { suppressed, reason: suppressReason } = checkSuppression(best.issue, best.family, finalConf);
    if (suppressed) suppressedCount++;

    const affectedLines = [...new Set(group.map(c => c.issue.line).filter((l): l is number => l !== null))].sort((a,b) => a-b);

    const exploitability = FAMILY_EXPLOITABILITY[best.family] ?? 50;
    const reachability   = SINK_REACHABILITY[best.sink] ?? 50;
    const blastRadius    = BLAST_RADIUS_MAP[best.family] ?? 'low';

    // Merge variant explanation context
    let canonical = { ...best.issue };
    if (variants.length > 0) {
      const variantSummary = variants.length === 1
        ? ` [+1 variant at L${variants[0].issue.line ?? '?'} — same root cause]`
        : ` [+${variants.length} variants at lines ${variants.map(v => v.issue.line ?? '?').join(', ')} — same root cause]`;
      canonical = {
        ...canonical,
        explanation: canonical.explanation + variantSummary,
        confidence: finalConf / 100,
      };
    }

    canonicals.push({
      id:            lineageId,
      family:        best.family,
      sink:          best.sink,
      sourceZone:    best.sourceZone,
      canonical,
      variants:      variants.map(v => v.issue),
      variantCount:  variants.length,
      affectedLines,
      confidence:    finalConf,
      exploitability,
      reachability,
      blastRadius,
      suppressed,
      suppressReason,
    });
  }

  // Step 4: sort — unsuppressed first, then by exploitability × confidence
  canonicals.sort((a, b) => {
    if (a.suppressed !== b.suppressed) return a.suppressed ? 1 : -1;
    return (b.exploitability * b.confidence) - (a.exploitability * a.confidence);
  });

  return {
    canonicals,
    suppressedCount,
    collapsedCount,
    totalInput,
    uniqueSurfaces: canonicals.filter(c => !c.suppressed).length,
  };
}

// ── Convert graph back to Issue[] for the existing pipeline ──────────────────
// Suppressed findings are converted to 'risk/low' instead of 'bug/high'
export function graphToIssues(graph: RootCauseGraph): Issue[] {
  return graph.canonicals.map(c => {
    const issue = { ...c.canonical };

    if (c.suppressed) {
      return {
        ...issue,
        type:      'risk' as const,
        severity:  'low' as const,
        category:  issue.category,
        explanation: `${issue.explanation} — SUPPRESSED: ${c.suppressReason}`,
        confidence: Math.max(10, c.confidence - 20) / 100,
      };
    }

    return {
      ...issue,
      confidence:    c.confidence / 100,
      exploitability: c.exploitability,
      reachability:  c.reachability,
      blastRadius:   c.blastRadius,
    };
  });
}

// ── Scoring engine rewrite ────────────────────────────────────────────────────
// Uses exploitability × reachability × confidence weighting
// NOT raw finding count
export function computeWeightedScore(graph: RootCauseGraph): number {
  let penalty = 0;

  for (const c of graph.canonicals) {
    if (c.suppressed) continue; // don't penalize suppressed

    const issue = c.canonical;
    // Base deduction from severity
    const baseDed: Record<string, Record<string, number>> = {
      bug:        { high: 20, medium: 10, low: 4 },
      risk:       { high: 12, medium: 6,  low: 3 },
      suggestion: { high: 2,  medium: 2,  low: 2 },
    };
    const base = baseDed[issue.type]?.[issue.severity] ?? 2;

    // Weight by confidence (low confidence = less penalty)
    const confFactor = c.confidence / 100;

    // Additional penalty for critical blast radius
    const blastFactor = { critical: 1.3, high: 1.1, medium: 0.9, low: 0.7 }[c.blastRadius];

    // Variant count adds small additional penalty (but diminishing)
    const variantBonus = Math.min(5, c.variantCount * 1.5);

    penalty += (base * confFactor * blastFactor) + variantBonus;
  }

  return Math.max(0, Math.round(100 - penalty));
}

// ── Summary builder ───────────────────────────────────────────────────────────
export function buildGraphSummary(graph: RootCauseGraph): string {
  const active    = graph.canonicals.filter(c => !c.suppressed);
  const critical  = active.filter(c => c.blastRadius === 'critical').length;
  const high      = active.filter(c => c.blastRadius === 'high').length;
  const families  = [...new Set(active.map(c => c.family))];

  const parts: string[] = [];
  if (critical > 0) parts.push(`${critical} critical exploit surface${critical > 1 ? 's' : ''}`);
  if (high > 0)     parts.push(`${high} high-severity`);
  if (graph.collapsedCount > 0) parts.push(`${graph.collapsedCount} duplicate${graph.collapsedCount > 1 ? 's' : ''} collapsed`);
  if (graph.suppressedCount > 0) parts.push(`${graph.suppressedCount} suppressed (low attacker reachability)`);
  if (families.length) parts.push(`families: ${families.slice(0, 4).join(', ')}`);

  return parts.join(' · ') || 'No unique exploit surfaces detected.';
}
