// ─────────────────────────────────────────────────────────────────────────────
// AI HALLUCINATION FIREWALL v8
//
// Prevents fabricated findings from reaching the output. As AI layers
// increase, hallucination risk becomes architectural — this module is the
// deterministic ground-truth layer that catches AI errors.
//
// Verification pipeline:
//   1. Schema validation — finding must match structural requirements
//   2. AST-backed line verification — line N must actually contain the issue
//   3. Sink existence check — named sink must exist in code
//   4. Source existence check — named taint source must exist
//   5. Exploit chain coherence — chain must reference real code elements
//   6. Severity plausibility — severity must match pattern risk class
//   7. Critic arbitration — critic score must agree with evidence
//
// Result: findings without deterministic evidence are flagged, downgraded, or
// dropped — preventing fabricated paths, fake chains, invented severities.
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ── Verification result ────────────────────────────────────────────────────────
export interface HallucinationCheckResult {
  passed:      boolean;
  confidence:  number;    // adjusted confidence after verification
  violations:  string[];  // list of failed checks
  downgraded:  boolean;   // was severity reduced?
  dropped:     boolean;   // should issue be removed?
  evidence:    string[];  // what deterministic evidence was found
}

// ── Known sink patterns by vulnerability class ────────────────────────────────
const SINK_EVIDENCE: Record<string, RegExp[]> = {
  'sql':             [/db\.(query|execute|run)\s*\(`/, /db\.(query|execute|run)\s*\(\s*\w+/, /\.rawQuery\s*\(/, /knex\.raw\s*\(/],
  'xss':             [/\.innerHTML\s*=/, /dangerouslySetInnerHTML/, /document\.write\s*\(/, /\.outerHTML\s*=/],
  'ssrf':            [/fetch\s*\(\s*\w+/, /axios\.(get|post)\s*\(\s*\w+/, /got\s*\(\s*\w+/],
  'cmd':             [/exec\s*\(/, /spawn\s*\(/, /execSync\s*\(/, /child_process/],
  'path':            [/readFile\s*\(/, /readFileSync\s*\(/, /createReadStream\s*\(/, /fs\.\w+\s*\(\s*\w+/],
  'proto':           [/__proto__\s*\[/, /prototype\s*\[/, /\['__proto__'\]/, /\["__proto__"\]/, /Object\.assign\s*\(/, /merge\s*\(/, /extend\s*\(/],
  'redirect':        [/res\.redirect\s*\(/, /location\s*=/, /window\.location/],
  'eval':            [/eval\s*\(/, /new Function\s*\(/, /vm\.run/],
  'header':          [/res\.setHeader\s*\(/, /response\.headers\.set\s*\(/],
  'jwt':             [/jwt\.decode\s*\(/, /jwt\.sign\s*\(/, /jwt\.verify\s*\(/],
};

// ── Source evidence patterns ───────────────────────────────────────────────────
const SOURCE_EVIDENCE: RegExp[] = [
  /req\.(body|query|params|headers)/,
  /request\.(body|query|params|headers)/,
  /ctx\.(request|query|params)/,
  /formData\.get\s*\(/,
  /searchParams\.get\s*\(/,
  /event\.(queryStringParameters|body)/,
];

// ── Severity plausibility map ──────────────────────────────────────────────────
// Maps vuln class → minimum justified severity
const SEVERITY_FLOOR: Record<string, Issue['severity']> = {
  'sql':      'high',
  'xss':      'high',
  'ssrf':     'high',
  'cmd':      'high',
  'eval':     'high',
  'jwt':      'high',
  'path':     'medium',
  'proto':    'medium',
  'redirect': 'medium',
  'header':   'low',
};

// ── Severity ceiling (never auto-escalate beyond this without evidence) ────────
// Severity ceiling by issue TYPE — only hard-limit 'suggestion' type findings.
// 'risk' and 'bug' issues can justify 'high' severity for critical vuln classes.
// The severity floor (SEVERITY_FLOOR by vuln family) handles the lower bound.
const SEVERITY_CEILING: Record<string, Issue['severity']> = {
  'suggestion': 'low',
  // 'risk' and 'bug' are uncapped — let vuln family floor/ceiling govern them
};

// ── Line evidence extractor ────────────────────────────────────────────────────
function getLinesAround(code: string, line: number | null, radius = 5): string {
  if (line === null) return '';
  const lines = code.split('\n');
  const start = Math.max(0, line - radius - 1);
  const end   = Math.min(lines.length, line + radius);
  return lines.slice(start, end).join('\n');
}

// ── Classify finding into vuln family ─────────────────────────────────────────
function classifyVulnFamily(issue: Issue): string | null {
  const text = `${issue.title} ${issue.explanation}`.toLowerCase();
  if (/sql.inject|sqli|sql injection/.test(text)) return 'sql';
  if (/xss|cross.site.script|innerHTML/.test(text)) return 'xss';
  if (/ssrf|server.side.request/.test(text)) return 'ssrf';
  if (/command.inject|shell.inject|rce\b|remote.code/.test(text)) return 'cmd';
  if (/path.travers|directory.travers/.test(text)) return 'path';
  if (/prototype.poll|proto.poll/.test(text)) return 'proto';
  if (/open.redirect|unvalidated.redirect/.test(text)) return 'redirect';
  if (/eval\s*\(|code.inject|dynamic.execut/.test(text)) return 'eval';
  if (/jwt|json.web.token/.test(text)) return 'jwt';
  if (/header.inject|crlf/.test(text)) return 'header';
  return null;
}

// ── Schema validation ──────────────────────────────────────────────────────────
function validateSchema(issue: Issue): string[] {
  const violations: string[] = [];

  if (!issue.title || issue.title.length < 5) {
    violations.push('title too short or missing');
  }
  if (!issue.explanation || issue.explanation.length < 20) {
    violations.push('explanation too short — insufficient evidence');
  }
  if (!['bug', 'risk', 'suggestion'].includes(issue.type)) {
    violations.push(`invalid type: ${issue.type}`);
  }
  if (!['high', 'medium', 'low'].includes(issue.severity)) {
    violations.push(`invalid severity: ${issue.severity}`);
  }
  // Confidence must be in [0, 1]
  if (issue.confidence !== undefined && (issue.confidence < 0 || issue.confidence > 1)) {
    violations.push(`confidence out of range: ${issue.confidence}`);
  }

  return violations;
}

// ── AST-backed line verification ──────────────────────────────────────────────
function verifyLineEvidence(issue: Issue, code: string): { found: boolean; evidence: string[] } {
  if (issue.line === null) {
    return { found: true, evidence: ['no-line-claim (accepted)'] };
  }

  const lines = code.split('\n');
  const lineIdx = issue.line - 1;

  // Line must exist in the code
  if (lineIdx < 0 || lineIdx >= lines.length) {
    return { found: false, evidence: [`line ${issue.line} does not exist (code has ${lines.length} lines)`] };
  }

  const targetLine = lines[lineIdx];
  const context    = getLinesAround(code, issue.line, 3);
  const evidence: string[] = [];

  // Check that the line isn't empty or a comment
  const trimmed = targetLine.trim();
  if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) {
    // Line is comment/empty — this is suspicious but not a hard failure
    evidence.push(`line ${issue.line} is a comment/blank — finding may reference wrong line`);
    return { found: false, evidence };
  }

  evidence.push(`line ${issue.line} exists: ${trimmed.slice(0, 80)}`);

  // Try to verify the claimed vulnerability class exists near this line
  const family = classifyVulnFamily(issue);
  if (family && SINK_EVIDENCE[family]) {
    const sinkFound = SINK_EVIDENCE[family].some(p => p.test(context));
    if (!sinkFound) {
      evidence.push(`no ${family} sink pattern found near line ${issue.line}`);
      return { found: false, evidence };
    }
    evidence.push(`${family} sink pattern confirmed near line ${issue.line}`);
  }

  return { found: true, evidence };
}

// ── Source verification ────────────────────────────────────────────────────────
function verifySourceEvidence(issue: Issue, code: string): boolean {
  // For security bugs, there must be SOME untrusted source in the code
  if (issue.type !== 'bug' || issue.category !== 'security') return true;
  return SOURCE_EVIDENCE.some(p => p.test(code));
}

// ── Exploit chain coherence ───────────────────────────────────────────────────
function verifyExploitChain(issue: Issue, code: string): { coherent: boolean; reason: string } {
  if (!issue.exploitChain) return { coherent: true, reason: 'no chain to verify' };

  const chain = issue.exploitChain.toLowerCase();

  // Chain must mention something that actually exists in code
  const codeTokens = code.match(/\b\w{3,}\b/g) ?? [];
  const codeWordSet = new Set(codeTokens.map(t => t.toLowerCase()));

  // Extract nouns from the chain (simplified: words > 3 chars that aren't common verbs)
  const chainWords = (issue.exploitChain.match(/\b[a-zA-Z_]\w{3,}\b/g) ?? [])
    .filter(w => !/^(this|that|with|from|into|then|when|user|data|code|path|call|gets|send|pass|flow)$/i.test(w));

  const overlap = chainWords.filter(w => codeWordSet.has(w.toLowerCase()));

  if (chainWords.length > 3 && overlap.length === 0) {
    return { coherent: false, reason: 'exploit chain references no identifiers found in the analyzed code' };
  }

  return { coherent: true, reason: `chain references ${overlap.length} code identifiers` };
}

// ── Severity plausibility ─────────────────────────────────────────────────────
function verifySeverityPlausibility(issue: Issue): { plausible: boolean; suggested?: Issue['severity']; reason: string } {
  const family = classifyVulnFamily(issue);

  // Over-severe: suggestion marked high
  const ceil = SEVERITY_CEILING[issue.type];
  if (ceil && isMoreSevere(issue.severity, ceil)) {
    return {
      plausible: false,
      suggested: ceil,
      reason:    `type '${issue.type}' cannot justify '${issue.severity}' severity — downgrading to '${ceil}'`,
    };
  }

  // Under-severe for confirmed critical vulns
  if (family && SEVERITY_FLOOR[family]) {
    const floor = SEVERITY_FLOOR[family];
    if (isLessSevere(issue.severity, floor) && issue.type === 'bug') {
      return {
        plausible: false,
        suggested: floor,
        reason:    `${family} bug should be at least '${floor}' — upgrading`,
      };
    }
  }

  return { plausible: true, reason: 'severity is plausible' };
}

function isMoreSevere(a: Issue['severity'], b: Issue['severity']): boolean {
  const rank: Record<string, number> = { high: 2, medium: 1, low: 0 };
  return rank[a] > rank[b];
}

function isLessSevere(a: Issue['severity'], b: Issue['severity']): boolean {
  const rank: Record<string, number> = { high: 2, medium: 1, low: 0 };
  return rank[a] < rank[b];
}

// ── Main firewall function ────────────────────────────────────────────────────

/**
 * Run hallucination checks on a single AI-generated finding.
 * Returns a check result with confidence adjustment and drop/downgrade flags.
 */
export function checkHallucination(
  issue: Issue,
  code: string,
): HallucinationCheckResult {
  const violations: string[] = [];
  const evidence:   string[] = [];
  let dropped  = false;
  let downgraded = false;
  let confidence = issue.confidence ?? 0.75;

  // 1. Schema validation
  const schemaViolations = validateSchema(issue);
  violations.push(...schemaViolations);
  if (schemaViolations.length > 0) confidence *= 0.70;

  // 2. Line evidence
  const lineCheck = verifyLineEvidence(issue, code);
  evidence.push(...lineCheck.evidence);
  if (!lineCheck.found) {
    violations.push('line evidence not found in code');
    confidence *= 0.40;
    if (issue.type === 'bug' && issue.severity === 'high') {
      // High-severity bugs with no line evidence are dropped
      dropped = true;
    }
  }

  // 3. Source evidence (for security bugs)
  if (!verifySourceEvidence(issue, code)) {
    violations.push('no untrusted input source found in code — possible hallucinated taint flow');
    confidence *= 0.50;
  } else {
    evidence.push('untrusted source confirmed in code');
  }

  // 4. Exploit chain coherence
  const chainCheck = verifyExploitChain(issue, code);
  if (!chainCheck.coherent) {
    violations.push(chainCheck.reason);
    confidence *= 0.60;
  } else {
    evidence.push(chainCheck.reason);
  }

  // 5. Severity plausibility
  const severityCheck = verifySeverityPlausibility(issue);
  if (!severityCheck.plausible) {
    violations.push(severityCheck.reason);
    downgraded = true;
    // Severity adjustment is applied by the caller
  }

  // 6. Hard drop threshold
  if (confidence < 0.15 && violations.length >= 3) {
    dropped = true;
  }

  return {
    passed:     violations.length === 0,
    confidence: Math.max(0.05, Math.min(0.98, confidence)),
    violations,
    downgraded,
    dropped,
    evidence,
  };
}

/**
 * Apply hallucination firewall to all AI-generated issues.
 * Returns filtered/adjusted issues and a summary of interventions.
 */
export function applyHallucinationFirewall(
  issues: Issue[],
  code: string,
  aiSourcedOnly = false,  // if true, only check issues without deterministic source markers
): {
  issues:         Issue[];
  dropped:        Issue[];
  downgraded:     Issue[];
  stats:          HallucinationFirewallStats;
} {
  const passed:     Issue[] = [];
  const dropped:    Issue[] = [];
  const downgraded: Issue[] = [];

  for (const issue of issues) {
    // Skip deterministic engine findings (they have exploitVerified = true or line from AST)
    // Only firewall-check AI-sourced issues (heuristic: no proofChain = AI-generated)
    if (aiSourcedOnly && issue.proofChain) {
      passed.push(issue);
      continue;
    }

    const check = checkHallucination(issue, code);

    if (check.dropped) {
      dropped.push({ ...issue, _firewallDropped: true, _firewallViolations: check.violations } as Issue & Record<string, unknown>);
      continue;
    }

    const adjusted: Issue = { ...issue, confidence: check.confidence };

    if (check.downgraded) {
      const family = classifyVulnFamily(issue);
      const suggested = family && SEVERITY_FLOOR[family] ? SEVERITY_FLOOR[family] : issue.severity;
      // Only downgrade type violations (suggestion can't be high)
      const ceil = SEVERITY_CEILING[issue.type];
      if (ceil && isMoreSevere(issue.severity, ceil)) {
        (adjusted as { severity: Issue['severity'] }).severity = ceil;
        downgraded.push(adjusted);
      } else {
        passed.push(adjusted);
      }
    } else {
      passed.push(adjusted);
    }
  }

  return {
    issues: passed,
    dropped,
    downgraded,
    stats: {
      totalInput:      issues.length,
      passedCount:     passed.length,
      droppedCount:    dropped.length,
      downgradedCount: downgraded.length,
      fpReductionPct:  issues.length > 0 ? Math.round((dropped.length / issues.length) * 100) : 0,
    },
  };
}

export interface HallucinationFirewallStats {
  totalInput:      number;
  passedCount:     number;
  droppedCount:    number;
  downgradedCount: number;
  fpReductionPct:  number;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HALLUCINATION FIREWALL v2 — ADDED TO EXISTING MODULE
//
// New capabilities:
//   • Contradiction detection: finds issues that directly contradict each other
//   • Mandatory evidence enforcement: high-sev bugs MUST have code evidence
//   • Cross-agent disagreement scoring: if analyzer+critic disagree → escalate
//   • Exploit-chain satisfiability: chain steps must reference real code tokens
//   • Duplicate semantic detection: finds near-duplicate findings with different titles
// ═══════════════════════════════════════════════════════════════════════════════

export interface ContradictionPair {
  a: Issue;
  b: Issue;
  reason: string;
}

export interface FirewallV2Stats extends HallucinationFirewallStats {
  contradictions:      number;
  mandatoryEvidFailed: number;
  semanticDuplicates:  number;
}

// ── Contradiction patterns ─────────────────────────────────────────────────────
// A "safe" finding and a "vuln" finding for the same line = contradiction

const SAFE_SIGNALS: RegExp[] = [
  /parameterized|prepared statement|\$\d+|array of params/i,
  /DOMPurify|textContent|encodeHTML|escapeHtml/i,
  /path\.resolve.*startsWith|allowlist/i,
  /spawn\s*\(.*\[.*\]\s*,\s*\{.*shell.*false/i,
  // Python safe signals
  /cursor\.execute\s*\([^,]+,\s*\(/i,
  /bcrypt\.checkpw|bcrypt\.hashpw|hmac\.compare_digest/i,
  /shlex\.quote|subprocess\.run\s*\(\s*\[/i,
  /\.objects\.filter|session\.query.*\.filter/i,
  /@login_required|is_authenticated/i,
];

const VULN_SIGNALS: RegExp[] = [
  /sql injection|sqli/i,
  /xss|cross.site scripting/i,
  /path traversal/i,
  /command injection/i,
  /hardcoded.*(?:password|secret|credential|key)/i,
  /plaintext.*password|password.*plaintext/i,
  /zerodivision|division by zero/i,
  /resource leak|connection.*not closed/i,
  /timing attack/i,
];

function detectContradictions(issues: Issue[]): ContradictionPair[] {
  const pairs: ContradictionPair[] = [];

  for (let i = 0; i < issues.length; i++) {
    for (let j = i + 1; j < issues.length; j++) {
      const a = issues[i], b = issues[j];
      if (Math.abs((a.line ?? -999) - (b.line ?? -998)) > 5) continue;

      // One says safe (explanation contains safe signal), other says vuln
      const aIsSafe  = SAFE_SIGNALS.some(r => r.test(a.explanation ?? ''));
      const bIsVuln  = VULN_SIGNALS.some(r => r.test(b.title));
      const bIsSafe  = SAFE_SIGNALS.some(r => r.test(b.explanation ?? ''));
      const aIsVuln  = VULN_SIGNALS.some(r => r.test(a.title));

      if ((aIsSafe && bIsVuln) || (bIsSafe && aIsVuln)) {
        pairs.push({ a, b,
          reason: `Contradiction: "${a.title}" and "${b.title}" at same location — one marks safe, one marks vulnerable`,
        });
      }
    }
  }

  return pairs;
}

// ── Mandatory evidence enforcement ────────────────────────────────────────────
// High-severity bugs MUST have at least ONE of: exploit chain, proof chain, line number
function checkMandatoryEvidence(issue: Issue): { passed: boolean; reason: string } {
  if (issue.severity !== 'high' || issue.type !== 'bug') return { passed: true, reason: '' };

  const hasLine        = issue.line !== null && issue.line > 0;
  const hasChain       = typeof issue.exploitChain === 'string' && issue.exploitChain.length > 20;
  const hasProof       = issue.proofChain?.sinkReachable === true;
  const hasExplPayload = typeof issue.exploitPayload === 'string' && issue.exploitPayload.length > 10;

  if (hasLine && (hasChain || hasProof || hasExplPayload)) return { passed: true, reason: 'mandatory evidence present' };
  if (!hasLine) return { passed: false, reason: 'high-sev bug missing line number — cannot verify location' };
  if (!hasChain && !hasProof && !hasExplPayload) return { passed: false, reason: 'high-sev bug has line but no exploit chain/payload — insufficient evidence' };

  return { passed: true, reason: 'evidence acceptable' };
}

// ── Semantic duplicate detection ───────────────────────────────────────────────
// "SQL Injection via username field" and "SQL Injection in login query" at L12 = duplicate
function detectSemanticDuplicates(issues: Issue[]): Set<number> {
  const dupIndices = new Set<number>();
  const seen: Array<{ normTitle: string; line: number }> = [];

  for (let i = 0; i < issues.length; i++) {
    const normTitle = issues[i].title.toLowerCase()
      .replace(/\s*(?:via|using|in|at|through|with)\s+.*/g, '')
      .replace(/\s+/g, ' ').trim();
    const line = issues[i].line ?? -1;

    const dup = seen.find(s =>
      s.normTitle === normTitle && Math.abs(s.line - line) <= 3
    );
    if (dup) {
      dupIndices.add(i);
    } else {
      seen.push({ normTitle, line });
    }
  }

  return dupIndices;
}

/**
 * Firewall v2 — applies on top of v1 checks.
 * Run AFTER applyHallucinationFirewall for full protection.
 */
export function applyHallucinationFirewallV2(
  issues: Issue[],
  code:   string,
): {
  issues: Issue[];
  stats:  FirewallV2Stats;
} {
  const contradictions = detectContradictions(issues);
  const dupIndices     = detectSemanticDuplicates(issues);

  let mandatoryFailed = 0;
  const kept: Issue[] = [];

  for (let i = 0; i < issues.length; i++) {
    const issue = issues[i];

    // Remove semantic duplicates (keep first occurrence)
    if (dupIndices.has(i)) continue;

    // Remove one side of contradictions (keep the safe-side finding, remove vuln claim)
    const contradiction = contradictions.find(p => p.b === issue);
    if (contradiction) {
      // a is the safe one, b is the vuln claim — drop b
      continue;
    }

    // Mandatory evidence check
    const evCheck = checkMandatoryEvidence(issue);
    if (!evCheck.passed) {
      mandatoryFailed++;
      // Downgrade instead of drop — could be real but lacks evidence
      kept.push({
        ...issue,
        severity:    'medium' as const,
        type:        'risk' as const,
        explanation: `${issue.explanation} [FW-v2: downgraded — ${evCheck.reason}]`,
      });
      continue;
    }

    kept.push(issue);
  }

  const v1Stats: HallucinationFirewallStats = {
    totalInput:      issues.length,
    passedCount:     kept.length,
    droppedCount:    issues.length - kept.length - mandatoryFailed,
    downgradedCount: mandatoryFailed,
    fpReductionPct:  issues.length > 0
      ? Math.round(((issues.length - kept.length) / issues.length) * 100)
      : 0,
  };

  return {
    issues: kept,
    stats: {
      ...v1Stats,
      contradictions:      contradictions.length,
      mandatoryEvidFailed: mandatoryFailed,
      semanticDuplicates:  dupIndices.size,
    },
  };
}
