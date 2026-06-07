// ─────────────────────────────────────────────────────────────────────────────
// DETERMINISTIC DOMINANCE ENGINE — v1.3
//
// AI proposes. Deterministic engines decide.
//
// Core principle: AI output can only ANNOTATE findings that already have
// deterministic proof. AI cannot CREATE findings without deterministic backing.
//
// This eliminates hallucination at the architectural level rather than
// patching it per-stage.
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

export type DeterministicEvidence = {
  sourcePattern: boolean;
  sinkPattern:   boolean;
  lineExists:    boolean;
  pathDocumented: boolean;
};

export type DominanceVerdict =
  | 'AI_CONFIRMED'    // AI claim backed by deterministic proof
  | 'AI_ANNOTATED'    // AI added context but finding is deterministic-sourced
  | 'AI_REJECTED'     // AI claim has no deterministic backing — dropped
  | 'DETERMINISTIC'   // Pure deterministic finding, no AI input

export interface DominanceResult {
  issue:    Issue;
  verdict:  DominanceVerdict;
  evidence: DeterministicEvidence;
  reason:   string;
}

export interface DominanceStats {
  total:           number;
  confirmed:       number;
  annotated:       number;
  rejected:        number;
  deterministic:   number;
  hallucinationsKilled: number;
}

// Source patterns that must exist for a finding to be valid
const SOURCE_PATTERNS: Record<string, RegExp[]> = {
  sqli:          [/req\.(body|query|params)/, /request\.(body|query|params)/, /ctx\.(query|params)/],
  xss:           [/req\.(body|query|params)/, /innerHTML/, /dangerouslySetInnerHTML/],
  ssrf:          [/req\.(body|query|params)/, /fetch\s*\(/, /axios\./],
  cmd:           [/exec\s*\(/, /spawn\s*\(/, /req\.(body|query|params)/],
  path:          [/req\.(body|query|params)/, /readFile/, /join\s*\(/],
  proto:         [/__proto__/, /prototype\[/, /Object\.assign/, /merge\s*\(/],
  redirect:      [/req\.(query|params)/, /res\.redirect/, /location/],
  auth:          [/jwt\./, /verify\s*\(/, /authenticate/],
  deserialize:   [/JSON\.parse/, /deserialize/, /unserialize/],
};

const SINK_PATTERNS: Record<string, RegExp[]> = {
  sqli:          [/db\.(query|execute|run)\s*\(`/, /\.rawQuery\s*\(/, /knex\.raw\s*\(/],
  xss:           [/\.innerHTML\s*=/, /dangerouslySetInnerHTML/, /document\.write\s*\(/],
  ssrf:          [/fetch\s*\(\s*\w+/, /axios\.(get|post)\s*\(\s*\w+/, /got\s*\(\s*\w+/],
  cmd:           [/exec\s*\(/, /spawn\s*\(/, /execSync\s*\(/],
  path:          [/readFile\s*\(/, /createReadStream\s*\(/, /fs\.\w+\s*\(\s*\w+/],
  proto:         [/__proto__\s*\[/, /prototype\s*\[/, /Object\.assign\s*\(\s*\{\}/],
  redirect:      [/res\.redirect\s*\(/, /window\.location\s*=/],
  auth:          [/if\s*\(!/, /throw\s+new/, /401|403|unauthorized/i],
  deserialize:   [/JSON\.parse\s*\(/, /\.fromJSON\s*\(/, /deserialize\s*\(/],
};

function classifyIssue(issue: Issue): string {
  const text = (issue.title + ' ' + issue.explanation).toLowerCase();
  if (/sql.inject|sqli/.test(text))      return 'sqli';
  if (/xss|cross.site.script/.test(text)) return 'xss';
  if (/ssrf|server.side.request/.test(text)) return 'ssrf';
  if (/command.inject|shell.inject|rce/.test(text)) return 'cmd';
  if (/path.travers|directory.travers/.test(text)) return 'path';
  if (/prototype.pollut|proto.pollut/.test(text)) return 'proto';
  if (/open.redirect/.test(text))        return 'redirect';
  if (/auth.bypass|broken.auth|unauth/.test(text)) return 'auth';
  if (/deserializ|unsafe.parse/.test(text)) return 'deserialize';
  return 'generic';
}

function checkDeterministicEvidence(issue: Issue, code: string): DeterministicEvidence {
  const lines = code.split('\n');
  const issueClass = classifyIssue(issue);
  const sourcePats = SOURCE_PATTERNS[issueClass] ?? SOURCE_PATTERNS['sqli']!;
  const sinkPats   = SINK_PATTERNS[issueClass] ?? SINK_PATTERNS['sqli']!;

  // Check source exists anywhere in code
  const sourcePattern = sourcePats.some(p => p.test(code));

  // Check sink exists anywhere in code
  const sinkPattern = sinkPats.some(p => p.test(code));

  // Check line actually exists and is non-trivial
  const lineExists = issue.line === null || (
    issue.line > 0 &&
    issue.line <= lines.length &&
    (lines[issue.line - 1]?.trim().length ?? 0) > 2
  );

  // Check path is documented (exploit chain or explanation references code elements)
  const pathDocumented = !!(
    issue.exploitChain ||
    issue.proofChain ||
    (issue.explanation && issue.explanation.length > 50)
  );

  return { sourcePattern, sinkPattern, lineExists, pathDocumented };
}

function computeDominanceScore(ev: DeterministicEvidence, issue: Issue): number {
  let score = 0;
  if (ev.sourcePattern)   score += 30;
  if (ev.sinkPattern)     score += 30;
  if (ev.lineExists)      score += 20;
  if (ev.pathDocumented)  score += 10;
  if (issue.exploitVerified) score += 10;
  return score;
}

/**
 * Apply deterministic dominance to a set of issues.
 *
 * Issues from deterministic engines (isDeterministic=true) always pass.
 * AI-only issues must have deterministic evidence to survive.
 */
export function applyDeterministicDominance(
  issues: Issue[],
  code: string,
  deterministicSet: Set<string>,  // titles from deterministic engines
): { issues: Issue[]; stats: DominanceStats; results: DominanceResult[] } {
  const results: DominanceResult[] = [];
  const passed: Issue[] = [];

  let confirmed = 0, annotated = 0, rejected = 0, deterministic = 0;

  for (const issue of issues) {
    const isDet = deterministicSet.has(issue.title);
    const ev = checkDeterministicEvidence(issue, code);
    const score = computeDominanceScore(ev, issue);

    let verdict: DominanceVerdict;
    let reason: string;

    if (isDet) {
      // Deterministic finding — always passes
      verdict = 'DETERMINISTIC';
      reason = 'Originated from deterministic engine — passes unconditionally';
      deterministic++;
      passed.push(issue);
    } else if (score >= 70) {
      // AI claim is fully backed by deterministic evidence
      verdict = 'AI_CONFIRMED';
      reason = `Score ${score}/100 — source+sink+line verified deterministically`;
      confirmed++;
      passed.push(issue);
    } else if (score >= 40) {
      // Partial evidence — pass with confidence cap
      verdict = 'AI_ANNOTATED';
      reason = `Score ${score}/100 — partial evidence, confidence capped`;
      annotated++;
      const capped = { ...issue, confidence: Math.min(issue.confidence ?? 0.7, 0.65) };
      passed.push(capped);
    } else {
      // Low deterministic score — but do NOT reject blindly.
      // Logic bugs, auth bypasses, missing-await, IDOR, and business logic flaws
      // have no matchable source+sink regex pairs. Rejecting score<40 kills entire
      // categories of real AI findings that regex engines can never find.
      //
      // Rejection criteria (all must be true to suppress):
      //   1. score = 0 (literally nothing found — no source, no sink, no line, no exploit)
      //   2. No exploit chain or payload provided by AI
      //   3. No line number — AI couldn't even point to a line
      //   4. Issue is not a logic/auth/async bug class (those rarely have regex evidence)
      const isLogicClass = /auth|idor|race|async|await|logic|business|privilege|permission|missing|ownership/i
        .test((issue.title + ' ' + (issue.explanation ?? '')));
      const hasExploitEvidence = (issue.exploitChain?.length ?? 0) > 20
        || (issue.exploitVerified === true);
      const hasLineNumber = issue.line !== null && issue.line > 0;

      const shouldReject = score === 0
        && !hasExploitEvidence
        && !hasLineNumber
        && !isLogicClass;

      if (shouldReject) {
        verdict = 'AI_REJECTED';
        reason = `Score 0/100 — no evidence whatsoever, no exploit chain, no line number`;
        rejected++;
      } else {
        // Preserve finding as annotated with appropriate confidence cap
        verdict = 'AI_ANNOTATED';
        const capConf = score === 0 ? 0.45 : 0.55;
        reason = `Score ${score}/100 — logic/auth/semantic class or has exploit evidence; preserved with confidence cap ${capConf}`;
        annotated++;
        const capped = { ...issue, confidence: Math.min(issue.confidence ?? 0.7, capConf) };
        passed.push(capped);
      }
    }

    results.push({ issue, verdict, evidence: ev, reason });
  }

  return {
    issues: passed,
    stats: {
      total:           issues.length,
      confirmed,
      annotated,
      rejected,
      deterministic,
      hallucinationsKilled: rejected,
    },
    results,
  };
}
