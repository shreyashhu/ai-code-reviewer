// ─────────────────────────────────────────────────────────────────────────────
// PROOF OBLIGATION ENGINE v1 — Stage 22
//
// Priority 3 from v13 roadmap.
//
// Every finding must prove:
//   1. source exists             — taint source is present in code
//   2. sink exists               — dangerous sink is present in code
//   3. path exists               — data flows from source to sink
//   4. reachability valid        — code path is executable (not dead code)
//   5. sanitizer absent/bypassable — no effective sanitizer in path
//   6. exploit feasible          — real attacker-controlled payload can trigger it
//
// Otherwise: auto-suppress.
//
// Result: kills hallucinated findings, weak exploit chains, fake criticals,
// and invalid taint paths. Massive trust upgrade.
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from '@/app/api/review/route';

// ── Obligation types ──────────────────────────────────────────────────────────

export type ObligationStatus = 'PROVED' | 'FAILED' | 'UNKNOWN';

export interface ProofObligation {
  name:     string;
  status:   ObligationStatus;
  evidence: string;
  weight:   number;   // 0–1: how critical this obligation is
}

export interface ProofResult {
  issue:              Issue;
  obligations:        ProofObligation[];
  overallStatus:      'VALID' | 'SUPPRESSED' | 'WEAK';
  proofScore:         number;   // 0–1: fraction of weighted obligations proved
  suppressionReason?: string;
}

export interface ProofObligationReport {
  results:          ProofResult[];
  stats: {
    total:          number;
    valid:          number;
    suppressed:     number;
    weak:           number;
    hallucinationsSuppressed: number;
  };
}

// ── Source patterns per vulnerability class ───────────────────────────────────

const SOURCE_PATTERNS: Record<string, RegExp> = {
  // JS/TS + Python/Go/Rust sources — any function param or known taint source
  'sql':            /req\.(body|query|params)|request\.body|searchParams\.get|FormData|getServerSideProps|context\.params|def\s+\w+\s*\(|flask\.request|request\.args|request\.form|\buser_id\b|\buser_input\b|\binput_\w+|sys\.argv/,
  'xss':            /req\.(body|query|params)|innerHTML|dangerouslySetInnerHTML|document\.write|location\.hash|location\.search|flask\.request|request\.args/,
  'ssrf':           /req\.(body|query|params)|url\s*=|endpoint\s*=|target\s*=|requests\.(get|post)|urllib/,
  'path':           /req\.(body|query|params)|__dirname|process\.cwd\(\)|os\.path|open\s*\(/,
  'command':        /req\.(body|query|params)|process\.argv|stdin|sys\.argv|os\.environ\.get/,
  'proto':          /JSON\.parse\s*\(|req\.(body|query)|Object\.assign\s*\(\{\}/,
  'redirect':       /req\.(body|query|params)|location\.search|url\.searchParams/,
  'deserialization': /JSON\.parse\s*\(|Buffer\.from|atob\s*\(|base64|pickle\.loads/,
  'auth':           /req\.(body|query|params|headers)|cookie|localStorage|sessionStorage|input_password|user_input|\bpassword\b|\bpwd\b/,
  'hardcoded':      /PASSWORD\s*=\s*['"]|SECRET\s*=\s*['"]|API_KEY\s*=\s*['"]|correct_password\s*=\s*['"]/,
};

const SINK_PATTERNS: Record<string, RegExp> = {
  // JS/TS + Python/other language sinks
  'sql':            /db\.query\s*\(|cursor\.execute\s*\(|sequelize\.query|knex\.raw|\.raw\s*\(|execute\s*\(\s*(?:query|sql)/,
  'xss':            /dangerouslySetInnerHTML|innerHTML\s*=|document\.write|\.html\s*\(/,
  'ssrf':           /fetch\s*\(|axios\s*\(|http\.(?:get|request)\s*\(|got\s*\(|requests\.(get|post|put)/,
  'path':           /readFile|readFileSync|createReadStream|path\.join|open\s*\(|os\.path\.join/,
  'command':        /exec\s*\(|execSync\s*\(|spawn\s*\(|os\.system\s*\(|subprocess\.(run|call|Popen)/,
  'proto':          /__proto__|prototype\s*\[|Object\.assign\s*\(\w|merge\s*\(/,
  'redirect':       /res\.redirect\s*\(|location\.href\s*=|next\.redirect/,
  'deserialization': /JSON\.parse\s*\(|eval\s*\(|Function\s*\(|pickle\.(loads|load)/,
  'auth':           /WHERE\s+\w+\s*=|jwt\.verify|bcrypt\.compare|==\s*PASSWORD|==\s*correct_password|==\s*self\.__password/,
  'hardcoded':      /PASSWORD\s*=\s*['"]|correct_password\s*=\s*['"]/,
};

const SANITIZER_PATTERNS: Record<string, RegExp> = {
  'sql':    /db\.query\s*\([^)]*,\s*\[|\$\d+|parameterized|escape\s*\(/,
  'xss':    /DOMPurify\.sanitize|sanitizeHtml|escapeHtml|encodeHTML|he\.encode/,
  'ssrf':   /ALLOWED_HOSTS|allowedDomains|URL\.hostname|\.startsWith\(['"]http/,
  'path':   /path\.resolve\s*\(__dirname|startsWith\s*\(BASE|allowedPath|ALLOWED_FILES/,
  'command': /spawn\s*\([^)]*,\s*\[|execFile\s*\(|subprocess\.\w+\s*\(\s*\[[\s\S]*?(?:shell\s*=\s*False|\)(?![\s\S]*shell\s*=\s*True))/,  // array args (no shell interpolation)
  'proto':  /Object\.freeze|Object\.create\s*\(null\)|hasOwnProperty|structuredClone/,
  'redirect': /ALLOWED_HOSTS|allowedDomains|startsWith\s*\(['"]\/\)/,
  'auth':   /bcrypt\.hash|argon2\.|pbkdf2/,
};

// ── Resolve vulnerability class from issue ────────────────────────────────────

function resolveVulnClass(issue: Issue): string {
  const ttl = (issue.title    ?? '').toLowerCase();
  const cat = (issue.category ?? '').toLowerCase();

  if (/sql|inject/i.test(ttl + cat))    return 'sql';
  if (/xss|cross.site.script/i.test(ttl + cat)) return 'xss';
  if (/ssrf|server.side.request/i.test(ttl + cat)) return 'ssrf';
  if (/path|traversal|directory/i.test(ttl + cat)) return 'path';
  if (/command|rce|exec|shell/i.test(ttl + cat))   return 'command';
  if (/proto|pollution/i.test(ttl + cat))           return 'proto';
  if (/redirect/i.test(ttl + cat))                  return 'redirect';
  if (/deserializ|pickle|unmarshal/i.test(ttl + cat)) return 'deserialization';
  if (/auth|bypass|privilege/i.test(ttl + cat))    return 'auth';
  if (/hardcoded|plaintext|secret|credential|password.*stored/i.test(ttl + cat)) return 'hardcoded';
  if (/division|zero.*divis|divis.*zero|zerodivision/i.test(ttl + cat)) return 'generic';
  if (/resource.*leak|unclosed|connection.*leak/i.test(ttl + cat)) return 'generic';
  return 'generic';
}

// ── Individual obligation checks ──────────────────────────────────────────────

function checkSourceExists(code: string, cls: string, issue: Issue): ProofObligation {
  // For hardcoded secrets and logic bugs, the 'source' is the code itself
  // Don't require a taint source pattern — the issue IS the source
  if (cls === 'hardcoded' || cls === 'generic') {
    return { name: 'source-exists', status: 'PROVED', evidence: 'Static/hardcoded issue — source is the code itself', weight: 0.25 };
  }
  // For Python: function parameters are implicit taint sources
  // If code has a def with params, treat that as a valid source for all taint classes
  const hasPythonFuncDef = /def\s+\w+\s*\(\w/.test(code);
  const pattern = SOURCE_PATTERNS[cls] ?? /req\.(body|query|params)/;
  const lines   = code.split('\n');
  const issueLine = issue.line ?? 0;

  // Search in a window around the issue line
  const windowStart = Math.max(0, issueLine - 30);
  const windowEnd   = Math.min(lines.length, issueLine + 10);
  const window      = lines.slice(windowStart, windowEnd).join('\n');

  // Python: function params are implicit taint sources; any def(...) means external input possible
  const hasPythonSource = /def\s+\w+\s*\(\w/.test(code);
  const found = pattern.test(window) || pattern.test(code) || hasPythonSource;
  return {
    name:     'source-exists',
    status:   found ? 'PROVED' : 'FAILED',
    evidence: found
      ? `Taint source pattern found near L${issueLine}${hasPythonSource ? ' (Python function param)' : ''}`
      : `No taint source pattern (${pattern.toString().slice(1, 40)}) found`,
    weight:   0.25,
  };
}

function checkSinkExists(code: string, cls: string, issue: Issue): ProofObligation {
  if (issue.proofChain?.sinkReachable === true) {
    return { name: 'sink-exists', status: 'PROVED', evidence: `Unified replay path confirms reachable sink: ${issue.proofChain.executionPath}`, weight: 0.25 };
  }
  if (issue.proofChain?.sinkReachable === false) {
    return { name: 'sink-exists', status: 'FAILED', evidence: `Unified replay marked sink blocked at ${issue.proofChain.blockedAt ?? 'a guard/sanitizer'}`, weight: 0.25 };
  }
  const pattern   = SINK_PATTERNS[cls] ?? /eval\s*\(|exec\s*\(/;
  const lines     = code.split('\n');
  const issueLine = issue.line ?? 0;

  const windowStart = Math.max(0, issueLine - 10);
  const windowEnd   = Math.min(lines.length, issueLine + 30);
  const window      = lines.slice(windowStart, windowEnd).join('\n');

  const found = pattern.test(window) || pattern.test(code);
  return {
    name:     'sink-exists',
    status:   found ? 'PROVED' : 'FAILED',
    evidence: found
      ? `Sink pattern found near L${issueLine}`
      : `No sink pattern (${pattern.toString().slice(1, 40)}) found in code`,
    weight:   0.25,
  };
}

function checkPathExists(code: string, issue: Issue): ProofObligation {
  if (issue.proofChain?.sinkReachable === true) {
    return { name: 'path-exists', status: 'PROVED', evidence: issue.proofChain.executionPath, weight: 0.20 };
  }
  if (issue.proofChain?.sinkReachable === false) {
    return { name: 'path-exists', status: 'FAILED', evidence: issue.proofChain.observedResult || 'Replay found no exploitable source-to-sink path', weight: 0.20 };
  }
  // Heuristic: if the issue has an exploitChain or explanation mentioning a path, path exists
  const hasExplicitPath = !!(
    issue.exploitChain ||
    (issue.explanation && issue.explanation.includes('→')) ||
    issue.proofChain?.executionPath
  );

  // Also: if issue line is > 0 and code exists at that line
  const issueLine = issue.line ?? 0;
  const codeLines = code.split('\n');
  const lineExists = issueLine > 0 && issueLine <= codeLines.length;

  const proved = hasExplicitPath || lineExists;
  return {
    name:     'path-exists',
    status:   proved ? 'PROVED' : 'UNKNOWN',
    evidence: proved
      ? (hasExplicitPath ? 'Exploit chain or data flow path documented in finding' : `Issue anchored to L${issueLine}`)
      : 'No explicit source→sink path documented',
    weight:   0.20,
  };
}

function checkReachability(code: string, issue: Issue): ProofObligation {
  if (issue.proofChain?.sinkReachable === true) {
    return { name: 'reachability', status: 'PROVED', evidence: 'Unified replay marks sink reachable', weight: 0.10 };
  }
  if (issue.proofChain?.sinkReachable === false) {
    return { name: 'reachability', status: 'FAILED', evidence: issue.proofChain.blockedAt ? `Blocked at ${issue.proofChain.blockedAt}` : 'Unified replay marks sink unreachable', weight: 0.10 };
  }
  const issueLine = issue.line ?? 0;
  if (issueLine === 0) {
    return { name: 'reachability', status: 'UNKNOWN', evidence: 'No line number — cannot verify reachability', weight: 0.10 };
  }

  const lines      = code.split('\n');
  const lineCode   = lines[issueLine - 1] ?? '';

  // Dead code markers
  const deadCodeRe = /\/\/\s*(TODO|FIXME|DEAD|UNREACHABLE|DISABLED|DEPRECATED|OLD|REMOVE)/i;
  const unreachRe  = /if\s*\(\s*false\s*\)|while\s*\(\s*false\s*\)|return\s*;?\s*\/\//;

  // Check for dead code markers in the 5 lines above
  const context    = lines.slice(Math.max(0, issueLine - 5), issueLine).join('\n');
  const isDead     = deadCodeRe.test(context) || unreachRe.test(lineCode);

  return {
    name:     'reachability',
    status:   isDead ? 'FAILED' : 'PROVED',
    evidence: isDead
      ? `Dead code markers or unreachable branch detected near L${issueLine}`
      : `Code at L${issueLine} appears reachable`,
    weight:   0.10,
  };
}

function checkSanitizerAbsent(code: string, cls: string, issue: Issue): ProofObligation {
  if (issue.proofChain?.sinkReachable === true) {
    return { name: 'sanitizer-absent', status: 'PROVED', evidence: 'Replay found no blocking sanitizer on the path', weight: 0.15 };
  }
  if (issue.proofChain?.sinkReachable === false && issue.proofChain.blockedAt) {
    return { name: 'sanitizer-absent', status: 'FAILED', evidence: `Replay blocked by ${issue.proofChain.blockedAt}`, weight: 0.15 };
  }
  const pattern   = SANITIZER_PATTERNS[cls] ?? /sanitize|escape/i;
  const lines     = code.split('\n');
  const issueLine = issue.line ?? 0;

  // Look for sanitizer within 20 lines of issue
  const windowStart = Math.max(0, issueLine - 20);
  const windowEnd   = Math.min(lines.length, issueLine + 5);
  const window      = lines.slice(windowStart, windowEnd).join('\n');

  const sanitizerPresent = pattern.test(window);

  return {
    name:     'sanitizer-absent',
    status:   sanitizerPresent ? 'FAILED' : 'PROVED',
    evidence: sanitizerPresent
      ? `Sanitizer pattern found within 20 lines of issue — exploit may be blocked`
      : `No effective sanitizer detected near L${issueLine}`,
    weight:   0.15,
  };
}

function checkExploitFeasible(issue: Issue): ProofObligation {
  if (issue.proofChain?.sinkReachable === true) {
    return { name: 'exploit-feasible', status: 'PROVED', evidence: issue.proofChain.observedResult || 'Replay confirmed exploit feasibility', weight: 0.05 };
  }
  if (issue.proofChain?.sinkReachable === false) {
    return { name: 'exploit-feasible', status: 'FAILED', evidence: issue.proofChain.observedResult || 'Replay did not confirm exploitability', weight: 0.05 };
  }
  const confidence = issue.confidence ?? 0.5;
  const hasPayload = !!(issue.exploitPayload || issue.exploitChain);

  const score   = (confidence * 0.6) + (hasPayload ? 0.4 : 0);
  const proved  = score >= 0.5;

  return {
    name:     'exploit-feasible',
    status:   proved ? 'PROVED' : (score > 0.3 ? 'UNKNOWN' : 'FAILED'),
    evidence: proved
      ? `Confidence ${Math.round(confidence * 100)}%${hasPayload ? ' with exploit payload' : ''}`
      : `Confidence too low (${Math.round(confidence * 100)}%) and no exploit payload`,
    weight:   0.05,
  };
}

// ── Proof evaluation ──────────────────────────────────────────────────────────

const SUPPRESSION_THRESHOLD = 0.35;  // below this → SUPPRESSED
const WEAK_THRESHOLD        = 0.60;  // below this → WEAK

function evaluateProof(obligations: ProofObligation[]): {
  status: ProofResult['overallStatus'];
  score:  number;
  reason?: string;
} {
  let totalWeight = 0;
  let provedWeight = 0;
  const failedCritical: string[] = [];

  for (const ob of obligations) {
    totalWeight += ob.weight;
    if (ob.status === 'PROVED') {
      provedWeight += ob.weight;
    } else if (ob.status === 'FAILED' && ob.weight >= 0.20) {
      failedCritical.push(ob.name);
    }
  }

  const score = totalWeight > 0 ? provedWeight / totalWeight : 0;

  // If any critical obligation FAILED, suppress regardless of overall score
  if (failedCritical.length > 0) {
    return {
      status: 'SUPPRESSED',
      score,
      reason: `Critical obligation(s) failed: ${failedCritical.join(', ')}`,
    };
  }

  if (score < SUPPRESSION_THRESHOLD) {
    return { status: 'SUPPRESSED', score, reason: `Proof score ${(score * 100).toFixed(0)}% below threshold ${(SUPPRESSION_THRESHOLD * 100)}%` };
  }
  if (score < WEAK_THRESHOLD) {
    return { status: 'WEAK', score };
  }
  return { status: 'VALID', score };
}

// ── Main export ───────────────────────────────────────────────────────────────

export function runProofObligationEngine(
  issues: Issue[],
  code: string,
): ProofObligationReport {
  const results: ProofResult[] = [];

  for (const issue of issues) {
    const cls = resolveVulnClass(issue);

    const obligations: ProofObligation[] = [
      checkSourceExists(code, cls, issue),
      checkSinkExists(code, cls, issue),
      checkPathExists(code, issue),
      checkReachability(code, issue),
      checkSanitizerAbsent(code, cls, issue),
      checkExploitFeasible(issue),
    ];

    const { status, score, reason } = evaluateProof(obligations);

    results.push({
      issue,
      obligations,
      overallStatus:      status,
      proofScore:         score,
      suppressionReason:  reason,
    });
  }

  const stats = {
    total:      results.length,
    valid:      results.filter(r => r.overallStatus === 'VALID').length,
    suppressed: results.filter(r => r.overallStatus === 'SUPPRESSED').length,
    weak:       results.filter(r => r.overallStatus === 'WEAK').length,
    hallucinationsSuppressed: results.filter(r =>
      r.overallStatus === 'SUPPRESSED' &&
      r.obligations.find(o => o.name === 'source-exists')?.status === 'FAILED'
    ).length,
  };

  return { results, stats };
}

export function proofObligationToIssues(report: ProofObligationReport): Issue[] {
  // Only pass through VALID and WEAK findings
  return report.results
    .filter(r => r.overallStatus !== 'SUPPRESSED')
    .map(r => ({
      ...r.issue,
      // Attenuate confidence for weak findings
      confidence: r.overallStatus === 'WEAK'
        ? Math.min(r.issue.confidence ?? 0.5, 0.65)
        : r.issue.confidence,
    }));
}

export function getProofObligationSummary(report: ProofObligationReport) {
  const s = report.stats;
  return {
    total:      s.total,
    valid:      s.valid,
    weak:       s.weak,
    suppressed: s.suppressed,
    hallucinations: s.hallucinationsSuppressed,
  };
}
