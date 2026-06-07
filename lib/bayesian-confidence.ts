// ─────────────────────────────────────────────────────────────────────────────
// BAYESIAN CONFIDENCE MODELING ENGINE v1
//
// Replaces heuristic confidence scores with evidence-weighted probability.
//
// Prior: base exploitability probability by vuln class
// Likelihood updates (each multiplies the prior):
//   • Taint source confirmed           → ×1.6
//   • Sink confirmed in code           → ×1.5
//   • Deterministic engine confirmed   → ×2.0
//   • Exploit replay verified          → ×3.0
//   • Symbolic execution confirms path → ×1.8
//   • Auth guard on path               → ×0.15
//   • Sanitizer confirmed              → ×0.20
//   • Parameterized query              → ×0.05  (near-zero probability)
//   • Trust model suppressed           → ×0.10
//   • AI-only (no det. confirmation)   → ×0.60
//   • Multiple independent confirmations → ×1.3 per extra source
//
// Final probability is clamped [0.01, 0.97] and mapped to a
// calibrated confidence score + severity recommendation.
// ─────────────────────────────────────────────────────────────────────────────

export interface BayesianEvidence {
  // Positive evidence (increases confidence)
  taintSourceConfirmed:    boolean;
  sinkConfirmed:           boolean;
  deterministicConfirmed:  boolean;
  exploitReplayVerified:   boolean;
  symbolicPathConfirmed:   boolean;
  multipleIndependentPaths: number;   // count > 1

  // Negative evidence (decreases confidence)
  authGuardPresent:        boolean;
  sanitizerPresent:        boolean;
  parameterizedQuery:      boolean;
  trustModelSuppressed:    boolean;
  aiOnlyNoDeterministic:   boolean;
  noTaintSource:           boolean;
}

export interface BayesianResult {
  prior:               number;   // base probability for vuln class
  posterior:           number;   // final probability after all updates
  confidence:          number;   // 0–100 score for display
  recommendedSeverity: 'high' | 'medium' | 'low';
  calibrationNote:     string;
  updateSteps:         Array<{ factor: string; multiplier: number; after: number }>;
}

// ── Prior probabilities by vulnerability class ────────────────────────────────
// Represents: given this pattern was detected, what's the base probability it's real?
const CLASS_PRIORS: Record<string, number> = {
  'sql':           0.55,   // SQL keywords + input = often real but also FPs
  'xss':           0.50,   // Similar
  'cmd':           0.70,   // exec() with dynamic args almost always real
  'eval':          0.65,   // eval() with input is usually real
  'path':          0.60,
  'proto':         0.45,   // Prototype pollution has many safe mitigations
  'ssrf':          0.50,
  'redirect':      0.55,
  'header':        0.40,
  'jwt':           0.65,
  'deserialize':   0.80,   // Very high — rarely false positive
  // Logic/auth classes — AI finds these; no det confirmation expected
  'auth':          0.72,   // Missing auth checks are almost always real when flagged
  'idor':          0.68,   // IDOR with no ownership check = real
  'logic':         0.60,   // Logic bugs require reasoning — if AI flags, likely real
  'race':          0.58,   // Race conditions plausible but harder to prove
  'default':       0.50,
};

function classifyVuln(title: string, category: string): string {
  const t = (title + category).toLowerCase();
  if (/sql|sqli/.test(t))                             return 'sql';
  if (/xss|cross.site/.test(t))                       return 'xss';
  if (/cmd|command|exec|spawn/.test(t))               return 'cmd';
  if (/eval|function\s*\(|vm\./.test(t))             return 'eval';
  if (/path|traversal|readfile/.test(t))              return 'path';
  if (/proto/.test(t))                                return 'proto';
  if (/ssrf|server.side/.test(t))                     return 'ssrf';
  if (/redirect/.test(t))                             return 'redirect';
  if (/header|crlf/.test(t))                          return 'header';
  if (/jwt|token/.test(t))                            return 'jwt';
  if (/deserializ|pickle/.test(t))                    return 'deserialize';
  // Logic/auth/semantic classes — must come after taint classes
  if (/missing auth|broken auth|auth bypass|no auth|unauthenticated|access control/.test(t)) return 'auth';
  if (/idor|insecure direct|object reference|ownership/.test(t))  return 'idor';
  if (/race condition|toctou|double.spend|concurren/.test(t))     return 'race';
  if (/logic|business logic|privilege|permission|missing check/.test(t)) return 'logic';
  return 'default';
}

function clamp(v: number): number { return Math.max(0.01, Math.min(0.97, v)); }

export function computeBayesianConfidence(
  title:    string,
  category: string,
  evidence: BayesianEvidence,
): BayesianResult {
  const vulnClass = classifyVuln(title, category);
  const prior     = CLASS_PRIORS[vulnClass] ?? CLASS_PRIORS.default;
  let   prob      = prior;
  const steps: BayesianResult['updateSteps'] = [];

  const update = (factor: string, mult: number) => {
    if (Math.abs(mult - 1.0) < 0.001) return; // skip no-ops
    prob = clamp(prob * mult);
    steps.push({ factor, multiplier: mult, after: Math.round(prob * 100) / 100 });
  };

  // ── Positive updates ──────────────────────────────────────────────────────
  if (evidence.deterministicConfirmed)  update('deterministic engine confirmed', 2.0);
  if (evidence.exploitReplayVerified)   update('exploit replay verified', 3.0);
  if (evidence.symbolicPathConfirmed)   update('symbolic path confirmed', 1.8);
  if (evidence.taintSourceConfirmed)    update('taint source confirmed', 1.6);
  if (evidence.sinkConfirmed)           update('sink confirmed in code', 1.5);
  if (evidence.multipleIndependentPaths > 1) {
    const extra = evidence.multipleIndependentPaths - 1;
    update(`${extra} additional independent path(s)`, Math.pow(1.3, Math.min(extra, 3)));
  }

  // ── Negative updates ──────────────────────────────────────────────────────
  if (evidence.parameterizedQuery)      update('parameterized query confirmed', 0.05);
  if (evidence.authGuardPresent)        update('auth guard on path', 0.15);
  if (evidence.sanitizerPresent)        update('sanitizer confirmed', 0.20);
  if (evidence.trustModelSuppressed)    update('trust model suppressed', 0.10);
  // AI-only penalty only applies to taint-class vulns (SQLi, XSS, SSRF, path traversal).
  // Logic bugs, auth bypasses, IDOR, missing-await, and business logic flaws have no
  // deterministic representation — penalising them for "no det confirmation" is incorrect
  // and systematically suppresses AI's most valuable findings.
  const isLogicOrAuthClass = /auth|idor|race|async|await|logic|business|privilege|permission|missing|ownership|proto/i
    .test(title + ' ' + category);
  if (evidence.aiOnlyNoDeterministic && !isLogicOrAuthClass) {
    update('AI-only, no deterministic confirmation (taint class)', 0.60);
  }
  // noTaintSource penalty also shouldn't apply to logic/auth bugs
  if (evidence.noTaintSource && !isLogicOrAuthClass) {
    update('no taint source found', 0.40);
  }

  const posterior    = prob;
  const confidence   = Math.round(posterior * 100);

  // Severity recommendation based on posterior
  let recommendedSeverity: BayesianResult['recommendedSeverity'];
  if (posterior >= 0.75) recommendedSeverity = 'high';
  else if (posterior >= 0.40) recommendedSeverity = 'medium';
  else recommendedSeverity = 'low';

  // Calibration note
  let calibrationNote: string;
  if (posterior >= 0.85) calibrationNote = 'High confidence — multiple independent confirmations';
  else if (posterior >= 0.65) calibrationNote = 'Moderate-high confidence — strong pattern with partial confirmation';
  else if (posterior >= 0.40) calibrationNote = 'Moderate confidence — pattern present but reachability uncertain';
  else if (posterior >= 0.20) calibrationNote = 'Low confidence — mitigations likely present, flagged as risk only';
  else calibrationNote = 'Very low confidence — likely false positive, suppressing or downgrading';

  return { prior, posterior, confidence, recommendedSeverity, calibrationNote, updateSteps: steps };
}

// ── Batch application ─────────────────────────────────────────────────────────

export interface IssueForCalibration {
  title:               string;
  category:            string;
  severity:            'high' | 'medium' | 'low';
  type:                'bug' | 'risk' | 'suggestion';
  line:                number | null;
  confidence?:         number;
  exploitVerified?:    boolean;
  proofChain?:         { sinkReachable?: boolean };
  [k: string]:         unknown;
}

export interface CalibrationStats {
  totalInput:       number;
  upgraded:         number;
  downgraded:       number;
  avgConfidence:    number;
  highConfidence:   number;  // count with confidence >= 75
}

function buildEvidence(
  issue: IssueForCalibration,
  code:  string,
  deterministicTitles: Set<string>,
  suppressedTitles:    Set<string>,
): BayesianEvidence {
  const isDet  = deterministicTitles.has(issue.title);
  const isSupp = suppressedTitles.has(issue.title);
  const ctx = issue.line
    ? code.split('\n').slice(Math.max(0, issue.line - 5), issue.line + 5).join('\n')
    : '';

  return {
    taintSourceConfirmed:    /req\.(body|query|params)|searchParams\.get|formData\.get/.test(ctx),
    sinkConfirmed:           /db\.(query|execute)|innerHTML|eval\s*\(|exec\s*\(|readFile|redirect\s*\(/.test(ctx),
    deterministicConfirmed:  isDet,
    exploitReplayVerified:   issue.exploitVerified === true,
    symbolicPathConfirmed:   issue.proofChain?.sinkReachable === true,
    multipleIndependentPaths: 1,
    authGuardPresent:        /(?:session|isAuth|requireAuth|checkAuth)/.test(ctx),
    sanitizerPresent:        /DOMPurify|encodeHTML|escapeHtml|parameterize|\$\d+|\?/.test(ctx),
    parameterizedQuery:      /db\.(query|execute|run)\s*\([^)]+,\s*\[/.test(ctx) || /\$\d+/.test(ctx),
    trustModelSuppressed:    isSupp,
    aiOnlyNoDeterministic:   !isDet,
    noTaintSource:           !/req\.|searchParams|formData|params\.|headers\./.test(ctx),
  };
}

export function applyBayesianCalibration(
  issues:              IssueForCalibration[],
  code:                string,
  deterministicTitles: Set<string> = new Set(),
  suppressedTitles:    Set<string> = new Set(),
): {
  issues: IssueForCalibration[];
  stats:  CalibrationStats;
} {
  let upgraded = 0, downgraded = 0, totalConf = 0;

  const calibrated = issues.map(issue => {
    const evidence = buildEvidence(issue, code, deterministicTitles, suppressedTitles);
    const result   = computeBayesianConfidence(issue.title, issue.category, evidence);

    const oldSev = issue.severity;
    const newSev = result.recommendedSeverity;

    let upgraded_   = false;
    let downgraded_ = false;

    // Don't change severity if deterministic engine set it — trust det. engine
    const newSeverity = evidence.deterministicConfirmed ? oldSev : newSev;
    if (newSeverity !== oldSev) {
      const sevOrder = { high: 2, medium: 1, low: 0 };
      if (sevOrder[newSeverity] > sevOrder[oldSev]) upgraded_   = true;
      else                                           downgraded_ = true;
    }

    if (upgraded_)   upgraded++;
    if (downgraded_) downgraded++;
    totalConf += result.confidence;

    return {
      ...issue,
      severity:   newSeverity,
      confidence: result.posterior,
      _bayesianNote: result.calibrationNote,
      _bayesianSteps: result.updateSteps.length,
    };
  });

  const highConf = calibrated.filter(i => (i.confidence ?? 0) >= 0.75).length;

  return {
    issues: calibrated,
    stats: {
      totalInput:    issues.length,
      upgraded,
      downgraded,
      avgConfidence: issues.length > 0 ? Math.round(totalConf / issues.length) : 0,
      highConfidence: highConf,
    },
  };
}
