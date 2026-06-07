import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ─── Schema ──────────────────────────────────────────────────────────────────

export type IssueSeverity = 'high' | 'medium' | 'low';
export type IssueType = 'bug' | 'risk' | 'suggestion';
export type IssueCategory = 'security' | 'logic' | 'performance' | 'maintainability';

export interface Issue {
  type: IssueType;
  severity: IssueSeverity;
  confidence: number;
  category: IssueCategory;
  line: number | null;
  title: string;
  explanation: string;
  fix: string | null;
  /** Populated when a fix was present but rejected as unsafe */
  fixRejectionReason?: string;
  // v4 fields
  exploitChain?: string;
  exploitVerified?: boolean;
  exploitPayload?: string;
  consensusScore?: number;
  escalate?: boolean;
  exploitability?: number;
  reachability?: number;
  blastRadius?: string;
  astPatched?: boolean;
  patchConfidence?: number;
  proofChain?: {
    payload: string;
    executionPath: string;
    blockedAt: string | null;
    observedResult: string;
    sinkReachable: boolean;
  };
  // v7 fields
  familyId?:      string;
  familyLabel?:   string;
  familySinks?:   string[];
  familyLines?:   number[];
  familyCount?:   number;
  familyVariants?: Issue[];
  decayResult?:   unknown;
  _suppressionReason?: string;
  roleVotes?: {
    analyzer: string;
    critic: string;
    exploitVerifier: string;
    fixValidator: string;
  };
}

export interface ReviewResult {
  summary: string;
  score: number;
  language: string;
  issues: Issue[];
  optimized_code: string;
  /**
   * auditPassed: true means the pipeline's heuristic checks passed.
   * It does NOT mean the code is safe or the analysis is complete.
   * Manual review is always required before acting on results.
   */
  auditPassed: boolean;
  auditDetail: string;
  // v4: pipeline telemetry
  pipelineMetadata?: {
    taintSources:       number;
    callGraphNodes:     number;
    frameworksDetected: string[];
    consensusStats?:    { total: number; agreed: number; escalated: number; rejected: number };
    astPatchesApplied:  number;
    engineVersion:      string;
    rootCauseGraph?: {
      uniqueSurfaces: number;
      collapsed:      number;
      suppressed:     number;
      totalInput:     number;
    };
    reachabilityStats?: {
      total:        number;
      externalAnon: number;
      authRequired: number;
      adminOnly:    number;
      deadCode:     number;
      devOnly:      number;
    };
    exploitReplay?: {
      total:    number;
      verified: number;
      blocked:  number;
    };
    // v7+
    decayStats?: {
      totalInput:     number;
      activeCount:    number;
      suppressedCount: number;
      fpReductionPct: number;
    };
    clusterStats?: {
      familyCount: number;
      collapsed:   number;
      inputCount:  number;
      topFamilies: Array<{ family: string; count: number }>;
    };
    scoringBreakdown?: {
      positiveRewards:    number;
      adjustedDeductions: number;
      securityRewards:    Array<{ label: string; reward: number }>;
    };
    attackChains?: {
      chainCount:  number;
      maxSeverity: string;
      chains:      Array<{ id: string; title: string }>;
    };
    // v8+
    semanticGraph?: {
      authGaps:         number;
      crossModuleChains: number;
    };
    hallucinationFirewall?: {
      droppedCount:   number;
      survivedCount:  number;
    };
    trustModel?: {
      suppressedCount:  number;
      suppressedTitles: string[];
    };
    changeSurface?: {
      highRiskSurfaces: number;
    };
    // v9+
    symbolicExecution?: {
      constraints:      number;
      suppressedSinks:  number;
      authGuardedLines: number;
    };
    remediation?: {
      certified:   number;
      partial:     number;
      bypassed:    number;
      regressions: number;
    };
    bayesianCalibration?: {
      calibrated: number;
      upgraded:   number;
      downgraded: number;
    };
    firewallV2?: {
      droppedCount:  number;
      survivedCount: number;
    };
    // v10+
    constraintChains?: {
      total:              number;
      fullyValidated:     number;
      partiallyValidated: number;
      highestCvss:        number;
      criticalCount:      number;
    };
  };
}

export const FALLBACK_RESULT: ReviewResult = Object.freeze({
  summary: 'Analysis failed. Please try again.',
  score: 0,
  language: 'unknown',
  issues: [],
  optimized_code: '',
  auditPassed: false,
  auditDetail: 'Parse failure — result cannot be trusted.',
});

// ─── Confidence caps (hard limits, enforced client-side) ─────────────────────

const CONFIDENCE_CAPS: Record<IssueType, { security?: number; default: number }> = {
  bug:        { security: 0.95, default: 0.90 },
  risk:       { default: 0.80 },
  suggestion: { default: 0.70 },
};

function applyConfidenceCap(type: IssueType, category: IssueCategory, raw: number): number {
  const caps = CONFIDENCE_CAPS[type];
  const cap = (type === 'bug' && category === 'security' && caps.security != null)
    ? caps.security
    : caps.default;
  return parseFloat(Math.min(cap, Math.max(0, raw)).toFixed(2));
}

// ─── Security reclassification patterns ──────────────────────────────────────

const SECURITY_BUG_PATTERNS = [
  /sql.{0,20}inject/i,
  /inject.{0,20}sql/i,
  /xss|cross.site.script/i,
  /command.inject|shell.inject/i,
  /path.travers/i,
  /prototype.poll/i,
  /remote.code.exec|rce\b/i,
  /eval\(.{0,30}user|user.{0,30}eval\(/i,
  /new Function\(/i,
  /hardcoded.{0,20}(secret|password|key|token)/i,
];

function isSecurityBug(title: string, explanation: string): boolean {
  const text = `${title} ${explanation}`;
  return SECURITY_BUG_PATTERNS.some((re) => re.test(text));
}

// ─── Fix safety guard (AGGRESSIVE) ───────────────────────────────────────────
// Any fix that gives a FALSE SENSE OF SECURITY is worse than no fix.
// These patterns are rejected outright; the issue is surfaced with an
// explanation so the engineer understands WHY no fix was auto-generated.

const FORBIDDEN_FIX_PATTERNS: Array<{ re: RegExp; reason: string }> = [
  // Regex character-class stripping used as sanitization
  {
    re: /\.replace\s*\(\s*\/\[['"`]/,
    reason: 'Regex character-class stripping does not prevent injection. Use parameterized queries.',
  },
  // SQL keyword blacklist via replace
  {
    re: /\.replace\s*\(\s*\/[^/]*(?:select|drop|insert|update|delete)\b/i,
    reason: 'SQL keyword blacklist via replace() is bypassable. Use parameterized queries.',
  },
  // vm.runInContext without prototype freeze
  {
    re: /vm\.runInContext\s*\(/,
    reason: 'vm.runInContext() without Object.freeze on prototype chains does NOT prevent sandbox escapes.',
  },
  // DOMPurify without explicit config
  {
    re: /DOMPurify\.sanitize\s*\(\s*[\w.[\]]+\s*\)(?!\s*,)/,
    reason: 'DOMPurify.sanitize() without ALLOWED_TAGS/ALLOWED_ATTR config may still pass dangerous attributes.',
  },
  // JSON.stringify for deep equality
  {
    re: /JSON\.stringify\s*\([^)]+\)\s*===\s*JSON\.stringify/,
    reason: 'JSON.stringify comparison fails on key ordering. Use _.isEqual(a, b) from lodash.',
  },
  // .replace() used as an explicit HTML/JS/SQL sanitizer (not general string ops).
  // We only reject it when the replacement targets security-sensitive characters
  // (angle brackets, quotes, script tags, SQL keywords) directly — not every
  // .replace() call, which would incorrectly block safe fixes like filename
  // normalization (filename.replace(/[^\w.-]/g,'_')) or URL rewriting.
  {
    re: /\b\w+\s*=\s*\w+\.replace\s*\(\s*\/[^/]*(?:<|>|script|onerror|onload|SELECT|DROP|INSERT|UPDATE|DELETE)[^/]*\//i,
    reason: 'replace() targeting HTML/SQL characters is not a reliable sanitizer. Use textContent, parameterized queries, or a structural allowlist instead.',
  },
  // Bare global escape() used as a security sanitizer.
  // Only flags the global escape() — NOT method calls like db.escape() or
  // mysql.escape(), which are valid DB sanitization APIs.
  {
    re: /(?<![.\w])escape\s*\(/,
    reason: 'The global escape() function is deprecated and is not a security sanitizer. Use parameterized queries or textContent.',
  },
  // innerHTML assignment with any non-literal right-hand side
  {
    re: /\.innerHTML\s*=\s*(?!['"`]<)/,
    reason: 'innerHTML assignment with a non-literal value is an XSS sink. Use element.textContent or a safe DOM API instead.',
  },
  // vm2 sandbox (known escape CVEs)
  {
    re: /require\s*\(\s*['"]vm2['"]\s*\)/,
    reason: 'vm2 has multiple known sandbox-escape CVEs and is unmaintained. Use isolated-vm or remove dynamic execution.',
  },
];

export interface FixValidationResult {
  safe: boolean;
  reason?: string;
}

export function validateFix(fix: string, category: IssueCategory): FixValidationResult {
  if (fix.trim().length < 3) return { safe: false, reason: 'Fix is too short to be meaningful.' };

  // Run forbidden-pattern check on ALL categories.
  // A logic-category fix that contains a regex-sanitization pattern or
  // JSON.stringify equality is just as dangerous as a security one — it gives
  // engineers false confidence regardless of where the issue was classified.
  for (const { re, reason } of FORBIDDEN_FIX_PATTERNS) {
    if (re.test(fix)) {
      return { safe: false, reason };
    }
  }

  return { safe: true };
}

// ─── Result verification ──────────────────────────────────────────────────────
// "verified" is NOT "we got JSON from the model".
// It requires the result to pass a trust-boundary audit.

function auditResult(result: ReviewResult): { auditPassed: boolean; detail: string } {
  const problems: string[] = [];

  // 1. ANY bug (not just security) with null fix AND no rejection reason AND no
  //    explicit "cannot safely auto-fix" in the explanation = silent gap.
  //    "No code change required" is only valid for suggestions.
  // Bugs with no fix AND no rejection reason AND no explanation of why = silent gap.
  // A fixRejectionReason (even auto-generated by validateFix) counts as documented.
  const silentBugIndices: number[] = [];
  result.issues.forEach((i, idx) => {
    if (
      i.type === 'bug' &&
      i.fix === null &&
      !i.fixRejectionReason &&
      !/cannot safely auto.fix|architectural|remove dynamic|no safe fix|forbidden|unsafe/i.test(i.explanation)
    ) {
      silentBugIndices.push(idx);
    }
  });
  if (silentBugIndices.length > 0) {
    // Stamp a reason rather than failing the audit — the result is still useful
    silentBugIndices.forEach((idx) => {
      result.issues[idx] = {
        ...result.issues[idx],
        fixRejectionReason:
          'No safe auto-fix available — manual remediation required.',
      };
    });
  }

  // 2. High-severity issues must have substantive explanations
  const vagueHighIssues = result.issues.filter(
    (i) => i.severity === 'high' && i.explanation.length < 60
  );
  if (vagueHighIssues.length > 0) {
    problems.push(
      `${vagueHighIssues.length} high-severity issue(s) have insufficiently detailed explanations (< 60 chars). Do not act without manual review.`
    );
  }

  // 3. Score vs computed inconsistency — known model hallucination pattern
  const recomputedScore = computeScore(result.issues);
  const scoreDrift = Math.abs(result.score - recomputedScore);
  if (scoreDrift > 15) {
    problems.push(
      `Score reported by model (${result.score}) diverges from computed score (${recomputedScore}) by ${scoreDrift} points — corrected.`
    );
    result.score = recomputedScore;
  }

  // 4. Zero issues — warn but don't hard-fail; the model may have correctly found nothing.
  //    The UI already shows the "Needs review" badge whenever auditPassed is false,
  //    so only truly suspicious results (score=100, empty summary) get flagged.
  if (result.issues.length === 0) {
    const suspiciousClean = result.score >= 100 && result.summary.trim().length < 20;
    if (suspiciousClean) {
      return {
        auditPassed: false,
        detail: 'No issues detected and summary is empty — possible prompt injection or model refusal. Manual review required.',
      };
    }
    // Legitimate clean result — pass audit with a note
    return {
      auditPassed: true,
      detail: 'No issues detected. Heuristic checks passed — independent manual review still recommended.',
    };
  }

  if (problems.length > 0) {
    return { auditPassed: false, detail: problems.join(' | ') };
  }

  return {
    auditPassed: true,
    detail: `${result.issues.length} issue(s) processed. Heuristic checks passed — manual review still required before shipping.`,
  };
}

// ─── Models ───────────────────────────────────────────────────────────────────

export type ModelId =
  | 'openai/gpt-4o-mini'
  | 'openai/gpt-4o'
  | 'anthropic/claude-3-haiku'
  | 'anthropic/claude-3.5-sonnet'
  | 'meta-llama/llama-3.1-8b-instruct'
  | 'auto';

export const MODELS: { id: ModelId; label: string; description: string }[] = [
  { id: 'auto',                              label: 'Auto',                description: 'Smart routing by code size (recommended)' },
  { id: 'openai/gpt-4o-mini',               label: 'GPT-4o Mini',         description: 'Fast & capable — free tier' },
  { id: 'openai/gpt-4o',                    label: 'GPT-4o',              description: 'Best OpenAI — free tier' },
  { id: 'anthropic/claude-3-haiku',         label: 'Claude 3 Haiku',      description: 'Precise reasoning — free tier' },
  { id: 'anthropic/claude-3.5-sonnet',      label: 'Claude 3.5 Sonnet',   description: 'Most capable — free tier' },
  { id: 'meta-llama/llama-3.1-8b-instruct', label: 'Llama 3.1 8B',       description: 'Open source — free tier' },
];

export function resolveModel(modelId: ModelId, codeLength: number): string {
  if (modelId !== 'auto') return modelId;
  // Large code benefits from claude-3.5-sonnet's wider context window
  return codeLength < 1500 ? 'openai/gpt-4o-mini' : 'anthropic/claude-3.5-sonnet';
}

// ─── Languages ───────────────────────────────────────────────────────────────

export const LANGUAGES = [
  { id: 'auto', label: 'Auto Detect', monaco: 'javascript' },
  { id: 'javascript', label: 'JavaScript', monaco: 'javascript' },
  { id: 'typescript', label: 'TypeScript', monaco: 'typescript' },
  { id: 'python', label: 'Python', monaco: 'python' },
  { id: 'rust', label: 'Rust', monaco: 'rust' },
  { id: 'go', label: 'Go', monaco: 'go' },
  { id: 'java', label: 'Java', monaco: 'java' },
  { id: 'cpp', label: 'C++', monaco: 'cpp' },
  { id: 'csharp', label: 'C#', monaco: 'csharp' },
  { id: 'php', label: 'PHP', monaco: 'php' },
  { id: 'ruby', label: 'Ruby', monaco: 'ruby' },
  { id: 'swift', label: 'Swift', monaco: 'swift' },
  { id: 'kotlin', label: 'Kotlin', monaco: 'kotlin' },
  { id: 'sql', label: 'SQL', monaco: 'sql' },
  { id: 'bash', label: 'Bash', monaco: 'shell' },
];

export function getMonacoLanguage(langId: string): string {
  return LANGUAGES.find((l) => l.id === langId)?.monaco ?? 'javascript';
}

// ─── Loading messages ─────────────────────────────────────────────────────────

export const LOADING_MESSAGES = [
  'Stage 1 — Rule engine: 40+ rules across 8 vulnerability families...',
  'Stage 2 — Call graph & interprocedural taint (4-hop)...',
  'Stage 3 — Multi-role consensus: Analyzer + Critic + Verifier + Judge...',
  'Stage 4 — Judge arbitration: resolving disagreements...',
  'Stage 5 — AST patch synthesis: syntax-preserving rewrites...',
  'Stage 5b — Reachability: route graph + auth boundary analysis...',
  'Stage 5c — Exploit replay: verifying sink reachability...',
  'Stage 6 — Root-cause graph: collapsing duplicate findings...',
  'Stage 7 — Confidence decay: suppressing low-signal noise...',
  'Stage 8 — Family clustering: grouping by vulnerability class...',
  'Stage 9 — Attack chain synthesis: chaining findings into exploits...',
  'Stage 9b — Constraint-valid chains: SSRF→RCE, SQLi→auth bypass...',
  'Stage 10 — Semantic graph: auth gaps & cross-module chains...',
  'Stage 12 — Hallucination firewall: AST-backed claim verification...',
  'Stage 14 — Symbolic execution: constraint-aware path analysis...',
  'Stage 15 — Bayesian calibration: evidence-weighted severity...',
  'Stage 17 — Verified remediation: patch→taint→replay→certify...',
];

// ─── Priority sort ────────────────────────────────────────────────────────────

function issuePriority(issue: Issue): number {
  if (issue.type === 'bug' && issue.category === 'security') return 0;
  if (issue.type === 'bug' && issue.severity === 'high') return 1;
  if (issue.type === 'bug' && issue.severity === 'medium') return 2;
  if (issue.type === 'bug') return 3;
  if (issue.type === 'risk' && issue.severity === 'high') return 4;
  if (issue.type === 'risk' && issue.severity === 'medium') return 5;
  if (issue.type === 'risk') return 6;
  return 7;
}

// ─── JSON extraction ──────────────────────────────────────────────────────────

function extractOutermostObject(text: string): string | null {
  let depth = 0;
  let start = -1;
  let inString = false;
  let escape = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (escape) { escape = false; continue; }
    if (ch === '\\' && inString) { escape = true; continue; }
    if (ch === '"') { inString = !inString; continue; }
    if (inString) continue;
    if (ch === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0 && start !== -1) return text.slice(start, i + 1);
    }
  }
  return null;
}

function normalizeCategory(raw: unknown): IssueCategory {
  const valid: IssueCategory[] = ['security', 'logic', 'performance', 'maintainability'];
  return valid.includes(raw as IssueCategory) ? (raw as IssueCategory) : 'logic';
}

// ─── Prototype-collision key guard ───────────────────────────────────────────
// JSON.parse() in V8 does not pollute Object.prototype directly, so
// { "__proto__": {...} } in JSON is safe today. However, if any future
// refactor adds Object.assign(), a deep-merge library, or bracket-assignment
// over untrusted keys, the hazard would materialise silently. We eliminate
// it now by extracting fields into a null-prototype object — no inherited
// property lookup is possible regardless of key names.
function safeRecord(raw: object): Record<string, unknown> {
  const safe = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(raw)) {
    safe[key] = (raw as Record<string, unknown>)[key];
  }
  return safe;
}

function normalizeIssue(raw: unknown): Issue | null {
  if (typeof raw !== 'object' || raw === null) return null;
  // Null-prototype copy: __proto__ / constructor / prototype keys can never
  // reach Object.prototype even if a future merge/assign is introduced.
  const r = safeRecord(raw as object);

  const validTypes = ['bug', 'risk', 'suggestion'] as const;
  const validSeverities = ['high', 'medium', 'low'] as const;

  // Map hallucinated type names → canonical types instead of dropping the issue.
  // Models commonly return "vulnerability", "error", "warning", "security" etc.
  const typeAliases: Record<string, IssueType> = {
    vulnerability: 'bug', error: 'bug', critical: 'bug', security: 'bug',
    warning: 'risk', warn: 'risk', caution: 'risk', issue: 'risk',
    improvement: 'suggestion', info: 'suggestion', note: 'suggestion',
  };
  const rawType = typeof r.type === 'string' ? r.type.toLowerCase().trim() : '';
  const resolvedType: IssueType | undefined =
    validTypes.includes(rawType as IssueType)
      ? (rawType as IssueType)
      : typeAliases[rawType];
  if (!resolvedType) {
    console.warn('[normalizeIssue] Unrecognized type coerced to risk:', r.type, '| title:', r.title ?? '(none)');
  }
  let type: IssueType = resolvedType ?? 'risk';
  let severity = validSeverities.includes(r.severity as IssueSeverity) ? (r.severity as IssueSeverity) : 'medium';
  let category = normalizeCategory(r.category);

  const title = typeof r.title === 'string' ? r.title : '';
  const explanation = typeof r.explanation === 'string' ? r.explanation : '';

  // ── Security reclassification fence ──────────────────────────────────────
  if (isSecurityBug(title, explanation)) {
    type = 'bug';
    severity = 'high';
    category = 'security';
  }

  const rawConf = typeof r.confidence === 'number' ? r.confidence : 0.75;
  const confidence = applyConfidenceCap(type, category, rawConf);

  // ── AGGRESSIVE fix safety fence ───────────────────────────────────────────
  // Every fix is tested. Unsafe fixes are surfaced with a rejection reason
  // rather than silently nulled — so engineers know WHY there's no auto-fix.
  let fix: string | null = null;
  let fixRejectionReason: string | undefined;

  if (typeof r.fix === 'string' && r.fix.trim()) {
    const validation = validateFix(r.fix, category);
    if (validation.safe) {
      fix = r.fix;
    } else {
      fix = null;
      fixRejectionReason = validation.reason;
    }
  }

  return {
    type,
    severity,
    confidence,
    category,
    line: typeof r.line === 'number' && r.line > 0 ? Math.round(r.line) : null,
    title: title || 'Untitled Issue',
    explanation,
    fix,
    fixRejectionReason,
  };
}

function computeScore(issues: Issue[]): number {
  let penalty = 0;
  for (const issue of issues) {
    if (issue.type === 'suggestion') { penalty += 2; continue; }
    if (issue.severity === 'high') penalty += issue.type === 'bug' ? 20 : 12;
    else if (issue.severity === 'medium') penalty += issue.type === 'bug' ? 10 : 6;
    else penalty += issue.type === 'bug' ? 4 : 3;
  }
  return Math.max(0, 100 - penalty);
}

function normalizeResult(parsed: unknown): ReviewResult | null {
  if (typeof parsed !== 'object' || parsed === null) return null;
  let p = parsed as Record<string, unknown>;

  // Normalize the issues array key — models use many aliases
  const ISSUES_ALIASES = ['issues', 'findings', 'vulnerabilities', 'problems', 'errors', 'bugs', 'results', 'items'];
  const issuesKey = ISSUES_ALIASES.find(k => k in p && Array.isArray(p[k]));

  // Normalize the summary key — models sometimes use 'description', 'overview', 'analysis'
  const SUMMARY_ALIASES = ['summary', 'description', 'overview', 'analysis', 'assessment', 'report'];
  const summaryKey = SUMMARY_ALIASES.find(k => k in p && typeof p[k] === 'string');

  // If missing required keys, search one level deeper (e.g. {"result":{...}} or {"data":{...}})
  if (!issuesKey || !summaryKey) {
    for (const val of Object.values(p)) {
      if (typeof val === 'object' && val !== null) {
        const nested = val as Record<string, unknown>;
        const nestedIssuesKey   = ISSUES_ALIASES.find(k => k in nested && Array.isArray(nested[k]));
        const nestedSummaryKey  = SUMMARY_ALIASES.find(k => k in nested && typeof nested[k] === 'string');
        if (nestedIssuesKey && nestedSummaryKey) {
          console.warn('[normalizeResult] Unwrapped nested result');
          return normalizeResult(nested);
        }
      }
    }
    console.error('[normalizeResult] Cannot find issues+summary. Top-level keys:', Object.keys(p).join(', '));
    return null;
  }

  // Normalize to canonical keys so the rest of the function works uniformly
  if (issuesKey !== 'issues' || summaryKey !== 'summary') {
    console.warn(`[normalizeResult] Remapped keys: ${summaryKey}→summary, ${issuesKey}→issues`);
    p = { ...p, issues: p[issuesKey], summary: p[summaryKey] };
  }

  const rawIssues = Array.isArray(p.issues) ? p.issues : [];
  const issues: Issue[] = rawIssues
    .map(normalizeIssue)
    .filter((i): i is Issue => i !== null)
    .sort((a, b) => issuePriority(a) - issuePriority(b));

  const score = typeof p.score === 'number'
    ? Math.min(100, Math.max(0, Math.round(p.score)))
    : computeScore(issues);

  const result: ReviewResult = {
    summary: typeof p.summary === 'string' ? p.summary : '',
    score,
    language: typeof p.language === 'string' ? p.language : 'unknown',
    issues,
    optimized_code: typeof p.optimized_code === 'string' ? p.optimized_code : '',
    auditPassed: false,
    auditDetail: '',
  };

  // ── Heuristic audit — sets auditPassed + auditDetail ─────────────────────
  // auditPassed:true means heuristic checks passed, NOT that the code is safe.
  const audit = auditResult(result);
  result.auditPassed = audit.auditPassed;
  result.auditDetail = audit.detail;
  // Score may have been corrected by the auditor
  result.score = computeScore(result.issues);

  return result;
}

// ─── Truncation rescue ────────────────────────────────────────────────────────
// When the model is cut off mid-response (most commonly inside the
// `optimized_code` string value), the JSON is malformed. We attempt to salvage
// summary/score/language/issues by stripping the broken field and re-closing.
function rescueTruncated(text: string): ReviewResult | null {
  // Strategy A: strip an unterminated optimized_code value
  const withoutOptimized = text
    .replace(/,?\s*"optimized_code"\s*:\s*"(?:[^"\\]|\\.)*$/s, '')
    .replace(/,?\s*"optimized_code"\s*:\s*"(?:[^"\\]|\\.)*"[^}]*$/s, '')
    .trimEnd();
  const closedA = withoutOptimized.endsWith('}') ? withoutOptimized : withoutOptimized + '}';
  try {
    const parsed = JSON.parse(closedA);
    const result = normalizeResult(parsed);
    if (result) {
      console.warn('[safeParseJSON] Rescued truncated response — optimized_code stripped');
      result.optimized_code = '';
      return result;
    }
  } catch { /* fall through */ }

  // Strategy B: truncation mid-issues-array — use last complete issue entry
  const issuesMatch = text.match(/^([\s\S]*?"issues"\s*:\s*\[)([\s\S]*)$/);
  if (issuesMatch) {
    const prefix = issuesMatch[1];
    const issueContent = issuesMatch[2];
    const lastBrace = issueContent.lastIndexOf('}');
    if (lastBrace !== -1) {
      const minimalJson = prefix + issueContent.slice(0, lastBrace + 1) + '],"summary":"Analysis may be incomplete — response was truncated.","score":0}';
      try {
        const parsed = JSON.parse(minimalJson);
        const result = normalizeResult(parsed);
        if (result) {
          console.warn('[safeParseJSON] Rescued partially truncated issues array');
          return result;
        }
      } catch { /* fall through */ }
    }
  }
  return null;
}

export function safeParseJSON(text: string): ReviewResult {
  const stripped = text.replace(/```(?:json)?\s*/g, '').replace(/```/g, '').trim();
  // Always log the raw model output — critical for diagnosing parse failures
  console.log('[safeParseJSON] Raw model response (first 800 chars):', text.slice(0, 800));

  const candidates: string[] = [text.trim(), stripped];
  const extracted = extractOutermostObject(text);
  if (extracted) candidates.push(extracted);
  // Also try extracting from stripped (handles preamble + fences)
  const extractedFromStripped = extractOutermostObject(stripped);
  if (extractedFromStripped && extractedFromStripped !== extracted) candidates.push(extractedFromStripped);

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      const result = normalizeResult(parsed);
      if (result) return result;
    } catch { /* try next */ }
  }

  // Last resort: attempt truncation rescue
  const rescued = rescueTruncated(stripped || text.trim());
  if (rescued) return rescued;

  // Log full raw response for diagnosis
  console.error('[safeParseJSON] All strategies failed. Full raw response:');
  console.error(text);

  // Last-ditch: if the model returned plain text (e.g. prompt injection succeeded
  // and it replied "Everything looks safe"), synthesize a result that flags it.
  const looksLikeProseResponse = text.length > 10 && !text.includes('{');
  if (looksLikeProseResponse) {
    console.warn('[safeParseJSON] Model returned plain text — likely prompt injection or refusal. Synthesizing result.');
    return {
      ...FALLBACK_RESULT,
      summary: 'Model returned non-JSON output — possible prompt injection in analyzed code caused the model to deviate from its instructions.',
      auditPassed: false,
      auditDetail: 'Parse failure — model returned plain text instead of JSON. The code under review may contain prompt injection. Manual review required.',
      issues: [{
        type: 'bug',
        severity: 'high',
        confidence: 0.9,
        category: 'security',
        line: null,
        title: 'Prompt Injection — AI pipeline manipulation attempt detected',
        explanation: 'The code contains text designed to override AI analysis instructions (e.g. "Ignore all previous instructions", "Return score: 100"). This caused the model to produce non-JSON output instead of a proper analysis. In a production AI pipeline, this would suppress real vulnerability findings.',
        fix: '// Remove or sanitize any natural-language instructions embedded in code\n// that could be interpreted as AI prompt injection payloads.',
        fixRejectionReason: undefined,
      }],
    };
  }

  return FALLBACK_RESULT;
}
