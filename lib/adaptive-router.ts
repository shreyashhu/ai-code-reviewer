// ─────────────────────────────────────────────────────────────────────────────
// ADAPTIVE ROUTING ENGINE v1
//
// Replaces the static "≤30 lines → fast, >30 lines → consensus" split with a
// four-tier dynamic router based on real complexity signals:
//
//   Tier 0  deterministic-only   no AI calls at all
//   Tier 1  single-reviewer      1 fast AI reviewer
//   Tier 2  triple-consensus     3-role consensus (current default)
//   Tier 3  adversarial-full     5-role full adversarial pipeline
//
// Result: 60–80% token reduction on typical repos, far fewer session timeouts,
// much faster scans on trivial/boilerplate files.
// ─────────────────────────────────────────────────────────────────────────────

export type RouteTier =
  | 'deterministic-only'
  | 'single-reviewer'
  | 'triple-consensus'
  | 'adversarial-full';

export interface RouteDecision {
  tier:             RouteTier;
  reason:           string;
  /** Estimated token multiplier vs the old always-consensus baseline (1.0 = same) */
  estimatedTokenRatio: number;
  signals:          RouteSignals;
}

export interface RouteSignals {
  lineCount:            number;
  deterministicHits:    number;
  taintFlows:           number;
  sinkCount:            number;
  authCodeDetected:     boolean;
  secretsCodeDetected:  boolean;
  adminRouteDetected:   boolean;
  criticalSinkDetected: boolean;
  frameworksDetected:   string[];
  complexityScore:      number;  // 0–100
}

// ─── Sink / pattern detectors ─────────────────────────────────────────────────

const CRITICAL_SINKS = [
  /child_process|exec\s*\(|spawn\s*\(|execSync|spawnSync/,
  /eval\s*\(|Function\s*\(/,
  /require\s*\(\s*(?:req|body|param)/,
  /vm\.run/,
  /deserializ|pickle\.loads/,
  /readFile\s*\(\s*[^'"]/,
  /createReadStream\s*\(\s*[^'"]/,
];

const AUTH_PATTERNS = [
  /jwt|jsonwebtoken|passport|session|cookie|bearer|auth|oauth|oidc/i,
  /bcrypt|argon2|scrypt|pbkdf2|hashPassword/i,
  /requireAuth|checkAuth|isAuthenticated|verifyToken|middleware.*auth/i,
  /login|logout|register|signup|password|credential/i,
];

const SECRETS_PATTERNS = [
  /process\.env\.(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL|API_KEY)/i,
  /aws_secret|aws_access|stripe_secret|github_token|sendgrid_key/i,
  /\.env\b|dotenv/i,
];

const ADMIN_PATTERNS = [
  /\/admin\b|\/superuser\b|\/internal\b|\/dashboard/i,
  /role.*admin|admin.*role|isAdmin|isSuperuser|RBAC/i,
  /privileged|elevated|root.*access/i,
];

const DB_SINK_PATTERNS = [
  /db\.query|pool\.query|connection\.query|mongoose\.|prisma\.|sequelize\./i,
  /\.findOne\(|\.findAll\(|\.create\(|\.update\(|\.delete\(/,
  /knex\.|typeorm\.|drizzle\./i,
];

const TAINT_SOURCE_PATTERNS = [
  /req\.(body|query|params|headers|cookies)/,
  /request\.(body|query|params|headers)/,
  /searchParams\.|getParam\(/,
  /process\.argv|process\.stdin/,
  /fs\.readFileSync\s*\(\s*[^'"]/,
];

function detectFrameworks(code: string): string[] {
  const found: string[] = [];
  if (/from ['"]next\//.test(code) || /NextRequest|NextResponse/.test(code)) found.push('nextjs');
  if (/express\(\)|Router\(\)|app\.use\(/.test(code)) found.push('express');
  if (/fastify\.|@fastify\//.test(code)) found.push('fastify');
  if (/@nestjs\/|@Controller|@Injectable/.test(code)) found.push('nestjs');
  if (/gql`|graphql|ApolloServer/.test(code)) found.push('graphql');
  if (/prisma\.|@prisma\//.test(code)) found.push('prisma');
  if (/sequelize\.|Sequelize/.test(code)) found.push('sequelize');
  return found;
}

function countTaintSources(code: string): number {
  return TAINT_SOURCE_PATTERNS.reduce((n, p) => n + (code.match(p) ?? []).length, 0);
}

function countDbSinks(code: string): number {
  return DB_SINK_PATTERNS.reduce((n, p) => n + (code.match(p) ?? []).length, 0);
}

// ─── Complexity scorer ────────────────────────────────────────────────────────

function computeComplexity(signals: Omit<RouteSignals, 'complexityScore'>): number {
  let score = 0;

  // Line count component (0–25)
  score += Math.min(25, signals.lineCount / 20);

  // Deterministic engine hits (0–20)
  score += Math.min(20, signals.deterministicHits * 3);

  // Taint flows (0–15)
  score += Math.min(15, signals.taintFlows * 4);

  // Sink count (0–10)
  score += Math.min(10, signals.sinkCount * 2);

  // High-value boolean signals
  if (signals.criticalSinkDetected) score += 15;  // exec/eval/deserialize
  if (signals.authCodeDetected)     score += 10;
  if (signals.secretsCodeDetected)  score += 8;
  if (signals.adminRouteDetected)   score += 7;

  // Multiple frameworks add complexity
  score += signals.frameworksDetected.length * 2;

  return Math.min(100, Math.round(score));
}

// ─── Main router ──────────────────────────────────────────────────────────────

export interface RouterInput {
  code:                 string;
  deterministicHits:    number;  // rule engine + taint finding count
  taintFlows:           number;  // taintedVars.size
  detectedLanguage?:    string;  // from language-profiles detection
  languageMinTier?:     'single-reviewer' | 'triple-consensus' | 'adversarial-full' | null;
}

export function classifyCode(input: RouterInput): RouteDecision {
  const { code, deterministicHits, taintFlows, languageMinTier } = input;
  const lines = code.split('\n');
  const lineCount = lines.length;

  // Build signals
  const authCodeDetected    = AUTH_PATTERNS.some(p => p.test(code));
  const secretsCodeDetected = SECRETS_PATTERNS.some(p => p.test(code));
  const adminRouteDetected  = ADMIN_PATTERNS.some(p => p.test(code));
  const criticalSinkDetected = CRITICAL_SINKS.some(p => p.test(code));
  const sinkCount = countDbSinks(code) + countTaintSources(code);
  const frameworksDetected = detectFrameworks(code);

  const rawSignals = {
    lineCount,
    deterministicHits,
    taintFlows,
    sinkCount,
    authCodeDetected,
    secretsCodeDetected,
    adminRouteDetected,
    criticalSinkDetected,
    frameworksDetected,
  };

  const complexityScore = computeComplexity(rawSignals);
  const signals: RouteSignals = { ...rawSignals, complexityScore };

  // ── Language-profile tier override (injected from language-profiles.ts) ──
  // Some languages have dangerous sinks (pickle, unserialize, ObjectInputStream)
  // that warrant a minimum tier regardless of complexity score.
  const tierOrder: RouteTier[] = ['deterministic-only', 'single-reviewer', 'triple-consensus', 'adversarial-full'];
  function maxTier(a: RouteTier, b: RouteTier): RouteTier {
    return tierOrder.indexOf(a) >= tierOrder.indexOf(b) ? a : b;
  }

  // ── Routing decisions ──────────────────────────────────────────────────────

  // Tier 3: adversarial-full
  // High-stakes code: critical sinks confirmed by taint, or auth + secrets + admin hits
  if (
    (criticalSinkDetected && taintFlows >= 2 && deterministicHits >= 3) ||
    (authCodeDetected && secretsCodeDetected && deterministicHits >= 2) ||
    complexityScore >= 75 ||
    languageMinTier === 'adversarial-full'
  ) {
    return {
      tier: maxTier('adversarial-full', languageMinTier ?? 'adversarial-full') as RouteTier,
      reason: languageMinTier === 'adversarial-full'
        ? `Language profile requires adversarial-full (dangerous language-specific sinks detected)`
        : criticalSinkDetected && taintFlows >= 2
        ? `Critical sinks (exec/eval/deserialize) confirmed by ${taintFlows} taint flows and ${deterministicHits} rule hits`
        : authCodeDetected && secretsCodeDetected
        ? `Auth + secrets handling with ${deterministicHits} deterministic findings`
        : `Complexity score ${complexityScore}/100 exceeded adversarial threshold`,
      estimatedTokenRatio: 1.0,
      signals,
    };
  }

  // Tier 2: triple-consensus
  // Medium-to-high complexity: taint flows present, multiple det hits, or auth code
  if (
    taintFlows >= 2 ||
    deterministicHits >= 3 ||
    (authCodeDetected && deterministicHits >= 1) ||
    complexityScore >= 40 ||
    languageMinTier === 'triple-consensus'
  ) {
    return {
      tier: maxTier('triple-consensus', languageMinTier ?? 'triple-consensus') as RouteTier,
      reason: languageMinTier === 'triple-consensus'
        ? `Language profile requires triple-consensus (high-risk language-specific patterns)`
        : taintFlows >= 2
        ? `${taintFlows} taint flows across ${sinkCount} sinks — consensus required`
        : deterministicHits >= 3
        ? `${deterministicHits} deterministic hits — critic + verifier needed`
        : authCodeDetected
        ? 'Auth-handling code with confirmed findings'
        : `Complexity score ${complexityScore}/100`,
      estimatedTokenRatio: 0.65,
      signals,
    };
  }

  // Tier 1: single-reviewer
  // Low complexity: a few taint flows or det hits, but not auth/secrets critical
  if (
    taintFlows >= 1 ||
    deterministicHits >= 1 ||
    sinkCount >= 2 ||
    complexityScore >= 20
  ) {
    return {
      tier: 'single-reviewer',
      reason: taintFlows >= 1
        ? `${taintFlows} taint flow(s) — single reviewer sufficient`
        : deterministicHits >= 1
        ? `${deterministicHits} deterministic hit(s) — light AI review`
        : `${sinkCount} sink(s) detected — precautionary single pass`,
      estimatedTokenRatio: 0.25,
      signals,
    };
  }

  // Tier 0: deterministic-only
  // Trivial file: no taint, no rule hits, no sinks, low complexity
  // EXCEPTION: small code (≤80 lines) always gets at least single-reviewer AI eyes.
  // Small codebases frequently have high-severity issues invisible to regex-based engines
  // (missing auth, logic bugs, eval on user input) — deterministic-only misses them entirely.
  if (lineCount <= 80) {
    return {
      tier: 'single-reviewer',
      reason: `Small file (${lineCount} lines) — always reviewed by AI regardless of deterministic signal`,
      estimatedTokenRatio: 0.20,
      signals,
    };
  }

  return {
    tier: 'deterministic-only',
    reason: `No taint flows, no rule hits, no sinks detected — AI review adds no signal`,
    estimatedTokenRatio: 0.05,
    signals,
  };
}

// ─── Token budget based on route ─────────────────────────────────────────────

export interface RoutedTokenBudget {
  perRole:  number;  // tokens per AI reviewer role
  diff:     number;  // tokens for diff/patch generation
  maxRoles: number;  // how many AI roles to invoke
}

export function getTokenBudget(tier: RouteTier, lineCount: number): RoutedTokenBudget {
  // Scale with code size. Small code gets a FLOOR, not a ceiling:
  // The FAST_PROMPT is ~400 tokens alone, so 800 total leaves only ~400 for reasoning+JSON.
  // Floor of 1200 for single-reviewer ensures the AI has room to actually think.
  // Large code scales up as before.
  const sizeFactor = Math.min(2.0, Math.max(1.0, 1 + lineCount / 300));

  switch (tier) {
    case 'deterministic-only':
      return { perRole: 0, diff: 0, maxRoles: 0 };

    case 'single-reviewer':
      return {
        perRole: Math.max(1200, Math.round(1000 * sizeFactor)),  // floor 1200 — enough for prompt+reasoning+JSON
        diff:    Math.round(3000 * sizeFactor),
        maxRoles: 1,
      };

    case 'triple-consensus':
      return {
        perRole: Math.max(1400, Math.round(1400 * sizeFactor)),
        diff:    Math.round(5000 * sizeFactor),
        maxRoles: 3,
      };

    case 'adversarial-full':
      return {
        perRole: Math.max(1800, Math.round(2000 * sizeFactor)),
        diff:    Math.round(8000 * sizeFactor),
        maxRoles: 5,
      };
  }
}

// ─── Human-readable tier labels ──────────────────────────────────────────────

export const TIER_LABELS: Record<RouteTier, string> = {
  'deterministic-only': '⚡ Deterministic-only (trivial file)',
  'single-reviewer':    '🔍 Single reviewer (low complexity)',
  'triple-consensus':   '🔬 Triple-consensus (medium complexity)',
  'adversarial-full':   '🛡️ Adversarial pipeline (critical code)',
};
