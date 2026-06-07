// ─────────────────────────────────────────────────────────────────────────────
// BUSINESS-IMPACT RISK MODEL v1
//
// Replaces heuristic confidence-based severity with real risk signals:
//
//   Signal                  Weight
//   ─────────────────────── ──────
//   Internet reachable?      +3
//   Unauthenticated?         +3
//   Admin-only route?        −2  (reduces attack surface)
//   Secrets accessible?      +2
//   Cloud credentials?       +3
//   Lateral movement?        +2
//   PII / sensitive data?    +2
//   Publicly documented CVE? +1
//   Production-only path?    +1 (versus dev/test only)
//
// The model computes a "Business Impact Score" (BIS) 0–100 per finding and
// uses it to set/validate severity, suppressing "fake criticals" and elevating
// under-reported high-impact findings.
// ─────────────────────────────────────────────────────────────────────────────

export interface RiskContext {
  /** Is the vulnerable route reachable without auth from the internet? */
  internetReachable: boolean;
  /** Is the route behind authentication middleware? */
  authenticated:     boolean;
  /** Is the route restricted to admin/privileged roles? */
  adminOnly:         boolean;
  /** Does the path access secret env vars / API keys? */
  secretsAccessible: boolean;
  /** Are cloud credentials (AWS/GCP/Azure) on the data path? */
  cloudCredentials:  boolean;
  /** Can exploitation pivot to other services / host? */
  lateralMovement:   boolean;
  /** Does the path process PII or GDPR-relevant data? */
  sensitiveData:     boolean;
  /** Is this production code (not dev/test fixtures)? */
  productionPath:    boolean;
}

export interface RiskAdjustedIssue {
  /** Original severity before risk modeling */
  originalSeverity:  'high' | 'medium' | 'low';
  /** Severity after business-impact adjustment */
  adjustedSeverity:  'high' | 'medium' | 'low';
  /** 0–100 business impact score */
  businessImpact:    number;
  /** Plain-language explanation of the adjustment */
  impactRationale:   string;
  /** Was this a "fake critical" that was downgraded? */
  downgraded:        boolean;
  /** Was this a hidden high-impact issue that was upgraded? */
  upgraded:          boolean;
  context:           RiskContext;
}

export interface RiskModelStats {
  totalInput:     number;
  downgraded:     number;
  upgraded:       number;
  unchanged:      number;
  avgBisScore:    number;
  fakeCriticals:  number;  // high→medium/low
}

// ─── Code-level signals ───────────────────────────────────────────────────────

const INTERNET_REACHABLE_PATTERNS = [
  /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)/,   // Next.js route handlers
  /app\.(get|post|put|delete|patch)\s*\(/,                             // Express
  /router\.(get|post|put|delete|patch)\s*\(/,
  /@(Get|Post|Put|Delete|Patch)\s*\(/,                                 // NestJS
  /http_method|@app\.route/,                                           // Flask-style
];

const AUTH_GUARD_PATTERNS = [
  /requireAuth|checkAuth|isAuthenticated|verifyToken|authenticate/i,
  /if\s*\(!?\s*session\b/,
  /if\s*\(!?\s*user\b/,
  /middleware.*auth|auth.*middleware/i,
  /passport\.|jwt\.verify|jwtVerify/,
  /getServerSession|getSession|cookies\(\).*token/i,
];

const ADMIN_ONLY_PATTERNS = [
  /role\s*===?\s*['"]admin['"]/i,
  /isAdmin|isSuperuser|hasRole.*admin/i,
  /requireAdmin|adminOnly|requireRole.*admin/i,
  /\/admin\b|\/superuser\b|admin.*endpoint/i,
];

const SECRETS_PATTERNS = [
  /process\.env\.(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|API_KEY)/i,
  /AWS_SECRET|AWS_ACCESS|STRIPE_SECRET|GITHUB_TOKEN|SENDGRID/i,
  /getSecretValue|ssm\.getParameter|secretsManager/i,
];

const CLOUD_CREDENTIAL_PATTERNS = [
  /aws\.config\.|s3\.|ec2\.|lambda\.|SES\.|SNS\.|SQS\./i,
  /storage\.bucket|bigquery\.|firestore\./i,
  /AzureStorage|BlobServiceClient/i,
  /iam|credentials\s*:\s*\{.*accessKey/i,
];

const LATERAL_MOVEMENT_PATTERNS = [
  /child_process|exec\s*\(|spawn\s*\(/,
  /kubectl|docker\s+|k8s\b/i,
  /ssh\.connect|sshClient/i,
  /http\.request\s*\(\s*(?:req|body|input)/,
  /fetch\s*\(\s*(?:req|url|input)/,
  /internal.*service|service.*discovery/i,
];

const SENSITIVE_DATA_PATTERNS = [
  /ssn|social.security|passport.number/i,
  /credit.card|card.number|cvv|pan\b/i,
  /health.record|medical|diagnosis|hipaa/i,
  /gdpr|personal.data|pii\b/i,
  /email.*user|user.*email|phone.*user|dob|date.of.birth/i,
];

const DEV_TEST_PATTERNS = [
  /test\b|spec\b|fixture|mock|stub|fake/i,
  /\.test\.|\.spec\.|__tests__|__mocks__/,
  /localhost|127\.0\.0\.1|development/i,
];

// ─── Context extractor ────────────────────────────────────────────────────────

export function extractRiskContext(code: string, line: number | null): RiskContext {
  // For line-specific analysis, examine a window around the line
  const lines     = code.split('\n');
  const windowStart = Math.max(0, (line ?? 0) - 20);
  const windowEnd   = Math.min(lines.length, (line ?? lines.length) + 20);
  const window    = lines.slice(windowStart, windowEnd).join('\n');

  // Check window first, fall back to whole-file for route-level signals
  const internetReachable = INTERNET_REACHABLE_PATTERNS.some(p => p.test(code));
  const authenticated     = AUTH_GUARD_PATTERNS.some(p => p.test(window) || p.test(code));
  const adminOnly         = ADMIN_ONLY_PATTERNS.some(p => p.test(window) || p.test(code));
  const secretsAccessible = SECRETS_PATTERNS.some(p => p.test(code));
  const cloudCredentials  = CLOUD_CREDENTIAL_PATTERNS.some(p => p.test(code));
  const lateralMovement   = LATERAL_MOVEMENT_PATTERNS.some(p => p.test(window));
  const sensitiveData     = SENSITIVE_DATA_PATTERNS.some(p => p.test(code));
  const productionPath    = !DEV_TEST_PATTERNS.some(p => p.test(code));

  return {
    internetReachable,
    authenticated,
    adminOnly,
    secretsAccessible,
    cloudCredentials,
    lateralMovement,
    sensitiveData,
    productionPath,
  };
}

// ─── BIS calculator ───────────────────────────────────────────────────────────

export function computeBusinessImpact(ctx: RiskContext): number {
  let score = 40; // baseline

  // Positive risk factors (increase impact)
  if (ctx.internetReachable) score += 20;
  if (!ctx.authenticated)    score += 15;
  if (ctx.cloudCredentials)  score += 15;
  if (ctx.secretsAccessible) score += 10;
  if (ctx.lateralMovement)   score += 10;
  if (ctx.sensitiveData)     score += 8;
  if (ctx.productionPath)    score += 5;

  // Negative risk factors (reduce impact)
  if (ctx.authenticated)  score -= 15;
  if (ctx.adminOnly)      score -= 15;
  if (!ctx.productionPath) score -= 20;

  return Math.max(0, Math.min(100, Math.round(score)));
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

function bisToSeverity(bis: number): 'high' | 'medium' | 'low' {
  if (bis >= 65) return 'high';
  if (bis >= 35) return 'medium';
  return 'low';
}

function buildRationale(ctx: RiskContext, bis: number): string {
  const factors: string[] = [];
  if (ctx.internetReachable && !ctx.authenticated) factors.push('unauthenticated internet exposure');
  else if (ctx.internetReachable) factors.push('internet-reachable');
  if (ctx.cloudCredentials) factors.push('cloud credentials on path');
  if (ctx.secretsAccessible) factors.push('secrets accessible');
  if (ctx.lateralMovement) factors.push('lateral movement possible');
  if (ctx.sensitiveData) factors.push('PII/sensitive data');
  if (ctx.adminOnly) factors.push('admin-only route (reduced exposure)');
  if (!ctx.productionPath) factors.push('non-production code');
  return factors.length > 0
    ? `BIS ${bis}: ${factors.join(', ')}`
    : `BIS ${bis}: standard exposure`;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

export interface IssueMinimal {
  severity: 'high' | 'medium' | 'low';
  line:     number | null;
  title:    string;
  type:     string;
}

export function applyRiskModel<T extends IssueMinimal>(
  issues:  T[],
  code:    string,
): { issues: Array<T & { riskAdjustment?: RiskAdjustedIssue }>; stats: RiskModelStats } {
  let downgraded = 0, upgraded = 0, unchanged = 0, fakeCriticals = 0;
  let totalBis = 0;

  const adjusted = issues.map(issue => {
    // Only model security-class issues
    if (issue.type === 'suggestion') {
      unchanged++;
      return issue as T & { riskAdjustment?: RiskAdjustedIssue };
    }

    const ctx = extractRiskContext(code, issue.line);
    const bis = computeBusinessImpact(ctx);
    totalBis += bis;
    const adjustedSeverity = bisToSeverity(bis);

    const wasHigh   = issue.severity === 'high';
    const nowLower  = wasHigh && adjustedSeverity !== 'high';
    const wasLow    = issue.severity === 'low';
    const nowHigher = wasLow && adjustedSeverity !== 'low';

    if (nowLower) { downgraded++; if (wasHigh) fakeCriticals++; }
    else if (nowHigher) { upgraded++; }
    else { unchanged++; }

    const riskAdjustment: RiskAdjustedIssue = {
      originalSeverity: issue.severity,
      adjustedSeverity,
      businessImpact:   bis,
      impactRationale:  buildRationale(ctx, bis),
      downgraded:       nowLower,
      upgraded:         nowHigher,
      context:          ctx,
    };

    return {
      ...issue,
      severity:        adjustedSeverity,
      riskAdjustment,
    };
  });

  return {
    issues: adjusted,
    stats: {
      totalInput:    issues.length,
      downgraded,
      upgraded,
      unchanged,
      avgBisScore:   issues.length > 0 ? Math.round(totalBis / issues.length) : 0,
      fakeCriticals,
    },
  };
}
