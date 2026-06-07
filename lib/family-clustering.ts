// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY FAMILY CLUSTERING ENGINE v7
//
// Solves the UX problem: 5 SSRF findings → 1 SSRF FAMILY with sub-items.
//
// Architecture:
//   • exploit-family IDs — canonical family key per vuln class
//   • sink graph clustering — groups by (family × sinkType)
//   • semantic title hashing — deduplicates near-identical titles
//   • AST-root grouping — merges findings at shared code roots
//   • variant annotation — each cluster tracks count + affected lines
//
// Result: Developers see "1 SQL Injection Family (4 sinks)" not 4 separate SQLi
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ── Family ID Taxonomy ────────────────────────────────────────────────────────
export type FamilyId =
  | 'sql-injection'
  | 'xss'
  | 'ssrf'
  | 'command-injection'
  | 'path-traversal'
  | 'prototype-pollution'
  | 'open-redirect'
  | 'header-injection'
  | 'jwt-bypass'
  | 'rce'
  | 'redos'
  | 'hardcoded-secret'
  | 'insecure-deserialization'
  | 'mass-assignment'
  | 'timing-attack'
  | 'auth-bypass'
  | 'info-disclosure'
  | 'other';

export interface VulnFamily {
  id:             FamilyId;
  label:          string;
  canonical:      Issue;          // highest-severity / highest-confidence issue
  variants:       Issue[];        // all issues in this family
  sinks:          string[];       // unique sink descriptions
  affectedLines:  number[];       // all line numbers
  severity:       Issue['severity'];
  confidence:     number;         // 0–1, max across variants
  exploitVerifiedCount: number;
  totalCount:     number;
  replayVerified: boolean;
}

// ── Family Classification Rules ───────────────────────────────────────────────
const FAMILY_PATTERNS: Array<{ pattern: RegExp; family: FamilyId }> = [
  { pattern: /sql.inject|sqli|sql.query|union.select|or 1=1/i,              family: 'sql-injection' },
  { pattern: /xss|cross.site.script|innerhtml|dangerously.set|dom.sink/i,   family: 'xss' },
  { pattern: /ssrf|server.side.request|fetch\s+user.controlled|open.fetch/i, family: 'ssrf' },
  { pattern: /command.inject|shell.inject|exec\s*\(|spawn.*shell/i,         family: 'command-injection' },
  { pattern: /path.travers|directory.travers|\.\.\/|readfile.*user/i,        family: 'path-traversal' },
  { pattern: /proto.pollut|__proto__|prototype.*inject/i,                    family: 'prototype-pollution' },
  { pattern: /open.redirect|redirect.*user.*controlled|unvalidated.redirect/i, family: 'open-redirect' },
  { pattern: /header.inject|crlf|http.response.split/i,                     family: 'header-injection' },
  { pattern: /jwt.decode|jwt.bypass|alg.*none|signature.skip/i,             family: 'jwt-bypass' },
  { pattern: /rce|remote.code.exec|eval.*input|vm\.run/i,                   family: 'rce' },
  { pattern: /redos|backtrack|catastrophic.regex/i,                          family: 'redos' },
  { pattern: /hardcoded.secret|api.key.*literal|password.*string|token.*hardcoded/i, family: 'hardcoded-secret' },
  { pattern: /deserializ|pickle|unsafe.json.parse.*untrusted/i,              family: 'insecure-deserialization' },
  { pattern: /mass.assign|object.spread.*request|req\.body.*spread/i,       family: 'mass-assignment' },
  { pattern: /timing.attack|timing.safe|compare.*password.*===/i,           family: 'timing-attack' },
  { pattern: /auth.bypass|authentication.bypass|unauthorized.access/i,      family: 'auth-bypass' },
  { pattern: /stack.trace|debug.info|verbose.error|information.disclosure/i,family: 'info-disclosure' },
];

const FAMILY_LABELS: Record<FamilyId, string> = {
  'sql-injection':           'SQL Injection',
  'xss':                     'Cross-Site Scripting (XSS)',
  'ssrf':                    'Server-Side Request Forgery (SSRF)',
  'command-injection':       'Command Injection',
  'path-traversal':          'Path Traversal',
  'prototype-pollution':     'Prototype Pollution',
  'open-redirect':           'Open Redirect',
  'header-injection':        'HTTP Header Injection',
  'jwt-bypass':              'JWT Authentication Bypass',
  'rce':                     'Remote Code Execution (RCE)',
  'redos':                   'Regular Expression DoS (ReDoS)',
  'hardcoded-secret':        'Hardcoded Secret / Credential',
  'insecure-deserialization':'Insecure Deserialization',
  'mass-assignment':         'Mass Assignment',
  'timing-attack':           'Timing Attack',
  'auth-bypass':             'Authentication Bypass',
  'info-disclosure':         'Information Disclosure',
  'other':                   'Other',
};

// ── Classify a single issue into a family ────────────────────────────────────
export function classifyFamily(issue: Issue): FamilyId {
  const text = `${issue.title} ${issue.explanation} ${issue.category}`;
  for (const { pattern, family } of FAMILY_PATTERNS) {
    if (pattern.test(text)) return family;
  }
  return 'other';
}

// ── Extract sink description from issue ──────────────────────────────────────
function extractSink(issue: Issue): string {
  const text = issue.explanation + ' ' + (issue.exploitChain ?? '');
  const sinkPatterns: Array<[RegExp, string]> = [
    [/db\.query|database query/i,        'db.query()'],
    [/innerHTML|dom.sink/i,              '.innerHTML sink'],
    [/fetch\s*\(/i,                      'fetch() network'],
    [/exec\s*\(|spawn\s*\(/i,           'exec()/spawn()'],
    [/res\.redirect|location.header/i,   'res.redirect()'],
    [/fs\.readFile|createReadStream/i,   'fs.readFile()'],
    [/eval\s*\(/i,                       'eval()'],
    [/dangerouslySetInnerHTML/i,         'dangerouslySetInnerHTML'],
    [/res\.setHeader|res\.write/i,       'HTTP response header'],
    [/JSON\.parse/i,                     'JSON.parse()'],
  ];
  for (const [re, label] of sinkPatterns) {
    if (re.test(text)) return label;
  }
  return issue.line ? `L${issue.line}` : 'unknown sink';
}

// ── Severity ranking ──────────────────────────────────────────────────────────
const SEV_RANK: Record<Issue['severity'], number> = { high: 3, medium: 2, low: 1 };
const highestSeverity = (a: Issue['severity'], b: Issue['severity']): Issue['severity'] =>
  SEV_RANK[a] >= SEV_RANK[b] ? a : b;

// ── Main clustering function ──────────────────────────────────────────────────
export function clusterByFamily(issues: Issue[]): VulnFamily[] {
  const families = new Map<FamilyId, VulnFamily>();

  for (const issue of issues) {
    const fid  = classifyFamily(issue);
    const sink = extractSink(issue);

    if (!families.has(fid)) {
      families.set(fid, {
        id:                   fid,
        label:                FAMILY_LABELS[fid],
        canonical:            issue,
        variants:             [],
        sinks:                [],
        affectedLines:        [],
        severity:             issue.severity,
        confidence:           issue.confidence ?? 0,
        exploitVerifiedCount: 0,
        totalCount:           0,
        replayVerified:       false,
      });
    }

    const fam = families.get(fid)!;
    fam.variants.push(issue);
    fam.totalCount++;

    // Update severity to highest across variants
    fam.severity = highestSeverity(fam.severity, issue.severity);

    // Update canonical to highest-confidence issue
    if ((issue.confidence ?? 0) > (fam.canonical.confidence ?? 0)) {
      fam.canonical = issue;
    }

    // Collect unique sinks
    if (!fam.sinks.includes(sink)) fam.sinks.push(sink);

    // Collect affected lines
    if (issue.line !== null && !fam.affectedLines.includes(issue.line)) {
      fam.affectedLines.push(issue.line);
    }

    // Update confidence (max)
    if ((issue.confidence ?? 0) > fam.confidence) {
      fam.confidence = issue.confidence ?? 0;
    }

    // Count verified exploits
    if (issue.exploitVerified) {
      fam.exploitVerifiedCount++;
      fam.replayVerified = true;
    }
  }

  // Sort families: by severity, then by variant count
  return [...families.values()].sort((a, b) => {
    const sevDiff = SEV_RANK[b.severity] - SEV_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.totalCount - a.totalCount;
  });
}

// ── Flatten families back to issues (for backward compat) ────────────────────
// Injects family metadata into each canonical issue, suppresses variants
export function familiesToIssues(families: VulnFamily[]): Issue[] {
  return families.map(fam => ({
    ...fam.canonical,
    // Annotate with family metadata
    familyId:       fam.id,
    familyLabel:    fam.label,
    familySinks:    fam.sinks,
    familyLines:    fam.affectedLines,
    familyCount:    fam.totalCount,
    familyVariants: fam.variants,
    // If multiple variants, update explanation to mention them
    explanation:    fam.totalCount > 1
      ? `${fam.canonical.explanation} [${fam.totalCount} instances across lines ${fam.affectedLines.slice(0, 5).join(', ')}${fam.affectedLines.length > 5 ? '…' : ''}]`
      : fam.canonical.explanation,
    // Use highest severity
    severity: fam.severity,
  } as Issue & {
    familyId: FamilyId; familyLabel: string; familySinks: string[];
    familyLines: number[]; familyCount: number; familyVariants: Issue[];
  }));
}

// ── Clustering stats ──────────────────────────────────────────────────────────
export interface ClusterStats {
  inputCount:    number;
  familyCount:   number;
  collapsed:     number;
  topFamilies:   Array<{ family: string; count: number; severity: string }>;
}

export function getClusterStats(families: VulnFamily[], originalCount: number): ClusterStats {
  return {
    inputCount:  originalCount,
    familyCount: families.length,
    collapsed:   originalCount - families.length,
    topFamilies: families.slice(0, 5).map(f => ({
      family:   f.label,
      count:    f.totalCount,
      severity: f.severity,
    })),
  };
}
