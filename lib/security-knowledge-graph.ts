// ─────────────────────────────────────────────────────────────────────────────
// SECURITY KNOWLEDGE GRAPH v1
//
// Priority 9 from v13 roadmap.
//
// Provides real-world exploit intelligence so AI reasons with historical
// security knowledge rather than isolated logic.
//
// Includes:
//   • CVE mapping (known CVEs by pattern)
//   • CWE mapping (weakness enumeration)
//   • Sanitizer bypass database
//   • Framework exploit database
//   • Historical exploit chains
//   • Known dangerous patterns with CVSS scores
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from '@/app/api/review/route';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface CweEntry {
  id:          string;   // e.g. "CWE-89"
  name:        string;
  description: string;
  severity:    'critical' | 'high' | 'medium' | 'low';
}

export interface CveEntry {
  id:          string;   // e.g. "CVE-2021-44228"
  cwe:         string;
  cvss:        number;
  description: string;
  pattern:     RegExp;   // code pattern that matches this CVE class
  framework?:  string;
}

export interface SanitizerBypass {
  sanitizer:   string;
  bypassPayload: string;
  description: string;
  cwe:         string;
}

export interface FrameworkExploit {
  framework:   string;
  pattern:     RegExp;
  title:       string;
  description: string;
  cwe:         string;
  cvss:        number;
  reference:   string;
}

export interface KnowledgeMatch {
  issue:       Issue;
  cwe?:        CweEntry;
  cves:        CveEntry[];
  exploits:    FrameworkExploit[];
  bypasses:    SanitizerBypass[];
  enriched:    Issue;   // issue with CVE/CWE annotations
}

export interface KnowledgeGraphReport {
  matches:     KnowledgeMatch[];
  stats: {
    total:       number;
    cweMatched:  number;
    cveMatched:  number;
    exploitMatched: number;
    avgCvss:     number;
  };
}

// ── CWE database (subset of most common web vulns) ────────────────────────────

const CWE_DB: CweEntry[] = [
  { id: 'CWE-89',  name: 'SQL Injection',                   description: 'Improper neutralization of special elements in SQL commands.',           severity: 'critical' },
  { id: 'CWE-79',  name: 'Cross-site Scripting (XSS)',       description: 'Improper neutralization of input during web page generation.',           severity: 'high'     },
  { id: 'CWE-78',  name: 'OS Command Injection',             description: 'Improper neutralization of special elements in OS commands.',            severity: 'critical' },
  { id: 'CWE-88',  name: 'Argument Injection or Modification',description: 'Improper neutralization of argument delimiters in command invocation.',   severity: 'medium'   },
  { id: 'CWE-22',  name: 'Path Traversal',                   description: 'Improper limitation of a pathname to a restricted directory.',           severity: 'high'     },
  { id: 'CWE-918', name: 'SSRF',                             description: 'Server-Side Request Forgery allows forging internal requests.',          severity: 'high'     },
  { id: 'CWE-502', name: 'Deserialization of Untrusted Data',description: 'Deserializing untrusted data without validation.',                      severity: 'critical' },
  { id: 'CWE-1321',name: 'Prototype Pollution',              description: 'Improperly controlled modification of Object prototype attributes.',      severity: 'high'     },
  { id: 'CWE-601', name: 'Open Redirect',                    description: 'URL redirection to untrusted site.',                                    severity: 'medium'   },
  { id: 'CWE-400', name: 'ReDoS',                            description: 'Uncontrolled resource consumption via malicious regex input.',           severity: 'medium'   },
  { id: 'CWE-287', name: 'Improper Authentication',          description: 'Authentication not properly implemented or bypassable.',                 severity: 'critical' },
  { id: 'CWE-862', name: 'Missing Authorization',            description: 'Missing or insufficient authorization check.',                          severity: 'high'     },
  { id: 'CWE-798', name: 'Hard-coded Credentials',           description: 'Credentials hard-coded in source code.',                                severity: 'critical' },
  { id: 'CWE-327', name: 'Broken Crypto',                    description: 'Use of broken or risky cryptographic algorithm.',                       severity: 'high'     },
  { id: 'CWE-916', name: 'Weak Password Hashing',            description: 'Password stored without sufficient computational effort.',               severity: 'high'     },
  { id: 'CWE-312', name: 'Cleartext Storage of Credentials', description: 'Sensitive data stored in cleartext.',                                   severity: 'high'     },
  { id: 'CWE-352', name: 'CSRF',                             description: 'Cross-site request forgery via lack of CSRF token.',                    severity: 'medium'   },
  { id: 'CWE-476', name: 'Null Dereference',                 description: 'Null pointer or undefined property access.',                            severity: 'medium'   },
  { id: 'CWE-770', name: 'Resource Exhaustion',              description: 'Allocation of resources without limits.',                               severity: 'medium'   },
];

// ── CVE database (representative recent high-impact ones) ─────────────────────

const CVE_DB: CveEntry[] = [
  {
    id: 'CVE-2021-44228', cwe: 'CWE-917', cvss: 10.0,
    description: 'Log4Shell: JNDI injection via user-controlled log input.',
    pattern: /log(?:ger)?\.(info|warn|error|debug)\s*\(\s*[^'"]/,
    framework: 'log4j',
  },
  {
    id: 'CVE-2021-21315', cwe: 'CWE-78', cvss: 7.8,
    description: 'systeminformation OS command injection via user-controlled input.',
    pattern: /systeminformation|si\.(cpu|mem|disk|os)\s*\(/,
    framework: 'systeminformation',
  },
  {
    id: 'CVE-2022-23812', cwe: 'CWE-1321', cvss: 9.8,
    description: 'node-ipc malicious package with prototype pollution.',
    pattern: /require\s*\(\s*['"]node-ipc['"]\s*\)/,
    framework: 'node-ipc',
  },
  {
    id: 'CVE-2020-7699', cwe: 'CWE-1321', cvss: 7.5,
    description: 'express-fileupload prototype pollution via file upload.',
    pattern: /express-fileupload|req\.files\s*\.\s*\w+\s*\.mv/,
    framework: 'express-fileupload',
  },
  {
    id: 'CVE-2022-24434', cwe: 'CWE-400', cvss: 7.5,
    description: 'dicer ReDoS via multipart headers.',
    pattern: /multipart|busboy|formidable|multer/,
    framework: 'multipart',
  },
  {
    id: 'CVE-2021-3918', cwe: 'CWE-1321', cvss: 9.8,
    description: 'json-schema prototype pollution in older versions.',
    pattern: /require\s*\(\s*['"]json-schema['"]\s*\)/,
    framework: 'json-schema',
  },
  {
    id: 'CVE-2022-25878', cwe: 'CWE-1321', cvss: 7.5,
    description: 'protobufjs prototype pollution.',
    pattern: /require\s*\(\s*['"]protobufjs['"]\s*\)/,
    framework: 'protobufjs',
  },
  {
    id: 'CVE-2017-16138', cwe: 'CWE-22', cvss: 7.5,
    description: 'mime path traversal via crafted MIME type lookup.',
    pattern: /require\s*\(\s*['"]mime['"]\s*\)|mime\.lookup\s*\(/,
    framework: 'mime',
  },
];

// ── Sanitizer bypass database ─────────────────────────────────────────────────

const SANITIZER_BYPASS_DB: SanitizerBypass[] = [
  {
    sanitizer:    'encodeURIComponent',
    bypassPayload: 'javascript:alert(1)',
    description:  'encodeURIComponent does not prevent javascript: protocol URIs in href attributes.',
    cwe:          'CWE-79',
  },
  {
    sanitizer:    'String.replace (single occurrence)',
    bypassPayload: '<scr<script>ipt>alert(1)</script>',
    description:  '.replace() without /g flag only replaces first occurrence — attacker nests payload.',
    cwe:          'CWE-79',
  },
  {
    sanitizer:    'allowlist hostname check via includes()',
    bypassPayload: 'https://evil.com?host=trusted.com',
    description:  'includes() matches anywhere in the URL — use startsWith() + exact hostname comparison.',
    cwe:          'CWE-918',
  },
  {
    sanitizer:    'parseInt()',
    bypassPayload: '1e2 (scientific notation)',
    description:  'parseInt("1e2") returns 1, not 100 — use Number() and isInteger() together.',
    cwe:          'CWE-20',
  },
  {
    sanitizer:    'path.normalize()',
    bypassPayload: '%2e%2e%2fpasswd (URL-encoded traversal)',
    description:  'path.normalize() does not decode URL-encoded characters — decode first.',
    cwe:          'CWE-22',
  },
];

// ── Framework exploit database ────────────────────────────────────────────────

const FRAMEWORK_EXPLOIT_DB: FrameworkExploit[] = [
  {
    framework: 'next.js',
    pattern:   /getServerSideProps|getStaticProps|searchParams|params\s*:\s*\{/,
    title:     'Next.js Server-Side Props Injection',
    description: 'User-controlled searchParams or route params passed unsanitized to server-side logic.',
    cwe:       'CWE-20',
    cvss:      7.5,
    reference: 'https://nextjs.org/docs/pages/building-your-application/data-fetching/get-server-side-props',
  },
  {
    framework: 'express',
    pattern:   /app\.use\s*\(.*\)\s*app\.(get|post|put)/,
    title:     'Express Middleware Order Vulnerability',
    description: 'Route registered before authentication middleware — requests may bypass auth.',
    cwe:       'CWE-862',
    cvss:      8.1,
    reference: 'https://expressjs.com/en/guide/using-middleware.html',
  },
  {
    framework: 'prisma',
    pattern:   /prisma\.\$queryRaw\s*\`[^`]*\$\{|prisma\.\$executeRaw\s*\`[^`]*\$\{/,
    title:     'Prisma Raw Query Injection',
    description: 'Prisma $queryRaw with template literals is injection-safe, but $queryRawUnsafe is not.',
    cwe:       'CWE-89',
    cvss:      9.1,
    reference: 'https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access',
  },
  {
    framework: 'jsonwebtoken',
    pattern:   /jwt\.verify\s*\([^,)]+,\s*(?:secret|key|process\.env)/,
    title:     'JWT Algorithm Confusion',
    description: 'jwt.verify() without explicit algorithms option allows HS256/RS256 confusion attacks.',
    cwe:       'CWE-327',
    cvss:      7.5,
    reference: 'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
  },
  {
    framework: 'mongoose',
    pattern:   /\.find\s*\(\s*\{[^}]*\$where|\$regex[^}]*\}/,
    title:     'MongoDB Operator Injection',
    description: 'User-controlled keys can inject MongoDB query operators ($where, $regex) for auth bypass.',
    cwe:       'CWE-89',
    cvss:      8.1,
    reference: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection',
  },
];

// ── Matching logic ────────────────────────────────────────────────────────────

function matchCwe(issue: Issue): CweEntry | undefined {
  const ttl = (issue.title    ?? '').toLowerCase();
  const cat = (issue.category ?? '').toLowerCase();
  const expl = (issue.explanation ?? '').toLowerCase();
  const combined = `${ttl} ${cat} ${expl.replace(/^\[cwe-\d+:[^\]]+\]\s*/i, '')}`;

  const issueCwe = (issue as Issue & { cwe?: string }).cwe?.toUpperCase();
  if (issueCwe) return CWE_DB.find(c => c.id === issueCwe);

  const explicit = (issue.title + ' ' + issue.explanation).match(/\bCWE-\d+\b/i)?.[0]?.toUpperCase();
  if (explicit) return CWE_DB.find(c => c.id === explicit);

  if (/command|os command|rce|exec|shell/i.test(combined)) return CWE_DB.find(c => c.id === 'CWE-78');
  if (/sql|sqli|sql injection/i.test(combined))       return CWE_DB.find(c => c.id === 'CWE-89');
  if (/xss|cross.site.script/i.test(combined)) return CWE_DB.find(c => c.id === 'CWE-79');
  if (/path|traversal/i.test(combined))   return CWE_DB.find(c => c.id === 'CWE-22');
  if (/ssrf/i.test(combined))             return CWE_DB.find(c => c.id === 'CWE-918');
  if (/deserializ/i.test(combined))       return CWE_DB.find(c => c.id === 'CWE-502');
  if (/proto.pollu/i.test(combined))      return CWE_DB.find(c => c.id === 'CWE-1321');
  if (/redirect/i.test(combined))         return CWE_DB.find(c => c.id === 'CWE-601');
  if (/redos|regex/i.test(combined))      return CWE_DB.find(c => c.id === 'CWE-400');
  if (/auth.bypass|broken.auth/i.test(combined)) return CWE_DB.find(c => c.id === 'CWE-287');
  if (/missing.auth|unauthorized/i.test(combined)) return CWE_DB.find(c => c.id === 'CWE-862');
  if (/hardcoded|hard.coded/i.test(combined)) return CWE_DB.find(c => c.id === 'CWE-798');
  if (/crypto|cipher|md5|sha1/i.test(combined)) return CWE_DB.find(c => c.id === 'CWE-327');
  if (/password.hash|bcrypt/i.test(combined)) return CWE_DB.find(c => c.id === 'CWE-916');
  if (/csrf/i.test(combined))             return CWE_DB.find(c => c.id === 'CWE-352');
  return undefined;
}

function matchCves(code: string): CveEntry[] {
  return CVE_DB.filter(cve => cve.pattern.test(code));
}

function matchFrameworkExploits(code: string): FrameworkExploit[] {
  return FRAMEWORK_EXPLOIT_DB.filter(fe => fe.pattern.test(code));
}

function matchSanitizerBypasses(code: string, issue: Issue): SanitizerBypass[] {
  const bypasses: SanitizerBypass[] = [];

  if (/encodeURIComponent/.test(code) && /href|src|url/i.test(code)) {
    bypasses.push(SANITIZER_BYPASS_DB[0]);
  }
  if (/\.replace\s*\([^g)]*\)/.test(code) && !/\.replace\s*\([^)]*\/g/.test(code) && /xss|html/i.test(issue.category ?? '')) {
    bypasses.push(SANITIZER_BYPASS_DB[1]);
  }
  if (/\.includes\s*\(/.test(code) && /ssrf|redirect/i.test(issue.category ?? '')) {
    bypasses.push(SANITIZER_BYPASS_DB[2]);
  }
  if (/path\.normalize/.test(code) && /path|traversal/i.test(issue.category ?? '')) {
    bypasses.push(SANITIZER_BYPASS_DB[4]);
  }

  return bypasses;
}

// ── Enrich issue with knowledge ───────────────────────────────────────────────

function enrichIssue(issue: Issue, cwe: CweEntry | undefined, cves: CveEntry[], exploits: FrameworkExploit[]): Issue {
  const enriched = { ...issue };

  if (cwe) {
    enriched.explanation = `[${cwe.id}: ${cwe.name}] ${enriched.explanation.replace(/^\[CWE-\d+:[^\]]+\]\s*/i, '')}`;
  }

  if (cves.length > 0) {
    const cveList = cves.map(c => `${c.id} (CVSS ${c.cvss})`).join(', ');
    enriched.explanation += `\n\n🔍 Related CVEs: ${cveList}`;
  }

  if (exploits.length > 0) {
    const expList = exploits.map(e => `${e.title} (CVSS ${e.cvss}, ${e.cwe})`).join('; ');
    enriched.explanation += `\n\n⚠️ Known framework exploits: ${expList}`;
  }

  // Upgrade severity if CVEs are critical (CVSS ≥ 9.0)
  const maxCvss = cves.reduce((max, c) => Math.max(max, c.cvss), 0);
  if (maxCvss >= 9.0 && enriched.severity !== 'high') {
    enriched.severity = 'high';
  }

  return enriched;
}

// ── Main export ───────────────────────────────────────────────────────────────

export function applySecurityKnowledgeGraph(
  issues: Issue[],
  code: string,
): KnowledgeGraphReport {
  const codeCves    = matchCves(code);
  const codeExploits = matchFrameworkExploits(code);

  const matches: KnowledgeMatch[] = issues.map(issue => {
    const cwe      = matchCwe(issue);
    const cves     = codeCves;   // all CVEs apply to the file-level context
    const exploits = codeExploits;
    const bypasses = matchSanitizerBypasses(code, issue);
    const enriched = enrichIssue(issue, cwe, cves, exploits);

    return { issue, cwe, cves, exploits, bypasses, enriched };
  });

  const cvssScores = matches.flatMap(m => m.cves.map(c => c.cvss));
  const avgCvss    = cvssScores.length > 0 ? cvssScores.reduce((a, b) => a + b, 0) / cvssScores.length : 0;

  return {
    matches,
    stats: {
      total:          matches.length,
      cweMatched:     matches.filter(m => m.cwe !== undefined).length,
      cveMatched:     matches.filter(m => m.cves.length > 0).length,
      exploitMatched: matches.filter(m => m.exploits.length > 0).length,
      avgCvss:        Math.round(avgCvss * 10) / 10,
    },
  };
}

export function knowledgeGraphToIssues(report: KnowledgeGraphReport): Issue[] {
  return report.matches.map(m => m.enriched);
}

export function getKnowledgeGraphContext(code: string): string {
  const cves     = matchCves(code);
  const exploits = matchFrameworkExploits(code);
  if (cves.length === 0 && exploits.length === 0) return '';

  const lines: string[] = ['## Security Knowledge Context'];
  if (cves.length > 0) {
    lines.push('Known CVEs matching code patterns:');
    cves.forEach(c => lines.push(`  - ${c.id} (CVSS ${c.cvss}): ${c.description}`));
  }
  if (exploits.length > 0) {
    lines.push('Known framework exploits:');
    exploits.forEach(e => lines.push(`  - [${e.cwe}] ${e.title}: ${e.description}`));
  }
  return lines.join('\n');
}
