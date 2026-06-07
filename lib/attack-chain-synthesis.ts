// ─────────────────────────────────────────────────────────────────────────────
// ATTACK CHAIN SYNTHESIS ENGINE v7
//
// Synthesizes multi-step attack chains from isolated findings:
//   SSRF → metadata endpoint → AWS creds → admin API → RCE
//
// Architecture:
//   • Graph traversal over findings (edges = exploitability links)
//   • Exploit preconditions — what each vuln class requires + enables
//   • Privilege escalation modeling — maps from access level gained
//   • Chain scoring — chains scored by combined severity × probability
//
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ── Attack primitives (what each vuln class provides/requires) ────────────────
interface AttackPrimitive {
  family:       string[];   // matches classifyFamily() output
  provides:     string[];   // capabilities gained after exploitation
  requires:     string[];   // prerequisites for exploitation (empty = no prereq)
  chainLabel:   string;     // human-readable step label
  chainImpact:  string;     // what attacker gains
}

const ATTACK_PRIMITIVES: AttackPrimitive[] = [
  {
    family:      ['xss'],
    provides:    ['session-token', 'cookie-access', 'dom-control', 'credential-theft'],
    requires:    [],
    chainLabel:  'XSS → Session Hijack',
    chainImpact: 'Attacker steals session cookies / auth tokens → account takeover',
  },
  {
    family:      ['sql-injection'],
    provides:    ['db-read', 'db-write', 'credential-dump', 'auth-bypass', 'data-exfil'],
    requires:    [],
    chainLabel:  'SQLi → Database Access',
    chainImpact: 'Full database read/write → credential dump → lateral movement',
  },
  {
    family:      ['ssrf'],
    provides:    ['internal-network-access', 'cloud-metadata-access', 'credential-theft', 'internal-service-rce'],
    requires:    [],
    chainLabel:  'SSRF → Internal Network',
    chainImpact: 'Server makes requests to internal IPs → cloud metadata → IAM credentials',
  },
  {
    family:      ['command-injection'],
    provides:    ['rce', 'file-system-access', 'network-pivot', 'persistence'],
    requires:    [],
    chainLabel:  'Command Injection → RCE',
    chainImpact: 'Arbitrary OS command execution → full server compromise',
  },
  {
    family:      ['path-traversal'],
    provides:    ['file-read', 'source-code-disclosure', 'credential-file-access'],
    requires:    [],
    chainLabel:  'Path Traversal → File Read',
    chainImpact: 'Arbitrary file reads → /etc/passwd, .env files, private keys',
  },
  {
    family:      ['jwt-bypass'],
    provides:    ['auth-bypass', 'privilege-escalation', 'admin-access'],
    requires:    [],
    chainLabel:  'JWT Bypass → Admin Access',
    chainImpact: 'Forged JWT with admin role → full application privilege escalation',
  },
  {
    family:      ['prototype-pollution'],
    provides:    ['property-injection', 'auth-bypass', 'rce'],
    requires:    [],
    chainLabel:  'Prototype Pollution → Auth Bypass',
    chainImpact: '__proto__.isAdmin = true → bypass authorization checks → privilege escalation',
  },
  {
    family:      ['open-redirect'],
    provides:    ['phishing-vector', 'token-theft', 'oauth-hijack'],
    requires:    [],
    chainLabel:  'Open Redirect → Token Theft',
    chainImpact: 'User redirected to attacker site → OAuth tokens / session cookies stolen',
  },
  {
    family:      ['header-injection'],
    provides:    ['cache-poisoning', 'response-splitting', 'session-fixation'],
    requires:    [],
    chainLabel:  'Header Injection → Cache Poisoning',
    chainImpact: 'Injected CRLF → HTTP response splitting → cache poisoning → mass XSS',
  },
  {
    family:      ['hardcoded-secret'],
    provides:    ['credential-theft', 'api-access', 'cloud-access', 'third-party-access'],
    requires:    [],
    chainLabel:  'Hardcoded Secret → API Compromise',
    chainImpact: 'Leaked API key → full access to third-party service / cloud account',
  },
  {
    family:      ['auth-bypass'],
    provides:    ['admin-access', 'data-access', 'privilege-escalation'],
    requires:    [],
    chainLabel:  'Auth Bypass → Unauthorized Access',
    chainImpact: 'Authentication bypassed → access to protected resources',
  },
];

// ── Escalation chains (what combinations of capabilities enable) ─────────────
const ESCALATION_CHAINS: Array<{
  requires:  string[];
  enables:   string;
  label:     string;
  severity:  'critical' | 'high';
}> = [
  {
    requires: ['internal-network-access', 'cloud-metadata-access'],
    enables:  'IAM credential theft via AWS metadata service',
    label:    'SSRF → AWS Metadata → IAM Creds',
    severity: 'critical',
  },
  {
    requires: ['IAM credential theft via AWS metadata service'],
    enables:  'Full AWS account takeover via stolen IAM credentials',
    label:    '→ AWS Account Takeover',
    severity: 'critical',
  },
  {
    requires: ['credential-dump', 'auth-bypass'],
    enables:  'Full authentication bypass with leaked credentials',
    label:    'SQLi → Cred Dump → Admin Takeover',
    severity: 'critical',
  },
  {
    requires: ['session-token', 'admin-access'],
    enables:  'Admin account takeover via stolen session + privilege escalation',
    label:    'XSS + Auth Bypass → Admin Takeover',
    severity: 'critical',
  },
  {
    requires: ['file-read', 'credential-file-access'],
    enables:  'Secret exfiltration via arbitrary file reads (.env, private keys)',
    label:    'Path Traversal → .env Secrets → API Takeover',
    severity: 'critical',
  },
  {
    requires: ['rce', 'network-pivot'],
    enables:  'Full infrastructure compromise via RCE + lateral movement',
    label:    'RCE → Network Pivot → Lateral Movement',
    severity: 'critical',
  },
  {
    requires: ['credential-theft', 'api-access'],
    enables:  'Third-party service compromise via stolen API keys',
    label:    'Hardcoded Key → Service Takeover',
    severity: 'high',
  },
  {
    requires: ['property-injection', 'auth-bypass'],
    enables:  'Privilege escalation via prototype pollution + auth logic bypass',
    label:    'Prototype Pollution → Admin Escalation',
    severity: 'critical',
  },
];

// ── Result types ─────────────────────────────────────────────────────────────
export interface AttackChainStep {
  finding:    Issue;
  primitive:  AttackPrimitive;
  stepLabel:  string;
  capabilities: string[];
}

export interface SynthesizedChain {
  id:           string;
  title:        string;
  steps:        AttackChainStep[];
  escalations:  string[];
  severity:     'critical' | 'high';
  description:  string;
  likelihood:   number;   // 0–100
  impact:       string;
  chainLength:  number;
}

export interface ChainSynthesisResult {
  chains:       SynthesizedChain[];
  isolated:     Issue[];            // findings that didn't participate in any chain
  chainCount:   number;
  maxSeverity:  'critical' | 'high' | 'none';
}

// ── Main chain synthesis ─────────────────────────────────────────────────────
export function synthesizeAttackChains(issues: Issue[]): ChainSynthesisResult {
  const chains: SynthesizedChain[] = [];
  const participatingIssues = new Set<string>();

  // Map each issue to its attack primitives
  const issueWithPrimitives = issues.map(issue => {
    const text = `${issue.title} ${issue.explanation} ${issue.category}`.toLowerCase();
    const primitives = ATTACK_PRIMITIVES.filter(p =>
      p.family.some(f => text.includes(f.replace(/-/g, ' ')) || text.includes(f))
    );
    return { issue, primitives };
  });

  // Collect all capabilities across all findings
  const allCapabilities = new Set<string>();
  for (const { primitives } of issueWithPrimitives) {
    for (const p of primitives) {
      for (const cap of p.provides) allCapabilities.add(cap);
    }
  }

  // Check escalation chains — which are achievable with current capabilities?
  const achievableEscalations: string[] = [];
  for (const esc of ESCALATION_CHAINS) {
    if (esc.requires.every(req => allCapabilities.has(req) || achievableEscalations.includes(req))) {
      achievableEscalations.push(esc.enables);
    }
  }

  // Build multi-step chains by finding compatible issue pairs/triples
  const chainCandidates: SynthesizedChain[] = [];

  // Single-issue significant chains
  for (const { issue, primitives } of issueWithPrimitives) {
    for (const prim of primitives) {
      if (prim.provides.includes('rce') || prim.provides.includes('admin-access') || prim.provides.includes('credential-dump')) {
        const chain = buildSingleStepChain(issue, prim, achievableEscalations);
        if (chain) chainCandidates.push(chain);
      }
    }
  }

  // Multi-issue chains (2-step)
  for (let i = 0; i < issueWithPrimitives.length; i++) {
    const a = issueWithPrimitives[i];
    for (let j = i + 1; j < issueWithPrimitives.length; j++) {
      const b = issueWithPrimitives[j];
      const chain = buildTwoStepChain(a, b, achievableEscalations);
      if (chain) chainCandidates.push(chain);
    }
  }

  // Deduplicate and keep best chains
  const seen = new Set<string>();
  for (const chain of chainCandidates) {
    if (!seen.has(chain.title)) {
      seen.add(chain.title);
      chains.push(chain);
      for (const step of chain.steps) {
        participatingIssues.add(step.finding.title);
      }
    }
  }

  // Sort by severity + length
  chains.sort((a, b) => {
    if (a.severity === 'critical' && b.severity !== 'critical') return -1;
    if (b.severity === 'critical' && a.severity !== 'critical') return 1;
    return b.chainLength - a.chainLength;
  });

  const isolated = issues.filter(i => !participatingIssues.has(i.title));
  const maxSeverity: ChainSynthesisResult['maxSeverity'] =
    chains.some(c => c.severity === 'critical') ? 'critical' :
    chains.length > 0 ? 'high' : 'none';

  return {
    chains:      chains.slice(0, 5), // top 5 chains
    isolated,
    chainCount:  chains.length,
    maxSeverity,
  };
}

function buildSingleStepChain(
  issue: Issue,
  prim: AttackPrimitive,
  escalations: string[],
): SynthesizedChain | null {
  const relevantEsc = escalations.filter(e =>
    prim.provides.some(cap => e.toLowerCase().includes(cap.replace(/-/g, ' ')))
  );

  if (!relevantEsc.length && !prim.provides.includes('rce')) return null;

  return {
    id:          `chain-${issue.line}-${prim.family[0]}`,
    title:       prim.chainLabel,
    steps:       [{ finding: issue, primitive: prim, stepLabel: prim.chainLabel, capabilities: prim.provides }],
    escalations: relevantEsc,
    severity:    prim.provides.includes('rce') || relevantEsc.some(e => e.includes('takeover')) ? 'critical' : 'high',
    description: prim.chainImpact,
    likelihood:  Math.round((issue.confidence ?? 0.7) * (issue.exploitability ?? 70)),
    impact:      relevantEsc[0] ?? prim.chainImpact,
    chainLength: 1,
  };
}

function buildTwoStepChain(
  a: { issue: Issue; primitives: AttackPrimitive[] },
  b: { issue: Issue; primitives: AttackPrimitive[] },
  escalations: string[],
): SynthesizedChain | null {
  for (const pa of a.primitives) {
    for (const pb of b.primitives) {
      // Check if A's output feeds B's requirements
      const aProvides = new Set(pa.provides);
      const bRequires = pb.requires;

      if (bRequires.length > 0 && bRequires.some(req => aProvides.has(req))) {
        const combinedCaps = [...pa.provides, ...pb.provides];
        const relevantEsc = escalations.filter(e =>
          combinedCaps.some(cap => e.toLowerCase().includes(cap.replace(/-/g, ' ')))
        );

        return {
          id:          `chain-${a.issue.line}-${b.issue.line}`,
          title:       `${pa.chainLabel} → ${pb.chainLabel}`,
          steps: [
            { finding: a.issue, primitive: pa, stepLabel: pa.chainLabel, capabilities: pa.provides },
            { finding: b.issue, primitive: pb, stepLabel: pb.chainLabel, capabilities: pb.provides },
          ],
          escalations: relevantEsc,
          severity:    'critical',
          description: `${pa.chainImpact} → enables ${pb.chainImpact}`,
          likelihood:  Math.round(
            ((a.issue.confidence ?? 0.7) + (b.issue.confidence ?? 0.7)) / 2 * 70
          ),
          impact:      relevantEsc[0] ?? `${pa.chainImpact} → ${pb.chainImpact}`,
          chainLength: 2,
        };
      }
    }
  }
  return null;
}
