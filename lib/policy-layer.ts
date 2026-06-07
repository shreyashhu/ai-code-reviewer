// ─────────────────────────────────────────────────────────────────────────────
// RUNTIME POLICY LAYER — v1.4
//
// Organizational controls over what the scanner flags, suppresses, escalates,
// and blocks on. Key concepts:
//
//   PolicyRule  — a single condition + action
//   PolicyPack  — a named set of rules (OWASP, PCI-DSS, SOC2, custom)
//   PolicyEngine — evaluates rules against findings
//
// Supported actions:
//   suppress    — hide the finding from output
//   escalate    — promote severity one level
//   demote      — demote severity one level
//   require-fix — mark finding as must-fix (blocks CI gate)
//   annotate    — attach a compliance note without changing severity
//
// Env variable: POLICY_PACK (comma-separated pack names to activate)
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ─── Types ────────────────────────────────────────────────────────────────────

export type PolicyAction =
  | 'suppress'
  | 'escalate'
  | 'demote'
  | 'require-fix'
  | 'annotate'

export type PolicyCondition = {
  /** Match issue category (substring, case-insensitive) */
  category?:     string;
  /** Match issue title (substring, case-insensitive) */
  titleContains?: string;
  /** Match severity */
  severity?:     'high' | 'medium' | 'low';
  /** Match file path pattern (regex string) */
  pathPattern?:  string;
  /** Match exploit verified flag */
  exploitVerified?: boolean;
  /** Match confidence threshold: suppress if confidence < this */
  confidenceBelow?: number;
}

export interface PolicyRule {
  id:          string;
  name:        string;
  description: string;
  condition:   PolicyCondition;
  action:      PolicyAction;
  /** Text to attach when action='annotate' or for audit log */
  note?:       string;
  /** Which environments this rule applies to */
  environments?: string[];  // 'production' | 'staging' | 'development' | '*'
}

export interface PolicyPack {
  id:    string;
  name:  string;
  rules: PolicyRule[];
}

export interface PolicyResult {
  issue:          Issue;
  appliedRules:   string[];   // rule IDs that matched
  finalAction:    PolicyAction | null;
  complianceNote: string | null;
  blocked:        boolean;    // require-fix in CI gate
}

export interface PolicyStats {
  total:       number;
  suppressed:  number;
  escalated:   number;
  demoted:     number;
  requireFix:  number;
  annotated:   number;
  byPack:      Record<string, number>;
}

// ─── Built-in policy packs ────────────────────────────────────────────────────

const OWASP_TOP10_PACK: PolicyPack = {
  id: 'owasp-top10', name: 'OWASP Top 10',
  rules: [
    {
      id: 'owasp-sqli-require-fix', name: 'OWASP A03 — SQL Injection must fix',
      description: 'SQL injection is OWASP Top 10 A03. Always require fix.',
      condition: { category: 'sql', severity: 'high' },
      action: 'require-fix',
      note: 'OWASP Top 10 A03:2021 — Injection',
    },
    {
      id: 'owasp-xss-require-fix', name: 'OWASP A03 — XSS must fix',
      description: 'XSS is OWASP Top 10 A03. Require fix on high severity.',
      condition: { category: 'xss', severity: 'high' },
      action: 'require-fix',
      note: 'OWASP Top 10 A03:2021 — Injection (XSS)',
    },
    {
      id: 'owasp-idor-escalate', name: 'OWASP A01 — IDOR escalate to high',
      description: 'IDOR/broken access control is OWASP #1. Always escalate.',
      condition: { category: 'idor' },
      action: 'escalate',
      note: 'OWASP Top 10 A01:2021 — Broken Access Control',
    },
  ],
};

const PCI_DSS_PACK: PolicyPack = {
  id: 'pci-dss', name: 'PCI-DSS v4',
  rules: [
    {
      id: 'pci-hardcoded-secrets', name: 'PCI 6.3.3 — Hardcoded credentials must fix',
      description: 'PCI-DSS requires no hardcoded authentication credentials.',
      condition: { category: 'secret', severity: 'high' },
      action: 'require-fix',
      note: 'PCI-DSS v4 Requirement 6.3.3',
    },
    {
      id: 'pci-crypto-escalate', name: 'PCI 4.2 — Weak crypto must escalate',
      description: 'PCI-DSS bans MD5, SHA1, DES for cardholder data.',
      condition: { category: 'crypto' },
      action: 'escalate',
      note: 'PCI-DSS v4 Requirement 4.2.1',
    },
  ],
};

const SOC2_PACK: PolicyPack = {
  id: 'soc2', name: 'SOC 2 Type II',
  rules: [
    {
      id: 'soc2-auth-require-fix', name: 'SOC2 CC6 — Auth bypass must fix',
      description: 'SOC2 CC6 requires logical access controls.',
      condition: { category: 'auth', severity: 'high' },
      action: 'require-fix',
      note: 'SOC2 CC6.1 — Logical and Physical Access Controls',
    },
    {
      id: 'soc2-low-confidence-suppress', name: 'SOC2 — Suppress low-confidence findings',
      description: 'SOC2 audits are harmed by noise; suppress below 40% confidence.',
      condition: { confidenceBelow: 0.40 },
      action: 'suppress',
      note: 'SOC2 audit quality gate',
    },
  ],
};

const STRICT_PACK: PolicyPack = {
  id: 'strict', name: 'Strict (all criticals block)',
  rules: [
    {
      id: 'strict-all-high', name: 'All high severity must fix',
      description: 'Block CI on any high severity finding.',
      condition: { severity: 'high' },
      action: 'require-fix',
    },
    {
      id: 'strict-verified-escalate', name: 'Verified exploits always escalate',
      description: 'Exploit-verified findings are always escalated.',
      condition: { exploitVerified: true },
      action: 'escalate',
    },
  ],
};

const TEST_ENV_PACK: PolicyPack = {
  id: 'test-env', name: 'Test environment suppressions',
  rules: [
    {
      id: 'test-env-suppress-medium', name: 'Suppress medium in test env',
      description: 'Medium findings are expected in test environments.',
      condition: { severity: 'medium' },
      action: 'suppress',
      environments: ['development', 'test'],
      note: 'Test environment policy — not applicable in production',
    },
  ],
};

export const BUILT_IN_PACKS: Record<string, PolicyPack> = {
  'owasp-top10': OWASP_TOP10_PACK,
  'pci-dss':     PCI_DSS_PACK,
  'soc2':        SOC2_PACK,
  'strict':      STRICT_PACK,
  'test-env':    TEST_ENV_PACK,
};

// ─── Active packs (loaded from env or set programmatically) ───────────────────

let _activePacks: PolicyPack[] = [];
let _environment: string = process.env.NODE_ENV ?? 'production';

export function loadPoliciesFromEnv(): void {
  const packNames = (process.env.POLICY_PACK ?? '').split(',').map(s => s.trim()).filter(Boolean);
  _activePacks = packNames.map(name => BUILT_IN_PACKS[name]).filter(Boolean);
  _environment = process.env.DEPLOY_ENV ?? process.env.NODE_ENV ?? 'production';
  if (_activePacks.length > 0) {
    console.log(`[policy] loaded packs: ${_activePacks.map(p => p.name).join(', ')} env=${_environment}`);
  }
}

export function setActivePacks(packs: PolicyPack[]): void {
  _activePacks = packs;
}

export function addCustomRule(rule: PolicyRule): void {
  const customPack = _activePacks.find(p => p.id === 'custom');
  if (customPack) {
    customPack.rules.push(rule);
  } else {
    _activePacks.push({ id: 'custom', name: 'Custom Rules', rules: [rule] });
  }
}

// ─── Condition evaluator ──────────────────────────────────────────────────────

function matchesCondition(issue: Issue, condition: PolicyCondition): boolean {
  if (condition.severity && issue.severity !== condition.severity) return false;
  if (condition.category && !issue.category.toLowerCase().includes(condition.category.toLowerCase())) return false;
  if (condition.titleContains && !issue.title.toLowerCase().includes(condition.titleContains.toLowerCase())) return false;
  if (condition.exploitVerified !== undefined && issue.exploitVerified !== condition.exploitVerified) return false;
  if (condition.confidenceBelow !== undefined) {
    const conf = issue.confidence ?? 1.0;
    if (conf >= condition.confidenceBelow) return false;
  }
  return true;
}

// ─── Policy engine ────────────────────────────────────────────────────────────

export function applyPolicyLayer(
  issues: Issue[],
  packs: PolicyPack[] = _activePacks,
  env: string = _environment,
): { issues: Issue[]; stats: PolicyStats; auditLog: PolicyResult[] } {
  if (packs.length === 0) {
    return {
      issues,
      stats: { total: issues.length, suppressed: 0, escalated: 0, demoted: 0, requireFix: 0, annotated: 0, byPack: {} },
      auditLog: [],
    };
  }

  const auditLog: PolicyResult[] = [];
  const stats: PolicyStats = { total: issues.length, suppressed: 0, escalated: 0, demoted: 0, requireFix: 0, annotated: 0, byPack: {} };
  const activeIssues: Issue[] = [];

  for (const issue of issues) {
    const matchedRules: string[] = [];
    let finalAction: PolicyAction | null = null;
    let complianceNote: string | null = null;

    for (const pack of packs) {
      for (const rule of pack.rules) {
        // Check environment applicability
        if (rule.environments && !rule.environments.includes('*') && !rule.environments.includes(env)) continue;
        if (!matchesCondition(issue, rule.condition)) continue;

        matchedRules.push(rule.id);
        // Higher-priority actions win (require-fix > escalate > suppress > annotate)
        const priority = ['require-fix', 'escalate', 'demote', 'suppress', 'annotate'];
        if (finalAction === null || priority.indexOf(rule.action) < priority.indexOf(finalAction)) {
          finalAction = rule.action;
        }
        if (rule.note) complianceNote = rule.note;
        stats.byPack[pack.id] = (stats.byPack[pack.id] ?? 0) + 1;
      }
    }

    const result: PolicyResult = {
      issue, appliedRules: matchedRules, finalAction, complianceNote,
      blocked: finalAction === 'require-fix',
    };
    auditLog.push(result);

    if (finalAction === 'suppress') {
      stats.suppressed++;
      continue; // drop from output
    }

    // Apply mutations
    const mutated = { ...issue } as Issue & { policyNote?: string; requireFix?: boolean };
    if (finalAction === 'escalate') {
      mutated.severity = mutated.severity === 'low' ? 'medium' : 'high';
      stats.escalated++;
    } else if (finalAction === 'demote') {
      mutated.severity = mutated.severity === 'high' ? 'medium' : 'low';
      stats.demoted++;
    } else if (finalAction === 'require-fix') {
      mutated.requireFix = true;
      stats.requireFix++;
    } else if (finalAction === 'annotate') {
      stats.annotated++;
    }
    if (complianceNote) mutated.policyNote = complianceNote;

    activeIssues.push(mutated);
  }

  return { issues: activeIssues, stats, auditLog };
}

// ─── CI gate ─────────────────────────────────────────────────────────────────

export function evaluateCIGate(auditLog: PolicyResult[]): {
  pass: boolean;
  blockedCount: number;
  reason: string | null;
} {
  const blocked = auditLog.filter(r => r.blocked);
  if (blocked.length === 0) return { pass: true, blockedCount: 0, reason: null };
  return {
    pass: false,
    blockedCount: blocked.length,
    reason: `${blocked.length} finding(s) require a fix before merge: ${blocked.slice(0, 3).map(r => r.issue.title).join(', ')}${blocked.length > 3 ? '...' : ''}`,
  };
}

// Initialize on import
loadPoliciesFromEnv();
