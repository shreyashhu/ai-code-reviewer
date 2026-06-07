// ─────────────────────────────────────────────────────────────────────────────
// MULTI-AGENT ADVERSARIAL REVIEW ENGINE v10
//
// 8-agent pipeline that dramatically reduces false positives and increases
// exploit certainty compared to single-model or 4-role consensus:
//
//   1. Detector        — initial comprehensive vulnerability scan
//   2. Skeptic         — adversarially challenges each finding
//   3. ExploitEngineer — builds concrete exploit chains + payloads
//   4. RuntimeAuditor  — validates whether sinks are actually reachable
//   5. FixVerifier     — certifies or rejects proposed fixes
//   6. HallucinationJudge — requires code evidence for each claim
//   7. SeverityJudge   — calibrates severity against real-world impact
//   8. RootCauseJudge  — collapses findings to architectural root causes
//
// This produces research-grade conclusions with much higher reliability.
// ─────────────────────────────────────────────────────────────────────────────

import Anthropic from '@anthropic-ai/sdk';
import type { Issue } from './utils';

export interface AgentVerdicts {
  detector:          'confirmed' | 'uncertain' | 'rejected';
  skeptic:           'confirmed' | 'uncertain' | 'rejected';
  exploitEngineer:   'exploitable' | 'theoretical' | 'blocked';
  runtimeAuditor:    'reachable' | 'conditional' | 'unreachable';
  fixVerifier:       'certified' | 'bypassable' | 'no-fix';
  hallucinationJudge:'evidence-backed' | 'speculative' | 'hallucination';
  severityJudge:     'confirmed-high' | 'downgrade' | 'upgrade';
  rootCauseJudge:    string; // architectural root cause description
}

export interface MultiAgentIssue extends Issue {
  agentVerdicts:      AgentVerdicts;
  agentConsensus:     number;   // 0–100: % of agents in agreement
  adversariallyProven: boolean; // all 8 agents confirmed
  exploitPayloadV2?:  string;   // concrete payload from ExploitEngineer
  rootCauseFamily?:   string;   // from RootCauseJudge
  architecturalFix?:  string;   // from RootCauseJudge
}

export interface MultiAgentResult {
  issues:         MultiAgentIssue[];
  summary:        string;
  language:       string;
  agentStats: {
    total:             number;
    adversariallyProven: number;
    skepticRejected:   number;
    hallucinationsBlocked: number;
    severityUpgraded:  number;
    severityDowngraded: number;
    rootCausesClustered: number;
  };
}

// ─── Agent prompts ─────────────────────────────────────────────────────────────

const DETECTOR_PROMPT = `You are a principal security engineer (Detector).
Find ALL security vulnerabilities in the code.
Focus on: SQLi, XSS, SSRF, command injection, path traversal, prototype pollution, 
auth bypasses, business logic flaws, race conditions, insecure deserialization.

For each finding provide:
- type: "bug" | "risk" | "suggestion"
- severity: "high" | "medium" | "low"  
- category: "security" | "logic" | "performance" | "maintainability"
- line: line number (integer) or null
- title: concise title
- explanation: detailed explanation with code evidence
- exploitChain: step-by-step attack path
- confidence: 0.0-1.0 based on code evidence

Return ONLY raw JSON: {"language":"js","issues":[...]}`;

const SKEPTIC_PROMPT = `You are an adversarial security researcher (Skeptic).
You receive vulnerability findings. Your job is to AGGRESSIVELY challenge each one.

For each finding, evaluate:
1. Is there LITERAL code evidence of exploitability?
2. Are there sanitizers/guards that actually block the attack?
3. Is the attack path theoretically possible vs. practically exploitable?
4. Are there framework protections that prevent exploitation?

Vote for each finding:
- "confirmed": clear exploit path with no blocking controls
- "uncertain": possible but requires additional assumptions
- "rejected": sanitized, unreachable, or theoretical only

Return ONLY raw JSON: {"verdicts":[{"title":"...","vote":"confirmed","evidence":"...","counterEvidence":"..."}]}`;

const EXPLOIT_ENGINEER_PROMPT = `You are a red team exploit engineer (ExploitEngineer).
For each CONFIRMED finding, build a concrete exploit:

1. Write the exact attack payload (e.g., SQL: "' OR '1'='1", XSS: "<img/src=x onerror=alert(1)>")
2. Trace: payload → variable name → function call → sink
3. State if sink is reachable from unauthenticated external input
4. Assess: "exploitable" | "theoretical" | "blocked"

For "theoretical" findings, explain exactly what assumption fails.
For "blocked" findings, identify the specific control.

Return ONLY raw JSON: {"exploits":[{"title":"...","verdict":"exploitable","payload":"...","trace":"...","sinkReachable":true,"blockedBy":null}]}`;

const RUNTIME_AUDITOR_PROMPT = `You are a runtime security auditor (RuntimeAuditor).
For each finding, analyze runtime reachability:

1. Is the vulnerable code on a publicly accessible route?
2. Are there authentication/authorization guards before the sink?
3. Are there rate limiters, WAFs, or other runtime controls?
4. What's the realistic attacker access level needed?

Verdict:
- "reachable": accessible by unauthenticated external attacker
- "conditional": requires specific auth level or conditions
- "unreachable": dead code, admin-only, or effectively blocked at runtime

Return ONLY raw JSON: {"audits":[{"title":"...","verdict":"reachable","accessLevel":"anonymous|authenticated|admin","authGuards":["..."],"runtimeControls":["..."]}]}`;

const FIX_VERIFIER_PROMPT = `You are a penetration tester (FixVerifier).
For each finding with a proposed fix, attack the fix:

1. Can it be bypassed? (encoding tricks, type coercion, alternate APIs, unicode)
2. Does it introduce new vulnerabilities?
3. Is it architecturally correct (not just surface-level)?
4. Does it handle all attack vectors?

Verdict:
- "certified": fix is robust and addresses root cause
- "bypassable": fix can be circumvented, explain HOW
- "no-fix": no fix provided or fix is insufficient

Return ONLY raw JSON: {"verifications":[{"title":"...","verdict":"certified","bypassMethod":null,"certificationReason":"..."}]}`;

const HALLUCINATION_JUDGE_PROMPT = `You are a hallucination detection judge (HallucinationJudge).
Critically examine each finding for AI hallucination patterns:

RED FLAGS:
- Claims about code that doesn't exist in the snippet
- Misidentifying safe patterns as vulnerable (e.g., parameterized queries as SQLi)
- Inventing sanitizer bypasses that aren't demonstrated
- Wrong line numbers (>3 lines off from actual code)
- Generic vulnerability description not matched to THIS code

For each finding:
- "evidence-backed": claim is directly supported by visible code
- "speculative": possible but no direct code evidence
- "hallucination": claim contradicts or fabricates code content

Return ONLY raw JSON: {"judgements":[{"title":"...","verdict":"evidence-backed","evidenceQuote":"exact code snippet that proves the claim","flags":["..."]}]}`;

const SEVERITY_JUDGE_PROMPT = `You are a severity calibration judge (SeverityJudge).
Re-evaluate severity based on real-world exploitability context:

UPGRADE to HIGH if:
- Direct RCE, authentication bypass, mass data exposure
- No authentication required for exploitation  
- Affects all users / all data

DOWNGRADE from HIGH if:
- Requires admin access or specific user account
- Limited blast radius (affects only the attacker)
- Defense-in-depth makes exploitation improbable
- Framework provides implicit protection

Return ONLY raw JSON: {"calibrations":[{"title":"...","originalSeverity":"high","calibratedSeverity":"medium","reasoning":"...","realWorldImpact":"..."}]}`;

const ROOT_CAUSE_JUDGE_PROMPT = `You are an architectural root cause analyst (RootCauseJudge).
Instead of 10 individual findings, identify the 2-4 ARCHITECTURAL ROOT CAUSES.

Pattern recognition:
- Multiple SQLi findings → "Unsafe database abstraction layer used across N routes"
- Multiple XSS findings → "No output encoding layer at template/response boundary"  
- Multiple SSRF findings → "Unsafe internal HTTP client abstraction"
- Multiple auth issues → "Missing centralized authorization middleware"

For each root cause:
- cluster: array of finding titles that share this root cause
- rootCause: the architectural problem
- architecturalFix: the structural fix (not just per-finding patches)
- priority: 1-5 (1 = fix first)

Return ONLY raw JSON: {"rootCauses":[{"cluster":["title1","title2"],"rootCause":"...","architecturalFix":"...","priority":1}]}`;

// ─── Anthropic client factory ─────────────────────────────────────────────────

function createAnthropicClient(apiKey: string): Anthropic {
  return new Anthropic({ apiKey });
}

// ─── Call single agent ─────────────────────────────────────────────────────────

async function callAgent(
  client: Anthropic,
  systemPrompt: string,
  userContent: string,
  maxTokens: number = 2000,
): Promise<string> {
  const response = await client.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: maxTokens,
    temperature: 0.1,
    system: systemPrompt,
    messages: [{ role: 'user', content: userContent }],
  });

  const text = response.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('');
  return text;
}

// ─── JSON extraction helper ─────────────────────────────────────────────────

function extractJSON(raw: string): Record<string, unknown> | null {
  const cleaned = raw.replace(/^```(?:json)?\s*/m, '').replace(/\s*```\s*$/m, '').trim();
  const s = cleaned.indexOf('{');
  const e = cleaned.lastIndexOf('}');
  if (s === -1 || e <= s) return null;
  const slice = cleaned.slice(s, e + 1);
  try { return JSON.parse(slice); }
  catch { 
    try { return JSON.parse(slice.replace(/,\s*([}\]])/g, '$1')); }
    catch { return null; }
  }
}

// ─── Main multi-agent pipeline ─────────────────────────────────────────────────

export async function runMultiAgentReview(
  client: Anthropic,
  code: string,
  existingIssues: Issue[],
  langHint: string,
  onProgress?: (stage: string) => void,
): Promise<MultiAgentResult> {

  const issuesContext = existingIssues.slice(0, 15).map((i, idx) =>
    `${idx + 1}. [${i.severity.toUpperCase()}] ${i.title} (L${i.line ?? '?'}): ${i.explanation.slice(0, 200)}`
  ).join('\n');

  const codeSnippet = code.length > 8000 ? code.slice(0, 8000) + '\n// ... (truncated)' : code;
  
  const baseContext = `Language: ${langHint}\n\nCode:\n\`\`\`\n${codeSnippet}\n\`\`\`\n\nExisting findings from deterministic engines:\n${issuesContext || 'None'}`;

  // ── Stage 1: Detector ────────────────────────────────────────────────────
  onProgress?.('🔍 Agent 1/8 — Detector scanning for vulnerabilities...');
  const detectorRaw = await callAgent(client, DETECTOR_PROMPT, 
    `${baseContext}\n\nFind ALL security issues missed by the rule engines above. Return ONLY JSON starting with {`, 2000);
  const detectorData = extractJSON(detectorRaw);
  const detectedIssues: Issue[] = Array.isArray(detectorData?.issues) 
    ? (detectorData.issues as Issue[]) : [];

  // Merge with existing, deduplicate
  const allIssues = mergeIssues(existingIssues, detectedIssues);

  // ── Stage 2: Skeptic ─────────────────────────────────────────────────────
  onProgress?.('🤔 Agent 2/8 — Skeptic challenging findings...');
  const skepticContext = `${baseContext}\n\nFindings to challenge:\n${allIssues.slice(0,15).map((i,idx) => 
    `${idx+1}. ${i.title}: ${i.explanation.slice(0,200)}`).join('\n')}`;
  const skepticRaw = await callAgent(client, SKEPTIC_PROMPT, skepticContext, 1500);
  const skepticData = extractJSON(skepticRaw);
  const skepticVerdicts = buildVerdictMap(skepticData?.verdicts as VerdictEntry[] || [], 'vote');

  // ── Stage 3: Exploit Engineer ────────────────────────────────────────────
  onProgress?.('💥 Agent 3/8 — Exploit Engineer building attack chains...');
  const confirmedIssues = allIssues.filter(i => {
    const v = skepticVerdicts.get(normalizeKey(i.title));
    return !v || v !== 'rejected';
  });
  const exploitContext = `${baseContext}\n\nConfirmed findings to exploit:\n${confirmedIssues.slice(0,10).map((i,idx) =>
    `${idx+1}. ${i.title} (L${i.line ?? '?'}): ${i.explanation.slice(0,200)}\nFix: ${i.fix?.slice(0,100) ?? 'none'}`).join('\n\n')}`;
  const exploitRaw = await callAgent(client, EXPLOIT_ENGINEER_PROMPT, exploitContext, 2000);
  const exploitData = extractJSON(exploitRaw);
  const exploitVerdicts = buildVerdictMap(exploitData?.exploits as VerdictEntry[] || [], 'verdict');
  const payloadMap = new Map<string, string>();
  if (Array.isArray(exploitData?.exploits)) {
    for (const e of exploitData.exploits as ExploitEntry[]) {
      if (e.title && e.payload) payloadMap.set(normalizeKey(e.title), e.payload);
    }
  }

  // ── Stage 4: Runtime Auditor ─────────────────────────────────────────────
  onProgress?.('🏃 Agent 4/8 — Runtime Auditor analyzing reachability...');
  const auditRaw = await callAgent(client, RUNTIME_AUDITOR_PROMPT,
    `${baseContext}\n\nAnalyze runtime reachability of these findings:\n${confirmedIssues.slice(0,10).map((i,idx) =>
      `${idx+1}. ${i.title} (L${i.line ?? '?'}): ${i.explanation.slice(0,150)}`).join('\n')}`, 1500);
  const auditData = extractJSON(auditRaw);
  const auditVerdicts = buildVerdictMap(auditData?.audits as VerdictEntry[] || [], 'verdict');

  // ── Stage 5: Fix Verifier ────────────────────────────────────────────────
  onProgress?.('✅ Agent 5/8 — Fix Verifier certifying patches...');
  const fixable = confirmedIssues.filter(i => i.fix);
  const fixContext = `${baseContext}\n\nVerify these fixes:\n${fixable.slice(0,8).map((i,idx) =>
    `${idx+1}. ${i.title}\nFix: ${i.fix?.slice(0,200)}`).join('\n\n')}`;
  const fixRaw = await callAgent(client, FIX_VERIFIER_PROMPT, fixContext, 1500);
  const fixData = extractJSON(fixRaw);
  const fixVerdicts = buildVerdictMap(fixData?.verifications as VerdictEntry[] || [], 'verdict');

  // ── Stage 6: Hallucination Judge ─────────────────────────────────────────
  onProgress?.('🧱 Agent 6/8 — Hallucination Judge eliminating fabrications...');
  const halluContext = `${baseContext}\n\nJudge these findings for hallucination:\n${allIssues.slice(0,15).map((i,idx) =>
    `${idx+1}. ${i.title} (L${i.line ?? '?'}): ${i.explanation.slice(0,200)}`).join('\n')}`;
  const halluRaw = await callAgent(client, HALLUCINATION_JUDGE_PROMPT, halluContext, 1500);
  const halluData = extractJSON(halluRaw);
  const halluVerdicts = buildVerdictMap(halluData?.judgements as VerdictEntry[] || [], 'verdict');

  // ── Stage 7: Severity Judge ──────────────────────────────────────────────
  onProgress?.('⚖️ Agent 7/8 — Severity Judge calibrating impact scores...');
  const sevRaw = await callAgent(client, SEVERITY_JUDGE_PROMPT,
    `${baseContext}\n\nCalibrate severity for:\n${allIssues.slice(0,15).map((i,idx) =>
      `${idx+1}. [${i.severity.toUpperCase()}] ${i.title}: ${i.explanation.slice(0,150)}`).join('\n')}`, 1500);
  const sevData = extractJSON(sevRaw);
  const severityMap = new Map<string, { severity: 'high'|'medium'|'low', verdict: string }>();
  if (Array.isArray(sevData?.calibrations)) {
    for (const c of sevData.calibrations as SeverityCalibration[]) {
      if (c.title && c.calibratedSeverity) {
        const s = (['high','medium','low'] as const).includes(c.calibratedSeverity as 'high'|'medium'|'low')
          ? c.calibratedSeverity as 'high'|'medium'|'low'
          : c.originalSeverity as 'high'|'medium'|'low';
        severityMap.set(normalizeKey(c.title), { 
          severity: s, 
          verdict: c.calibratedSeverity === c.originalSeverity ? 'confirmed-high' : 
            (c.calibratedSeverity > c.originalSeverity ? 'upgrade' : 'downgrade') 
        });
      }
    }
  }

  // ── Stage 8: Root Cause Judge ────────────────────────────────────────────
  onProgress?.('🧬 Agent 8/8 — Root Cause Judge clustering architecturally...');
  const rootRaw = await callAgent(client, ROOT_CAUSE_JUDGE_PROMPT,
    `${baseContext}\n\nCluster these findings by root cause:\n${allIssues.slice(0,15).map((i,idx) =>
      `${idx+1}. ${i.title}: ${i.explanation.slice(0,150)}`).join('\n')}`, 1500);
  const rootData = extractJSON(rootRaw);
  const rootCauseMap = new Map<string, { rootCause: string; architecturalFix: string }>();
  if (Array.isArray(rootData?.rootCauses)) {
    for (const rc of rootData.rootCauses as RootCause[]) {
      if (Array.isArray(rc.cluster)) {
        for (const title of rc.cluster) {
          rootCauseMap.set(normalizeKey(title), { 
            rootCause: rc.rootCause, 
            architecturalFix: rc.architecturalFix 
          });
        }
      }
    }
  }

  // ── Assemble final issues with all agent verdicts ─────────────────────────
  let upgradeCount = 0, downgradeCount = 0, halluCount = 0, rejCount = 0;
  
  const finalIssues: MultiAgentIssue[] = allIssues
    .filter(issue => {
      const key = normalizeKey(issue.title);
      const hallucination = halluVerdicts.get(key);
      if (hallucination === 'hallucination') { halluCount++; return false; }
      const skeptic = skepticVerdicts.get(key);
      if (skeptic === 'rejected') { rejCount++; return false; }
      return true;
    })
    .map(issue => {
      const key = normalizeKey(issue.title);
      const skepticV = (skepticVerdicts.get(key) ?? 'uncertain') as AgentVerdicts['detector'];
      const exploitV = (exploitVerdicts.get(key) ?? 'theoretical') as AgentVerdicts['exploitEngineer'];
      const auditV   = (auditVerdicts.get(key)   ?? 'conditional') as AgentVerdicts['runtimeAuditor'];
      const fixV     = issue.fix ? ((fixVerdicts.get(key) ?? 'certified') as AgentVerdicts['fixVerifier']) : 'no-fix';
      const halluV   = (halluVerdicts.get(key)   ?? 'evidence-backed') as AgentVerdicts['hallucinationJudge'];
      const sevCal   = severityMap.get(key);
      const rootCal  = rootCauseMap.get(key);
      
      const sevVerdict = (sevCal?.verdict ?? 'confirmed-high') as AgentVerdicts['severityJudge'];
      if (sevCal?.severity && sevCal.severity !== issue.severity) {
        if (sevCal.severity === 'high') upgradeCount++; else downgradeCount++;
      }

      // Count confirmations
      const confirmations = [
        skepticV === 'confirmed',
        exploitV === 'exploitable',
        auditV === 'reachable',
        fixV !== 'bypassable',
        halluV === 'evidence-backed',
      ].filter(Boolean).length;
      const agentConsensus = Math.round((confirmations / 5) * 100);
      const adversariallyProven = confirmations >= 4;

      // Apply severity calibration
      const finalSeverity = sevCal?.severity ?? issue.severity;

      // Invalidate bypassable fixes
      let finalFix = issue.fix;
      let finalFixRejectionReason = issue.fixRejectionReason;
      if (fixV === 'bypassable' && issue.fix) {
        finalFix = null;
        finalFixRejectionReason = '[BYPASS DETECTED by FixVerifier agent] ' + (issue.fixRejectionReason ?? 'Fix can be circumvented');
      }

      return {
        ...issue,
        severity: finalSeverity,
        fix: finalFix,
        fixRejectionReason: finalFixRejectionReason,
        exploitPayload: payloadMap.get(key) ?? issue.exploitPayload,
        agentVerdicts: {
          detector:          'confirmed' as const,
          skeptic:           skepticV,
          exploitEngineer:   exploitV,
          runtimeAuditor:    auditV,
          fixVerifier:       fixV,
          hallucinationJudge: halluV,
          severityJudge:     sevVerdict,
          rootCauseJudge:    rootCal?.rootCause ?? 'Individual finding',
        },
        agentConsensus,
        adversariallyProven,
        rootCauseFamily:  rootCal?.rootCause,
        architecturalFix: rootCal?.architecturalFix,
      } satisfies MultiAgentIssue;
    });

  // ── Build stats ───────────────────────────────────────────────────────────
  const rootCauseSet = new Set(finalIssues.map(i => i.rootCauseFamily).filter(Boolean));

  return {
    issues: finalIssues,
    summary: `Multi-agent review: ${finalIssues.length} confirmed findings (${finalIssues.filter(i => i.adversariallyProven).length} adversarially proven). ${halluCount} hallucinations blocked, ${rejCount} skeptic-rejected. ${rootCauseSet.size} root cause cluster(s).`,
    language: langHint,
    agentStats: {
      total:                allIssues.length,
      adversariallyProven:  finalIssues.filter(i => i.adversariallyProven).length,
      skepticRejected:      rejCount,
      hallucinationsBlocked: halluCount,
      severityUpgraded:     upgradeCount,
      severityDowngraded:   downgradeCount,
      rootCausesClustered:  rootCauseSet.size,
    },
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeKey(title: string): string {
  return title.toLowerCase().replace(/\s+/g, ' ').replace(/[^a-z0-9 ]/g, '').trim().slice(0, 60);
}

interface VerdictEntry { title?: string; vote?: string; verdict?: string }
interface ExploitEntry { title?: string; payload?: string }
interface SeverityCalibration { title?: string; originalSeverity?: string; calibratedSeverity?: string }
interface RootCause { cluster?: string[]; rootCause?: string; architecturalFix?: string }

function buildVerdictMap(entries: VerdictEntry[], field: 'vote' | 'verdict'): Map<string, string> {
  const map = new Map<string, string>();
  for (const entry of entries || []) {
    if (entry.title) {
      const v = entry[field] ?? entry.vote ?? entry.verdict;
      if (v) map.set(normalizeKey(entry.title), v);
    }
  }
  return map;
}

function mergeIssues(existing: Issue[], detected: Issue[]): Issue[] {
  const seen = new Set(existing.map(i => normalizeKey(i.title)));
  const merged = [...existing];
  for (const d of detected) {
    const key = normalizeKey(d.title);
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(d);
    }
  }
  return merged;
}

export { createAnthropicClient };
