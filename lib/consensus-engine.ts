// ─────────────────────────────────────────────────────────────────────────────
// MODEL CONSENSUS ENGINE v4
//
// Replaces single-model reasoning with a 5-role consensus pipeline:
//   1. Analyzer      — finds issues
//   2. Adversarial Critic — attacks findings, removes false positives
//   3. Exploit Verifier  — traces payload→sink, confirms exploitability
//   4. Fix Validator     — attacks proposed fixes, rejects bypassable ones
//   5. Final Judge       — arbitrates disagreements, produces confidence scores
//
// When roles disagree → escalate flag set for human review.
// Dramatically reduces hallucinations vs single-model.
// ─────────────────────────────────────────────────────────────────────────────

import OpenAI from 'openai';
import type { Issue } from './utils';

export interface ConsensusIssue extends Issue {
  consensusScore:    number;   // 0–100: agreement across roles
  escalate:          boolean;  // true if roles disagreed significantly
  roleVotes: {
    analyzer:       'confirmed' | 'uncertain' | 'rejected';
    critic:         'confirmed' | 'uncertain' | 'rejected';
    exploitVerifier:'confirmed' | 'uncertain' | 'rejected';
    fixValidator:   'valid' | 'bypassable' | 'none';
  };
  proofChain?: {
    payload:         string;
    executionPath:   string;
    blockedAt:       string | null;
    observedResult:  string;
    sinkReachable:   boolean;
  };
}

export interface ConsensusResult {
  summary:         string;
  score:           number;
  language:        string;
  issues:          ConsensusIssue[];
  escalated:       ConsensusIssue[];
  consensusStats:  { total: number; agreed: number; escalated: number; rejected: number };
}

// ─── Role-Specific Prompts ─────────────────────────────────────────────────────

const ANALYZER_ROLE = `You are a principal security engineer (Analyzer role).
Find security vulnerabilities and logic bugs that static rule engines miss.

CRITICAL — SMALL CODE IS NOT SAFE CODE: Do not let simple or short code lower your guard.
A 5-line function with eval(req.query.x) is a critical RCE. A missing auth check in 3 lines
is a critical access control bypass. Scrutinize every line with equal rigor regardless of file size.

TARGET: logic bugs, auth bypasses, business logic flaws, async race conditions, type coercion exploits,
missing authorization checks, IDOR, broken access control, insecure state management, hardcoded secrets,
dangerous eval sinks (Function(), eval(), vm.run()), unsafe redirects, missing input validation.
DO NOT re-report issues in RULE ENGINE CONFIRMED list.

ROOT-CAUSE DEDUPLICATION (strict):
- Same SQLi pattern at N lines → ONE finding mentioning all lines
- Same XSS sink family → ONE finding
- Violating dedup = response discarded

CONFIDENCE (required 0.0-1.0):
  0.90-0.98: trace payload→var→sink explicitly, no assumptions
  0.70-0.89: strong pattern, minor assumption about input source
  0.40-0.69: possible but reachability unclear → type="risk"
  <0.40:     skip entirely

FALSE POSITIVE GUARD: db.query(sql,[params]) is NOT SQLi. encodeHtml output is NOT XSS.
crypto.timingSafeEqual is NOT a timing attack. Only flag what code evidence proves.

Return ONLY raw JSON: {"language":"js","issues":[{"type":"bug","severity":"high","category":"security","line":N,"title":"...","explanation":"cite exact code","exploitChain":"step by step","confidence":0.92,"fix":"..."}]}`;

const CRITIC_ROLE = `You are a balanced security reviewer (Critic role).
Your job is accuracy — neither FP elimination nor alarmism. Miss nothing real; keep nothing false.

For EACH finding evaluate:
1. LITERAL code evidence: exact vulnerable line visible? Quote it.
2. Data flow: does tainted input actually reach the sink without sanitization?
3. Sanitizer: does the code call an EFFECTIVE sanitizer in the actual execution path?
4. Framework protection: proven ORM parameterization, auto-escaping, etc in THIS code?
5. Reachability: is this path reachable from external input? Dead code = rejected.
6. Small code: short files rarely have framework protections — don't assume them.

VOTE:
- "confirmed": clear exploit path visible in code, no effective blocking control present
- "uncertain": plausible vulnerability, minor assumption needed about input routing
- "rejected": conclusively sanitized, proven framework-protected, or unreachable dead code

IMPORTANT: Do NOT reject based on:
- "the developer probably intended to sanitize this" — only actual code counts
- "frameworks usually protect against this" — only THIS code's actual framework usage counts
- Code being short or simple — that's not evidence of safety

Parameterized queries with array params = NOT SQLi. DOMPurify.sanitize() in path = NOT XSS.
Process.env sent in res.send() = real leak regardless of code size.

Return ONLY raw JSON: {"issues":[{"title":"...","criticVote":"confirmed","evidence":"exact code line","counterEvidence":"what blocks it or null","exploitChain":"..."}]}`;

const EXPLOIT_VERIFIER_ROLE = `You are a red team lead (Exploit Verifier role).
For each confirmed finding, verify exploitability:
1. State exact attack payload
2. Trace: payload → variable → sink
3. State if sink is reachable from external input
4. Set exploitVerified=true if exploitable, false if not
5. Set sinkReachable=true/false

DO NOT add new findings. Only verify.
Return ONLY raw JSON: {"issues":[{"title":"...","exploitVerified":true,"sinkReachable":true,"payload":"...","executionPath":"...","blockedAt":null,"observedResult":"..."}]}`;

const FIX_VALIDATOR_ROLE = `You are a penetration tester (Fix Validator role).
For each finding with a proposed fix, attack the fix:
  - Can the fix be bypassed? (regex bypass, double-encode, type coercion, alternate API)
  - Is the fix syntactically correct?
  - Does the fix introduce new vulnerabilities?
Vote: "valid" | "bypassable" | "none"
If bypassable, set fix=null and explain why in fixRejectionReason.
Return ONLY raw JSON: {"issues":[{"title":"...","fixVote":"valid","fixRejectionReason":null}]}`;

const JUDGE_ROLE = `You are the security lead (Final Judge).
Arbitrate findings voted on by Analyzer, Critic, Exploit Verifier, and Fix Validator.

ARBITRATION (apply in order):
1. Critic "rejected" AND exploitVerified=false → REMOVE (false positive)
2. Critic "confirmed" AND exploitVerified=true → KEEP, consensusScore=95
3. Critic "confirmed", exploitVerified=false → KEEP, consensusScore=75, escalate=true
4. Critic "uncertain" + exploitVerified=true → KEEP, consensusScore=70
5. Critic "uncertain" + exploitVerified=false → KEEP as risk, consensusScore=55, escalate=true
6. Critic "rejected" + exploitVerified=true → KEEP (critic wrong), consensusScore=65, escalate=true
7. Analyzer found issue but Critic had no vote (new issue, no prior det hit) → evaluate independently:
   - If exploitVerified=true OR clear code evidence: KEEP, consensusScore=72, escalate=false
   - If plausible but uncertain: KEEP as risk, consensusScore=52, escalate=true
   - If implausible: REMOVE

SMALL CODE REMINDER: A finding on 10-line code with eval(userInput) is real. Do not over-suppress
just because the codebase is small or simple. Judge by code evidence, not by code size.

FIX: If fixVote="bypassable" → set fix=null, include fixRejectionReason.

SCORING (start=100, floor=0):
  bug/high=-20  bug/medium=-10  bug/low=-4
  risk/high=-12  risk/medium=-6  risk/low=-3
  suggestion=-2

Return ONLY raw JSON: {"summary":"N confirmed vulnerabilities. Top: [title].","score":N,"language":"...","issues":[{...all fields + consensusScore:N, escalate:bool, roleVotes:{analyzer,critic,exploitVerifier,fixValidator}}]}`;

// ─── Compact issue serializer (saves tokens) ──────────────────────────────────
function compactIssues(issues: Issue[]): string {
  return issues.map((i, idx) => {
    const parts = [
      `[${idx}] ${i.severity.toUpperCase()} ${i.type} L${i.line ?? '?'}: ${i.title}`,
      // 200 chars for explanation — logic/auth bugs use explanation as primary evidence
      `EXPLAIN: ${i.explanation?.slice(0, 200)}`,
    ];
    // 120 for exploit chain — enough for step-by-step payload trace
    if (i.exploitChain) parts.push(`CHAIN: ${i.exploitChain.slice(0, 120)}`);
    if (i.exploitPayload) parts.push(`PAYLOAD: ${i.exploitPayload.slice(0, 80)}`);
    if (i.fix) parts.push(`FIX: ${i.fix.slice(0, 100)}`);
    return parts.join(' | ');
  }).join('\n');
}

// ─── JSON extractor ───────────────────────────────────────────────────────────
function safeJSON(raw: string): Record<string, unknown> {
  const text  = raw.replace(/^```(?:json)?\s*/m, '').replace(/\s*```\s*$/m, '').trim();
  const start = text.indexOf('{');
  const end   = text.lastIndexOf('}');
  if (start === -1 || end <= start) return {};
  try { return JSON.parse(text.slice(start, end + 1)); }
  catch { return {}; }
}

// ─── Role caller ─────────────────────────────────────────────────────────────
async function callRole(
  client: OpenAI,
  model: string,
  systemPrompt: string,
  userMsg: string,
  maxTokens: number,
): Promise<string> {
  try {
    const res = await client.chat.completions.create({
      model,
      messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userMsg }],
      temperature: 0.1,
      max_tokens: maxTokens,
    });
    return res.choices[0]?.message?.content ?? '{}';
  } catch {
    return '{}';
  }
}

// ─── Vote merger ──────────────────────────────────────────────────────────────
type VoteMap = Map<string, {
  analyzer?:       'confirmed' | 'uncertain' | 'rejected';
  critic?:         'confirmed' | 'uncertain' | 'rejected';
  exploitVerified?: boolean;
  sinkReachable?:  boolean;
  fixVote?:        'valid' | 'bypassable' | 'none';
  fixRejectionReason?: string | null;
  payload?:        string;
  executionPath?:  string;
  blockedAt?:      string | null;
  observedResult?: string;
  exploitChain?:   string;
}>;

function mergeVotes(
  baseIssues: Issue[],
  analyzerRaw: Record<string, unknown>,
  criticRaw:   Record<string, unknown>,
  verifierRaw: Record<string, unknown>,
  fixRaw:      Record<string, unknown>,
): VoteMap {
  const votes: VoteMap = new Map();

  // Initialize from base issues
  baseIssues.forEach(i => votes.set(i.title, {}));

  // Merge analyzer votes
  const aIssues = (analyzerRaw.issues as unknown[] ?? []);
  for (const ai of aIssues) {
    const a   = ai as Record<string, unknown>;
    const key = String(a.title ?? '');
    if (key) votes.set(key, { ...votes.get(key), analyzer: 'confirmed' });
  }

  // Merge critic votes
  const cIssues = (criticRaw.issues as unknown[] ?? []);
  for (const ci of cIssues) {
    const c   = ci as Record<string, unknown>;
    const key = String(c.title ?? '');
    const vote = String(c.criticVote ?? c.vote ?? 'uncertain') as 'confirmed' | 'uncertain' | 'rejected';
    if (key && votes.has(key)) {
      votes.set(key, {
        ...votes.get(key),
        critic: vote,
        exploitChain: String(c.exploitChain ?? votes.get(key)?.exploitChain ?? ''),
      });
    }
  }

  // Merge exploit verifier
  const vIssues = (verifierRaw.issues as unknown[] ?? []);
  for (const vi of vIssues) {
    const v   = vi as Record<string, unknown>;
    const key = String(v.title ?? '');
    if (key && votes.has(key)) {
      votes.set(key, {
        ...votes.get(key),
        exploitVerified: Boolean(v.exploitVerified),
        sinkReachable:   Boolean(v.sinkReachable),
        payload:         String(v.payload ?? ''),
        executionPath:   String(v.executionPath ?? ''),
        blockedAt:       v.blockedAt ? String(v.blockedAt) : null,
        observedResult:  String(v.observedResult ?? ''),
      });
    }
  }

  // Merge fix validator
  const fIssues = (fixRaw.issues as unknown[] ?? []);
  for (const fi of fIssues) {
    const f   = fi as Record<string, unknown>;
    const key = String(f.title ?? '');
    if (key && votes.has(key)) {
      votes.set(key, {
        ...votes.get(key),
        fixVote:             String(f.fixVote ?? 'none') as 'valid' | 'bypassable' | 'none',
        fixRejectionReason:  f.fixRejectionReason ? String(f.fixRejectionReason) : null,
      });
    }
  }

  return votes;
}

// ─── Judge arbitration ────────────────────────────────────────────────────────
function arbitrate(
  baseIssues: Issue[],
  votes: VoteMap,
  judgeRaw: Record<string, unknown>,
): ConsensusResult {
  const judgeIssues = (judgeRaw.issues as unknown[] ?? []);
  const judgeMap = new Map<string, Record<string, unknown>>();
  for (const ji of judgeIssues) {
    const j = ji as Record<string, unknown>;
    if (j.title) judgeMap.set(String(j.title), j);
  }

  const SCORE_DED: Record<string, Record<string, number>> = {
    bug:        { high: 20, medium: 10, low: 4 },
    risk:       { high: 12, medium: 6,  low: 3 },
    suggestion: { high: 2,  medium: 2,  low: 2 },
  };

  const consensusIssues: ConsensusIssue[] = [];
  const rejected: string[] = [];

  for (const issue of baseIssues) {
    const v = votes.get(issue.title) ?? {};
    const jEntry = judgeMap.get(issue.title);

    // Count positive votes
    const positives = [
      v.analyzer === 'confirmed',
      v.critic   === 'confirmed',
      v.exploitVerified === true,
    ].filter(Boolean).length;

    const negatives = [
      v.analyzer === 'rejected',
      v.critic   === 'rejected',
      v.exploitVerified === false,
    ].filter(Boolean).length;

    // Judge override
    const judgeConsensus = jEntry ? Number(jEntry.consensusScore ?? 75) : null;
    const judgeEscalate  = jEntry ? Boolean(jEntry.escalate) : false;

    // Arbitration rules
    if (negatives >= 2 && positives === 0) {
      rejected.push(issue.title);
      continue; // Remove false positive
    }

    const consensusScore = judgeConsensus ?? Math.max(30, Math.min(95,
      positives * 30 + (negatives > 0 ? -15 * negatives : 0) + 50
    ));
    const escalate = judgeEscalate || (positives === 1 && negatives === 1) || consensusScore < 60;

    const fixVote = v.fixVote ?? 'none';
    const finalFix = fixVote === 'bypassable' ? null : (issue.fix ?? null);
    const finalFixRejection = fixVote === 'bypassable'
      ? (v.fixRejectionReason ?? 'Fix was found to be bypassable by Fix Validator')
      : issue.fixRejectionReason;

    consensusIssues.push({
      ...issue,
      fix:                finalFix,
      fixRejectionReason: finalFixRejection ?? undefined,
      exploitVerified:    v.exploitVerified,
      exploitChain:       v.exploitChain ?? issue.exploitChain,
      consensusScore,
      escalate,
      roleVotes: {
        analyzer:       v.analyzer ?? 'uncertain',
        critic:         v.critic ?? 'uncertain',
        exploitVerifier: v.exploitVerified === true ? 'confirmed' : v.exploitVerified === false ? 'rejected' : 'uncertain',
        fixValidator:   fixVote,
      },
      proofChain: v.payload ? {
        payload:       v.payload,
        executionPath: v.executionPath ?? '',
        blockedAt:     v.blockedAt ?? null,
        observedResult:v.observedResult ?? '',
        sinkReachable: v.sinkReachable ?? true,
      } : undefined,
    });
  }

  const score = Math.max(0, consensusIssues.reduce(
    (s, i) => s - (SCORE_DED[i.type]?.[i.severity] ?? 2), 100
  ));

  const escalated = consensusIssues.filter(i => i.escalate);
  const summary = typeof judgeRaw.summary === 'string'
    ? judgeRaw.summary
    : `${consensusIssues.length} issues, ${escalated.length} escalated for human review.`;

  return {
    summary,
    score,
    language: String(judgeRaw.language ?? 'unknown'),
    issues:   consensusIssues,
    escalated,
    consensusStats: {
      total:     baseIssues.length,
      agreed:    consensusIssues.filter(i => i.consensusScore >= 80).length,
      escalated: escalated.length,
      rejected:  rejected.length,
    },
  };
}

// ─── Main Consensus Pipeline ──────────────────────────────────────────────────
export async function runConsensus(
  client: OpenAI,
  model: string,
  code: string,
  baseIssues: Issue[],
  langHint:  string,
  ruleCtx:   string,
  taintCtx:  string,
  budgetPerPass: number,
): Promise<ConsensusResult> {
  // NOTE: Do NOT early-exit when baseIssues is empty.
  // Small/simple code with zero deterministic hits still needs independent AI analysis.
  // The Analyzer role may find issues the engines missed (missing auth, logic bugs, eval sinks).
  // Only skip if we truly have nothing to work with (no code).
  if (!code || code.trim().length < 5) {
    return {
      summary: 'No code provided.',
      score: 100,
      language: langHint,
      issues: [],
      escalated: [],
      consensusStats: { total: 0, agreed: 0, escalated: 0, rejected: 0 },
    };
  }

  const compact = compactIssues(baseIssues);
  const noDetFindings = baseIssues.length === 0;

  // Run all 4 roles in parallel (saves latency vs serial)
  const [analyzerRaw, criticRaw, verifierRaw, fixRaw] = await Promise.all([
    callRole(client, model, ANALYZER_ROLE,
      `Language: ${langHint}\n${noDetFindings ? 'RULE ENGINE: no deterministic findings — perform full independent security review. Small or simple code is NOT automatically safe.' : `RULE ENGINE (already confirmed, do not re-report): ${ruleCtx}`}\nTAINT: ${taintCtx}\n\nCODE:\n${code.slice(0, 4000)}\n\nFind issues engines missed. Return JSON.`,
      budgetPerPass),

    callRole(client, model, CRITIC_ROLE,
      `Language: ${langHint}\nFINDINGS TO REVIEW:\n${compact}\n\nFor each finding, vote confirmed/uncertain/rejected with evidence. Return JSON.`,
      budgetPerPass),

    callRole(client, model, EXPLOIT_VERIFIER_ROLE,
      `Language: ${langHint}\nFINDINGS:\n${compact}\n\nVerify exploitability of each. Return JSON.`,
      budgetPerPass),

    callRole(client, model, FIX_VALIDATOR_ROLE,
      `Language: ${langHint}\nFINDINGS WITH FIXES:\n${compact}\n\nAttack each fix. Return JSON.`,
      budgetPerPass),
  ]);

  const [aData, cData, vData, fData] = [analyzerRaw, criticRaw, verifierRaw, fixRaw].map(safeJSON);

  // When baseIssues is empty (no deterministic hits), the Analyzer may have found
  // new issues independently. Promote those to the base issue list so arbitrate can process them.
  let effectiveBase = baseIssues;
  if (noDetFindings) {
    const analyzerIssues = (aData.issues as unknown[] ?? []).map((raw: unknown) => {
      const a = raw as Record<string, unknown>;
      const TM: Record<string, Issue['type']>     = { bug:'bug', vulnerability:'bug', risk:'risk', suggestion:'suggestion' };
      const SM: Record<string, Issue['severity']> = { high:'high', critical:'high', medium:'medium', low:'low' };
      return {
        type:        TM[String(a.type ?? '').toLowerCase()]        ?? 'risk',
        severity:    SM[String(a.severity ?? '').toLowerCase()]    ?? 'medium',
        category:    String(a.category ?? 'security'),
        line:        typeof a.line === 'number' ? a.line : null,
        title:       String(a.title ?? '').slice(0, 120),
        explanation: String(a.explanation ?? '').slice(0, 400),
        fix:         typeof a.fix === 'string' ? a.fix : null,
        exploitChain:typeof a.exploitChain === 'string' ? a.exploitChain : undefined,
        confidence:  typeof a.confidence === 'number' ? a.confidence : 0.7,
      } as Issue;
    }).filter(i => i.title.length >= 5);
    if (analyzerIssues.length > 0) {
      effectiveBase = analyzerIssues;
    }
  }

  // Merge votes
  const votes = mergeVotes(effectiveBase, aData, cData, vData, fData);

  // Final judge pass
  const judgeInput = JSON.stringify({
    issues: [...votes.entries()].map(([title, v]) => ({ title, ...v })),
  });

  const judgeRaw = await callRole(client, model, JUDGE_ROLE,
    `Language: ${langHint}\nVOTES:\n${judgeInput.slice(0, 3000)}\n\nArbitrate. Return final JSON.`,
    budgetPerPass);
  const judgeData = safeJSON(judgeRaw);

  return arbitrate(effectiveBase, votes, judgeData);
}
