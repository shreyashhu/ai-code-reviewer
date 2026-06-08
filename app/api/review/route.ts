import { NextRequest, NextResponse } from 'next/server';
import OpenAI from 'openai';
import { runSecurityRules } from '@/lib/security-rules';
import { runTaintAnalysis } from '@/lib/taint-engine';
import { runPipeline } from '@/lib/pipeline';
import { runConsensus } from '@/lib/consensus-engine';
import { generatePatches } from '@/lib/ast-patch-engine';
import { buildRootCauseGraph, graphToIssues, buildGraphSummary } from '@/lib/root-cause-graph';
import { analyzeReachability, adjustSeverityByReachability } from '@/lib/reachability-engine';
import { runExploitReplay } from '@/lib/exploit-replay';
import { applyDecayToIssues, type DecayStats } from '@/lib/confidence-decay';
import { clusterByFamily, familiesToIssues, getClusterStats, type ClusterStats } from '@/lib/family-clustering';
import { computeWeightedScore, type WeightedScoreResult } from '@/lib/weighted-scoring';
import { synthesizeAttackChains, type ChainSynthesisResult } from '@/lib/attack-chain-synthesis';
import { buildSemanticGraph, semanticGraphToIssues, getSemanticGraphSummary, type SemanticGraphSummary } from '@/lib/semantic-graph';
import { applyHallucinationFirewall, applyHallucinationFirewallV2, type HallucinationFirewallStats, type FirewallV2Stats } from '@/lib/hallucination-firewall';
import { applyTrustModel, type TrustModelStats } from '@/lib/trust-model';
import { analyzeChangeSurface, prioritizeByChangeSurface, getChangeSurfaceSummary, type ChangeSurfaceSummary } from '@/lib/differential-analysis';
import { runSymbolicExecution, applySymbolicExecution } from '@/lib/symbolic-execution';
import { verifyRemediation } from '@/lib/verified-remediation';
import { applyBayesianCalibration, type CalibrationStats } from '@/lib/bayesian-confidence';
import { synthesizeConstraintChains } from '@/lib/constraint-chains';
import { classifyCode, getTokenBudget, TIER_LABELS, type RouteDecision } from '@/lib/adaptive-router';
import { cacheKey, withCache, withCacheSync, getCacheStats } from '@/lib/analysis-cache';
import { applyRiskModel, type RiskModelStats } from '@/lib/risk-model';
import { ObservabilitySession, recordScanToProcessStats, estimateTokens } from '@/lib/observability';
import { computeRepoFingerprint, getRepoMemory, applySecurityMemory, type MemoryApplicationResult } from '@/lib/security-memory';
import { applyDeterministicDominance, type DominanceStats } from '@/lib/deterministic-dominance';
import { applyFPMinimizer, type FPMinimizerStats } from '@/lib/fp-minimizer';
import { runDeltaAnalysis, type DeltaAnalysisResult } from '@/lib/cicd-delta';
import { buildIncrementalGraph, type IncrementalGraphStats } from '@/lib/incremental-graph';
import { applyPolicyLayer, evaluateCIGate, type PolicyStats } from '@/lib/policy-layer';
import { assignModel, arbitrate } from '@/lib/model-specialization';
import { recordScanIssues, checkTeamSuppression, purgeExpiredSuppressions, getRefinedMemoryStats } from '@/lib/memory-refinement';
import { runBenchmark, calculateStats, detectRegressions, getLatestRunId, TEST_VECTORS } from '@/lib/benchmark-harness';
import { runRuntimeVerification, runtimeVerificationToIssues, getRuntimeVerificationSummary, type RuntimeVerificationReport } from '@/lib/runtime-verification';
import { buildWholeSystemGraph, wholeSystemGraphToIssues, getWholeSystemSummary, type WholeSystemSummary } from '@/lib/whole-system-graph';
import { runProofObligationEngine, proofObligationToIssues, getProofObligationSummary } from '@/lib/proof-obligation';
import { applySecurityKnowledgeGraph, knowledgeGraphToIssues, getKnowledgeGraphContext } from '@/lib/security-knowledge-graph';
import { detectLanguage, getProfile, getLanguageRoutingOverride, buildLanguagePromptSupplement, getLanguageSafeSinks, type LanguageId } from '@/lib/language-profiles';
import { buildCodeContext } from '@/lib/code-context-manager';
import { runParallel2, unwrapOrDefault } from '@/lib/parallel-pipeline';

export interface Issue {
  type: 'bug' | 'risk' | 'suggestion';
  severity: 'high' | 'medium' | 'low';
  category: string;
  line: number | null;
  title: string;
  explanation: string;
  exploitPayload?: string;
  fix: string | null;
  fixRejectionReason?: string;
  exploitVerified?: boolean;
  exploitChain?: string;
  consensusScore?: number;
  escalate?: boolean;
  confidence?: number;
  exploitability?: number;
  reachability?: number;
  blastRadius?: string;
  cwe?: string;
  cweName?: string;
  proofChain?: { payload: string; executionPath: string; blockedAt: string | null; observedResult: string; sinkReachable: boolean; };
  roleVotes?: { analyzer: string; critic: string; exploitVerifier: string; fixValidator: string; };
  astPatched?: boolean;
  patchConfidence?: number;
}

export interface ReviewResult {
  summary: string; score: number; language: string; issues: Issue[]; optimized_code: string; auditPassed: boolean; auditDetail: string;
  pipelineMetadata?: {
    taintSources: number; callGraphNodes: number; frameworksDetected: string[];
    projectIndex?: { files: number; routes: number; sensitiveRoutes: number; unauthenticatedSensitiveRoutes: number; imports: number; exports: number; crossFileEdges: number };
    consensusStats?: { total: number; agreed: number; escalated: number; rejected: number };
    astPatchesApplied: number; engineVersion: string;
    rootCauseGraph?: { uniqueSurfaces: number; collapsed: number; suppressed: number; totalInput: number };
    decayStats?: DecayStats; clusterStats?: ClusterStats;
    scoringBreakdown?: { positiveRewards: number; adjustedDeductions: number; securityRewards: Array<{ label: string; reward: number }> };
    attackChains?: ChainSynthesisResult; semanticGraph?: SemanticGraphSummary;
    hallucinationFirewall?: HallucinationFirewallStats; trustModel?: TrustModelStats; changeSurface?: ChangeSurfaceSummary;
    symbolicExecution?: { constraints: number; suppressedSinks: number; authGuardedLines: number };
    remediation?: { certified: number; partial: number; bypassed: number; regressions: number };
    bayesianCalibration?: CalibrationStats; firewallV2?: FirewallV2Stats;
    constraintChains?: { total: number; fullyValidated: number; partiallyValidated: number; highestCvss: number; criticalCount: number };
    adaptiveRoute?: { tier: string; reason: string; estimatedTokenRatio: number; complexityScore: number };
    riskModel?: { totalInput: number; downgraded: number; upgraded: number; fakeCriticals: number; avgBisScore: number };
    securityMemory?: { newFindings: number; recurringFindings: number; suppressed: number; escalated: number; resolvedFindings: number };
    observability?: { totalDurationMs: number; totalTokens: number; estimatedCostUsd: number; slowestStage: string | null; cacheHitRate: number };
    analysisCache?: { hitRate: number; estimatedSavedTokens: number };
    runtimeVerification?: { total: number; verified: number; blocked: number; partial: number; unreachable: number; upgraded: number; downgraded: number };
    wholeSystemGraph?: WholeSystemSummary;
    proofObligations?: { total: number; valid: number; weak: number; suppressed: number; hallucinations: number };
    knowledgeGraph?: { cweMatched: number; cveMatched: number; exploitMatched: number; avgCvss: number };
    deterministicDominance?: { total: number; confirmed: number; annotated: number; rejected: number; deterministic: number; hallucinationsKilled: number };
    fpMinimizer?: { total: number; frameworkSafe: number; sanitizerCertain: number; deadCode: number; privilegeGated: number; testCode: number; typeSafe: number; active: number };
    deltaAnalysis?: { mode: string; newIssues: number; regressions: number; resolved: number; newTrustBoundaries: string[]; newSinks: string[] };
    incrementalGraph?: { totalNodes: number; dirtyNodes: number; recomputed: number; skipped: number; attackPaths: number; serviceDeps: number; asyncBridges: number };
    policyLayer?: { total: number; suppressed: number; escalated: number; demoted: number; requireFix: number; ciGate: boolean; ciBlockReason: string | null };
    modelSpecialization?: { securityModel: string; remediationModel: string; estimatedCostSavingPct: number };
    memoryRefinement?: { activeVulns: number; resolvedVulns: number; teamSuppressions: number; escalatingDrifts: number; volatileDrifts: number };
    benchmarkStats?: { precision: number; recall: number; f1: number; fpRate: number; regressions: number };
    languageProfile?: { detected: string; hint: string; criticalSinksFound: number; routingOverride: string | null; supplement: boolean };
    smartContext?: { totalLines: number; keptLines: number; truncated: boolean; securityDensity: number; hotspotCount: number };
  };
}

function asUtilIssues(issues: Issue[]): import('@/lib/utils').Issue[] { return issues as unknown as import('@/lib/utils').Issue[]; }

const VALID_MODELS = new Set(['openai/gpt-4o-mini', 'openai/gpt-4o', 'anthropic/claude-3-haiku', 'anthropic/claude-3.5-sonnet', 'meta-llama/llama-3.1-8b-instruct', 'auto']);
const VALID_LANGUAGES = new Set(['auto', 'javascript', 'typescript', 'python', 'rust', 'go', 'java', 'cpp', 'csharp', 'php', 'ruby', 'swift', 'kotlin', 'sql', 'bash']);

const MODEL_CHAIN = [
  'openai/gpt-4o-mini',
  'anthropic/claude-3-haiku',
  'meta-llama/llama-3.1-8b-instruct:free',
  'google/gemma-2-9b-it:free',
  'mistralai/mistral-7b-instruct:free',
];

function startKeepalive(ctrl: ReadableStreamDefaultController, enc: TextEncoder): ReturnType<typeof setInterval> {
  return setInterval(() => { try { ctrl.enqueue(enc.encode(': keepalive\n\n')); } catch { /* stream closed */ } }, 10_000);
}

// FIX: Added Taint Path Hallucination Guard to stop AI from inventing fake data flows
const FAST_PROMPT = `You are a principal security engineer performing a thorough security audit.
Deterministic engines have already run — your job is finding what they missed AND validating everything independently.
CRITICAL LANGUAGE CHECK: If the code provided is Python, Rust, Go, or Java, but you were told it is JavaScript, IGNORE the JavaScript hint and analyze the code in its actual native language.
CRITICAL — SMALL/SIMPLE CODE IS NOT AUTOMATICALLY SAFE: Short or simple-looking code frequently contains high-severity issues: hardcoded secrets, SQL injection, eval on user input, missing auth checks, prototype pollution, weak crypto, race conditions. Scrutinize every line regardless of code size.
WHAT TO FIND: Logic bugs, Auth/authz, Business logic, Type coercion, Async bugs, Hidden eval sinks, Dead validators, Secrets/config, Missing rate limits.
STRICT DEDUPLICATION: Same root-cause at N lines → ONE finding mentioning all lines.
TAINT PATH HALLUCINATION GUARD: Do NOT invent taint chains or claim a variable reaches a sink if the code does not explicitly show it. If you cannot trace the exact variable to the sink, do not report it as a taint flow.
CONFIDENCE CALIBRATION (0.0-1.0): 0.90-0.98 (proven), 0.70-0.89 (strong), 0.40-0.69 (risk), <0.40 (skip).
FALSE POSITIVE GUARD: db.query(sql,[params]) is NOT SQLi. encodeHtml output is NOT XSS.
Return ONLY raw JSON: { "summary": "...", "score":N, "language": "js", "issues":[{"type": "bug", "severity": "high", "category": "security", "line":N, "title": "...", "explanation": "...", "fix": "...", "exploitChain": "...", "confidence":0.92}]}`;

function extractJSON(raw: string): Record<string, unknown> | null {
  const t = raw.replace(/^`(?:json)?\s*/m, '').replace(/\s*`\s*$/m, '').trim();
  const s = t.indexOf('{'), e = t.lastIndexOf('}');
  if (s === -1 || e <= s) return null;
  const sl = t.slice(s, e + 1);
  try { return JSON.parse(sl); } catch { try { return JSON.parse(sl.replace(/,\s*([}\]])/g, '$1')); } catch { return null; } }
}

function normalizeIssues(raw: unknown[]): Issue[] {
  const TM: Record<string, Issue['type']> = { bug:'bug',error:'bug',vulnerability:'bug',critical:'bug',security:'bug',risk:'risk',warning:'risk',caution:'risk',suggestion:'suggestion',improvement:'suggestion',info:'suggestion',note:'suggestion' };
  const SM: Record<string, Issue['severity']> = { high:'high',critical:'high',severe:'high',medium:'medium',moderate:'medium',low:'low',minor:'low' };
  return raw.map((r: unknown): Issue | null => {
    if (!r || typeof r !== 'object') return null;
    const i = r as Record<string, unknown>;
    const type = TM[String(i.type ?? '').toLowerCase()] ?? 'risk';
    const severity = SM[String(i.severity ?? '').toLowerCase()] ?? 'medium';
    const title = String(i.title ?? i.name ?? '').slice(0, 120);
    const explanation = String(i.explanation ?? i.description ?? '').slice(0, 400);
    if (!title) return null;
    const VALID_CATEGORIES = new Set(['security', 'logic', 'performance', 'maintainability']);
    const rawCat = String(i.category ?? '').toLowerCase();
    const category = VALID_CATEGORIES.has(rawCat) ? rawCat : 'security';
    return { type, severity, category, line: typeof i.line === 'number' ? i.line : null, title, explanation, fix: typeof i.fix === 'string' && i.fix.trim() ? i.fix.trim() : null, fixRejectionReason: typeof i.fixRejectionReason === 'string' ? i.fixRejectionReason : undefined, exploitVerified: typeof i.exploitVerified === 'boolean' ? i.exploitVerified : undefined, exploitChain: typeof i.exploitChain === 'string' ? i.exploitChain : undefined };
  }).filter((i): i is Issue => i !== null);
}

function semanticDedup(issues: Issue[]): Issue[] {
  const canonical = new Map<string, Issue>();
  const paths = new Map<string, number>();
  for (const issue of issues) {
    const tn = issue.title.toLowerCase().replace(/\s+/g,' ').replace(/\b(?:via|using|with|in|at|through)\b./g,'').trim();
    const lg = issue.line !== null ? Math.floor(issue.line / 3) : -1;
    const key = `${issue.type}:${issue.severity}:${tn}:${lg}`;
    if (!canonical.has(key)) { canonical.set(key, { ...issue }); paths.set(key, 1); }
    else {
      const count = (paths.get(key) ?? 1) + 1; paths.set(key, count);
      const c = canonical.get(key)!;
      c.explanation = c.explanation.replace(/ \+\d+ similar\.?/,'') + ` [+${count-1} similar path(s) — same root cause]`;
    }
  }
  return Array.from(canonical.values());
}

function buildResult(parsed: Record<string, unknown>, hard: Issue[]): ReviewResult {
  const KEYS = ['issues','findings','vulnerabilities','problems','bugs','results'];
  const ik = KEYS.find(k => k in parsed && Array.isArray(parsed[k]));
  const rawAI = ik ? normalizeIssues(parsed[ik] as unknown[]) : [];
  const seenT = new Set(hard.map(i => i.title.toLowerCase().trim()));
  const seenS = new Set(hard.map(i => `${i.line ?? 0}:${i.severity}`));
  const aiF = rawAI.filter(i => {
    const tk = i.title.toLowerCase().trim(), sk = `${i.line ?? 0}:${i.severity}`;
    if (seenT.has(tk)) return false; if (seenS.has(sk) && i.line !== null) return false;
    seenT.add(tk); seenS.add(sk); return true;
  });
  const deduped = semanticDedup([...hard, ...aiF]);
  const weightedResult = computeWeightedScore(deduped as import('@/lib/utils').Issue[], [], '');
  const score = weightedResult.score;
  const bc = deduped.filter(i => i.type==='bug').length, rc = deduped.filter(i => i.type==='risk').length;
  return { summary: typeof parsed.summary==='string' ? parsed.summary : `Found ${bc} bug(s) and ${rc} risk(s).`, score, language: typeof parsed.language==='string' ? parsed.language : 'unknown', issues: deduped, optimized_code: '', auditPassed: deduped.length > 0 || score < 100, auditDetail: deduped.length > 0 ? `${bc} bug(s), ${rc} risk(s) found. Score: ${score}/100.` : 'No issues detected.' };
}

async function callModel(client: OpenAI, model: string, messages: OpenAI.Chat.ChatCompletionMessageParam[], maxTokens: number): Promise<string | null> {
  try {
    const res = await client.chat.completions.create({ model, messages, temperature: 0.1, max_tokens: maxTokens });
    console.log(`[API] ${model} chars=${res.choices[0]?.message?.content?.length ?? 0} finish=${res.choices[0]?.finish_reason}`);
    return res.choices[0]?.message?.content ?? '';
  } catch (err) {
    const status = (err as Record<string, unknown>)?.status as number | undefined;
    console.error(`[API] ${model} failed HTTP ${status}`);
    if (status === 401 || status === 403 || status === 402) throw err;
    return null;
  }
}

async function callWithFallback(client: OpenAI, preferred: string, messages: OpenAI.Chat.ChatCompletionMessageParam[], maxTokens: number): Promise<string> {
  const seen = new Set<string>();
  const chain = [preferred, ...MODEL_CHAIN].filter(m => !seen.has(m) && !!seen.add(m));
  for (let i = 0; i < chain.length; i++) {
    const model = chain[i]!;
    if (i > 0) console.warn(`[fallback] Model ${chain[i-1]} failed — downgrading to ${model}.`);
    const r = await callModel(client, model, messages, maxTokens);
    if (r !== null) return r;
  }
  throw new Error('All models failed. Check OPENROUTER_API_KEY and credits.');
}

export async function POST(req: NextRequest) {
  const ct = req.headers.get('content-type') ?? '';
  if (!ct.toLowerCase().includes('application/json')) return NextResponse.json({ error: 'Content-Type must be application/json.' }, { status: 415 });

  let body: unknown;
  try { body = await req.json(); } catch { return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 }); }

  const userApiKey = req.headers.get('x-openrouter-key');
  const apiKey = userApiKey || process.env.OPENROUTER_API_KEY;
  if (!apiKey) return NextResponse.json({ error: 'OpenRouter API Key is required. Please add it in the dashboard settings.' }, { status: 401 });

  const { code: rawCode, model: rawModel, language: rawLanguage } = (body ?? {}) as { code?: string; model?: string; language?: string };
  if (!rawCode || typeof rawCode !== 'string' || !rawCode.trim()) return NextResponse.json({ error: 'code is required.' }, { status: 400 });
  if (rawModel !== undefined && !VALID_MODELS.has(rawModel)) return NextResponse.json({ error: 'Invalid model.' }, { status: 400 });
  if (rawLanguage !== undefined && !VALID_LANGUAGES.has(rawLanguage)) return NextResponse.json({ error: 'Invalid language.' }, { status: 400 });

  const code = rawCode.trim(), langHint = rawLanguage && rawLanguage !== 'auto' ? rawLanguage : 'auto-detect';
  const preferred = rawModel && rawModel !== 'auto' ? rawModel : 'openai/gpt-4o-mini';
  const client = new OpenAI({ apiKey, baseURL: 'https://openrouter.ai/api/v1', defaultHeaders: { 'HTTP-Referer': 'https://ai-code-review.dev', 'X-Title': 'AI Code Review v1.5' } });
  const FALLBACK: ReviewResult = { summary: 'Analysis failed. Please try again.', score: 0, language: 'unknown', issues: [], optimized_code: '', auditPassed: false, auditDetail: 'Parse failure.' };

  const detectedLang = detectLanguage(code, langHint) as LanguageId;
  const langProfile  = getProfile(detectedLang);
  const langSupplement = buildLanguagePromptSupplement(detectedLang, code);
  const langRoutingOverride = getLanguageRoutingOverride(detectedLang, code);
  console.log(`[Language] detected=${detectedLang} hint=${langHint} routingOverride=${langRoutingOverride ?? 'none'}`);

  const stream = new ReadableStream({
    async start(controller) {
      const enc = new TextEncoder();
      const emit = (data: object) => { try { controller.enqueue(enc.encode(`data: ${JSON.stringify(data)}\n\n`)); } catch { /**/ } };
      const _keepalive = startKeepalive(controller, enc);
      const obs = new ObservabilitySession();

      try {
        emit({ type: 'stage', stage: 'parse', label: '🔍 Stage 1 — Rule engine & taint analysis...' });
        const ck = cacheKey(code, langHint);

        obs.startStage('security-rules');
        const { value: hardcodedFindings, cached: rulesCached } = withCacheSync('security-rules', ck, () => runSecurityRules(code) as unknown as Record<string, unknown>);
        obs.endStage('security-rules');

        obs.startStage('taint-engine', rulesCached);
        const { value: taintReport, cached: taintCached } = withCacheSync('taint-engine', ck, () => runTaintAnalysis(code) as unknown as Record<string, unknown>);
        obs.endStage('taint-engine');

        emit({ type: 'stage', stage: 'parse', label: '🔗 Stage 2 — Call graph, CFG & interprocedural taint...' });
        obs.startStage('pipeline', taintCached);
        const { value: pipelineReport, cached: pipelineCached } = withCacheSync('pipeline', ck, () => runPipeline(code) as unknown as Record<string, unknown>);
        obs.endStage('pipeline');

        const hr = hardcodedFindings as unknown as ReturnType<typeof runSecurityRules>;
        const tr = taintReport as unknown as ReturnType<typeof runTaintAnalysis>;
        const pr = pipelineReport as unknown as ReturnType<typeof runPipeline>;
        
        const projectIndexSummary = { files: pr.projectIndex.files.length, routes: pr.projectIndex.routes.length, sensitiveRoutes: pr.projectIndex.routes.filter(r => r.sensitive).length, unauthenticatedSensitiveRoutes: pr.projectIndex.routes.filter(r => r.sensitive && !r.authGuard).length, imports: pr.projectIndex.imports.length, exports: pr.projectIndex.exports.length, crossFileEdges: pr.projectIndex.crossFileEdges.length };

        const taintIssues: Issue[] = [...tr.sqlVulns.filter(f => !tr.sqlSafeLines.has(f.line)), ...tr.xssVulns.filter(f => !tr.xssSafeLines.has(f.line)), ...tr.cmdVulns, ...tr.pathVulns, ...tr.redirectVulns, ...tr.headerVulns.filter(f => !tr.headerSafeLines.has(f.line)), ...tr.protoVulns.filter(f => !tr.protoSafeLines.has(f.line))].map(f => ({ type: 'bug' as const, severity: 'high' as const, category: 'security', line: f.line, title: f.title, explanation: f.evidence, fix: null }));
        const ruleIssues: Issue[] = hr.map(f => ({ type: 'bug' as const, severity: f.severity, category: f.category, line: f.line, title: f.title, explanation: f.explanation, exploitPayload: f.exploitPayload, fix: f.fix, fixRejectionReason: f.fixRejectionReason }));
        const pipelineIssues: Issue[] = pr.findings.map(f => ({ type: 'bug' as const, severity: f.severity, category: f.category, line: f.line, title: f.title, explanation: f.explanation, fix: f.fix, fixRejectionReason: f.fixRejectionReason, exploitChain: f.exploitChain, exploitPayload: f.exploitPayload, confidence: f.confidence / 100, exploitability: f.exploitability, reachability: f.reachability, blastRadius: f.blastRadius, cwe: f.cwe, cweName: f.cweName }));

        const allDet = [...ruleIssues, ...taintIssues, ...pipelineIssues];
        const seenK = new Set<string>();
        const mergedDet = allDet.filter(i => { const k = `${i.line ?? '?'}:${i.title.toLowerCase().slice(0,35)}`; if(seenK.has(k)) return false; seenK.add(k); return true; });

        obs.startStage('adaptive-routing');
        const routeDecision: RouteDecision = classifyCode({ code, deterministicHits: mergedDet.length, taintFlows: tr.taintedVars.size, detectedLanguage: detectedLang, languageMinTier: langRoutingOverride });
        obs.endStage('adaptive-routing');
        
        const routedBudget = getTokenBudget(routeDecision.tier, code.split('\n').length);
        if (routedBudget.perRole > 800) routedBudget.perRole = 800;
        if (routedBudget.diff > 800) routedBudget.diff = 800;

        emit({ type: 'stage', stage: 'parse', label: `🧭 Adaptive routing → ${TIER_LABELS[routeDecision.tier]}` });
        console.log(`[Route] ${routeDecision.tier} reason="${routeDecision.reason}" tokenRatio=${routeDecision.estimatedTokenRatio}`);

        const contextResult = buildCodeContext(code, 6000);
        const codeForAI = contextResult.context;
        if (contextResult.truncated) console.log(`[SmartContext] kept=${contextResult.keptLines}/${contextResult.totalLines} lines density=${contextResult.securityDensity}/100`);

        const ruleCtx = mergedDet.slice(0,8).map(i => `L${i.line??'?'}:${i.title}`).join(' | ') || 'none';
        const taintCtx = (tr.summary || 'no proven findings').slice(0, 400);

        let finalIssues: Issue[] = mergedDet;
        let finalSummary = '', finalLanguage = langHint;
        let consensusStatsFinal: ReviewResult['pipelineMetadata'] = undefined;

        if (routeDecision.tier === 'deterministic-only') {
          emit({ type: 'stage', stage: 'bugs', label: '⚡ Deterministic-only mode — no AI calls needed' });
          finalSummary = `Deterministic analysis complete. ${mergedDet.length} finding(s).`;
        } else if (routeDecision.tier === 'single-reviewer') {
          emit({ type: 'stage', stage: 'bugs', label: '🔍 Single-reviewer mode (low complexity)...' });
          obs.startStage('single-reviewer-ai');
          const fastRaw = await callWithFallback(client, preferred, [
            { role: 'system', content: FAST_PROMPT + (langSupplement ? `\n\nLANGUAGE-SPECIFIC RULES:\n${langSupplement}` : '') },
            { role: 'user', content: `Language: ${detectedLang !== 'unknown' ? detectedLang : langHint}\nTAINT ENGINE: ${taintCtx}\n${ruleCtx !== 'none' ? `ALREADY CONFIRMED BY RULES (do not re-report): ${ruleCtx}` : 'RULES: no deterministic findings — do a full independent review'}\n${getKnowledgeGraphContext(codeForAI)}\n\n====== CODE ======\n${codeForAI}\n====== END ======\n\nFind all security/logic issues engines missed. Return ONLY JSON starting with {` },
          ], routedBudget.perRole);
          obs.endStage('single-reviewer-ai');
          obs.recordTokensFromStrings('single-reviewer-ai', preferred, codeForAI, fastRaw);
          const parsed = extractJSON(fastRaw) ?? {};
          const ar = buildResult(parsed, mergedDet); 
          finalIssues = ar.issues; finalSummary = ar.summary; finalLanguage = ar.language;
        } else {
          const tierLabel = routeDecision.tier === 'adversarial-full' ? '🛡️ Adversarial pipeline (5-role)...' : '🔬 Triple-consensus (3-role)...';
          emit({ type: 'stage', stage: 'bugs', label: `Stage 3 — ${tierLabel}` });
          obs.startStage('consensus-ai');
          const { value: cachedConsensus, cached: consCached } = await withCache('consensus-result', ck, () => runConsensus(client, preferred, codeForAI, mergedDet as import('@/lib/utils').Issue[], langHint, ruleCtx, taintCtx, routedBudget.perRole) as unknown as Promise<Record<string, unknown>>);
          obs.endStage('consensus-ai');
          const consensusResult = cachedConsensus as unknown as Awaited<ReturnType<typeof runConsensus>>;
          if (!consCached) obs.recordTokensFromStrings('consensus-ai', preferred, codeForAI, JSON.stringify(consensusResult));
          
          emit({ type: 'stage', stage: 'audit', label: `⚖️ Stage 4 — Judge arbitration (${consensusResult.escalated.length} escalated)...` });
          const consensusIssues = consensusResult.issues as Issue[];
          finalIssues = semanticDedup([...mergedDet, ...consensusIssues]);
          finalSummary = consensusResult.summary; finalLanguage = consensusResult.language;
          consensusStatsFinal = { taintSources: tr.taintedVars.size, callGraphNodes: pr.callGraph.nodes.size, frameworksDetected: pr.frameworkContext.detected, projectIndex: projectIndexSummary, consensusStats: consensusResult.consensusStats, astPatchesApplied: 0, engineVersion: 'v1.5-consensus' };
        }

        obs.recordStageResult('ai-review', mergedDet.length, finalIssues.length);

        if (finalIssues.length === 0) {
          emit({ type: 'stage', stage: 'audit', label: '✅ No issues found — skipping post-processing stages' });
          const obsReport = obs.report(); obs.logSummary(); recordScanToProcessStats(obsReport); const cacheStats = getCacheStats();
          const cleanScore = routeDecision.tier === 'deterministic-only' ? 92 : routeDecision.tier === 'single-reviewer' ? 95 : 100;
          const result: ReviewResult = { summary: finalSummary || 'No security issues detected.', score: cleanScore, language: finalLanguage, issues: [], optimized_code: '', auditPassed: true, auditDetail: 'No issues detected.', pipelineMetadata: { taintSources: tr.taintedVars.size, callGraphNodes: pr.callGraph.nodes.size, frameworksDetected: pr.frameworkContext.detected, projectIndex: projectIndexSummary, astPatchesApplied: 0, engineVersion: 'v1.5', adaptiveRoute: { tier: routeDecision.tier, reason: routeDecision.reason, estimatedTokenRatio: routeDecision.estimatedTokenRatio, complexityScore: routeDecision.signals.complexityScore }, observability: { totalDurationMs: obsReport.totalDurationMs, totalTokens: obsReport.totalInputTokens + obsReport.totalOutputTokens, estimatedCostUsd: obsReport.estimatedCostUsd, slowestStage: obsReport.slowestStage, cacheHitRate: obsReport.cacheHitSummary.rate }, analysisCache: { hitRate: cacheStats.hitRate, estimatedSavedTokens: cacheStats.estimatedSavedTokens } } };
          emit({ type: 'done', result }); return;
        }

        emit({ type: 'stage', stage: 'diff', label: '🔧 Stage 5 — AST-based syntax-preserving patch generation...' });
        obs.startStage('ast-patch');
        const patchReqs = finalIssues.filter(i => i.fix !== null && i.line !== null).map(i => ({ ruleId: i.title.toLowerCase().replace(/\s+/g,'-'), lineNumber: i.line! }));
        let astPatchedCode = '', astPatchCount = 0;
        if (patchReqs.length > 0) {
          try { const patchResult = generatePatches(code, patchReqs.slice(0,10)); if (patchResult.patchCount > 0) { astPatchedCode = patchResult.patchedCode; astPatchCount = patchResult.patchCount; for (const patch of patchResult.patches) { const issue = finalIssues.find(i => i.line === patch.lineNumber); if (issue) { issue.astPatched = true; issue.patchConfidence = patch.confidence; } } } } catch(e) { console.warn('[AST patch] non-fatal:', e instanceof Error ? e.message : e); }
        }
        obs.endStage('ast-patch');

        let optimizedCode = astPatchedCode;
        if (!optimizedCode) {
          const fixable = finalIssues.filter(i => i.fix !== null);
          if (fixable.length > 0) {
            try { const fixList = fixable.slice(0,8).map(i => `Line ${i.line??'?'} (${i.title}): ${i.fix}`).join('\n'); obs.startStage('diff-ai'); const diffRaw = await callWithFallback(client, preferred, [{ role: 'system', content: 'Apply ALL listed fixes. Return ONLY the complete corrected source code. No markdown. No explanation.' }, { role: 'user', content: `ORIGINAL:\n${codeForAI}\n\nFIXES:\n${fixList}\n\nReturn corrected source:` }], routedBudget.diff); obs.endStage('diff-ai'); optimizedCode = diffRaw.replace(/^```[\w]*\r?\n?/,'').replace(/\r?\n?```$/,'').trim(); } catch(e) { console.warn('[Diff] non-fatal:', e instanceof Error ? e.message : e); }
          }
        }

        emit({ type: 'stage', stage: 'audit', label: '🧬 Stage 6 — Root-cause graph: collapsing duplicates...' });
        let rcGraph = buildRootCauseGraph(asUtilIssues(finalIssues)); let rcIssues = graphToIssues(rcGraph); let graphSummary = buildGraphSummary(rcGraph);
        
        emit({ type: 'stage', stage: 'audit', label: '📉 Stage 7 — Confidence decay...' });
        const { active: activeIssues, suppressed: suppressedIssues, decayStats } = applyDecayToIssues(rcIssues, code, 20);
        
        emit({ type: 'stage', stage: 'audit', label: '🗂️ Stage 8 — Family clustering...' });
        const families = clusterByFamily(activeIssues); const clusteredIssues = familiesToIssues(families); const clusterStats = getClusterStats(families, activeIssues.length);
        const weightedScore = computeWeightedScore(clusteredIssues, families, code, decayStats); let score = weightedScore.score;
        
        emit({ type: 'stage', stage: 'audit', label: '⛓️ Stage 9 — Attack chain synthesis...' });
        const chainResult = synthesizeAttackChains(clusteredIssues);
        
        emit({ type: 'stage', stage: 'audit', label: '🔗 Stage 9b — Constraint-valid chain validation...' });
        const constraintChains = synthesizeConstraintChains(clusteredIssues, code);
        for (const chain of constraintChains.criticalChains) { const matchedIssue = clusteredIssues.find(i => chain.entryPoint.toLowerCase().includes(i.title.toLowerCase().slice(0, 25))); if (matchedIssue && chain.fullyValidated) { matchedIssue.exploitChain = (matchedIssue.exploitChain ?? '') + `\n[CONSTRAINT-PROVEN CVSS ${chain.cvssEstimate}] ${chain.title}`; } }

        let v8Issues = clusteredIssues;
        const trustResult = applyTrustModel(v8Issues, code); v8Issues = trustResult.activeIssues;
        const firewallResult = applyHallucinationFirewall(v8Issues, code, true); v8Issues = firewallResult.issues;
        const changeSurface = analyzeChangeSurface(code); const changeSurfaceSummary = getChangeSurfaceSummary(changeSurface);
        v8Issues = prioritizeByChangeSurface(v8Issues, changeSurface);

        let bayesResult: Awaited<ReturnType<typeof applyBayesianCalibration>> | null = null;
        try { const deterministicTitles = new Set<string>(((pr as Record<string, unknown>).hardcodedFindings as Array<{ title: string }> ?? []).map((f: { title: string }) => f.title)); const suppressedTitles = new Set<string>(Array.from((trustResult.stats as Record<string, unknown>)?.suppressedTitles as string[] ?? [])); bayesResult = applyBayesianCalibration(v8Issues as Parameters<typeof applyBayesianCalibration>[0], code, deterministicTitles, suppressedTitles); v8Issues = bayesResult.issues as typeof v8Issues; } catch(e) {}

        let fw2Result: ReturnType<typeof applyHallucinationFirewallV2> | null = null;
        try { fw2Result = applyHallucinationFirewallV2(v8Issues, code); v8Issues = fw2Result.issues; } catch(e) {}

        const fixableIssues = v8Issues.filter(i => i.fix !== null);
        const remediationReport = optimizedCode ? verifyRemediation(code, optimizedCode, fixableIssues) : null;
        if (remediationReport) { for (const r of remediationReport.results) { const match = v8Issues.find(i => i.title === r.issueTitle && Math.abs((i.line ?? 0) - (r.issueLine ?? -1)) <= 2); if (match) { (match as Record<string, unknown>).remediationStatus = r.status; (match as Record<string, unknown>).remediationConfidence = r.confidence; if (r.status === 'BYPASSED') { match.fix = null; match.fixRejectionReason = `[BYPASS DETECTED] ${r.evidence}`; } } } }

        const finalRcIssues = v8Issues;
        const riskResult = applyRiskModel(finalRcIssues, code); const riskModelledIssues = riskResult.issues as typeof finalRcIssues;
        const repoFingerprint = computeRepoFingerprint(code); const repoMemory = getRepoMemory(repoFingerprint);
        const memoryResult: MemoryApplicationResult = applySecurityMemory(riskModelledIssues as Parameters<typeof applySecurityMemory>[0], repoMemory);
        const memoryActiveIssues = memoryResult.issues as typeof finalRcIssues; const postV11Issues = memoryActiveIssues;

        const [rtvResult, wsgResult] = await runParallel2(
          { name: 'runtime-verification', fn: () => { const report = runRuntimeVerification(postV11Issues, code); return { report, issues: runtimeVerificationToIssues(report), summary: getRuntimeVerificationSummary(report) }; }, timeoutMs: 12_000 },
          { name: 'whole-system-graph', fn: () => { const graph = buildWholeSystemGraph(code); const issues = wholeSystemGraphToIssues(graph); const summary = getWholeSystemSummary(graph); return { graph, issues, summary }; }, timeoutMs: 12_000 },
        );

        type RtvDefault = { report: RuntimeVerificationReport; issues: Issue[]; summary: string };
        type WsgDefault = { graph: ReturnType<typeof buildWholeSystemGraph>; issues: Issue[]; summary: WholeSystemSummary };
        const rtvDefault: RtvDefault = { report: { stats: { total: 0, verified: 0, blocked: 0, partial: 0, unreachable: 0, skipped: 0, upgraded: 0, downgraded: 0 }, results: [] } as unknown as RuntimeVerificationReport, issues: [], summary: 'skipped' };
        const wsgDefault: WsgDefault = { graph: null as unknown as ReturnType<typeof buildWholeSystemGraph>, issues: [], summary: { crossModuleFindings: 0, totalNodes: 0, authGapCount: 0, dataFlowPaths: 0 } as WholeSystemSummary };

        const { report: runtimeVerifReport, issues: runtimeVerifIssues } = unwrapOrDefault(rtvResult, rtvDefault as typeof rtvDefault);
        const { issues: wholeSysIssues, summary: wholeSysSummary } = unwrapOrDefault(wsgResult, wsgDefault as typeof wsgDefault);
        const combinedV13Issues = [...runtimeVerifIssues, ...wholeSysIssues];

        const proofReport = runProofObligationEngine(combinedV13Issues, code); const provedIssues = proofObligationToIssues(proofReport); const proofSummary = getProofObligationSummary(proofReport);
        const knowledgeReport = applySecurityKnowledgeGraph(provedIssues, code); const enrichedIssues = knowledgeGraphToIssues(knowledgeReport); const postV13Issues = enrichedIssues;

        emit({ type: 'stage', stage: 'audit', label: '⚖️ Stage 24 — Deterministic dominance: AI proposes, deterministic decides...' });
        obs.startStage('deterministic-dominance');
        const originalDeterministicIssues = [...ruleIssues, ...taintIssues, ...pipelineIssues];
        const dominanceResult = applyDeterministicDominance(postV13Issues, code, originalDeterministicIssues);
        const postDominanceIssues = dominanceResult.issues;
        obs.endStage('deterministic-dominance');

        const fpResult = applyFPMinimizer(postDominanceIssues, code); const postFPIssues = fpResult.issues;
        const deltaResult = runDeltaAnalysis(postFPIssues, code);
        const graphResult = buildIncrementalGraph(code, cacheKey(code));
        
        const secAssignment = assignModel('security'); const remAssignment = assignModel('remediation'); const costSaving = Math.round((1 - (secAssignment.costFactor + remAssignment.costFactor) / 2) * 100);

        purgeExpiredSuppressions();
        const teamSuppressionFiltered = postFPIssues.filter(issue => { const sup = checkTeamSuppression({ title: issue.title, category: issue.category, severity: issue.severity, confidence: issue.confidence }); return !sup; });
        recordScanIssues(teamSuppressionFiltered.map(i => ({ title: i.title, category: i.category, severity: i.severity, confidence: i.confidence, line: i.line })));
        const memRefinedStats = getRefinedMemoryStats();

        const policyResult = applyPolicyLayer(teamSuppressionFiltered);
        let ciGate = evaluateCIGate(policyResult.auditLog);

        // ── STRICT CI GATE OVERRIDE (v1.4.3) ──────────────────────────────────────
        // A production CI gate MUST fail if there are ANY High/Critical bugs.
        const highCriticalBugs = teamSuppressionFiltered.filter(i => 
          i.type === 'bug' && (i.severity === 'high' || i.severity === 'critical')
        );
        if (highCriticalBugs.length > 0) {
          ciGate = { pass: false, ciBlockReason: `${highCriticalBugs.length} High/Critical vulnerability(ies) found. Merge blocked.` };
        }

        let benchReport: { precision: number; recall: number; f1: number; fpRate: number; regressions: number } | undefined;
        try { const benchResults = runBenchmark(TEST_VECTORS, (vecCode) => { try { return runSecurityRules(vecCode); } catch { return []; } }); const benchStats = calculateStats(benchResults); const prevRunId = getLatestRunId(); const regReport = detectRegressions(`run-${Date.now()}`, benchResults, prevRunId); benchReport = { precision: Math.round(benchStats.precision * 100) / 100, recall: Math.round(benchStats.recall * 100) / 100, f1: Math.round(benchStats.f1 * 100) / 100, fpRate: Math.round(benchStats.fpRate * 100) / 100, regressions: regReport.regressions.length }; } catch(e) {}

        // ── FINAL AGGRESSIVE DEDUPLICATION (v1.4.3) ───────────────────────────────
        // Merges findings that share the same line number and vulnerability family
        const preDedupIssues = policyResult.issues;
        const familyRegex = /sqli|sql.inject|command.inject|cmd.inject|path.travers|xss|jwt|auth.bypass|secret|credential/i;
        const dedupMap = new Map<string, Issue>();
        
        for (const issue of preDedupIssues) {
          const familyMatch = (issue.title + ' ' + issue.explanation).match(familyRegex);
          const family = familyMatch ? familyMatch[0].toLowerCase() : issue.title.toLowerCase().slice(0, 20);
          const lineKey = issue.line ?? 'null';
          const dedupKey = `${family}:${lineKey}`;
          
          if (!dedupMap.has(dedupKey)) {
            dedupMap.set(dedupKey, { ...issue });
          } else {
            const existing = dedupMap.get(dedupKey)!;
            if (issue.exploitChain && !existing.exploitChain) existing.exploitChain = issue.exploitChain;
            if (issue.fix && !existing.fix) existing.fix = issue.fix;
          }
        }
        const finalV14Issues = Array.from(dedupMap.values());

        const bc = finalV14Issues.filter(i => i.type==='bug').length; const rc = finalV14Issues.filter(i => i.type==='risk').length;
        const finalWeightedScore = computeWeightedScore(finalV14Issues, families, code, decayStats); score = finalWeightedScore.score;

        const obsReport = obs.report(); obs.logSummary(); recordScanToProcessStats(obsReport); const cacheStats = getCacheStats();

        const result: ReviewResult = {
          summary: finalSummary || (bc > 0 || rc > 0 ? `Found ${bc} critical bug(s) and ${rc} risk(s). ${graphSummary}` : graphSummary) || `Found ${bc} bug(s) and ${rc} risk(s).`,
          score, language: finalLanguage, issues: finalV14Issues, optimized_code: optimizedCode, auditPassed: ciGate.pass,
          auditDetail: finalV14Issues.length > 0 ? `${clusterStats.familyCount} vuln family(ies), ${clusterStats.collapsed} collapsed, ${suppressedIssues.length} decay-suppressed, ${trustResult.stats.suppressedCount} trust-suppressed, ${firewallResult.stats.droppedCount}+${fw2Result?.stats.droppedCount ?? 0} firewall-dropped, ${memoryResult.stats.suppressed} memory-suppressed, ${policyResult.stats.suppressed} policy-suppressed. Score: ${score}/100.${ciGate.pass ? '' : ` ⛔ CI BLOCKED: ${ciGate.ciBlockReason}`}` : 'No issues detected.',
          pipelineMetadata: {
            taintSources: tr.taintedVars.size, callGraphNodes: pr.callGraph.nodes.size, frameworksDetected: pr.frameworkContext.detected, consensusStats: consensusStatsFinal?.consensusStats, projectIndex: projectIndexSummary, astPatchesApplied: astPatchCount, engineVersion: 'v1.5',
            rootCauseGraph: { uniqueSurfaces: rcGraph.uniqueSurfaces, collapsed: rcGraph.collapsedCount, suppressed: rcGraph.suppressedCount, totalInput: rcGraph.totalInput },
            decayStats, clusterStats, scoringBreakdown: { positiveRewards: finalWeightedScore.positiveRewards, adjustedDeductions: finalWeightedScore.adjustedDeductions, securityRewards: finalWeightedScore.securityRewards }, attackChains: chainResult,
            semanticGraph: getSemanticGraphSummary(buildSemanticGraph(code)), hallucinationFirewall: firewallResult.stats, trustModel: trustResult.stats, changeSurface: changeSurfaceSummary, symbolicExecution: undefined, bayesianCalibration: bayesResult?.stats, firewallV2: fw2Result?.stats,
            constraintChains: constraintChains.chains.length > 0 ? { total: constraintChains.chains.length, fullyValidated: constraintChains.fullyValidated, partiallyValidated: constraintChains.partiallyValidated, highestCvss: constraintChains.highestCvss, criticalCount: constraintChains.criticalChains.length } : undefined,
            remediation: remediationReport ? { certified: remediationReport.certifiedFixed, partial: remediationReport.partial, bypassed: remediationReport.bypassed, regressions: remediationReport.results.filter(r => r.regression).length } : undefined,
            adaptiveRoute: { tier: routeDecision.tier, reason: routeDecision.reason, estimatedTokenRatio: routeDecision.estimatedTokenRatio, complexityScore: routeDecision.signals.complexityScore },
            riskModel: { totalInput: riskResult.stats.totalInput, downgraded: riskResult.stats.downgraded, upgraded: riskResult.stats.upgraded, fakeCriticals: riskResult.stats.fakeCriticals, avgBisScore: riskResult.stats.avgBisScore },
            securityMemory: { newFindings: memoryResult.stats.newFindings, recurringFindings: memoryResult.stats.recurringFindings, suppressed: memoryResult.stats.suppressed, escalated: memoryResult.stats.escalated, resolvedFindings: memoryResult.stats.resolvedFindings },
            observability: { totalDurationMs: obsReport.totalDurationMs, totalTokens: obsReport.totalInputTokens + obsReport.totalOutputTokens, estimatedCostUsd: obsReport.estimatedCostUsd, slowestStage: obsReport.slowestStage, cacheHitRate: obsReport.cacheHitSummary.rate },
            analysisCache: { hitRate: cacheStats.hitRate, estimatedSavedTokens: cacheStats.estimatedSavedTokens },
            runtimeVerification: { total: runtimeVerifReport.stats.total, verified: runtimeVerifReport.stats.verified, blocked: runtimeVerifReport.stats.blocked, partial: runtimeVerifReport.stats.partial, unreachable: runtimeVerifReport.stats.unreachable, upgraded: runtimeVerifReport.stats.upgraded, downgraded: runtimeVerifReport.stats.downgraded },
            wholeSystemGraph: wholeSysSummary, proofObligations: proofSummary, knowledgeGraph: { cweMatched: knowledgeReport.stats.cweMatched, cveMatched: knowledgeReport.stats.cveMatched, exploitMatched: knowledgeReport.stats.exploitMatched, avgCvss: knowledgeReport.stats.avgCvss },
            deterministicDominance: { total: dominanceResult.stats.total, confirmed: dominanceResult.stats.confirmed, annotated: dominanceResult.stats.annotated, rejected: dominanceResult.stats.rejected, deterministic: dominanceResult.stats.deterministic, hallucinationsKilled: dominanceResult.stats.hallucinationsKilled },
            fpMinimizer: { total: fpResult.stats.total, frameworkSafe: fpResult.stats.frameworkSafe, sanitizerCertain: fpResult.stats.sanitizerCertain, deadCode: fpResult.stats.deadCode, privilegeGated: fpResult.stats.privilegeGated, testCode: fpResult.stats.testCode, typeSafe: fpResult.stats.typeSafe, active: fpResult.stats.active },
            deltaAnalysis: { mode: deltaResult.mode, newIssues: deltaResult.newIssues.length, regressions: deltaResult.regressions.length, resolved: deltaResult.resolvedIssues.length, newTrustBoundaries: deltaResult.newTrustBoundaries, newSinks: deltaResult.newSinks },
            incrementalGraph: graphResult.stats, policyLayer: { total: policyResult.stats.total, suppressed: policyResult.stats.suppressed, escalated: policyResult.stats.escalated, demoted: policyResult.stats.demoted, requireFix: policyResult.stats.requireFix, ciGate: ciGate.pass, ciBlockReason: ciGate.ciBlockReason },
            modelSpecialization: { securityModel: secAssignment.modelId, remediationModel: remAssignment.modelId, estimatedCostSavingPct: costSaving },
            memoryRefinement: { activeVulns: memRefinedStats.activeVulns, resolvedVulns: memRefinedStats.resolvedVulns, teamSuppressions: memRefinedStats.teamSuppressions, escalatingDrifts: memRefinedStats.escalatingDrifts, volatileDrifts: memRefinedStats.volatileDrifts },
            benchmarkStats: benchReport, languageProfile: { detected: detectedLang, hint: langHint, criticalSinksFound: langProfile.criticalSinks.filter(p => p.test(code)).length, routingOverride: langRoutingOverride, supplement: langSupplement.length > 0 },
            smartContext: contextResult.truncated ? { totalLines: contextResult.totalLines, keptLines: contextResult.keptLines, truncated: contextResult.truncated, securityDensity: contextResult.securityDensity, hotspotCount: contextResult.hotspots.length } : undefined,
          },
        };
        emit({ type: 'done', result });

      } catch(err) {
        const status = (err as Record<string, unknown>)?.status as number | undefined;
        const message = err instanceof Error ? err.message : String(err);
        console.error('[stream] fatal:', status, message);
        let userMsg = 'Analysis unavailable. Please try again.';
        if (status === 401 || status === 403) userMsg = 'Invalid API key — check your dashboard settings.';
        else if (status === 402) userMsg = 'Out of credits — top up at openrouter.ai/settings/credits or use a :free model.';
        else if (status === 429) userMsg = 'Rate limit — wait a moment and retry';
        else if (message.includes('All models failed')) userMsg = message;
        emit({ type: 'error', error: userMsg, result: FALLBACK });
      } finally {
        clearInterval(_keepalive);
        try { controller.close(); } catch { /**/ }
      }
    },
  });

  return new Response(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no', 'Transfer-Encoding': 'chunked' } });
}