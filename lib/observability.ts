// ─────────────────────────────────────────────────────────────────────────────
// OBSERVABILITY ENGINE v1
//
// Provides per-stage timing, token telemetry, cache hit rates, and
// FP/FN tracking so the pipeline can be optimized intelligently.
//
// "Without this, you cannot optimize intelligently." — roadmap doc
//
// All state is scoped to a single analysis run (pass an ObservabilitySession
// object through the pipeline stages).
// ─────────────────────────────────────────────────────────────────────────────

// ─── Types ────────────────────────────────────────────────────────────────────

export interface StageTiming {
  stage:      string;
  startMs:    number;
  endMs:      number;
  durationMs: number;
  cached:     boolean;
}

export interface TokenUsage {
  stage:         string;
  model:         string;
  inputTokens:   number;
  outputTokens:  number;
  totalTokens:   number;
  estimatedCost: number;  // USD
}

export interface StageResult {
  stage:       string;
  findingsDelta: number;  // positive = added findings, negative = suppressed
  issuesIn:    number;
  issuesOut:   number;
}

export interface ObservabilityReport {
  runId:           string;
  totalDurationMs: number;
  stages:          StageTiming[];
  tokens:          TokenUsage[];
  stageResults:    StageResult[];
  totalInputTokens:  number;
  totalOutputTokens: number;
  estimatedCostUsd:  number;
  slowestStage:      string | null;
  fastestStage:      string | null;
  cacheHitSummary:   { total: number; hits: number; rate: number };
}

// ─── Cost model ───────────────────────────────────────────────────────────────
// Rough per-1k-token prices for common models (input / output)

const MODEL_COSTS: Record<string, [number, number]> = {
  'openai/gpt-4o-mini':          [0.00015,  0.0006 ],
  'openai/gpt-4o':               [0.005,    0.015  ],
  'anthropic/claude-3-haiku':    [0.00025,  0.00125],
  'anthropic/claude-3-sonnet':   [0.003,    0.015  ],
  'anthropic/claude-3-5-sonnet': [0.003,    0.015  ],
  'google/gemini-flash-1.5':     [0.000075, 0.0003 ],
  'meta-llama/llama-3.1-8b':    [0.0001,   0.0001 ],
  'default':                     [0.001,    0.002  ],
};

function estimateCost(model: string, inputTok: number, outputTok: number): number {
  const [inRate, outRate] = MODEL_COSTS[model] ?? MODEL_COSTS['default']!;
  return (inputTok / 1000) * inRate + (outputTok / 1000) * outRate;
}

// Rough token estimation from character count (1 token ≈ 4 chars)
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

// ─── Session ──────────────────────────────────────────────────────────────────

let _runCounter = 0;

export class ObservabilitySession {
  readonly runId: string;

  private timings = new Map<string, StageTiming & { _start: number }>();
  private tokens:  TokenUsage[]    = [];
  private results: StageResult[]   = [];
  private cacheHits   = 0;
  private cacheTotal  = 0;

  constructor() {
    _runCounter++;
    this.runId = `run-${Date.now()}-${_runCounter}`;
  }

  // ── Stage timing ───────────────────────────────────────────────────────────

  startStage(stage: string, cached = false): void {
    this.timings.set(stage, {
      stage,
      startMs:    Date.now(),
      endMs:      0,
      durationMs: 0,
      cached,
      _start:     Date.now(),
    });
    this.cacheTotal++;
    if (cached) this.cacheHits++;
  }

  endStage(stage: string): void {
    const t = this.timings.get(stage);
    if (!t) return;
    t.endMs = Date.now();
    t.durationMs = t.endMs - t._start;
  }

  // ── Token tracking ────────────────────────────────────────────────────────

  recordTokens(
    stage:        string,
    model:        string,
    inputTokens:  number,
    outputTokens: number,
  ): void {
    this.tokens.push({
      stage,
      model,
      inputTokens,
      outputTokens,
      totalTokens:   inputTokens + outputTokens,
      estimatedCost: estimateCost(model, inputTokens, outputTokens),
    });
  }

  /**
   * Convenience: estimate from string lengths when actual token counts
   * are unavailable (most OpenRouter responses don't return usage).
   */
  recordTokensFromStrings(
    stage:   string,
    model:   string,
    prompt:  string,
    reply:   string,
  ): void {
    this.recordTokens(stage, model, estimateTokens(prompt), estimateTokens(reply));
  }

  // ── Stage issue counts ─────────────────────────────────────────────────────

  recordStageResult(stage: string, issuesIn: number, issuesOut: number): void {
    this.results.push({
      stage,
      issuesIn,
      issuesOut,
      findingsDelta: issuesOut - issuesIn,
    });
  }

  // ── Report ─────────────────────────────────────────────────────────────────

  report(): ObservabilityReport {
    const completedTimings = [...this.timings.values()]
      .filter(t => t.endMs > 0)
      .map(({ stage, startMs, endMs, durationMs, cached }) =>
        ({ stage, startMs, endMs, durationMs, cached }));

    const totalMs   = completedTimings.reduce((n, t) => n + t.durationMs, 0);
    const sorted    = [...completedTimings].sort((a, b) => b.durationMs - a.durationMs);
    const slowest   = sorted[0]?.stage ?? null;
    const fastest   = sorted[sorted.length - 1]?.stage ?? null;

    const totalInputTokens  = this.tokens.reduce((n, t) => n + t.inputTokens,  0);
    const totalOutputTokens = this.tokens.reduce((n, t) => n + t.outputTokens, 0);
    const estimatedCostUsd  = this.tokens.reduce((n, t) => n + t.estimatedCost, 0);

    return {
      runId:             this.runId,
      totalDurationMs:   totalMs,
      stages:            completedTimings,
      tokens:            this.tokens,
      stageResults:      this.results,
      totalInputTokens,
      totalOutputTokens,
      estimatedCostUsd:  Math.round(estimatedCostUsd * 100_000) / 100_000,
      slowestStage:      slowest,
      fastestStage:      fastest,
      cacheHitSummary: {
        total: this.cacheTotal,
        hits:  this.cacheHits,
        rate:  this.cacheTotal > 0 ? this.cacheHits / this.cacheTotal : 0,
      },
    };
  }

  // ── Logging helper ─────────────────────────────────────────────────────────

  logSummary(): void {
    const r = this.report();
    console.log(
      `[obs] run=${r.runId} total=${r.totalDurationMs}ms ` +
      `tokens=${r.totalInputTokens}in/${r.totalOutputTokens}out ` +
      `cost=$${r.estimatedCostUsd.toFixed(4)} ` +
      `cache=${r.cacheHitSummary.hits}/${r.cacheHitSummary.total} ` +
      `slowest=${r.slowestStage}`,
    );
    for (const t of r.stages.sort((a, b) => b.durationMs - a.durationMs).slice(0, 5)) {
      console.log(`  [stage] ${t.stage}: ${t.durationMs}ms${t.cached ? ' (cached)' : ''}`);
    }
  }
}

// ─── Singleton accessor ───────────────────────────────────────────────────────
// Each POST request creates its own session via `new ObservabilitySession()`.
// This module also exposes a process-level stats aggregator for long-running
// deployments (e.g. to expose a /health endpoint with scan counts).

export interface ProcessStats {
  totalScans:     number;
  totalTokensIn:  number;
  totalTokensOut: number;
  totalCostUsd:   number;
  avgDurationMs:  number;
  lastScanAt:     number | null;
}

let _processStats: ProcessStats = {
  totalScans:     0,
  totalTokensIn:  0,
  totalTokensOut: 0,
  totalCostUsd:   0,
  avgDurationMs:  0,
  lastScanAt:     null,
};

export function recordScanToProcessStats(report: ObservabilityReport): void {
  _processStats.totalScans++;
  _processStats.totalTokensIn  += report.totalInputTokens;
  _processStats.totalTokensOut += report.totalOutputTokens;
  _processStats.totalCostUsd   += report.estimatedCostUsd;
  _processStats.avgDurationMs   =
    (_processStats.avgDurationMs * (_processStats.totalScans - 1) + report.totalDurationMs)
    / _processStats.totalScans;
  _processStats.lastScanAt = Date.now();
}

export function getProcessStats(): ProcessStats {
  return { ..._processStats };
}
