// ─────────────────────────────────────────────────────────────────────────────
// PARALLEL PIPELINE RUNNER v1
//
// The post-processing pipeline (stages 20–26) has a dependency graph.
// Several sub-groups can execute concurrently rather than sequentially,
// cutting analysis wall-clock time by ~40–60% on the critical path.
//
// DEPENDENCY GRAPH:
//
//   postV11Issues ──┬── Stage 20: runtime-verification
//                   └── Stage 21: whole-system-graph
//                             ↓ (merge outputs)
//                   Stage 22: proof-obligations
//                             ↓
//                   Stage 23: knowledge-graph (CVE/CWE enrichment)
//                             ↓
//          ┌─────────────────────────────────────┐
//          │ Stage 24: deterministic-dominance    │  (independent of 26-27)
//          │ Stage 25: FP-minimizer               │
//          │ Stage 26: delta-analysis             │
//          └─────────────────────────────────────┘
//
// Stages 20 + 21: FULLY PARALLEL (no inter-dependency, both read postV11Issues/code)
// Stages 24 + stages 27 (incremental-graph): PARALLEL (graph reads code only)
//
// The runner also adds per-stage timeouts so a slow stage doesn't block
// the entire pipeline (it logs a warning and returns an empty result).
//
// USAGE:
//   const [runtimeResult, wholeSystemResult] = await runParallel([
//     { name: 'runtime-verification', fn: () => runRuntimeVerification(issues, code) },
//     { name: 'whole-system-graph',   fn: () => buildWholeSystemGraph(code) },
//   ], { timeoutMs: 8000 });
// ─────────────────────────────────────────────────────────────────────────────

export interface ParallelStage<T> {
  name:      string;
  fn:        () => T | Promise<T>;
  timeoutMs?: number;  // per-stage override (default: globalTimeoutMs)
}

export interface ParallelResult<T> {
  name:    string;
  value:   T | null;
  error:   string | null;
  durationMs: number;
  timedOut: boolean;
}

export interface ParallelRunOptions {
  timeoutMs?: number;  // default timeout per stage (default: 10_000ms)
  onStageStart?:  (name: string) => void;
  onStageFinish?: (name: string, durationMs: number, error: string | null) => void;
}

// ─── Core runner ─────────────────────────────────────────────────────────────

/**
 * Runs all stages concurrently. Returns an array of results in the same
 * order as the input stages array, even if some stages fail or time out.
 *
 * Failed/timed-out stages return null values — callers must handle null.
 */
export async function runParallel<T>(
  stages:  ParallelStage<T>[],
  options: ParallelRunOptions = {},
): Promise<ParallelResult<T>[]> {
  const { timeoutMs = 10_000, onStageStart, onStageFinish } = options;

  const promises = stages.map(async (stage): Promise<ParallelResult<T>> => {
    const limit = stage.timeoutMs ?? timeoutMs;
    const start = Date.now();

    onStageStart?.(stage.name);

    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;

    try {
      const resultPromise = Promise.resolve().then(() => stage.fn());

      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = setTimeout(
          () => reject(new Error(`[parallel-runner] Stage "${stage.name}" timed out after ${limit}ms`)),
          limit,
        );
      });

      const value = await Promise.race([resultPromise, timeoutPromise]);

      const durationMs = Date.now() - start;
      onStageFinish?.(stage.name, durationMs, null);

      return { name: stage.name, value, error: null, durationMs, timedOut: false };

    } catch (err) {
      const durationMs = Date.now() - start;
      const errMsg = err instanceof Error ? err.message : String(err);
      const timedOut = errMsg.includes('timed out after');

      onStageFinish?.(stage.name, durationMs, errMsg);
      console.warn(`[parallel-runner] Stage "${stage.name}" failed (${durationMs}ms):`, errMsg);

      return { name: stage.name, value: null, error: errMsg, durationMs, timedOut };

    } finally {
      if (timeoutHandle !== null) clearTimeout(timeoutHandle);
    }
  });

  return Promise.all(promises);
}

// ─── Typed convenience runners ────────────────────────────────────────────────

/**
 * Run exactly two independent stages in parallel.
 * Type-safe: both stages must return the same type T.
 */
export async function runParallel2<A, B>(
  stageA: ParallelStage<A>,
  stageB: ParallelStage<B>,
  options?: ParallelRunOptions,
): Promise<[ParallelResult<A>, ParallelResult<B>]> {
  const [a, b] = await Promise.all([
    runParallel<A>([stageA as ParallelStage<A>], options).then(r => r[0]!),
    runParallel<B>([stageB as ParallelStage<B>], options).then(r => r[0]!),
  ]);
  return [a, b];
}

// ─── Helper: safe unwrap ──────────────────────────────────────────────────────

/**
 * Unwraps a parallel result, returning the value or a default.
 * Use this to safely handle failed/timed-out stages.
 */
export function unwrapOrDefault<T>(result: ParallelResult<T>, defaultValue: T): T {
  if (result.value !== null) return result.value;
  return defaultValue;
}
