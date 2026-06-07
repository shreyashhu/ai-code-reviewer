// ─────────────────────────────────────────────────────────────────────────────
// MULTI-MODEL SPECIALIZATION — v1.4
//
// One model for everything produces mediocre results at unnecessary cost.
// This module assigns the right model class to each task:
//
//   routing         → small/fast (haiku, gpt-4o-mini)
//   syntax/AST      → code-specialized (deepseek, starcoder)
//   security reason → frontier (claude-sonnet, gpt-4o)
//   remediation     → patch-tuned (gpt-4o-mini fine-tuned for code edits)
//   arbitration     → deterministic-assisted (deterministic result wins ties)
//
// Hallucination and cost both drop when you stop asking a frontier model
// to do work a deterministic engine handles better.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Types ────────────────────────────────────────────────────────────────────

export type TaskKind =
  | 'routing'         // classify code tier
  | 'syntax'          // AST-level pattern check
  | 'security'        // security reasoning + exploit analysis
  | 'remediation'     // generate patch
  | 'arbitration'     // resolve conflicting verdicts

export type ModelClass =
  | 'small-fast'      // 4o-mini, haiku — routing + cheap tasks
  | 'code-specialized'// deepseek-coder, starcoder — syntax
  | 'frontier'        // claude-sonnet, gpt-4o — security reasoning
  | 'patch-tuned'     // 4o-mini for code diffs — remediation
  | 'deterministic'   // no AI — pure rule engine

export interface ModelAssignment {
  task:        TaskKind;
  modelClass:  ModelClass;
  modelId:     string;     // concrete model string for API calls
  reason:      string;
  /** Estimated relative cost vs frontier (1.0 = same cost) */
  costFactor:  number;
}

export interface SpecializationStats {
  taskBreakdown: Record<TaskKind, number>;
  estimatedCostSavingFactor: number;  // vs always-frontier baseline
}

// ─── Model registry ──────────────────────────────────────────────────────────

const MODEL_REGISTRY: Record<ModelClass, { primary: string; fallback: string; costFactor: number }> = {
  'small-fast':       { primary: 'openai/gpt-4o-mini',        fallback: 'anthropic/claude-3-haiku',   costFactor: 0.03 },
  'code-specialized': { primary: 'openai/gpt-4o-mini',        fallback: 'openai/gpt-4o-mini',         costFactor: 0.03 },
  'frontier':         { primary: 'anthropic/claude-sonnet-4', fallback: 'openai/gpt-4o',              costFactor: 1.0  },
  'patch-tuned':      { primary: 'openai/gpt-4o-mini',        fallback: 'anthropic/claude-3-haiku',   costFactor: 0.03 },
  'deterministic':    { primary: '__deterministic__',          fallback: '__deterministic__',          costFactor: 0.0  },
};

// ─── Task → model class mapping ───────────────────────────────────────────────

const TASK_CLASS_MAP: Record<TaskKind, ModelClass> = {
  routing:      'small-fast',
  syntax:       'code-specialized',
  security:     'frontier',
  remediation:  'patch-tuned',
  arbitration:  'deterministic',
};

// ─── Assignment engine ────────────────────────────────────────────────────────

export function assignModel(task: TaskKind, availableModels?: string[]): ModelAssignment {
  const modelClass = TASK_CLASS_MAP[task];
  const registry   = MODEL_REGISTRY[modelClass];

  let modelId = registry.primary;
  if (availableModels && availableModels.length > 0) {
    // Fall back to whatever the caller has configured if primary isn't available
    if (!availableModels.includes(modelId)) {
      modelId = availableModels.find(m => m === registry.fallback) ?? availableModels[0];
    }
  }

  const reasons: Record<TaskKind, string> = {
    routing:     'Small/fast model sufficient for code classification; no security reasoning needed',
    syntax:      'Code-specialized model produces fewer hallucinations on AST/pattern tasks',
    security:    'Frontier model required for nuanced exploit reasoning and chain analysis',
    remediation: 'Patch-tuned model produces tighter diffs with lower off-by-one error rates',
    arbitration: 'Deterministic engine wins ties; AI arbitration only needed when deterministic is ambiguous',
  };

  return {
    task, modelClass, modelId,
    reason: reasons[task],
    costFactor: registry.costFactor,
  };
}

export function assignAll(tasks: TaskKind[], availableModels?: string[]): ModelAssignment[] {
  return tasks.map(t => assignModel(t, availableModels));
}

// ─── Cost estimation ──────────────────────────────────────────────────────────

export function estimateCostSaving(assignments: ModelAssignment[]): number {
  if (assignments.length === 0) return 0;
  const totalActual   = assignments.reduce((s, a) => s + a.costFactor, 0);
  const totalFrontier = assignments.length * 1.0;
  return 1 - totalActual / totalFrontier;
}

// ─── Stats collector ──────────────────────────────────────────────────────────

const _stats: Record<TaskKind, number> = {
  routing: 0, syntax: 0, security: 0, remediation: 0, arbitration: 0,
};

export function recordTaskCall(task: TaskKind): void {
  _stats[task] = (_stats[task] ?? 0) + 1;
}

export function getSpecializationStats(assignments: ModelAssignment[]): SpecializationStats {
  return {
    taskBreakdown: { ..._stats },
    estimatedCostSavingFactor: estimateCostSaving(assignments),
  };
}

// ─── Arbitration helper ───────────────────────────────────────────────────────

/**
 * Resolve a conflict between AI and deterministic verdicts.
 * Deterministic always wins if it has an opinion.
 * If deterministic is neutral, use the AI verdict with a confidence penalty.
 */
export function arbitrate(
  deterministicVerdict: 'flag' | 'suppress' | 'neutral',
  aiVerdict: 'flag' | 'suppress',
  aiConfidence: number,
): { verdict: 'flag' | 'suppress'; confidence: number; source: 'deterministic' | 'ai' } {
  if (deterministicVerdict !== 'neutral') {
    return { verdict: deterministicVerdict, confidence: 1.0, source: 'deterministic' };
  }
  // AI wins only when deterministic has no opinion, and confidence is penalized
  return {
    verdict:    aiVerdict,
    confidence: Math.min(aiConfidence, 0.70),  // cap at 70% without deterministic backing
    source:     'ai',
  };
}
