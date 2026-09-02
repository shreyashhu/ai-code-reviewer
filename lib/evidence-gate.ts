/**
 * Last-mile quality gate for findings that originate from a probabilistic model.
 * A useful review must point back to the submitted source; otherwise it is not
 * presented as a finding. Deterministic findings are retained, but still get a
 * source excerpt so the UI can make the evidence inspectable.
 */
export interface EvidenceIssue {
  type: 'bug' | 'risk' | 'suggestion';
  severity: 'high' | 'medium' | 'low';
  title: string;
  explanation: string;
  line: number | null;
  confidence?: number;
  evidence?: { status: 'verified' | 'supported'; excerpt: string; score: number };
}

export interface EvidenceGateStats {
  input: number;
  retained: number;
  rejected: number;
  verified: number;
}

const SINK_PATTERN = /\b(?:eval|exec|system|shell_exec|Process\.Start|Runtime\.getRuntime|pickle\.loads?|unserialize|deserialize|query|execute|raw|innerHTML|dangerouslySetInnerHTML|redirect|open|readFile|writeFile|child_process|password|secret|token|api[_-]?key)\b/i;
const STOP_WORDS = new Set(['with', 'from', 'that', 'this', 'into', 'code', 'input', 'data', 'user', 'issue', 'risk', 'security', 'missing', 'unsafe', 'potential', 'possible', 'vulnerability', 'injection', 'validation']);

function excerptFor(lines: string[], line: number | null): { excerpt: string; validLine: boolean; sourceLine: string } {
  if (line === null || line < 1 || line > lines.length) return { excerpt: '', validLine: false, sourceLine: '' };
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  return {
    excerpt: lines.slice(start, end).map((value, index) => `${start + index + 1}: ${value}`).join('\n'),
    validLine: true,
    sourceLine: lines[line - 1] ?? '',
  };
}

function hasClaimAnchor(issue: EvidenceIssue, code: string): boolean {
  const terms = `${issue.title} ${issue.explanation}`
    .toLowerCase()
    .match(/[a-z_][a-z0-9_.-]{4,}/g) ?? [];
  return terms.some(term => !STOP_WORDS.has(term) && code.toLowerCase().includes(term));
}

export function gateFindings<T extends EvidenceIssue>(issues: T[], code: string, deterministicTitles: Set<string>): { issues: T[]; stats: EvidenceGateStats } {
  const lines = code.split(/\r?\n/);
  let rejected = 0;
  let verified = 0;
  const retained = issues.flatMap(issue => {
    const deterministic = deterministicTitles.has(issue.title.toLowerCase().trim());
    const { excerpt, validLine, sourceLine } = excerptFor(lines, issue.line);
    const score = (deterministic ? 4 : 0) + (validLine ? 2 : 0) + (sourceLine && SINK_PATTERN.test(sourceLine) ? 2 : 0) + (hasClaimAnchor(issue, code) ? 1 : 0);

    // Suggestions are intentionally lower-stakes, but bugs and risks need a
    // concrete source location plus either a known rule, sink, or claim anchor.
    const threshold = issue.type === 'suggestion' ? 2 : 3;
    if ((issue.type !== 'suggestion' && !validLine) || score < threshold) {
      rejected++;
      return [];
    }
    if (deterministic || score >= 4) verified++;
    return [{
      ...issue,
      confidence: Math.min(issue.confidence ?? 0.7, deterministic || score >= 4 ? 0.95 : 0.78),
      evidence: { status: deterministic || score >= 4 ? 'verified' : 'supported', excerpt, score },
    }];
  });

  return { issues: retained, stats: { input: issues.length, retained: retained.length, rejected, verified } };
}
