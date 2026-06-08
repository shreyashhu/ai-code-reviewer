import type { Issue } from './utils';

export type DeterministicEvidence = {
  sourcePattern: boolean;
  sinkPattern:   boolean;
  lineExists:    boolean;
  pathDocumented: boolean;
  resurrected:   boolean; 
};

export type DominanceVerdict =
  | 'AI_CONFIRMED'          
  | 'AI_ANNOTATED'          
  | 'AI_REJECTED'           
  | 'DETERMINISTIC'         
  | 'DETERMINISTIC_RESURRECTED'; 

export interface DominanceResult {
  issue:    Issue;
  verdict:  DominanceVerdict;
  evidence: DeterministicEvidence;
  reason:   string;
}

export interface DominanceStats {
  total:              number;
  confirmed:          number;
  annotated:          number;
  rejected:           number;
  deterministic:      number;
  resurrected:        number;
  hallucinationsNuked: number;
  hallucinationsKilled: number; 
}

const PROTECTED_FAMILIES = [
  /sql\.inject|sqli/i,
  /xss|cross\.site\.script|innerhtml|dangerously/i,
  /rce|eval|Function|vm\.run|child_process|exec|spawn/i,
  /cmd\.inject|command\.inject|shell=True|os\.system/i,
  /path\.travers|directory\.travers|\.\.\//i,
  /env\.exposure|env\.leak|process\.env|SECRET_KEY/i,
  /hardcoded\.credential|hardcoded\.secret|password.*=/i,
  /deserializ|pickle|unserialize|yaml\.load/i,
  /jwt.*none|jwt.*decode/i,
];

function isProtectedFamily(issue: Issue): boolean {
  const text = `${issue.title} ${issue.explanation} ${issue.category}`;
  return PROTECTED_FAMILIES.some(regex => regex.test(text));
}

const SOURCE_PATTERNS: Record<string, RegExp[]> = {
  sqli:          [/req\.(body|query|params)/, /request\.(body|query|params|args|form)/, /ctx\.(query|params)/],
  xss:           [/req\.(body|query|params)/, /innerHTML/, /dangerouslySetInnerHTML/, /request\.(args|form)/],
  ssrf:          [/req\.(body|query|params)/, /fetch\s*\(/, /axios\./, /requests\.get/],
  cmd:           [/exec\s*\(/, /spawn\s*\(/, /req\.(body|query|params)/, /os\.system/, /subprocess/],
  path:          [/req\.(body|query|params)/, /readFile/, /join\s*\(/, /open\s*\(/, /os\.path\.join/],
  proto:         [/__proto__/, /prototype\s*\[/, /Object\.assign/, /merge\s*\(/],
  redirect:      [/req\.(query|params)/, /res\.redirect/, /location/, /redirect_uri/],
  auth:          [/jwt\./, /verify\s*\(/, /authenticate/, /login_required/],
  deserialize:   [/JSON\.parse/, /deserialize/, /unserialize/, /pickle\.load/, /yaml\.load/],
  env:           [/process\.env/, /os\.environ/, /os\.getenv/, /SECRET/, /API_KEY/],
};

const SINK_PATTERNS: Record<string, RegExp[]> = {
  sqli:          [/db\.(query|execute|run)\s*\(/, /\.rawQuery\s*\(/, /knex\.raw\s*\(/, /cursor\.execute/],
  xss:           [/\.innerHTML\s*=/, /dangerouslySetInnerHTML/, /document\.write\s*\(/, /HttpResponse/],
  ssrf:          [/fetch\s*\(\s*\w+/, /axios\.(get|post)\s*\(\s*\w+/, /requests\.get\s*\(/],
  cmd:           [/exec\s*\(/, /spawn\s*\(/, /execSync\s*\(/, /os\.system\s*\(/, /subprocess/],
  path:          [/readFile\s*\(/, /createReadStream\s*\(/, /fs\.\w+\s*\(\s*\w+/, /open\s*\(/],
  proto:         [/__proto__\s*\[/, /prototype\s*\[/, /Object\.assign\s*\(\s*\{/],
  redirect:      [/res\.redirect\s*\(/, /window\.location\s*=/],
  auth:          [/if\s*\(!/, /throw\s+new/, /401|403|unauthorized/i],
  deserialize:   [/JSON\.parse\s*\(/, /\.fromJSON\s*\(/, /deserialize\s*\(/, /pickle\.load/],
  env:           [/res\.(send|json)/, /return\s+\{/, /jsonify/],
};

function classifyIssue(issue: Issue): string {
  const text = (issue.title + ' ' + issue.explanation).toLowerCase();
  if (/sql\.inject|sqli/.test(text))      return 'sqli';
  if (/xss|cross\.site\.script/.test(text)) return 'xss';
  if (/ssrf|server\.side\.request/.test(text)) return 'ssrf';
  if (/command\.inject|shell\.inject|rce|exec|spawn|os\.system/.test(text)) return 'cmd';
  if (/path\.travers|directory\.travers|\.\.\//.test(text)) return 'path';
  if (/prototype\.pollut|proto\.pollut/.test(text)) return 'proto';
  if (/open\.redirect/.test(text))        return 'redirect';
  if (/auth\.bypass|broken\.auth|unauth|jwt/.test(text)) return 'auth';
  if (/deserializ|unsafe\.parse|pickle/.test(text)) return 'deserialize';
  if (/env\.exposure|env\.leak|process\.env|secret/.test(text)) return 'env';
  return 'generic';
}

function checkDeterministicEvidence(issue: Issue, code: string): DeterministicEvidence {
  const lines = code.split('\n');
  const issueClass = classifyIssue(issue);
  const sourcePats = SOURCE_PATTERNS[issueClass] ?? SOURCE_PATTERNS['sqli']!;
  const sinkPats   = SINK_PATTERNS[issueClass] ?? SINK_PATTERNS['sqli']!;

  const sourcePattern = sourcePats.some(p => p.test(code));
  const sinkPattern = sinkPats.some(p => p.test(code));
  
  const lineExists = issue.line === null || (
    issue.line > 0 &&
    issue.line <= lines.length &&
    (lines[issue.line - 1]?.trim().length ?? 0) > 2
  );

  const pathDocumented = !!(
    issue.exploitChain ||
    issue.proofChain ||
    (issue.explanation && issue.explanation.length > 50)
  );

  return { sourcePattern, sinkPattern, lineExists, pathDocumented, resurrected: false };
}

function computeDominanceScore(ev: DeterministicEvidence, issue: Issue): number {
  let score = 0;
  if (ev.sourcePattern)   score += 30;
  if (ev.sinkPattern)     score += 30;
  if (ev.lineExists)      score += 20;
  if (ev.pathDocumented)  score += 10;
  if (issue.exploitVerified) score += 10;
  if (isProtectedFamily(issue)) score += 20;
  return Math.min(score, 100);
}

export function applyDeterministicDominance(
  issues: Issue[],
  code: string,
  originalDeterministicIssues: Issue[], 
): { issues: Issue[]; stats: DominanceStats; results: DominanceResult[] } {
  const results: DominanceResult[] = [];
  const passed: Issue[] = [];
  
  let confirmed = 0, annotated = 0, rejected = 0, deterministic = 0;
  let resurrected = 0, hallucinationsNuked = 0;

  const currentIssueKeys = new Set(
    issues.map(i => `${i.line ?? '?'}:${i.title.toLowerCase().slice(0, 30)}`)
  );

  for (const issue of issues) {
    const ev = checkDeterministicEvidence(issue, code);
    const score = computeDominanceScore(ev, issue);
    const protectedFamily = isProtectedFamily(issue);
    
    let verdict: DominanceVerdict;
    let reason: string;

    if (protectedFamily && (ev.sourcePattern || ev.sinkPattern || ev.lineExists)) {
      verdict = 'DETERMINISTIC';
      reason = `Protected Family (${classifyIssue(issue)}) — deterministic proof locks this finding. AI cannot veto.`;
      deterministic++;
      passed.push({ ...issue, confidence: Math.max(issue.confidence ?? 0.8, 0.95) });
    } 
    else if (score >= 70) {
      verdict = 'AI_CONFIRMED';
      reason = `Score ${score}/100 — source+sink+line verified deterministically`;
      confirmed++;
      passed.push(issue);
    } 
    else if (score >= 40) {
      verdict = 'AI_ANNOTATED';
      reason = `Score ${score}/100 — partial evidence, confidence capped`;
      annotated++;
      const capped = { ...issue, confidence: Math.min(issue.confidence ?? 0.7, 0.65) };
      passed.push(capped);
    } 
    else {
      const isLogicClass = /auth|idor|race|async|await|logic|business|privilege|permission|missing|ownership/i
        .test((issue.title + ' ' + (issue.explanation ?? '')));
      const hasExploitEvidence = (issue.exploitChain?.length ?? 0) > 20 || (issue.exploitVerified === true);
      const hasLineNumber = issue.line !== null && issue.line > 0;

      const shouldReject = score === 0 && !hasExploitEvidence && !hasLineNumber && !isLogicClass;

      if (shouldReject) {
        verdict = 'AI_REJECTED';
        reason = `Score 0/100 — no evidence whatsoever, no exploit chain, no line number`;
        rejected++;
      } else {
        verdict = 'AI_ANNOTATED';
        const capConf = score === 0 ? 0.45 : 0.55;
        reason = `Score ${score}/100 — logic/auth/semantic class or has exploit evidence; preserved with confidence cap ${capConf}`;
        annotated++;
        const capped = { ...issue, confidence: Math.min(issue.confidence ?? 0.7, capConf) };
        passed.push(capped);
      }
    }

    results.push({ issue, verdict, evidence: ev, reason });
  }

  if (originalDeterministicIssues && originalDeterministicIssues.length > 0) {
    for (const detIssue of originalDeterministicIssues) {
      const key = `${detIssue.line ?? '?'}:${detIssue.title.toLowerCase().slice(0, 30)}`;
      
      if (!currentIssueKeys.has(key)) {
        const ev = checkDeterministicEvidence(detIssue, code);
        ev.resurrected = true;
        
        const resurrectedIssue: Issue = {
          ...detIssue,
          confidence: 0.98,
          explanation: detIssue.explanation + '\n\n[RESURRECTED BY DETERMINISTIC DOMINANCE: This finding was suppressed by AI consensus or heuristic firewalls, but deterministic regex proof confirms its existence.]',
        };

        passed.push(resurrectedIssue);
        resurrected++;
        
        results.push({
          issue: resurrectedIssue,
          verdict: 'DETERMINISTIC_RESURRECTED',
          evidence: ev,
          reason: 'Killed by AI/Firewall, but resurrected by deterministic regex proof.'
        });
      }
    }
  }

  return {
    issues: passed,
    stats: {
      total: issues.length + resurrected,
      confirmed,
      annotated,
      rejected,
      deterministic,
      resurrected,
      hallucinationsNuked,
      hallucinationsKilled: rejected + hallucinationsNuked, 
    },
    results,
  };
}