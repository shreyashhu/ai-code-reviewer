// ─────────────────────────────────────────────────────────────────────────────
// STRUCTURAL TAINT ENGINE v3 — INTERPROCEDURAL + SSA + FRAMEWORK-AWARE
//
// Improvements over v2:
//  • Alias/SSA tracking: const b = a → b is tainted if a is (multi-hop)
//  • Interprocedural: tracks taint through function calls (call graph, 4 hops)
//  • Framework-aware: Next.js searchParams, params, Express, Lambda, Fastify
//  • More sinks: exec, spawn, path.join, readFile, redirect, createReadStream
//  • Context-sensitive sanitizer scoring (HTML / URL / SQL / CMD contexts)
//  • Dead-path suppression: guard clauses reduce false positives
//  • Compact summary output: prevents token waste in AI context window
// ─────────────────────────────────────────────────────────────────────────────

export interface TaintFinding {
  ruleId:    string;
  title:     string;
  line:      number;
  evidence:  string;
  confirmed: boolean;
  safe:      boolean;
  hopCount?: number;
}

export interface TaintReport {
  taintedVars:    Map<string, number>;
  sqlVulns:       TaintFinding[];
  sqlSafeLines:   Set<number>;
  xssVulns:       TaintFinding[];
  xssSafeLines:   Set<number>;
  protoVulns:     TaintFinding[];
  protoSafeLines: Set<number>;
  headerVulns:    TaintFinding[];
  headerSafeLines:Set<number>;
  cmdVulns:       TaintFinding[];
  pathVulns:      TaintFinding[];
  redirectVulns:  TaintFinding[];
  summary:        string;
}

// ── Sanitizer registries ──────────────────────────────────────────────────────
const HTML_SANITIZERS  = /encodeHTML|escapeHtml|DOMPurify\.sanitize|validator\.escape|he\.encode|xss\(/;
const URL_SANITIZERS   = /encodeURIComponent|URL\.parse|new URL\(/;
const SQL_SANITIZERS   = /(?:escape|sanitize)Sql|mysql\.escape/;
const CRLF_SANITIZERS  = /\.replace\s*\(\s*\/\[\\r\\n|\.replace\s*\(\s*\/\\r\\n/;
const PATH_SANITIZERS  = /path\.normalize|\.replace\s*\(.*\.\./;
const SQL_SAFE_CALL    = /db\.(?:query|execute|run)\s*\([^)]*,\s*\[/;
const SAFE_URL_ALLOW   = /(?:ALLOWED_HOSTS|allowedDomains|whitelist|allowlist)/i;

// ── Taint Sources (multi-framework) ──────────────────────────────────────────
interface SourcePattern { re: RegExp; destructure: boolean; label: string }

const SOURCE_PATTERNS: SourcePattern[] = [
  // Express / Fastify
  { re: /(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:query|params|body|headers)\.(\w+)/, destructure: false, label: 'express-direct' },
  { re: /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*req\.(?:query|params|body|headers)/, destructure: true,  label: 'express-destructure' },
  { re: /req\.(?:query|params|body|headers)\.(\w+)/, destructure: false, label: 'express-inline' },
  // Next.js
  { re: /(?:const|let|var)\s+(\w+)\s*=\s*(?:request|req)\.nextUrl\.searchParams\.get\(/, destructure: false, label: 'nextjs-searchParams' },
  { re: /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?params/, destructure: true,  label: 'nextjs-params' },
  { re: /searchParams\.get\s*\(\s*['"](\w+)['"]/, destructure: false, label: 'nextjs-searchParams-get' },
  // Koa / generic ctx
  { re: /(?:ctx|context|c)\.(?:query|params|body|request\.body)\.(\w+)/, destructure: false, label: 'ctx' },
  // AWS Lambda
  { re: /event\.(?:queryStringParameters|body|pathParameters)\.(\w+)/, destructure: false, label: 'lambda' },
  // Browser / FormData
  { re: /formData\.get\s*\(\s*['"](\w+)['"]/, destructure: false, label: 'formdata' },
  { re: /new\s+URLSearchParams\s*\([^)]*\)\s*\.get\s*\(\s*['"](\w+)['"]/, destructure: false, label: 'urlsearchparams' },
  { re: /(?:const|let|var)\s+(\w+)\s*=\s*new\s+URL\s*\([^)]+\)\.searchParams/, destructure: false, label: 'url-searchparams' },
  // GraphQL resolvers
  { re: /(?:const|let|var)\s+(\w+)\s*=\s*args\.(\w+)/, destructure: false, label: 'graphql-args' },
  { re: /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*args/, destructure: true,  label: 'graphql-args-destructure' },
  // gRPC / tRPC
  { re: /(?:const|let|var)\s+(\w+)\s*=\s*input\.(\w+)/, destructure: false, label: 'trpc-input' },
  { re: /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*input/, destructure: true,  label: 'trpc-input-destructure' },
  // Python Flask/Django style
  { re: /request\.form\.get\s*\(\s*['"](\w+)['"]/, destructure: false, label: 'flask-form' },
  { re: /request\.args\.get\s*\(\s*['"](\w+)['"]/, destructure: false, label: 'flask-args' },
  { re: /request\.json\.get\s*\(\s*['"](\w+)['"]/, destructure: false, label: 'flask-json' },
  { re: /os\.environ\.get\s*\(\s*['"](\w+)['"]/, destructure: false, label: 'python-env' },
  // Python: function parameters are external inputs (def func(user_id, user_input, ...))
  // Match common taint-y param names
  { re: /def\s+\w+\s*\((?:[^)]*,\s*)?(user_id|user_input|input_\w+|query|request|data|payload|message|content)(\s*,|\s*\))/, destructure: false, label: 'python-func-param' },
  // Python: any direct function param used in SQL/exec context (interprocedural)
  { re: /def\s+\w+\s*\(([a-z_]\w*)(?:\s*,|\s*\))/, destructure: false, label: 'python-any-param' },
];

// ── Function definitions for interprocedural analysis ──────────────────────
interface FuncDef { name: string; params: string[]; body: string; line: number }

function extractFunctions(lines: string[]): FuncDef[] {
  const fns: FuncDef[] = [];
  for (let i = 0; i < lines.length; i++) {
    // JS/TS: function foo(params) or const foo = (params) =>
    const jsM = lines[i].match(/(?:function\s+(\w+)\s*\(([^)]*)\)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?([^)=]*)\)?\s*=>)/);
    // Python: def foo(params):
    const pyM = lines[i].match(/def\s+(\w+)\s*\(([^)]*)\)\s*:/);
    const m = jsM ?? pyM;
    if (!m) continue;
    const name   = m[1] ?? m[3];
    if (!name) continue;
    const rawParams = m[2] ?? m[4] ?? '';
    const params = rawParams.split(',').map(p => p.trim().replace(/[=:].*/,'').replace(/^self$/, '').trim()).filter(p => /^\w+$/.test(p) && p !== 'self');
    const body   = lines.slice(i, Math.min(lines.length, i + 25)).join('\n');
    fns.push({ name, params, body, line: i + 1 });
  }
  return fns;
}

function funcPropagatesTaint(fn: FuncDef, taintedArgs: string[]): boolean {
  if (!taintedArgs.length) return false;
  const ret = fn.body.match(/return\s+([^;\n}]+)/);
  if (!ret) return false;
  return taintedArgs.some(p => {
    // Param appears directly or via template literal in return
    return fn.body.includes(p) && ret[1].includes(p);
  });
}

// ── Dead-path detection: lines after a guard return are suppressed ────────
function buildGuardedLines(lines: string[]): Set<number> {
  // Tracks lines that are guarded by a validation/early-return check.
  // Pattern: if (!input || typeof input !== 'string') return/throw/res.send(400)
  // Lines AFTER the guard in the same block are considered sanitized for that var.
  //
  // Strategy: find guard lines, mark the variable as validated from that line onward
  // within the same function scope. Conservative — only suppress for explicit guard forms.
  const guarded = new Set<number>();

  const GUARD_PATTERNS = [
    /if\s*\(\s*!(\w+)\s*\)\s*(?:return|throw|res\.(?:send|status|end))/,
    /if\s*\(\s*typeof\s+(\w+)\s*!==?\s*['"]string['"]\s*\)\s*(?:return|throw)/,
    /if\s*\(\s*!(\w+)\s*\|\|[^)]*\)\s*(?:return|throw)/,
    /if\s*\(\s*(\w+)\s*===?\s*(?:null|undefined)\s*\)\s*(?:return|throw)/,
    /(\w+)\s*=\s*parseInt\s*\(.*\);\s*if\s*\(\s*isNaN/,
    /const\s+(?:result|parsed|validated)\s*=\s*(?:schema|z\.\w+|Joi\.\w+)\s*\.(?:parse|validate|safeParse)\s*\(/,
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pat of GUARD_PATTERNS) {
      const m = line.match(pat);
      if (m) {
        // Mark the next 15 lines as guarded for this var (conservative window)
        const guardedVar = m[1];
        if (guardedVar) {
          for (let j = i + 1; j < Math.min(lines.length, i + 15); j++) {
            // Only mark as guarded if the guarded var appears in scope
            if (lines[j].includes(guardedVar)) {
              guarded.add(j + 1); // 1-indexed
            }
          }
        }
        break;
      }
    }
  }

  return guarded;
}

export function runTaintAnalysis(code: string): TaintReport {
  const lines = code.split('\n');
  const taintedVars   = new Map<string, number>();

  const sqlVulns:      TaintFinding[] = [];
  const sqlSafeLines   = new Set<number>();
  const xssVulns:      TaintFinding[] = [];
  const xssSafeLines   = new Set<number>();
  const protoVulns:    TaintFinding[] = [];
  const protoSafeLines = new Set<number>();
  const headerVulns:   TaintFinding[] = [];
  const headerSafeLines= new Set<number>();
  const cmdVulns:      TaintFinding[] = [];
  const pathVulns:     TaintFinding[] = [];
  const redirectVulns: TaintFinding[] = [];

  // ── Pass 0a: Build guarded-line set (validation/early-return suppression) ──
  const guardedLines = buildGuardedLines(lines);

  // ── Pass 0: Extract function defs (interprocedural) ───────────────────────
  const funcDefs = extractFunctions(lines);

  // ── Pass 1: Direct taint sources ─────────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln   = i + 1;

    for (const src of SOURCE_PATTERNS) {
      const m = src.re.exec(line);
      if (!m) continue;
      if (src.destructure) {
        // Extract each variable name from destructure pattern
        const inner = m[1];
        for (const nm of inner.matchAll(/(\w+)/g)) {
          if (nm[1] && !['const','let','var','async','await','true','false'].includes(nm[1]))
            taintedVars.set(nm[1], ln);
        }
      } else if (m[1]) {
        taintedVars.set(m[1], ln);
      }
    }
  }

  // ── Pass 2: SSA / alias propagation (up to 4 hops) ───────────────────────
  for (let hop = 0; hop < 4; hop++) {
    let changed = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const ln   = i + 1;

      // Simple alias: const b = a
      const simpleAlias = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*[;,\n]/);
      if (simpleAlias?.[1] && simpleAlias?.[2] && taintedVars.has(simpleAlias[2]) && !taintedVars.has(simpleAlias[1])) {
        taintedVars.set(simpleAlias[1], ln); changed = true; continue;
      }

      // Template alias: const b = `${a}` or `prefix-${a}`
      const tmpl = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{(\w+)\}/);
      if (tmpl?.[1] && tmpl?.[2] && taintedVars.has(tmpl[2]) && !taintedVars.has(tmpl[1])) {
        taintedVars.set(tmpl[1], ln); changed = true; continue;
      }

      // String concat alias: const b = a + x  or  const b = x + a
      const concatL = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*\+/);
      if (concatL?.[1] && concatL?.[2] && taintedVars.has(concatL[2]) && !taintedVars.has(concatL[1])) {
        taintedVars.set(concatL[1], ln); changed = true; continue;
      }
      const concatR = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*\S+\s*\+\s*(\w+)/);
      if (concatR?.[1] && concatR?.[2] && taintedVars.has(concatR[2]) && !taintedVars.has(concatR[1])) {
        taintedVars.set(concatR[1], ln); changed = true; continue;
      }

      // Function call alias: const b = fn(a)
      const callAlias = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(\w+)\s*\(([^)]*)\)/);
      if (callAlias?.[1] && callAlias?.[2]) {
        const result  = callAlias[1];
        const fnName  = callAlias[2];
        const argList = (callAlias[3] ?? '').split(',').map(s => s.trim());
        const tainted = argList.filter(a => taintedVars.has(a));
        if (tainted.length > 0 && !taintedVars.has(result)) {
          const fn = funcDefs.find(f => f.name === fnName);
          // If function is unknown or provably propagates, mark tainted
          if (!fn || funcPropagatesTaint(fn, tainted)) {
            taintedVars.set(result, ln); changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  // ── Pass 3: Sink classification ───────────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ln   = i + 1;
    const ctx  = lines.slice(Math.max(0, i - 4), i + 5).join('\n');
    const taintedOnLine = [...taintedVars.keys()].filter(v => line.includes(v));
    const isTainted = taintedOnLine.length > 0;
    // Skip findings on lines where a guard clause validated the input
    if (guardedLines.has(ln)) continue;

    // ── SQL ────────────────────────────────────────────────────────────────
    // JS: db.query() / Python: cursor.execute()
    if (/db\.(?:query|execute|run)\s*\(|cursor\.execute\s*\(/.test(line)) {
      if (SQL_SAFE_CALL.test(line)) {
        sqlSafeLines.add(ln);
      } else if (isTainted) {
        sqlVulns.push({ ruleId: 'sqli-taint', title: 'SQL Injection — tainted var reaches db call',
          line: ln, confirmed: true, safe: false, hopCount: taintedOnLine.length, evidence: line.trim().slice(0,120) });
      }
    }
    if (/["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^"'"]*["']\s*\+/i.test(line) && !SQL_SANITIZERS.test(line)) {
      sqlVulns.push({ ruleId:'sqli-concat', title:'SQL Injection — string concatenation',
        line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }
    if (/`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s[^`]*\$\{/i.test(line) && !SQL_SANITIZERS.test(line)) {
      sqlVulns.push({ ruleId:'sqli-template', title:'SQL Injection — template literal',
        line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }
    // Python: f-string SQL (query = f"SELECT ... {user_id}")
    if (/(?:query|sql|stmt)\s*=\s*f["'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)/i.test(line) && !SQL_SANITIZERS.test(line)) {
      sqlVulns.push({ ruleId:'sqli-python-fstring', title:'SQL Injection — Python f-string in query',
        line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }
    // Python: % formatting SQL (query = "SELECT ... %s" % var)
    if (/(?:query|sql|stmt)\s*=\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^"']*["']\s*%/i.test(line) && !SQL_SANITIZERS.test(line)) {
      sqlVulns.push({ ruleId:'sqli-python-percent', title:'SQL Injection — Python % string formatting in query',
        line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }

    // ── XSS ───────────────────────────────────────────────────────────────
    const htmlTmpl = line.match(/`[^`]*<[a-zA-Z][^`]*\$\{([^}]+)\}/);
    if (htmlTmpl) {
      const interp = htmlTmpl[1].trim();
      if (HTML_SANITIZERS.test(interp)) xssSafeLines.add(ln);
      else if (isTainted || taintedVars.has(interp))
        xssVulns.push({ ruleId:'xss-template', title:'XSS — unsanitized var in HTML template',
          line:ln, confirmed:true, safe:false, evidence:`\${${interp}} — no HTML sanitizer` });
    }
    const innerHtml = line.match(/\.innerHTML\s*=\s*([^;]+)/);
    if (innerHtml) {
      if (HTML_SANITIZERS.test(innerHtml[1])) xssSafeLines.add(ln);
      else if (isTainted)
        xssVulns.push({ ruleId:'xss-innerhtml', title:'XSS — tainted value in innerHTML',
          line:ln, confirmed:true, safe:false, evidence:innerHtml[0].trim().slice(0,120) });
    }
    // React-specific
    if (/dangerouslySetInnerHTML\s*=/.test(line) && isTainted)
      xssVulns.push({ ruleId:'xss-react', title:'XSS — dangerouslySetInnerHTML with tainted value',
        line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });

    // ── Command Injection ─────────────────────────────────────────────────
    if (/(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/.test(line) && isTainted) {
      if (!/,\s*\[/.test(line)) // array-form spawn is safer
        cmdVulns.push({ ruleId:'cmd-injection', title:'Command Injection — tainted input in exec/spawn',
          line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }

    // ── Path Traversal ────────────────────────────────────────────────────
    if (/(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(/.test(line) && isTainted) {
      if (!PATH_SANITIZERS.test(ctx))
        pathVulns.push({ ruleId:'path-traversal', title:'Path Traversal — tainted input in fs operation',
          line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }
    if (/path\.join\s*\(/.test(line) && isTainted && !PATH_SANITIZERS.test(ctx))
      pathVulns.push({ ruleId:'path-join', title:'Path Traversal — user input in path.join',
        line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });

    // ── Open Redirect ─────────────────────────────────────────────────────
    if (/res\.redirect\s*\(/.test(line) && isTainted) {
      const nearby = lines.slice(Math.max(0,i-5),i+1).join('\n');
      if (!SAFE_URL_ALLOW.test(nearby) && !URL_SANITIZERS.test(nearby))
        redirectVulns.push({ ruleId:'open-redirect', title:'Open Redirect — user URL in res.redirect',
          line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }

    // ── Prototype Pollution ───────────────────────────────────────────────
    if (/!==\s*['"]__proto__['"]/.test(line)) {
      const guards = (ctx.match(/(?:constructor|prototype)/g) ?? []).length;
      if (guards >= 2) protoSafeLines.add(ln);
      else protoVulns.push({ ruleId:'proto-incomplete', title:'Prototype Pollution — incomplete key guard',
        line:ln, confirmed:true, safe:false, evidence:'Only __proto__ blocked — constructor bypass open' });
    }
    if (/Object\.keys\s*\(/.test(line) && /forEach|for/.test(ctx)) protoSafeLines.add(ln);
    if (/includes\s*\(.*(?:__proto__|constructor|prototype)/.test(line) &&
        /constructor/.test(line) && /prototype/.test(line) && /__proto__/.test(line))
      protoSafeLines.add(ln);

    // ── Header Injection ──────────────────────────────────────────────────
    if (/setHeader\s*\(/.test(line) && (isTainted || /req\.(?:query|params|body)\./.test(line))) {
      const nearby = lines.slice(Math.max(0,i-5),i+2).join('\n');
      if (CRLF_SANITIZERS.test(nearby)) headerSafeLines.add(ln);
      else headerVulns.push({ ruleId:'header-injection', title:'Header Injection — unsanitized input in setHeader',
        line:ln, confirmed:true, safe:false, evidence:line.trim().slice(0,120) });
    }
  }

  const dedup = (arr: TaintFinding[]) => {
    const seen = new Set<string>();
    return arr.filter(f => { const k=`${f.ruleId}:${f.line}`; if(seen.has(k)) return false; seen.add(k); return true; });
  };

  const dSql  = dedup(sqlVulns);   const dXss   = dedup(xssVulns);
  const dProt = dedup(protoVulns); const dHead  = dedup(headerVulns);
  const dCmd  = dedup(cmdVulns);   const dPath  = dedup(pathVulns);
  const dRed  = dedup(redirectVulns);

  return {
    taintedVars, summary: buildSummary(taintedVars,dSql,sqlSafeLines,dXss,xssSafeLines,
      dProt,protoSafeLines,dHead,headerSafeLines,dCmd,dPath,dRed),
    sqlVulns:dSql, sqlSafeLines, xssVulns:dXss, xssSafeLines,
    protoVulns:dProt, protoSafeLines, headerVulns:dHead, headerSafeLines,
    cmdVulns:dCmd, pathVulns:dPath, redirectVulns:dRed,
  };
}

function buildSummary(
  tainted:Map<string,number>,
  sqlV:TaintFinding[], sqlS:Set<number>, xssV:TaintFinding[], xssS:Set<number>,
  protoV:TaintFinding[], protoS:Set<number>, headerV:TaintFinding[], headerS:Set<number>,
  cmdV:TaintFinding[], pathV:TaintFinding[], redirV:TaintFinding[],
): string {
  const out: string[] = [];
  if (tainted.size) out.push(`SOURCES: ${[...tainted.entries()].slice(0,8).map(([v,l])=>`${v}@L${l}`).join(', ')}`);
  const ln = (v: TaintFinding[], label: string, safe?: Set<number>) => {
    if (v.length) out.push(`${label}_PROVEN L${v.map(f=>f.line).join(',')}`);
    if (safe?.size) out.push(`${label}_SAFE L${[...safe].join(',')} — SKIP`);
  };
  ln(sqlV,'SQLI',sqlS); ln(xssV,'XSS',xssS); ln(protoV,'PROTO',protoS); ln(headerV,'HEADER',headerS);
  if (cmdV.length)  out.push(`CMD_INJECT L${cmdV.map(f=>f.line).join(',')}`);
  if (pathV.length) out.push(`PATH_TRAV L${pathV.map(f=>f.line).join(',')}`);
  if (redirV.length)out.push(`REDIRECT L${redirV.map(f=>f.line).join(',')}`);
  return out.join(' | ');
}
