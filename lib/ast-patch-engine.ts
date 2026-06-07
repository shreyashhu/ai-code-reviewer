// ─────────────────────────────────────────────────────────────────────────────
// AST PATCH ENGINE v4
//
// Generates syntax-preserving, import-safe, formatting-preserving code patches.
// Works on the line/token level (no full parser required — regex + structural analysis).
//
// Capabilities:
//  • Import injection (avoids duplicates)
//  • Function call wrapping (e.g., wrap value with sanitizer)
//  • Parameterized query rewrites (SQL concat → parameterized)
//  • Variable declaration rewriting
//  • Rollback support (returns original + patched)
//  • Formatting preservation (detects indent style, quote style)
//  • Lint-aware (no dangling commas, correct semicolons)
// ─────────────────────────────────────────────────────────────────────────────

export interface AstPatch {
  lineNumber:    number;
  original:      string;
  patched:       string;
  patchType:     PatchType;
  confidence:    number;     // 0–100: how safe this auto-patch is
  requiresImport?: ImportSpec;
  rollback:      () => string; // returns original line
  description:   string;
}

export type PatchType =
  | 'wrap-sanitizer'
  | 'parameterize-sql'
  | 'replace-function'
  | 'add-guard'
  | 'add-import'
  | 'replace-assignment'
  | 'const-time-compare'
  | 'spawn-array'
  | 'path-resolve-check';

export interface ImportSpec {
  from:          string;
  named?:        string[];
  default?:      string;
  isDestructure: boolean;
}

export interface CodeStyle {
  usesSemicolons: boolean;
  quoteMark:      '"' | "'";
  indentChar:     string;
  indentWidth:    number;
}

export interface PatchResult {
  originalCode:  string;
  patchedCode:   string;
  patches:       AstPatch[];
  addedImports:  ImportSpec[];
  patchCount:    number;
  rollback:      () => string;
}

// ─── Detect Code Style ────────────────────────────────────────────────────────
function detectCodeStyle(code: string): CodeStyle {
  const lines = code.split('\n').slice(0, 50);

  const semicolonLines  = lines.filter(l => /;\s*$/.test(l.trim())).length;
  const usesSemicolons  = semicolonLines > lines.length * 0.3;

  const singleQuotes    = (code.match(/'/g) ?? []).length;
  const doubleQuotes    = (code.match(/"/g) ?? []).length;
  const quoteMark: '"' | "'" = doubleQuotes >= singleQuotes ? '"' : "'";

  const tabLines        = lines.filter(l => l.startsWith('\t')).length;
  const indentChar      = tabLines > lines.length * 0.3 ? '\t' : ' ';
  const spacedLines     = lines.filter(l => l.startsWith('  ')).map(l => (l.match(/^(\s+)/)?.[1]?.length ?? 0));
  const indentWidth     = spacedLines.length ? Math.min(...spacedLines.filter(n => n > 0)) || 2 : 2;

  return { usesSemicolons, quoteMark, indentChar, indentWidth };
}

function semi(style: CodeStyle): string {
  return style.usesSemicolons ? ';' : '';
}

function q(style: CodeStyle, str: string): string {
  return `${style.quoteMark}${str}${style.quoteMark}`;
}

// ─── Import Manager ───────────────────────────────────────────────────────────
function hasImport(code: string, spec: ImportSpec): boolean {
  if (spec.default) {
    return new RegExp(`import\\s+${spec.default}\\s+from\\s+['"]${spec.from}['"]`).test(code);
  }
  if (spec.named) {
    return spec.named.every(n => new RegExp(`\\b${n}\\b`).test(code) && /import/.test(code));
  }
  return false;
}

function buildImportLine(spec: ImportSpec, style: CodeStyle): string {
  const s = semi(style);
  if (spec.default) {
    return `import ${spec.default} from ${q(style, spec.from)}${s}`;
  }
  if (spec.named) {
    return `import { ${spec.named.join(', ')} } from ${q(style, spec.from)}${s}`;
  }
  return '';
}

function injectImport(code: string, spec: ImportSpec, style: CodeStyle): string {
  if (hasImport(code, spec)) return code;
  const importLine = buildImportLine(spec, style);
  const lines = code.split('\n');

  // Find last existing import line
  let lastImportIdx = -1;
  for (let i = 0; i < Math.min(lines.length, 30); i++) {
    if (/^\s*import\s/.test(lines[i]) || /^\s*(?:const|var|let)\s+\w+\s*=\s*require/.test(lines[i])) {
      lastImportIdx = i;
    }
  }

  if (lastImportIdx >= 0) {
    lines.splice(lastImportIdx + 1, 0, importLine);
  } else {
    lines.unshift(importLine);
  }

  return lines.join('\n');
}

// ─── Patch Generators ─────────────────────────────────────────────────────────

/**
 * Wraps an expression in a sanitizer function call.
 * e.g. innerHTML = userInput → innerHTML = DOMPurify.sanitize(userInput)
 */
function wrapSanitizer(
  line: string,
  pattern: RegExp,
  wrapper: string,
  lineNumber: number,
  style: CodeStyle,
  description: string,
): AstPatch | null {
  const m = line.match(pattern);
  if (!m || !m[1]) return null;
  const target  = m[1];
  const patched = line.replace(target, `${wrapper}(${target})`);
  if (patched === line) return null;
  return {
    lineNumber,
    original:    line,
    patched,
    patchType:   'wrap-sanitizer',
    confidence:  85,
    description,
    rollback:    () => line,
  };
}

/**
 * Rewrites a string-concatenated SQL query to parameterized form.
 * e.g. db.query("SELECT * FROM u WHERE name = " + name)
 *   → db.query("SELECT * FROM u WHERE name = ?", [name])
 */
function parameterizeSql(
  line: string,
  lineNumber: number,
  style: CodeStyle,
): AstPatch | null {
  // Pattern: db.query("...SQL..." + varname) or db.query(`...SQL...${varname}`)
  const concatM = line.match(/db\.(?:query|execute|run)\s*\(\s*("(?:[^"]+)"\s*\+\s*(\w+))\s*\)/);
  if (concatM) {
    const sqlPart  = concatM[1].split('+')[0].trim().replace(/"$/, '');
    const varPart  = concatM[2].trim();
    const patched  = line.replace(concatM[0], `db.query(${sqlPart} ?", [${varPart}])`.replace('?"', '?"'));
    // Rebuild properly
    const sqlBase  = concatM[1].split('+')[0].trim().replace(/["']$/, '');
    const rebuilt  = line.replace(
      concatM[0],
      `db.query(${sqlBase}?${style.quoteMark}, [${varPart}])`,
    );
    if (rebuilt === line) return null;
    return {
      lineNumber, original: line, patched: rebuilt,
      patchType: 'parameterize-sql', confidence: 80,
      description: `Rewrote concatenated SQL to parameterized query with [${varPart}]`,
      rollback: () => line,
    };
  }

  // Template literal: db.query(`...${varname}...`)
  const tmplM = line.match(/db\.(?:query|execute|run)\s*\(`([^`]*)\$\{(\w+)\}([^`]*)`\)/);
  if (tmplM) {
    const sqlPre  = tmplM[1];
    const varName = tmplM[2];
    const sqlPost = tmplM[3];
    const rebuilt = line.replace(
      tmplM[0],
      `db.query(${q(style, sqlPre + '?' + sqlPost)}, [${varName}])`,
    );
    return {
      lineNumber, original: line, patched: rebuilt,
      patchType: 'parameterize-sql', confidence: 90,
      description: `Rewrote template literal SQL to parameterized query with [${varName}]`,
      rollback: () => line,
    };
  }

  return null;
}

/**
 * Rewrites exec(string + input) to spawn([cmd, arg]) array form.
 */
function rewriteExecToSpawn(
  line: string,
  lineNumber: number,
  style: CodeStyle,
): AstPatch | null {
  const execM = line.match(/exec(?:Sync)?\s*\(`([^`]+)\$\{(\w+)\}`\)/);
  if (!execM) return null;
  const cmd     = execM[1].trim();
  const arg     = execM[2];
  const indent  = line.match(/^(\s*)/)?.[1] ?? '';
  const rebuilt = `${indent}spawn(${q(style, cmd.trim())}, [${arg}], { shell: false })`;
  return {
    lineNumber, original: line, patched: rebuilt,
    patchType: 'spawn-array', confidence: 75,
    description: `Rewrote exec template-literal to spawn() with array args (shell: false)`,
    requiresImport: { from: 'child_process', named: ['spawn'], isDestructure: true },
    rollback: () => line,
  };
}

/**
 * Rewrites === secret comparison to crypto.timingSafeEqual.
 */
function rewriteTimingCompare(
  line: string,
  lineNumber: number,
  style: CodeStyle,
): AstPatch | null {
  const m = line.match(/((\w+)\s*===\s*(\w+))/);
  if (!m) return null;
  const [, full, a, b] = m;
  const rebuilt = line.replace(
    full,
    `crypto.timingSafeEqual(Buffer.from(${a}), Buffer.from(${b}))`,
  );
  return {
    lineNumber, original: line, patched: rebuilt,
    patchType: 'const-time-compare', confidence: 80,
    description: `Replaced === secret comparison with crypto.timingSafeEqual (prevents timing attacks)`,
    requiresImport: { from: 'crypto', default: 'crypto', isDestructure: false },
    rollback: () => line,
  };
}

/**
 * Adds a path.resolve + startsWith guard after a path.join call.
 */
function addPathTraversalGuard(
  lines: string[],
  lineNumber: number,
  style: CodeStyle,
  varName: string,
): AstPatch | null {
  const line   = lines[lineNumber - 1];
  const indent = line.match(/^(\s*)/)?.[1] ?? '';
  const s      = semi(style);
  const guard  = [
    `${indent}const __safePath = path.resolve(BASE_DIR, ${varName})${s}`,
    `${indent}if (!__safePath.startsWith(path.resolve(BASE_DIR))) throw new Error(${q(style, 'Forbidden: path traversal detected')})${s}`,
  ].join('\n');
  return {
    lineNumber, original: line, patched: line + '\n' + guard,
    patchType: 'path-resolve-check', confidence: 85,
    description: `Added path.resolve() + startsWith(BASE_DIR) guard after path.join`,
    requiresImport: { from: 'path', default: 'path', isDestructure: false },
    rollback: () => line,
  };
}

/**
 * Rewrites Object.assign(target, req.body) to safe destructure.
 */
function rewriteMassAssignment(
  line: string,
  lineNumber: number,
  style: CodeStyle,
): AstPatch | null {
  const m = line.match(/Object\.assign\s*\(\s*(\w+)\s*,\s*req\.body\s*\)/);
  if (!m) return null;
  const target  = m[1];
  const indent  = line.match(/^(\s*)/)?.[1] ?? '';
  const s       = semi(style);
  const rebuilt = `${indent}// TODO: allowlist expected fields from req.body\n${indent}const { /* field1, field2 */ } = req.body${s}\n${indent}Object.assign(${target}, { /* field1, field2 */ })${s}`;
  return {
    lineNumber, original: line, patched: rebuilt,
    patchType: 'replace-assignment', confidence: 65,
    description: `Replaced Object.assign(target, req.body) with safe destructure pattern`,
    rollback: () => line,
  };
}

/**
 * Rewrites JWT decode to verify with algorithm pinning.
 */
function rewriteJwtDecode(
  line: string,
  lineNumber: number,
  style: CodeStyle,
): AstPatch | null {
  const m = line.match(/jwt\.decode\s*\(([^)]+)\)/);
  if (!m) return null;
  const args    = m[1];
  const s       = semi(style);
  const rebuilt = line.replace(
    m[0],
    `jwt.verify(${args}, process.env.JWT_SECRET, { algorithms: [${q(style, 'HS256')}] })`,
  );
  return {
    lineNumber, original: line, patched: rebuilt,
    patchType: 'replace-function', confidence: 90,
    description: `Replaced jwt.decode() with jwt.verify() and pinned HS256 algorithm`,
    rollback: () => line,
  };
}

// ─── Main Patch Engine ────────────────────────────────────────────────────────
export interface PatchRequest {
  ruleId:    string;
  lineNumber: number;
  context?:  string;  // optional surrounding code for context
}

export function generatePatches(code: string, requests: PatchRequest[]): PatchResult {
  const style    = detectCodeStyle(code);
  const lines    = code.split('\n');
  const patches: AstPatch[] = [];
  const addedImports: ImportSpec[] = [];
  let   workingCode = code;

  // Sort by line descending so later lines don't shift earlier offsets
  const sorted = [...requests].sort((a, b) => b.lineNumber - a.lineNumber);

  for (const req of sorted) {
    const lineIdx = req.lineNumber - 1;
    if (lineIdx < 0 || lineIdx >= lines.length) continue;
    const line    = lines[lineIdx];
    let   patch: AstPatch | null = null;

    switch (req.ruleId) {
      case 'xss-innerhtml':
      case 'xss-template-html':
      case 'xss-react':
        patch = wrapSanitizer(
          line,
          /\.innerHTML\s*=\s*(.+)$|dangerouslySetInnerHTML.*?__html:\s*(.+?)[,}]/,
          'DOMPurify.sanitize',
          req.lineNumber, style,
          'Wrap HTML sink with DOMPurify.sanitize()',
        );
        if (patch) patch.requiresImport = { from: 'dompurify', default: 'DOMPurify', isDestructure: false };
        break;

      case 'sqli-concat':
      case 'sqli-template':
        patch = parameterizeSql(line, req.lineNumber, style);
        break;

      case 'cmd-injection-exec':
        patch = rewriteExecToSpawn(line, req.lineNumber, style);
        break;

      case 'timing-attack-comparison':
        patch = rewriteTimingCompare(line, req.lineNumber, style);
        break;

      case 'mass-assignment':
        patch = rewriteMassAssignment(line, req.lineNumber, style);
        break;

      case 'jwt-none-algorithm':
      case 'jwt-decode-auth':
        patch = rewriteJwtDecode(line, req.lineNumber, style);
        break;

      case 'path-traversal-join':
      case 'path-traversal-readfile':
        patch = addPathTraversalGuard(lines, req.lineNumber, style, 'filename');
        if (patch) patch.requiresImport = { from: 'path', default: 'path', isDestructure: false };
        break;

      case 'proto-incomplete-check':
        patch = {
          lineNumber: req.lineNumber, original: line,
          patched: line.replace(
            /!==\s*['"]__proto__['"]/,
            `=== '__proto__' || key === 'constructor' || key === 'prototype') continue; if (false`,
          ),
          patchType: 'add-guard', confidence: 88,
          description: "Extended prototype pollution guard to block all 3 vectors: __proto__, constructor, prototype",
          rollback: () => line,
        };
        break;
    }

    if (patch) {
      patches.push(patch);
      // Apply patch to working lines
      lines[lineIdx] = patch.patched;
      if (patch.requiresImport) addedImports.push(patch.requiresImport);
    }
  }

  // Rebuild code with patches applied
  let patchedCode = lines.join('\n');

  // Inject required imports (deduped)
  const seen = new Set<string>();
  for (const imp of addedImports) {
    const key = `${imp.from}:${imp.default ?? imp.named?.join(',')}`;
    if (!seen.has(key)) {
      seen.add(key);
      patchedCode = injectImport(patchedCode, imp, style);
    }
  }

  return {
    originalCode: code,
    patchedCode,
    patches,
    addedImports: [...seen].map(k => addedImports.find(i => `${i.from}:${i.default ?? i.named?.join(',')}` === k)!),
    patchCount:   patches.length,
    rollback:     () => code,
  };
}

/**
 * Summarize patches for display in the UI.
 */
export function describePatch(patch: AstPatch): string {
  const confidenceLabel = patch.confidence >= 90 ? 'high' : patch.confidence >= 75 ? 'medium' : 'low';
  return `[${confidenceLabel} confidence] ${patch.description}`;
}
