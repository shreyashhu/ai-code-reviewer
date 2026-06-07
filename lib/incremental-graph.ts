// ─────────────────────────────────────────────────────────────────────────────
// INCREMENTAL GRAPH ENGINE — v1.4
//
// Makes attack-path graphs scale to repository-sized inputs by persisting
// the graph between scans and only recomputing affected subgraphs.
//
// Architecture:
//   • Persistent graph stored as a flat node/edge adjacency map (JSON-serializable)
//   • Changed-node propagation: only nodes whose code hash changes are re-evaluated
//   • Incremental recomputation of attack paths from changed nodes outward
//   • Service dependency tracking: external calls, queue producers, event emitters
//   • Async-pattern tracing: Promise chains, setTimeout, setInterval, async/await
//
// For full repos: plug a Redis/Valkey adapter behind GraphStore.
// Default: in-process store (survives the request, resets on restart).
// ─────────────────────────────────────────────────────────────────────────────

import { createHash } from 'crypto';

// ─── Types ────────────────────────────────────────────────────────────────────

export type NodeKind =
  | 'source'       // user-controlled input
  | 'sink'         // dangerous operation
  | 'sanitizer'    // cleans tainted data
  | 'auth-gate'    // checks credentials before proceeding
  | 'service-dep'  // external service call
  | 'async-bridge' // Promise/callback/queue boundary
  | 'middleware'   // Express/Koa/Fastify middleware

export interface GraphNode {
  id:         string;
  kind:       NodeKind;
  label:      string;
  line:       number | null;
  codeHash:   string;   // SHA-256 of the code line(s) contributing to this node
  dirty:      boolean;  // needs recomputation
}

export interface GraphEdge {
  from:  string;
  to:    string;
  kind:  'data-flow' | 'control-flow' | 'service-call' | 'async'
}

export interface AttackPath {
  id:          string;
  nodes:       string[];   // ordered node IDs: source → sink
  hasSanitizer: boolean;
  hasAuthGate:  boolean;
  cvssEstimate: number;
  severity:    'high' | 'medium' | 'low';
}

export interface IncrementalGraphStats {
  totalNodes:     number;
  dirtyNodes:     number;
  recomputed:     number;
  skipped:        number;
  attackPaths:    number;
  serviceDeps:    number;
  asyncBridges:   number;
}

// ─── In-process store ─────────────────────────────────────────────────────────

class GraphStore {
  nodes = new Map<string, GraphNode>();
  edges: GraphEdge[] = [];
  paths: AttackPath[] = [];

  upsertNode(node: GraphNode): boolean {
    const existing = this.nodes.get(node.id);
    if (existing && existing.codeHash === node.codeHash) {
      return false; // unchanged — skip
    }
    this.nodes.set(node.id, { ...node, dirty: true });
    return true; // changed — needs recomputation
  }

  addEdge(edge: GraphEdge): void {
    const exists = this.edges.some(
      e => e.from === edge.from && e.to === edge.to && e.kind === edge.kind
    );
    if (!exists) this.edges.push(edge);
  }

  markClean(nodeId: string): void {
    const n = this.nodes.get(nodeId);
    if (n) n.dirty = false;
  }

  getDirty(): GraphNode[] {
    return [...this.nodes.values()].filter(n => n.dirty);
  }

  getDownstream(nodeId: string, visited = new Set<string>()): string[] {
    if (visited.has(nodeId)) return [];
    visited.add(nodeId);
    const direct = this.edges.filter(e => e.from === nodeId).map(e => e.to);
    return [...direct, ...direct.flatMap(id => this.getDownstream(id, visited))];
  }
}

const _store = new GraphStore();

// ─── Code-hash helper ─────────────────────────────────────────────────────────

function lineHash(line: string): string {
  return createHash('sha256').update(line.trim()).digest('hex').slice(0, 16);
}

// ─── Pattern sets ─────────────────────────────────────────────────────────────

const SOURCE_PATTERNS: [RegExp, string][] = [
  [/req\.(body|query|params)\b/,            'HTTP input'],
  [/process\.env\b/,                        'env var'],
  [/fs\.readFile|readFileSync/,             'file read'],
  [/JSON\.parse\s*\(/,                      'deserialized input'],
  [/message\.body|event\.data/,             'queue message'],
  [/socket\.on\s*\(/,                       'websocket input'],
];

const SINK_PATTERNS: [RegExp, string][] = [
  [/db\.(query|execute|run)\s*\(`/,         'raw SQL'],
  [/exec\s*\(|spawn\s*\(/,                  'shell exec'],
  [/eval\s*\(/,                             'eval'],
  [/innerHTML\s*=/,                         'innerHTML'],
  [/fetch\s*\(\s*\w/,                       'SSRF'],
  [/res\.redirect\s*\(/,                    'open redirect'],
  [/\.rawQuery\s*\(/,                       'raw query'],
  [/child_process/,                         'child process'],
];

const SANITIZER_PATTERNS: [RegExp, string][] = [
  [/DOMPurify\.sanitize/,                   'DOMPurify'],
  [/mysql\.escape|pg\.escapeLiteral/,       'DB escape'],
  [/validator\./,                           'validator'],
  [/Joi\.|Zod\.|yup\./,                     'schema validation'],
  [/encodeURIComponent|htmlspecialchars/,   'URI encode'],
];

const AUTH_GATE_PATTERNS: [RegExp, string][] = [
  [/requireAuth|isAuthenticated|verifyToken/,   'auth middleware'],
  [/jwt\.verify\s*\(/,                          'JWT verify'],
  [/bcrypt\.compare\s*\(/,                      'bcrypt compare'],
  [/requireAdmin|isAdmin|roles\.includes/,      'role gate'],
];

const SERVICE_DEP_PATTERNS: [RegExp, string][] = [
  [/axios\.(get|post|put|delete)/,          'HTTP call'],
  [/amqp|rabbitmq|kafka|bull\.add/,         'queue send'],
  [/redis\.set|memcache\.set/,              'cache write'],
  [/stripe\.|sendgrid\.|twilio\./,          'SaaS API'],
  [/prisma\.\w+\.(create|update|delete)/,   'DB write'],
];

const ASYNC_BRIDGE_PATTERNS: [RegExp, string][] = [
  [/new Promise\s*\(/,                      'Promise'],
  [/setTimeout|setInterval/,                'timer'],
  [/EventEmitter|\.emit\s*\(/,              'event emit'],
  [/\.then\s*\(\s*async/,                   'promise chain'],
  [/process\.nextTick/,                     'nextTick'],
];

// ─── Graph builder ────────────────────────────────────────────────────────────

function nodeId(kind: NodeKind, line: number): string {
  return `${kind}:L${line}`;
}

export function buildIncrementalGraph(
  code: string,
  scopeId = 'default',
): { stats: IncrementalGraphStats; paths: AttackPath[] } {
  const lines = code.split('\n');
  let recomputed = 0;
  let skipped = 0;

  const localSources: GraphNode[] = [];
  const localSinks:   GraphNode[] = [];

  // ── Pass 1: detect and upsert nodes ───────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const lineNum = i + 1;
    const hash = `${scopeId}:${lineHash(ln)}`;

    for (const [pat, label] of SOURCE_PATTERNS) {
      if (pat.test(ln)) {
        const n: GraphNode = { id: nodeId('source', lineNum), kind: 'source', label, line: lineNum, codeHash: hash, dirty: false };
        const changed = _store.upsertNode(n);
        if (changed) { recomputed++; localSources.push(n); } else skipped++;
      }
    }
    for (const [pat, label] of SINK_PATTERNS) {
      if (pat.test(ln)) {
        const n: GraphNode = { id: nodeId('sink', lineNum), kind: 'sink', label, line: lineNum, codeHash: hash, dirty: false };
        const changed = _store.upsertNode(n);
        if (changed) { recomputed++; localSinks.push(n); } else skipped++;
      }
    }
    for (const [pat, label] of SANITIZER_PATTERNS) {
      if (pat.test(ln)) {
        const n: GraphNode = { id: nodeId('sanitizer', lineNum), kind: 'sanitizer', label, line: lineNum, codeHash: hash, dirty: false };
        _store.upsertNode(n);
      }
    }
    for (const [pat, label] of AUTH_GATE_PATTERNS) {
      if (pat.test(ln)) {
        const n: GraphNode = { id: nodeId('auth-gate', lineNum), kind: 'auth-gate', label, line: lineNum, codeHash: hash, dirty: false };
        _store.upsertNode(n);
      }
    }
    for (const [pat, label] of SERVICE_DEP_PATTERNS) {
      if (pat.test(ln)) {
        const n: GraphNode = { id: nodeId('service-dep', lineNum), kind: 'service-dep', label, line: lineNum, codeHash: hash, dirty: false };
        _store.upsertNode(n);
      }
    }
    for (const [pat, label] of ASYNC_BRIDGE_PATTERNS) {
      if (pat.test(ln)) {
        const n: GraphNode = { id: nodeId('async-bridge', lineNum), kind: 'async-bridge', label, line: lineNum, codeHash: hash, dirty: false };
        _store.upsertNode(n);
      }
    }
  }

  // ── Pass 2: link dirty sources → nearest downstream sinks ─────────────────
  const dirtySourceIds = new Set(localSources.map(n => n.id));
  for (const src of localSources) {
    for (const sink of localSinks) {
      if (sink.line !== null && src.line !== null && sink.line > src.line) {
        _store.addEdge({ from: src.id, to: sink.id, kind: 'data-flow' });
      }
    }
    _store.markClean(src.id);
  }
  for (const sink of localSinks) _store.markClean(sink.id);

  // ── Pass 3: compute attack paths for dirty subgraph ───────────────────────
  _store.paths = _store.paths.filter(p => !p.nodes.some(nid => dirtySourceIds.has(nid)));

  const allNodes = [..._store.nodes.values()];
  const sanitizerLines = new Set(allNodes.filter(n => n.kind === 'sanitizer').map(n => n.line));
  const authGateLines  = new Set(allNodes.filter(n => n.kind === 'auth-gate').map(n => n.line));

  for (const src of localSources) {
    const downstream = _store.getDownstream(src.id);
    const sinkNodes = downstream
      .map(id => _store.nodes.get(id))
      .filter((n): n is GraphNode => n?.kind === 'sink');

    for (const sink of sinkNodes) {
      const pathLines = [src.line ?? 0, sink.line ?? 0].sort((a, b) => a - b);
      const hasSanitizer = [...sanitizerLines].some(l => l !== null && l > pathLines[0] && l < pathLines[1]);
      const hasAuthGate  = [...authGateLines].some(l => l !== null && l > pathLines[0] && l < pathLines[1]);

      const cvss = hasSanitizer ? 4.0 : hasAuthGate ? 5.5 : 8.5;
      const severity = cvss >= 7.0 ? 'high' : cvss >= 4.0 ? 'medium' : 'low';

      const path: AttackPath = {
        id: `${src.id}→${sink.id}`,
        nodes: [src.id, sink.id],
        hasSanitizer, hasAuthGate, cvssEstimate: cvss, severity,
      };
      _store.paths.push(path);
    }
  }

  const serviceDeps  = allNodes.filter(n => n.kind === 'service-dep').length;
  const asyncBridges = allNodes.filter(n => n.kind === 'async-bridge').length;

  return {
    stats: {
      totalNodes:   _store.nodes.size,
      dirtyNodes:   _store.getDirty().length,
      recomputed, skipped,
      attackPaths:  _store.paths.length,
      serviceDeps, asyncBridges,
    },
    paths: _store.paths,
  };
}

export function getGraphSummary(): string {
  const { nodes, edges, paths } = _store;
  return `${nodes.size} nodes, ${edges.length} edges, ${paths.length} attack paths`;
}

export function resetGraph(): void {
  _store.nodes.clear();
  _store.edges.length = 0;
  _store.paths.length = 0;
}
