'use client';

import { useState, useCallback, useRef, useEffect } from 'react';
import {
  Sparkles, Code2, AlertCircle, X, CheckCircle2, Loader2,
  Search, Bug, Shield, Wrench, Upload,
} from 'lucide-react';
import { CodeEditor } from '@/components/editor/CodeEditor';
import { AnalysisPanel } from '@/components/analysis/AnalysisPanel';
import { Button } from '@/components/ui/Button';
import {
  cn, MODELS, LANGUAGES, LOADING_MESSAGES,
  type ReviewResult, type ModelId,
} from '@/lib/utils';

const FILE_EXT: Record<string, string> = {
  javascript: 'main.js', typescript: 'main.ts', python: 'main.py',
  rust: 'main.rs', go: 'main.go', java: 'Main.java', cpp: 'main.cpp',
  csharp: 'Main.cs', php: 'main.php', ruby: 'main.rb', swift: 'main.swift',
  kotlin: 'Main.kt', sql: 'query.sql', bash: 'script.sh',
};

const EXT_TO_LANG: Record<string, string> = {
  js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript',
  py: 'python', rs: 'rust', go: 'go', java: 'java', cpp: 'cpp', cc: 'cpp',
  cs: 'csharp', php: 'php', rb: 'ruby', swift: 'swift', kt: 'kotlin',
  sql: 'sql', sh: 'bash', bash: 'bash',
};

const DEFAULT_CODE = `// Paste your code here for AI review
function processUserData(users) {
  var result = [];
  for (var i = 0; i < users.length; i++) {
    var user = users[i];
    if (user.password == "admin123") {
      result.push(user);
    }
    // TODO: add error handling
    fetch('/api/log', {
      method: 'POST',
      body: JSON.stringify({ userId: user.id, action: 'viewed' })
    });
  }
  return result;
}

function calculateTotal(items) {
  var total = 0;
  for (var i = 0; i < items.length; i++) {
    total = total + items[i].price * items[i].qty;
  }
  return total;
}`;

const PIPELINE_STAGES = [
  { icon: Search,       label: 'Rule engine & taint analysis (40+ rules)',          key: 'parse'    },
  { icon: Bug,          label: 'Call graph & multi-role consensus',                  key: 'bugs'     },
  { icon: Shield,       label: 'Constraint chains + semantic graph + proof engine',  key: 'security' },
  { icon: Wrench,       label: 'AST patches + verified remediation',                 key: 'fix'      },
  { icon: CheckCircle2, label: 'Deterministic dominance + FP minimizer + delta',     key: 'audit'    },
];

function PipelineStatus({ isLoading, msgIdx }: { isLoading: boolean; msgIdx: number }) {
  if (!isLoading) return null;
  const activeStage = Math.min(
    Math.floor(msgIdx / (LOADING_MESSAGES.length / PIPELINE_STAGES.length)),
    PIPELINE_STAGES.length - 1
  );

  return (
    <div
      className="flex items-center gap-3 px-4 py-2 flex-shrink-0"
      style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(124,58,237,0.04)' }}
    >
      <div className="flex items-center gap-2 flex-1 overflow-x-auto no-scrollbar">
        {PIPELINE_STAGES.map((stage, i) => {
          const Icon = stage.icon;
          const done   = i < activeStage;
          const active = i === activeStage;
          return (
            <div
              key={stage.key}
              className={cn(
                'flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-medium whitespace-nowrap flex-shrink-0 transition-all duration-300',
                done   && 'bg-green-500/10 border border-green-500/20 text-green-400',
                active && 'bg-violet-500/15 border border-violet-500/30 text-violet-300',
                !done && !active && 'bg-white/5 border border-white/5 text-zinc-600',
              )}
            >
              {done   && <CheckCircle2 className="w-3 h-3 flex-shrink-0" />}
              {active && <Loader2 className="w-3 h-3 flex-shrink-0 animate-spin" />}
              {!done && !active && <Icon className="w-3 h-3 flex-shrink-0" />}
              {stage.label}
            </div>
          );
        })}
      </div>
      <p className="text-[10px] text-zinc-500 whitespace-nowrap flex-shrink-0 fade-in-up" key={msgIdx}>
        {LOADING_MESSAGES[msgIdx]}
      </p>
    </div>
  );
}

export default function HomePage() {
  const [code, setCode]               = useState(DEFAULT_CODE);
  const [langId, setLangId]           = useState('javascript');
  const [modelId, setModelId]         = useState<ModelId>('auto');
  const [result, setResult]           = useState<ReviewResult | null>(null);
  const [isLoading, setIsLoading]     = useState(false);
  const [loadingMsgIdx, setLoadingMsgIdx] = useState(0);
  const [error, setError]             = useState<string | null>(null);
  const [splitPct, setSplitPct]       = useState(60);   // resizable panels
  const [isDragging, setIsDragging]   = useState(false);
  const [isDragOver, setIsDragOver]   = useState(false); // file drag-over on editor

  const editorFocusRef = useRef<(() => void) | null>(null);
  const fileInputRef   = useRef<HTMLInputElement>(null);
  const abortRef       = useRef<AbortController | null>(null);
  const intervalRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const debounceRef    = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dividerRef     = useRef<HTMLDivElement>(null);
  const containerRef   = useRef<HTMLDivElement>(null);

  // ── Rotate loading messages ──────────────────────────────────────────────
  useEffect(() => {
    if (isLoading) {
      setLoadingMsgIdx(0);
      intervalRef.current = setInterval(() => {
        setLoadingMsgIdx((p) => Math.min(p + 1, LOADING_MESSAGES.length - 1));
      }, 2200);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [isLoading]);

  // ── Resizable divider ────────────────────────────────────────────────────
  const handleDividerMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  useEffect(() => {
    if (!isDragging) return;
    const onMove = (e: MouseEvent) => {
      const container = containerRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const pct  = Math.min(75, Math.max(30, ((e.clientX - rect.left) / rect.width) * 100));
      setSplitPct(pct);
    };
    const onUp = () => setIsDragging(false);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); };
  }, [isDragging]);

  // ── File upload ──────────────────────────────────────────────────────────
  const handleFileContent = useCallback((file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
    const detected = EXT_TO_LANG[ext];
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      if (text) {
        setCode(text);
        if (detected) setLangId(detected);
        setResult(null);
        setError(null);
      }
    };
    reader.readAsText(file);
  }, []);

  const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFileContent(file);
    e.target.value = '';
  }, [handleFileContent]);

  // ── Drag-and-drop code files onto editor ─────────────────────────────────
  const handleEditorDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleEditorDragLeave = useCallback(() => setIsDragOver(false), []);

  const handleEditorDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileContent(file);
  }, [handleFileContent]);

  const bugLines = result?.issues
    .filter((i): i is typeof i & { line: number } => i.line !== null)
    .map((i) => i.line) ?? [];


  // ── Analysis ─────────────────────────────────────────────────────────────
  const runAnalysis = useCallback(async () => {
    if (!code.trim() || isLoading) return;
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch('/api/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, model: modelId, language: langId }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error ?? `Server error ${response.status}`);
      }
      if (!response.body) throw new Error('No response body received');

      const reader  = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      const flush = (buf: string): string => {
        const parts     = buf.split('\n\n');
        const remaining = parts.pop() ?? '';
        for (const part of parts) {
          if (!part.startsWith('data: ')) continue;
          try {
            const ev = JSON.parse(part.slice(6));
            if (ev.type === 'done')  setResult(ev.result);
            else if (ev.type === 'error') { setResult(ev.result); setError(ev.error); }
          } catch { /* skip malformed */ }
        }
        return remaining;
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) { if (buffer.trim()) flush(buffer + '\n\n'); break; }
        buffer += decoder.decode(value, { stream: true });
        buffer  = flush(buffer);
      }
    } catch (err) {
      if ((err as Error).name === 'AbortError') return;
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setIsLoading(false);
    }
  }, [code, modelId, langId, isLoading]);

  const handleAnalyze = useCallback(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(runAnalysis, 300);
  }, [runAnalysis]);

  const handleReset = useCallback(() => {
    setCode(DEFAULT_CODE);
    setResult(null);
    setError(null);
    if (abortRef.current) abortRef.current.abort();
    setIsLoading(false);
  }, []);

  const handleClearOutput = useCallback(() => {
    setResult(null);
    setError(null);
  }, []);

  // Apply optimized code from analysis panel back to the editor
  const handleApplyFix = useCallback((optimized: string) => {
    setCode(optimized);
    setResult(null);
    setError(null);
    setTimeout(() => editorFocusRef.current?.(), 50);
  }, []);

  // ── Global keyboard shortcuts ─────────────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const ctrl = e.ctrlKey || e.metaKey;
      if      (ctrl && e.key === 'Enter') { e.preventDefault(); handleAnalyze(); }
      else if (ctrl && e.key === 'k')     { e.preventDefault(); handleClearOutput(); }
      else if (ctrl && e.key === '/')     { e.preventDefault(); editorFocusRef.current?.(); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [handleAnalyze, handleClearOutput]);

  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      if (abortRef.current)    abortRef.current.abort();
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const fileName = langId !== 'auto' ? (FILE_EXT[langId] ?? `main.${langId}`) : 'main.js';

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: '#09090b' }}>
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        accept=".js,.jsx,.ts,.tsx,.py,.rs,.go,.java,.cpp,.cc,.cs,.php,.rb,.swift,.kt,.sql,.sh,.bash,.txt"
        onChange={handleFileInputChange}
      />

      {/* Ambient glow */}
      <div className="pointer-events-none fixed inset-0 z-0" style={{ background: 'radial-gradient(ellipse 80% 40% at 50% -10%, rgba(124,58,237,0.10) 0%, transparent 70%)' }} />
      <div className="pointer-events-none fixed inset-0 z-0" style={{ background: 'radial-gradient(ellipse 40% 30% at 80% 80%, rgba(37,99,235,0.05) 0%, transparent 60%)' }} />

      {/* Navbar */}
      <nav
        className="relative z-20 flex-shrink-0 flex items-center justify-between px-5 py-2.5"
        style={{ background: 'rgba(9,9,11,0.85)', borderBottom: '1px solid rgba(255,255,255,0.06)', backdropFilter: 'blur(20px) saturate(180%)', WebkitBackdropFilter: 'blur(20px) saturate(180%)', boxShadow: '0 1px 0 rgba(255,255,255,0.04)' }}
      >
        {/* Logo */}
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-600 to-blue-600 flex items-center justify-center" style={{ boxShadow: '0 0 12px rgba(124,58,237,0.4)' }}>
            <Code2 className="w-4 h-4 text-white" />
          </div>
          <span className="text-sm font-semibold text-zinc-100 tracking-tight">AI Code Review <span className="text-[10px] text-violet-400 font-mono">v1.4</span></span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          {/* Language */}
          <div className="relative">
            <select
              value={langId}
              onChange={(e) => setLangId(e.target.value)}
              className="appearance-none pl-3 pr-7 py-1.5 rounded-xl text-xs font-medium cursor-pointer bg-white/5 border border-white/10 text-zinc-300 focus:outline-none focus:border-violet-500/50 transition-all duration-200"
            >
              {LANGUAGES.map((l) => (
                <option key={l.id} value={l.id} style={{ background: '#18181b', color: '#e4e4e7' }}>{l.label}</option>
              ))}
            </select>
            <svg className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M6 9l6 6 6-6" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </div>

          {/* Model */}
          <div className="relative">
            <select
              value={modelId}
              onChange={(e) => setModelId(e.target.value as ModelId)}
              className="appearance-none pl-3 pr-7 py-1.5 rounded-xl text-xs font-medium cursor-pointer bg-white/5 border border-white/10 text-zinc-300 focus:outline-none focus:border-violet-500/50 transition-all duration-200"
            >
              {MODELS.map((m) => (
                <option key={m.id} value={m.id} style={{ background: '#18181b', color: '#e4e4e7' }}>{m.label} — {m.description}</option>
              ))}
            </select>
            <svg className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M6 9l6 6 6-6" strokeLinecap="round" strokeLinejoin="round" /></svg>
          </div>

          {/* Status chip */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border transition-all duration-300"
            style={{
              background:   isLoading ? 'rgba(234,179,8,0.08)' : 'rgba(34,197,94,0.08)',
              borderColor:  isLoading ? 'rgba(234,179,8,0.2)'  : 'rgba(34,197,94,0.2)',
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full flex-shrink-0"
              style={{
                background: isLoading ? '#facc15' : '#22c55e',
                boxShadow:  isLoading ? '0 0 6px #facc15' : '0 0 6px #22c55e',
                animation:  isLoading ? 'pulse 1s infinite' : undefined,
              }}
            />
            <span className="text-[10px] font-medium" style={{ color: isLoading ? '#facc15' : '#22c55e' }}>
              {isLoading ? 'Analyzing' : 'AI Ready'}
            </span>
          </div>

          {/* Analyze button */}
          <Button
            variant="accent" size="md" isLoading={isLoading}
            onClick={handleAnalyze} disabled={!code.trim()}
            leftIcon={!isLoading ? <Sparkles className="w-3.5 h-3.5" /> : undefined}
            className="min-w-[110px]"
            title="Ctrl+Enter"
          >
            {isLoading ? 'Analyzing...' : 'Analyze'}
          </Button>
        </div>
      </nav>

      {/* Error banner */}
      {error && (
        <div className="relative z-20 flex-shrink-0 flex items-center gap-3 px-5 py-2.5 bg-red-500/10 border-b border-red-500/20">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <p className="text-xs text-red-300 flex-1">{error}</p>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300 transition-colors flex-shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Pipeline status bar */}
      <PipelineStatus isLoading={isLoading} msgIdx={loadingMsgIdx} />

      {/* Main layout */}
      <main
        ref={containerRef}
        className="relative z-10 flex flex-1 overflow-hidden"
        style={{ cursor: isDragging ? 'col-resize' : 'default' }}
      >
        {/* Left: Editor */}
        <div
          className="flex flex-col overflow-hidden flex-shrink-0"
          style={{ width: `${splitPct}%`, borderRight: '1px solid rgba(255,255,255,0.06)', minHeight: 0 }}
        >
          {/* Editor toolbar */}
          <div className="flex items-center justify-between px-4 py-2 flex-shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <button onClick={handleReset} title="Reset editor" className="w-3 h-3 rounded-full group relative transition-transform hover:scale-110 active:scale-95" style={{ background: 'rgba(239,68,68,0.7)', boxShadow: '0 0 0 1px rgba(239,68,68,0.3)' }}>
                  <span className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 8 8" width="6" height="6" fill="none" stroke="rgba(0,0,0,0.6)" strokeWidth="1.5" strokeLinecap="round"><line x1="2" y1="2" x2="6" y2="6"/><line x1="6" y1="2" x2="2" y2="6"/></svg>
                  </span>
                </button>
                <button onClick={handleClearOutput} title="Clear output" className="w-3 h-3 rounded-full group relative transition-transform hover:scale-110 active:scale-95" style={{ background: 'rgba(234,179,8,0.7)', boxShadow: '0 0 0 1px rgba(234,179,8,0.3)' }}>
                  <span className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 8 8" width="6" height="6" fill="none" stroke="rgba(0,0,0,0.6)" strokeWidth="1.5" strokeLinecap="round"><line x1="2" y1="4" x2="6" y2="4"/></svg>
                  </span>
                </button>
                <button onClick={handleAnalyze} disabled={isLoading || !code.trim()} title="Run analysis — Ctrl+Enter" className="w-3 h-3 rounded-full group relative transition-transform hover:scale-110 active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed" style={{ background: 'rgba(34,197,94,0.7)', boxShadow: '0 0 0 1px rgba(34,197,94,0.3)' }}>
                  <span className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 8 8" width="5" height="5" fill="rgba(0,0,0,0.6)"><polygon points="2,1 7,4 2,7"/></svg>
                  </span>
                </button>
              </div>
              <span className="text-xs text-zinc-600 font-mono ml-1">{fileName}</span>
            </div>

            <div className="flex items-center gap-2">
              {/* Upload file button */}
              <button
                onClick={() => fileInputRef.current?.click()}
                title="Upload code file"
                className="flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-300 transition-colors px-1.5 py-0.5 rounded-md hover:bg-white/5"
              >
                <Upload className="w-3 h-3" />
                <span className="hidden sm:inline">Upload</span>
              </button>
              <span className="text-[10px] text-zinc-700 font-mono hidden sm:block">Ctrl+Enter · Ctrl+K · Ctrl+/</span>
              <span className="text-[10px] text-zinc-700 font-mono">{code.split('\n').length}L · {code.length}ch</span>
              {bugLines.length > 0 && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20">
                  {bugLines.length} issue{bugLines.length !== 1 ? 's' : ''} marked
                </span>
              )}
              {result && !isLoading && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/20 fade-in-up">
                  Score: {result.score}/100
                </span>
              )}
            </div>
          </div>

          {/* Monaco wrapper: flex-1 + min-h-0 so the div has a real pixel height */}
          <div
            className="relative overflow-hidden"
            style={{ flex: 1, minHeight: 0 }}
            onDragOver={handleEditorDragOver}
            onDragLeave={handleEditorDragLeave}
            onDrop={handleEditorDrop}
          >
            <CodeEditor
              value={code}
              onChange={setCode}
              language={langId}
              bugLines={bugLines}
              onFocusRef={editorFocusRef}
            />
            {/* Drag-over overlay */}
            {isDragOver && (
              <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 fade-in-up pointer-events-none"
                style={{ background: 'rgba(124,58,237,0.10)', border: '2px dashed rgba(124,58,237,0.5)' }}>
                <Upload className="w-8 h-8 text-violet-400" />
                <p className="text-sm font-medium text-violet-300">Drop to load file</p>
              </div>
            )}
          </div>
        </div>

        {/* Draggable divider */}
        <div
          ref={dividerRef}
          onMouseDown={handleDividerMouseDown}
          className="flex-shrink-0 group relative flex items-center justify-center"
          style={{ width: 6, cursor: 'col-resize', zIndex: 30 }}
        >
          <div
            className="absolute inset-y-0 w-px transition-all duration-150 group-hover:w-0.5"
            style={{ background: isDragging ? 'rgba(124,58,237,0.6)' : 'rgba(255,255,255,0.06)', left: '50%', transform: 'translateX(-50%)' }}
          />
          {/* grip dots */}
          <div className="relative z-10 flex flex-col gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
            {[0,1,2].map(i => (
              <div key={i} className="w-0.5 h-0.5 rounded-full" style={{ background: isDragging ? 'rgba(124,58,237,0.8)' : 'rgba(255,255,255,0.3)' }} />
            ))}
          </div>
        </div>

        {/* Right: Analysis */}
        <div className="flex flex-col overflow-hidden flex-1">
          <div className="flex items-center justify-between px-4 py-2 flex-shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Analysis</span>
            {result && !isLoading && (
              <div className="flex items-center gap-1.5">
                {result.language !== 'unknown' && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-zinc-500 font-mono capitalize">{result.language}</span>
                )}
                <span
                  title={result.auditDetail}
                  className={cn(
                    'text-[10px] px-1.5 py-0.5 rounded border font-semibold cursor-help',
                    result.auditPassed
                      ? 'bg-zinc-500/15 text-zinc-400 border-zinc-500/20'
                      : 'bg-amber-500/15 text-amber-400 border-amber-500/20'
                  )}
                >
                  {result.auditPassed ? 'Analysis done' : '⚠ Needs review'}
                </span>
              </div>
            )}
          </div>

          <div className="flex-1 overflow-hidden">
            <AnalysisPanel
              result={result}
              isLoading={isLoading}
              loadingMessage={LOADING_MESSAGES[loadingMsgIdx]}
              error={error}
              originalCode={code}
              onRetry={handleAnalyze}
              onApplyFix={handleApplyFix}
            />
          </div>

          <div className="flex-shrink-0 flex items-center justify-center py-2 px-4" style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}>
            <span className="text-[10px] text-zinc-700 hover:text-zinc-500 transition-colors">
              Made by{' '}
              <a href="https://t.me/AlpraxIsHim" target="_blank" rel="noopener noreferrer" className="text-zinc-600 hover:text-violet-400 transition-colors">
                @AlpraxIsHim
              </a>
              {' '}on TG
            </span>
          </div>
        </div>
      </main>
    </div>
  );
}
