'use client';
import { useState, useCallback, useRef, useEffect } from 'react';
import {
  Sparkles, Code2, AlertCircle, X, CheckCircle2, Loader2,
  Search, Bug, Shield, Wrench, Upload, Terminal, FileDown, FileJson, History
} from 'lucide-react';
import { CodeEditor } from '@/components/editor/CodeEditor';
import { AnalysisPanel } from '@/components/analysis/AnalysisPanel';
import { Button } from '@/components/ui/Button';
import { exportToPdf, exportToJson } from '@/lib/export-report';
import {
  cn, MODELS, LANGUAGES, LOADING_MESSAGES,
  type ReviewResult, type ModelId,
} from '@/lib/utils';

interface SavedScan {
  id: string;
  date: string;
  score: number;
  language: string;
  issueCount: number;
  summary: string;
  auditPassed: boolean;
  code: string;
  result: ReviewResult;
}

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
    fetch('/api/log', {
      method: 'POST',
      body: JSON.stringify({ userId: user.id, action: 'viewed' })
    });
  }
  return result;
}`;

const PIPELINE_STAGES = [
  { icon: Search,       label: 'Rule engine & taint analysis (40+ rules)',          key: 'parse'    },
  { icon: Bug,          label: 'Call graph & multi-role consensus',                  key: 'bugs'     },
  { icon: Shield,       label: 'Constraint chains + semantic graph + proof engine',  key: 'security' },
  { icon: Wrench,       label: 'AST patches + verified remediation',                 key: 'fix'      },
  { icon: CheckCircle2, label: 'Deterministic dominance + FP minimizer + delta',     key: 'audit'    },
];

const HACKER_COMMANDS = [
  { delay: 0, output: '[*] Initializing 31-stage security pipeline...' },
  { delay: 400, output: '[+] Loading security rules engine (60+ patterns)...' },
  { delay: 800, output: '[*] Scanning for hardcoded secrets and weak crypto...' },
  { delay: 1200, output: '[*] Running taint analysis: tracking source→sink flows...' },
  { delay: 1800, output: '[+] Building call graph and control flow graph...' },
  { delay: 2500, output: '[*] Detecting framework context (Express, React, Django)...' },
  { delay: 3200, output: '[+] Adaptive routing: analyzing code complexity...' },
  { delay: 4000, output: '[*] Launching AI consensus: Analyzer + Critic + Verifier...' },
  { delay: 5500, output: '[+] Synthesizing attack chains (SSRF→RCE, SQLi→auth bypass)...' },
  { delay: 7000, output: '[*] Running exploit replay: testing payload reachability...' },
  { delay: 8500, output: '[+] Root-cause graph: collapsing duplicate findings...' },
  { delay: 10000, output: '[*] Confidence decay: suppressing low-signal findings...' },
  { delay: 11500, output: '[+] Family clustering: grouping by vulnerability class...' },
  { delay: 13000, output: '[*] Computing weighted security score...' },
  { delay: 14500, output: '[+] Hallucination firewall: AST-backed verification...' },
  { delay: 16000, output: '[*] Bayesian calibration: evidence-weighted severity...' },
  { delay: 17500, output: '[+] Verified remediation: patch→taint→replay→certify...' },
  { delay: 19000, output: '[*] Business-impact risk model: filtering fake criticals...' },
  { delay: 20500, output: '[+] Security memory: suppressing recurring FPs...' },
  { delay: 22000, output: '[*] Runtime verification: simulating exploit payloads...' },
  { delay: 23500, output: '[+] Proof obligations: validating source+sink+path...' },
  { delay: 25000, output: '[*] Knowledge graph: CVE/CWE enrichment...' },
  { delay: 26500, output: '[+] Deterministic dominance: AI proposes, det decides...' },
  { delay: 28000, output: '[*] FP minimizer: framework guarantees + sanitizer certainty...' },
  { delay: 29500, output: '[+] CI/CD delta analysis: security diff vs baseline...' },
  { delay: 31000, output: '[*] Policy layer: OWASP/PCI-DSS/SOC2 compliance...' },
  { delay: 32500, output: '[+] Benchmark harness: precision/recall validation...' },
  { delay: 34000, output: '[✓] Pipeline complete. Generating report...' },
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
  const [langId, setLangId]           = useState('auto');
  const [modelId, setModelId]         = useState<ModelId>('auto');
  const [result, setResult]           = useState<ReviewResult | null>(null);
  const [isLoading, setIsLoading]     = useState(false);
  const [loadingMsgIdx, setLoadingMsgIdx] = useState(0);
  const [error, setError]             = useState<string | null>(null);
  
  const [userApiKey, setUserApiKey]   = useState('');
  const [showApiSettings, setShowApiSettings] = useState(false);
  const [isHackerMode, setIsHackerMode] = useState(false);
  const [hackerLogs, setHackerLogs] = useState<string[]>([]);
  const hackerLogRef = useRef<HTMLDivElement>(null);
  
  const [scanHistory, setScanHistory] = useState<SavedScan[]>([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);

  const [splitPct, setSplitPct]       = useState(60);
  const [isDragging, setIsDragging]   = useState(false);
  const [isDragOver, setIsDragOver]   = useState(false);
  
  const editorFocusRef = useRef<(() => void) | null>(null);
  const fileInputRef   = useRef<HTMLInputElement>(null);
  const abortRef       = useRef<AbortController | null>(null);
  const intervalRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const debounceRef    = useRef<ReturnType<typeof setTimeout> | null>(null);
  const dividerRef     = useRef<HTMLDivElement>(null);
  const containerRef   = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const savedKey = localStorage.getItem('openrouter_key');
    if (savedKey) setUserApiKey(savedKey);

    const savedHistory = localStorage.getItem('scan_history');
    if (savedHistory) {
      try { 
        const parsed = JSON.parse(savedHistory);
        setScanHistory(parsed.filter((s: SavedScan) => s.result && s.code)); 
      } catch (e) { console.error('Failed to parse history', e); }
    }
  }, []);

  useEffect(() => {
    if (hackerLogRef.current) {
      hackerLogRef.current.scrollTop = hackerLogRef.current.scrollHeight;
    }
  }, [hackerLogs]);

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

  const runAnalysis = useCallback(async () => {
    if (!code?.trim() || isLoading) return;
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setIsLoading(true);
    setError(null);
    setResult(null);

    if (isHackerMode) {
      setHackerLogs([]);
      HACKER_COMMANDS.forEach(({ delay, output }) => {
        setTimeout(() => {
          setHackerLogs(prev => [...prev, `${new Date().toLocaleTimeString()} ${output}`]);
        }, delay);
      });
    }

    try {
      const response = await fetch('/api/review', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-openrouter-key': userApiKey
        },
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
            if (ev.type === 'done')  {
              setResult(ev.result);
              
              // 🕒 Auto-save to history EXACTLY when a new scan finishes
              const newScan: SavedScan = {
                id: Date.now().toString(),
                date: new Date().toISOString(),
                score: ev.result.score,
                language: ev.result.language,
                issueCount: ev.result.issues.length,
                summary: ev.result.summary,
                auditPassed: ev.result.auditPassed,
                code: code,
                result: ev.result,
              };
              setScanHistory(prev => {
                const updated = [newScan, ...prev].slice(0, 15); 
                try {
                  localStorage.setItem('scan_history', JSON.stringify(updated));
                } catch (e) {
                  console.error('LocalStorage full', e);
                  try { localStorage.setItem('scan_history', JSON.stringify([newScan])); } catch {}
                }
                return updated;
              });
            }
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
      if (isHackerMode) {
        setHackerLogs(prev => [...prev, `${new Date().toLocaleTimeString()} [✓] Analysis complete. Results ready.`]);
      }
    }
  }, [code, modelId, langId, isLoading, userApiKey, isHackerMode]);

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

  const handleApplyFix = useCallback((optimized: string) => {
    setCode(optimized);
    setResult(null);
    setError(null);
    setTimeout(() => editorFocusRef.current?.(), 50);
  }, []);

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
    <div 
      className={cn("flex flex-col h-screen overflow-hidden transition-colors duration-500", isHackerMode && "hacker-mode")} 
      style={{ 
        background: isHackerMode ? '#000000' : '#09090b',
        fontFamily: isHackerMode ? "'JetBrains Mono', 'Fira Code', 'Courier New', monospace" : "inherit"
      }}
    >
      {isHackerMode && (
        <style dangerouslySetInnerHTML={{ __html: `
          .hacker-mode {
            background-image: 
              linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%),
              linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
            background-size: 100% 2px, 3px 100%;
          }
          .hacker-mode * { text-shadow: 0 0 2px rgba(0, 255, 0, 0.4); }
          .hacker-mode .text-zinc-100, .hacker-mode .text-zinc-300, .hacker-mode .text-white, 
          .hacker-mode .text-zinc-400, .hacker-mode .text-zinc-500 { color: #33ff33 !important; }
          .hacker-mode .text-violet-400, .hacker-mode .text-violet-300 { color: #00ff00 !important; }
          .hacker-mode .bg-violet-600, .hacker-mode .bg-violet-500 { 
            background-color: #00ff00 !important; 
            color: #000000 !important; 
            text-shadow: none !important; 
          }
          .hacker-mode .border-white\\/10, .hacker-mode .border-white\\/5 { border-color: rgba(0, 255, 0, 0.2) !important; }
          .hacker-mode .bg-white\\/5 { background-color: rgba(0, 255, 0, 0.05) !important; }
          .hacker-mode .bg-black\\/40 { background-color: rgba(0, 20, 0, 0.6) !important; }
          
          @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
          }
          .cursor-blink {
            animation: blink 1s infinite;
          }
        `}} />
      )}

      <input
        ref={fileInputRef}
        type="file"
        className="hidden"
        accept=".js,.jsx,.ts,.tsx,.py,.rs,.go,.java,.cpp,.cc,.cs,.php,.rb,.swift,.kt,.sql,.sh,.bash,.txt"
        onChange={handleFileInputChange}
      />
      
      {!isHackerMode && (
        <>
          <div className="pointer-events-none fixed inset-0 z-0" style={{ background: 'radial-gradient(ellipse 80% 40% at 50% -10%, rgba(124,58,237,0.10) 0%, transparent 70%)' }} />
          <div className="pointer-events-none fixed inset-0 z-0" style={{ background: 'radial-gradient(ellipse 40% 30% at 80% 80%, rgba(37,99,235,0.05) 0%, transparent 60%)' }} />
        </>
      )}

      <nav
        className="relative z-20 flex-shrink-0 flex items-center justify-between px-5 py-2.5"
        style={{ background: isHackerMode ? 'rgba(0,0,0,0.9)' : 'rgba(9,9,11,0.85)', borderBottom: '1px solid rgba(255,255,255,0.06)', backdropFilter: 'blur(20px) saturate(180%)', WebkitBackdropFilter: 'blur(20px) saturate(180%)', boxShadow: '0 1px 0 rgba(255,255,255,0.04)' }}
      >
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-600 to-blue-600 flex items-center justify-center" style={{ boxShadow: '0 0 12px rgba(124,58,237,0.4)' }}>
            <Code2 className="w-4 h-4 text-white" />
          </div>
          <span className="text-sm font-semibold text-zinc-100 tracking-tight">AI Code Review <span className="text-[10px] text-violet-400 font-mono">v1.4.2</span></span>
        </div>

        <div className="flex items-center gap-2">
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

          <button
            onClick={() => setShowHistoryModal(true)}
            className="p-1.5 rounded-lg bg-white/5 border border-white/10 text-zinc-400 hover:text-white hover:bg-white/10 transition-colors"
            title="Scan History"
          >
            <History className="w-4 h-4" />
          </button>

          <button
            onClick={() => setIsHackerMode(!isHackerMode)}
            className={cn(
              "p-1.5 rounded-lg border transition-all duration-300",
              isHackerMode
                ? "bg-green-500/20 border-green-500/50 text-green-400 shadow-[0_0_10px_rgba(34,197,94,0.4)]"
                : "bg-white/5 border-white/10 text-zinc-400 hover:text-white hover:bg-white/10"
            )}
            title={isHackerMode ? "Disable Hacker Mode" : "Enable Hacker Mode"}
          >
            <Terminal className="w-4 h-4" />
          </button>

          <button
            onClick={() => setShowApiSettings(true)}
            className="p-1.5 rounded-lg bg-white/5 border border-white/10 text-zinc-400 hover:text-white hover:bg-white/10 transition-colors"
            title={userApiKey ? "API Key Saved (Click to edit)" : "Add OpenRouter API Key"}
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
          </button>

          <Button
            variant="accent" size="md" isLoading={isLoading}
            onClick={handleAnalyze} disabled={!code?.trim()}
            leftIcon={!isLoading ? <Sparkles className="w-3.5 h-3.5" /> : undefined}
            className="min-w-[110px]"
            title="Ctrl+Enter"
          >
            {isLoading ? 'Analyzing...' : 'Analyze'}
          </Button>
        </div>
      </nav>

      {error && (
        <div className="relative z-20 flex-shrink-0 flex items-center gap-3 px-5 py-2.5 bg-red-500/10 border-b border-red-500/20">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <p className="text-xs text-red-300 flex-1">{error}</p>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300 transition-colors flex-shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {!isHackerMode && <PipelineStatus isLoading={isLoading} msgIdx={loadingMsgIdx} />}

      {isHackerMode && isLoading && (
        <div className="fixed inset-0 z-50 bg-black flex flex-col" style={{ fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace" }}>
          <div className="flex items-center justify-between px-4 py-2 bg-black border-b border-green-500/30">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
              </div>
              <span className="text-xs text-green-400 ml-2">root@ai-reviewer:~/security-audit</span>
            </div>
            <button
              onClick={() => setIsHackerMode(false)}
              className="text-green-400 hover:text-green-300 text-xs"
            >
              [ESC] Exit Terminal
            </button>
          </div>

          <div 
            ref={hackerLogRef}
            className="flex-1 overflow-y-auto p-4 text-xs leading-relaxed"
            style={{ 
              color: '#33ff33',
              textShadow: '0 0 2px rgba(0, 255, 0, 0.4)',
              backgroundImage: 'linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%)',
              backgroundSize: '100% 2px'
            }}
          >
            <div className="mb-2 text-green-600">
              AI Code Review Security Pipeline v1.4.2<br/>
              31-Stage Deterministic + AI Analysis Engine<br/>
              ──────────────────────────────────────────────────────────────────────
            </div>
            
            {hackerLogs.map((log, idx) => (
              <div key={idx} className="mb-1 fade-in-up">
                <span className="text-green-600">$ </span>
                {log}
              </div>
            ))}
            
            {isLoading && (
              <div className="mt-2 flex items-center gap-2">
                <span className="text-green-600">$ </span>
                <span className="inline-block w-2 h-4 bg-green-500 cursor-blink"></span>
              </div>
            )}
          </div>

          <div className="px-4 py-2 bg-black border-t border-green-500/30 flex items-center justify-between text-xs text-green-600">
            <span>Session: {new Date().toLocaleString()}</span>
            <span>Target: {fileName} ({code?.split('\n').length || 0} lines)</span>
          </div>
        </div>
      )}

      <main
        ref={containerRef}
        className="relative z-10 flex flex-1 overflow-hidden"
        style={{ cursor: isDragging ? 'col-resize' : 'default' }}
      >
        <div
          className="flex flex-col overflow-hidden flex-shrink-0"
          style={{ width: `${splitPct}%`, borderRight: '1px solid rgba(255,255,255,0.06)', minHeight: 0 }}
        >
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
                <button onClick={handleAnalyze} disabled={isLoading || !code?.trim()} title="Run analysis — Ctrl+Enter" className="w-3 h-3 rounded-full group relative transition-transform hover:scale-110 active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed" style={{ background: 'rgba(34,197,94,0.7)', boxShadow: '0 0 0 1px rgba(34,197,94,0.3)' }}>
                  <span className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 8 8" width="5" height="5" fill="rgba(0,0,0,0.6)"><polygon points="2,1 7,4 2,7"/></svg>
                  </span>
                </button>
              </div>
              <span className="text-xs text-zinc-600 font-mono ml-1">{fileName}</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => fileInputRef.current?.click()}
                title="Upload code file"
                className="flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-300 transition-colors px-1.5 py-0.5 rounded-md hover:bg-white/5"
              >
                <Upload className="w-3 h-3" />
                <span className="hidden sm:inline">Upload</span>
              </button>
              <span className="text-[10px] text-zinc-700 font-mono hidden sm:block">Ctrl+Enter · Ctrl+K · Ctrl+/</span>
              <span className="text-[10px] text-zinc-700 font-mono">{code?.split('\n').length || 0}L · {code?.length || 0}ch</span>
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

          <div
            className="relative overflow-hidden"
            style={{ flex: 1, minHeight: 0 }}
            onDragOver={handleEditorDragOver}
            onDragLeave={handleEditorDragLeave}
            onDrop={handleEditorDrop}
          >
            <CodeEditor
              value={code || ''}
              onChange={setCode}
              language={langId}
              bugLines={bugLines}
              onFocusRef={editorFocusRef}
            />
            {isDragOver && (
              <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 fade-in-up pointer-events-none"
                style={{ background: 'rgba(124,58,237,0.10)', border: '2px dashed rgba(124,58,237,0.5)' }}>
                <Upload className="w-8 h-8 text-violet-400" />
                <p className="text-sm font-medium text-violet-300">Drop to load file</p>
              </div>
            )}
          </div>
        </div>

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
          <div className="relative z-10 flex flex-col gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
            {[0,1,2].map(i => (
              <div key={i} className="w-0.5 h-0.5 rounded-full" style={{ background: isDragging ? 'rgba(124,58,237,0.8)' : 'rgba(255,255,255,0.3)' }} />
            ))}
          </div>
        </div>

        <div className="flex flex-col overflow-hidden flex-1">
          <div className="flex items-center justify-between px-4 py-2 flex-shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Analysis</span>
            {result && !isLoading && (
              <div className="flex items-center gap-2">
                <button 
                  onClick={() => exportToJson(result, code || '')}
                  className="flex items-center gap-1 px-2 py-1 rounded-md bg-white/5 border border-white/10 text-zinc-400 hover:text-white hover:bg-white/10 transition-colors text-[10px] font-medium"
                  title="Export Raw JSON"
                >
                  <FileJson className="w-3 h-3" /> JSON
                </button>
                <button 
                  onClick={() => exportToPdf(result, code || '')}
                  className="flex items-center gap-1 px-2 py-1 rounded-md bg-violet-600/20 border border-violet-500/30 text-violet-300 hover:bg-violet-600/30 transition-colors text-[10px] font-medium"
                  title="Export Professional PDF Report"
                >
                  <FileDown className="w-3 h-3" /> PDF Report
                </button>

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
              originalCode={code || ''}
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

      {showHistoryModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-zinc-900 border border-white/10 rounded-xl p-6 max-w-2xl w-full max-h-[80vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-white">Scan History</h2>
              <button onClick={() => setShowHistoryModal(false)} className="text-zinc-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            {scanHistory.length === 0 ? (
              <p className="text-zinc-500 text-center py-8">No scans recorded yet. Analyze some code to build your history!</p>
            ) : (
              <div className="flex-1 overflow-y-auto pr-2 space-y-3">
                {scanHistory.map((scan) => (
                  <div key={scan.id} className="p-4 bg-black/40 border border-white/5 rounded-lg flex items-center gap-4 hover:bg-white/5 transition-colors">
                    <div className={`w-12 h-12 rounded-full flex items-center justify-center font-bold text-lg flex-shrink-0 ${
                      scan.score >= 80 ? 'bg-green-500/20 text-green-400 border border-green-500/30' :
                      scan.score >= 50 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      'bg-red-500/20 text-red-400 border border-red-500/30'
                    }`}>
                      {scan.score}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-white font-medium truncate">{scan.summary.slice(0, 45)}{scan.summary.length > 45 ? '...' : ''}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-zinc-400 font-mono uppercase flex-shrink-0">{scan.language}</span>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-zinc-500">
                        <span>{new Date(scan.date).toLocaleString()}</span>
                        <span>•</span>
                        <span>{scan.issueCount} issue{scan.issueCount !== 1 ? 's' : ''}</span>
                      </div>
                    </div>
                    <div className="flex flex-col gap-2 flex-shrink-0">
                      <button 
                        onClick={() => {
                          setCode(scan.code || DEFAULT_CODE);
                          setResult(scan.result || null);
                          setShowHistoryModal(false);
                        }}
                        className="px-3 py-1.5 text-[10px] font-medium bg-violet-600/20 border border-violet-500/30 text-violet-300 rounded hover:bg-violet-600/30 transition-colors"
                      >
                        View Results
                      </button>
                      <button 
                        onClick={() => {
                          if (scan.result) exportToPdf(scan.result, scan.code || '');
                        }}
                        className="px-3 py-1.5 text-[10px] font-medium bg-white/5 border border-white/10 text-zinc-300 rounded hover:bg-white/10 transition-colors flex items-center justify-center gap-1"
                      >
                        <FileDown className="w-3 h-3" /> PDF
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="mt-4 pt-4 border-t border-white/10 flex justify-between items-center">
              <span className="text-xs text-zinc-500">{scanHistory.length} scan{scanHistory.length !== 1 ? 's' : ''} saved locally (max 15)</span>
              {scanHistory.length > 0 && (
                <button 
                  onClick={() => {
                    if (confirm('Clear all scan history?')) {
                      setScanHistory([]);
                      localStorage.removeItem('scan_history');
                    }
                  }}
                  className="text-xs text-red-400 hover:text-red-300 transition-colors"
                >
                  Clear History
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {showApiSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-zinc-900 border border-white/10 rounded-xl p-6 max-w-md w-full shadow-2xl">
            <h2 className="text-lg font-bold text-white mb-2">OpenRouter API Settings</h2>
            <p className="text-sm text-zinc-400 mb-4">
              Enter your OpenRouter API key. It is saved securely in your browser's local storage.
              <a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer" className="text-violet-400 hover:underline ml-1">Get a free key here.</a>
            </p>
            <input
              type="password"
              placeholder="sk-or-v1-..."
              value={userApiKey}
              onChange={(e) => setUserApiKey(e.target.value)}
              className="w-full p-3 bg-black/40 border border-white/10 rounded-lg text-white mb-4 focus:outline-none focus:ring-2 focus:ring-violet-500/50 font-mono text-sm"
            />
            <div className="flex gap-3">
              <button 
                onClick={() => {
                  localStorage.setItem('openrouter_key', userApiKey);
                  setShowApiSettings(false);
                }}
                className="flex-1 bg-violet-600 hover:bg-violet-700 text-white font-semibold py-2 px-4 rounded-lg transition-colors"
              >
                Save Key
              </button>
              <button 
                onClick={() => setShowApiSettings(false)}
                className="flex-1 bg-white/5 hover:bg-white/10 text-white font-semibold py-2 px-4 rounded-lg transition-colors border border-white/10"
              >
                Cancel
              </button>
            </div>
            {userApiKey && (
              <button
                onClick={() => {
                  setUserApiKey('');
                  localStorage.removeItem('openrouter_key');
                }}
                className="w-full mt-3 text-xs text-red-400 hover:text-red-300 transition-colors"
              >
                Clear saved key
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}