'use client';

import { useState, useCallback } from 'react';
import { diffLines } from 'diff';
import {
  Bug, Shield, Lightbulb, AlertTriangle, Copy, Check, GitCompare,
  LayoutDashboard, AlertCircle, Info,
  ChevronDown, ChevronUp, XCircle, Zap, Wrench, ShieldAlert, ArrowLeftRight,
  Network, Cpu, GitBranch, FlaskConical, TriangleAlert, Users, Eye,
} from 'lucide-react';
import { Tabs, type Tab } from '@/components/ui/Tabs';
import { Button } from '@/components/ui/Button';
import { cn, type ReviewResult, type Issue, type IssueType, type IssueCategory } from '@/lib/utils';

interface AnalysisPanelProps {
  result: ReviewResult | null;
  isLoading: boolean;
  loadingMessage: string;
  error: string | null;
  originalCode: string;
  onRetry: () => void;
  onApplyFix?: (optimizedCode: string) => void;
}

type TabId = 'overview' | 'bugs' | 'risks' | 'suggestions' | 'diff' | 'visual';

export function AnalysisPanel({ result, isLoading, loadingMessage, error, originalCode, onRetry, onApplyFix }: AnalysisPanelProps) {
  const [activeTab, setActiveTab] = useState<TabId>('overview');

  const bugs        = result?.issues.filter((i) => i.type === 'bug')        ?? [];
  const risks       = result?.issues.filter((i) => i.type === 'risk')       ?? [];
  const suggestions = result?.issues.filter((i) => i.type === 'suggestion') ?? [];

  const tabs: Tab[] = [
    { id: 'overview',     label: 'Overview',  icon: <LayoutDashboard className="w-3.5 h-3.5" /> },
    { id: 'bugs',         label: 'Bugs',      icon: <Bug             className="w-3.5 h-3.5" />, count: result ? bugs.length        : undefined },
    { id: 'risks',        label: 'Risks',     icon: <AlertTriangle   className="w-3.5 h-3.5" />, count: result ? risks.length       : undefined },
    { id: 'suggestions',  label: 'Suggest',   icon: <Lightbulb       className="w-3.5 h-3.5" />, count: result ? suggestions.length : undefined },
    { id: 'diff',         label: 'Diff',      icon: <GitCompare      className="w-3.5 h-3.5" /> },
    { id: 'visual',       label: 'Visual',    icon: <Eye             className="w-3.5 h-3.5" /> },
  ];

  if (error && !result) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
        <div className="w-12 h-12 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
          <XCircle className="w-6 h-6 text-red-400" />
        </div>
        <div className="text-center">
          <p className="text-sm font-semibold text-zinc-200 mb-1">Analysis Failed</p>
          <p className="text-xs text-zinc-500 max-w-xs leading-relaxed">{error}</p>
        </div>
        <Button variant="outline" size="sm" onClick={onRetry}>Retry</Button>
      </div>
    );
  }

  if (!result && !isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 p-8">
        <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mb-2">
          <svg className="w-8 h-8 opacity-20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <p className="text-sm font-medium text-zinc-400">Ready to analyze</p>
        <p className="text-xs text-zinc-600 text-center max-w-xs">
          Paste your code and click Analyze (or Ctrl+Enter) for structured AI feedback with exploit detection
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <Tabs tabs={tabs} activeTab={activeTab} onChange={(id) => setActiveTab(id as TabId)} className="px-4 flex-shrink-0" />

      {result && !result.auditPassed && (
        <div
          className="mx-4 mt-3 flex items-start gap-2 rounded-xl p-2.5 border flex-shrink-0"
          style={{ background: 'rgba(245,158,11,0.06)', borderColor: 'rgba(245,158,11,0.25)' }}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider mb-0.5">Heuristic Checks Did Not Pass — Manual Review Required</p>
            <p className="text-[10px] text-zinc-500 leading-relaxed">{result.auditDetail}</p>
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        <div key={activeTab} className="p-4 fade-in-up">
          {activeTab === 'overview'    && <OverviewTab    result={result}      isLoading={isLoading} loadingMessage={loadingMessage} />}
          {activeTab === 'bugs'        && <IssueList      issues={bugs}        isLoading={isLoading} emptyLabel="No bugs detected" emptyPositive />}
          {activeTab === 'risks'       && <IssueList      issues={risks}       isLoading={isLoading} emptyLabel="No risks detected" emptyPositive />}
          {activeTab === 'suggestions' && <IssueList      issues={suggestions} isLoading={isLoading} emptyLabel="No suggestions" />}
          {activeTab === 'diff'        && (
            <DiffTab
              original={originalCode}
              optimized={result?.optimized_code}
              isLoading={isLoading}
              onApplyFix={onApplyFix}
            />
          )}
          {activeTab === 'visual'      && <VisualSecurityTab result={result} isLoading={isLoading} />}
        </div>
      </div>
    </div>
  );
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────

function OverviewTab({ result, isLoading, loadingMessage }: { result: ReviewResult | null; isLoading: boolean; loadingMessage: string }) {
  if (isLoading) {
    return (
      <div className="flex flex-col gap-4">
        <LoadingState message={loadingMessage} />
        <SkeletonList count={3} />
      </div>
    );
  }
  if (!result) return <EmptyState label="No analysis yet" />;

  const bugs         = result.issues.filter((i) => i.type === 'bug');
  const risks        = result.issues.filter((i) => i.type === 'risk');
  const suggestions  = result.issues.filter((i) => i.type === 'suggestion');
  const securityBugs = bugs.filter((i) => i.category === 'security');

  const scoreColor = result.score >= 80 ? '#22c55e' : result.score >= 60 ? '#facc15' : '#ef4444';
  const scoreLabel = result.score >= 80 ? 'Good'    : result.score >= 60 ? 'Fair'    : 'Needs Work';

  return (
    <div className="flex flex-col gap-4">
      {/* Score card */}
      <div
        className="rounded-2xl p-4"
        style={{ background: 'linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)', border: '1px solid rgba(255,255,255,0.08)', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06)' }}
      >
        <div className="flex items-center justify-between mb-3">
          <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Quality Score</p>
          <span className="text-xs font-medium px-2 py-0.5 rounded-lg" style={{ background: `${scoreColor}20`, color: scoreColor, border: `1px solid ${scoreColor}30` }}>
            {scoreLabel}
          </span>
        </div>
        <div className="flex items-end gap-3 mb-3">
          <span className="text-4xl font-bold tabular-nums" style={{ color: scoreColor }}>{result.score}</span>
          <span className="text-zinc-600 text-lg mb-1">/100</span>
        </div>
        <div className="w-full h-1.5 rounded-full bg-white/5 overflow-hidden">
          <div className="h-full rounded-full transition-all duration-700" style={{ width: `${result.score}%`, background: `linear-gradient(90deg, ${scoreColor}80, ${scoreColor})` }} />
        </div>
      </div>

      {/* Summary */}
      {result.summary && (
        <div className="rounded-xl p-3" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Summary</p>
          <p className="text-xs text-zinc-400 leading-relaxed">{result.summary}</p>
        </div>
      )}

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-2">
        <StatCard label="Security Bugs" value={securityBugs.length}              color="#ef4444" icon={<Shield        className="w-3.5 h-3.5" />} urgent={securityBugs.length > 0} />
        <StatCard label="Logic Bugs"    value={bugs.length - securityBugs.length} color="#f97316" icon={<Bug           className="w-3.5 h-3.5" />} urgent={(bugs.length - securityBugs.length) > 0} />
        <StatCard label="Risks"         value={risks.length}                      color="#f59e0b" icon={<AlertTriangle className="w-3.5 h-3.5" />} />
        <StatCard label="Suggestions"   value={suggestions.length}                color="#8b5cf6" icon={<Lightbulb     className="w-3.5 h-3.5" />} />
      </div>

      {/* Top issues preview */}
      {result.issues.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-2">Top Issues</p>
          <div className="flex flex-col gap-1.5">
            {result.issues.slice(0, 3).map((issue, i) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-lg" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', issue.severity === 'high' ? 'bg-red-400' : issue.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400')} />
                <span className="text-[10px] text-zinc-400 flex-1 truncate">{issue.title}</span>
                {issue.line && <span className="text-[9px] text-zinc-600 font-mono flex-shrink-0">L{issue.line}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* v10: Pipeline metadata + all engine stats */}
      {result.pipelineMetadata && (
        <div className="rounded-xl p-3" style={{ background: 'rgba(124,58,237,0.06)', border: '1px solid rgba(124,58,237,0.18)' }}>
          <p className="text-[10px] font-semibold text-violet-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Cpu className="w-3 h-3" />Engine v1.4 — 31-Stage Pipeline + Constraint-Valid Attack Chains
          </p>
          <div className="grid grid-cols-2 gap-1.5">
            <MetaBadge icon={<Network className="w-3 h-3"/>} label="Taint sources" value={String(result.pipelineMetadata.taintSources)} />
            <MetaBadge icon={<GitBranch className="w-3 h-3"/>} label="Call graph nodes" value={String(result.pipelineMetadata.callGraphNodes)} />
            <MetaBadge icon={<Wrench className="w-3 h-3"/>} label="AST patches" value={String(result.pipelineMetadata.astPatchesApplied)} />
            {result.pipelineMetadata.frameworksDetected.length > 0 && (
              <MetaBadge icon={<Zap className="w-3 h-3"/>} label="Frameworks" value={result.pipelineMetadata.frameworksDetected.join(', ')} />
            )}
          </div>

          {/* v7: Confidence Decay Stats */}
          {result.pipelineMetadata.decayStats && result.pipelineMetadata.decayStats.totalInput > 0 && (() => {
            const ds = result.pipelineMetadata.decayStats!;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <Shield className="w-3 h-3"/>Confidence Decay Engine
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20 font-medium">
                    ✓ {ds.activeCount} active findings
                  </span>
                  {ds.suppressedCount > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
                      ⊘ {ds.suppressedCount} suppressed
                    </span>
                  )}
                  {ds.fpReductionPct > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      📉 {ds.fpReductionPct}% FP reduction
                    </span>
                  )}
                </div>
              </div>
            );
          })()}

          {/* v7: Family Clustering Stats */}
          {result.pipelineMetadata.clusterStats && result.pipelineMetadata.clusterStats.inputCount > 0 && (() => {
            const cs = result.pipelineMetadata.clusterStats!;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <Network className="w-3 h-3"/>Vuln Family Clustering
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-medium">
                    🎯 {cs.familyCount} unique famil{cs.familyCount !== 1 ? 'ies' : 'y'}
                  </span>
                  {cs.collapsed > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      ↗ {cs.collapsed} grouped
                    </span>
                  )}
                  {cs.topFamilies.slice(0, 2).map(f => (
                    <span key={f.family} className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-700/30 text-zinc-400 border border-zinc-700/40">
                      {f.family} ×{f.count}
                    </span>
                  ))}
                </div>
              </div>
            );
          })()}

          {/* v7: Attack Chain Synthesis */}
          {result.pipelineMetadata.attackChains && result.pipelineMetadata.attackChains.chainCount > 0 && (() => {
            const ac = result.pipelineMetadata.attackChains!;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <ArrowLeftRight className="w-3 h-3"/>Attack Chain Synthesis
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  <span className={`text-[9px] px-1.5 py-0.5 rounded border font-medium ${ac.maxSeverity === 'critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'}`}>
                    ⛓ {ac.chainCount} attack chain{ac.chainCount !== 1 ? 's' : ''}
                  </span>
                  {ac.maxSeverity === 'critical' && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                      🚨 Critical chain detected
                    </span>
                  )}
                  {ac.chains.slice(0, 1).map(c => (
                    <span key={c.id} className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-700/30 text-zinc-400 border border-zinc-700/40 truncate max-w-[160px]" title={c.title}>
                      {c.title.slice(0, 35)}{c.title.length > 35 ? '…' : ''}
                    </span>
                  ))}
                </div>
              </div>
            );
          })()}

          {/* v7: Weighted Scoring Rewards */}
          {result.pipelineMetadata.scoringBreakdown && result.pipelineMetadata.scoringBreakdown.positiveRewards > 0 && (() => {
            const sb = result.pipelineMetadata.scoringBreakdown!;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <Zap className="w-3 h-3"/>Security Rewards (+{sb.positiveRewards}pts)
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  {sb.securityRewards.slice(0, 4).map(r => (
                    <span key={r.label} className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">
                      ✓ {r.label}
                    </span>
                  ))}
                  {sb.securityRewards.length > 4 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-700/30 text-zinc-500 border border-zinc-700/40">
                      +{sb.securityRewards.length - 4} more
                    </span>
                  )}
                </div>
              </div>
            );
          })()}

          {/* v5: Root-cause graph stats */}
          {result.pipelineMetadata.rootCauseGraph && (() => {
            const rcg = result.pipelineMetadata.rootCauseGraph!;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <Network className="w-3 h-3"/>Root-Cause Graph
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-medium">
                    🎯 {rcg.uniqueSurfaces} unique exploit surface{rcg.uniqueSurfaces !== 1 ? 's' : ''}
                  </span>
                  {rcg.collapsed > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      ↗ {rcg.collapsed} duplicate{rcg.collapsed !== 1 ? 's' : ''} collapsed
                    </span>
                  )}
                  {rcg.suppressed > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
                      ⊘ {rcg.suppressed} suppressed (low reachability)
                    </span>
                  )}
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-700/30 text-zinc-500 border border-zinc-700/40">
                    {rcg.totalInput} raw findings in
                  </span>
                </div>
              </div>
            );
          })()}

          {result.pipelineMetadata.consensusStats && (
            <div className="mt-2 pt-2 border-t border-violet-500/15">
              <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1"><Users className="w-3 h-3"/>Multi-role Consensus</p>
              <div className="flex gap-2 flex-wrap">
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">✓ {result.pipelineMetadata.consensusStats.agreed} agreed</span>
                {result.pipelineMetadata.consensusStats.escalated > 0 && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">⚠ {result.pipelineMetadata.consensusStats.escalated} escalated</span>
                )}
                {result.pipelineMetadata.consensusStats.rejected > 0 && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">✕ {result.pipelineMetadata.consensusStats.rejected} rejected FPs</span>
                )}
              </div>
            </div>
          )}

          {(result.pipelineMetadata as ReviewResult['pipelineMetadata'] & { reachabilityStats?: { total:number; externalAnon:number; authRequired:number; adminOnly:number; deadCode:number; devOnly:number } })?.reachabilityStats && (() => {
            const rs = (result.pipelineMetadata as any).reachabilityStats;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <Shield className="w-3 h-3"/>Reachability Analysis
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  {rs.externalAnon > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-medium">🌐 {rs.externalAnon} public sinks</span>}
                  {rs.authRequired > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">🔐 {rs.authRequired} auth-required</span>}
                  {rs.adminOnly > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">👤 {rs.adminOnly} admin-only</span>}
                  {rs.deadCode > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">💀 {rs.deadCode} dead code</span>}
                  {rs.devOnly > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-600/10 text-zinc-500 border border-zinc-700/40">🧪 {rs.devOnly} dev-only</span>}
                </div>
              </div>
            );
          })()}

          {(result.pipelineMetadata as any)?.exploitReplay?.total > 0 && (() => {
            const er = (result.pipelineMetadata as any).exploitReplay;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <FlaskConical className="w-3 h-3"/>Exploit Replay Engine
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  {er.verified > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-medium">⚡ {er.verified} confirmed exploitable</span>}
                  {er.blocked > 0 && <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">✓ {er.blocked} blocked by sanitizer</span>}
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-zinc-700/30 text-zinc-500 border border-zinc-700/40">{er.total} replays run</span>
                </div>
              </div>
            );
          })()}


          {/* v10: Constraint-Valid Attack Chains */}
          {result.pipelineMetadata.constraintChains && result.pipelineMetadata.constraintChains.total > 0 && (() => {
            const cc = result.pipelineMetadata.constraintChains!;
            return (
              <div className="mt-2 pt-2 border-t border-violet-500/15">
                <p className="text-[9px] text-zinc-500 mb-1.5 uppercase tracking-wider font-medium flex items-center gap-1">
                  <ArrowLeftRight className="w-3 h-3"/>Constraint-Valid Attack Chains
                </p>
                <div className="flex gap-1.5 flex-wrap">
                  {cc.fullyValidated > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-medium">
                      🔗 {cc.fullyValidated} fully proven
                    </span>
                  )}
                  {cc.partiallyValidated > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      ⚠ {cc.partiallyValidated} partial
                    </span>
                  )}
                  {cc.highestCvss > 0 && (
                    <span className={`text-[9px] px-1.5 py-0.5 rounded border font-medium ${cc.highestCvss >= 9 ? 'bg-red-500/10 text-red-400 border-red-500/20' : cc.highestCvss >= 7 ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-zinc-700/30 text-zinc-400 border-zinc-700/40'}`}>
                      CVSS {cc.highestCvss.toFixed(1)}
                    </span>
                  )}
                  {cc.criticalCount > 0 && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30 font-semibold">
                      🚨 {cc.criticalCount} critical chain{cc.criticalCount !== 1 ? 's' : ''}
                    </span>
                  )}
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}

function MetaBadge({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5 rounded-lg p-1.5" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
      <span className="text-violet-400 flex-shrink-0">{icon}</span>
      <div className="min-w-0">
        <p className="text-[9px] text-zinc-600 truncate">{label}</p>
        <p className="text-[10px] text-zinc-300 font-medium truncate">{value}</p>
      </div>
    </div>
  );
}

function StatCard({ label, value, color, icon, urgent }: { label: string; value: number; color: string; icon: React.ReactNode; urgent?: boolean }) {
  return (
    <div
      className="rounded-xl p-3 transition-all duration-200"
      style={{
        background:   urgent && value > 0 ? `${color}10` : 'rgba(255,255,255,0.03)',
        border:      `1px solid ${urgent && value > 0 ? `${color}25` : 'rgba(255,255,255,0.07)'}`,
      }}
    >
      <div className="flex items-center justify-between mb-1">
        <span style={{ color: value > 0 ? color : '#52525b' }}>{icon}</span>
        <span className="text-2xl font-bold tabular-nums" style={{ color: value > 0 ? color : '#3f3f46' }}>{value}</span>
      </div>
      <p className="text-[10px] text-zinc-600">{label}</p>
    </div>
  );
}

// ─── Issue List ───────────────────────────────────────────────────────────────

function IssueList({ issues, isLoading, emptyLabel, emptyPositive }: { issues: Issue[]; isLoading: boolean; emptyLabel: string; emptyPositive?: boolean }) {
  if (isLoading) return <SkeletonList count={3} />;
  if (!issues.length) return <EmptyState label={emptyLabel} positive={emptyPositive} />;
  return (
    <div className="flex flex-col gap-3">
      {issues.map((issue, i) => (
        <IssueCard
          key={`${issue.type}|${issue.category}|${issue.severity}|${issue.line ?? 'x'}|${issue.title.slice(0, 28)}`}
          issue={issue}
          index={i}
        />
      ))}
    </div>
  );
}

// ─── Category Config ──────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<IssueCategory, { label: string; color: string; bg: string; border: string; icon: React.ReactNode }> = {
  security:        { label: 'Security',    color: 'text-red-300',    bg: 'bg-red-500/10',    border: 'border-red-500/25',    icon: <Shield  className="w-2.5 h-2.5" /> },
  logic:           { label: 'Logic',       color: 'text-orange-300', bg: 'bg-orange-500/10', border: 'border-orange-500/25', icon: <Bug     className="w-2.5 h-2.5" /> },
  performance:     { label: 'Performance', color: 'text-blue-300',   bg: 'bg-blue-500/10',   border: 'border-blue-500/25',   icon: <Zap     className="w-2.5 h-2.5" /> },
  maintainability: { label: 'Style',       color: 'text-violet-300', bg: 'bg-violet-500/10', border: 'border-violet-500/25', icon: <Wrench  className="w-2.5 h-2.5" /> },
};

function CategoryTag({ category }: { category: IssueCategory }) {
  const cfg = CATEGORY_CONFIG[category] ?? CATEGORY_CONFIG['security'];
  return (
    <span className={cn('flex items-center gap-0.5 rounded-md border font-medium text-[10px] px-1.5 py-0.5', cfg.color, cfg.bg, cfg.border)}>
      {cfg.icon}{cfg.label}
    </span>
  );
}

// ─── Issue Card ───────────────────────────────────────────────────────────────

const SEVERITY_BORDER: Record<string, string> = { high: '#ef4444', medium: '#f59e0b', low: '#3b82f6' };
const SEVERITY_GLOW:   Record<string, string> = { high: 'rgba(239,68,68,0.12)', medium: 'rgba(245,158,11,0.08)', low: 'rgba(59,130,246,0.06)' };

function IssueCard({ issue, index }: { issue: Issue; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const [copied,   setCopied]   = useState(false);

  const handleCopy = useCallback(async () => {
    if (!issue.fix) return;
    await navigator.clipboard.writeText(issue.fix);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [issue.fix]);

  const SeverityIcon = issue.severity === 'high' ? AlertCircle : issue.severity === 'medium' ? AlertTriangle : Info;

  const typeConfig: Record<IssueType, { color: string; bg: string; border: string; label: string; icon: React.ReactNode }> = {
    bug:        { color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/20',    label: 'Bug',        icon: <Bug           className="w-3 h-3" /> },
    risk:       { color: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/20',  label: 'Risk',       icon: <AlertTriangle className="w-3 h-3" /> },
    suggestion: { color: 'text-violet-400', bg: 'bg-violet-500/10', border: 'border-violet-500/20', label: 'Suggestion', icon: <Lightbulb     className="w-3 h-3" /> },
  };

  const tc            = typeConfig[issue.type];
  const confidencePct = Math.round(issue.confidence * 100);
  const borderColor   = SEVERITY_BORDER[issue.severity];
  const glowColor     = SEVERITY_GLOW[issue.severity];
  const animDelay     = `${index * 40}ms`;

  return (
    <div
      className="overflow-hidden rounded-xl transition-all duration-200 fade-in-up"
      style={{
        animationDelay: animDelay,
        background: expanded
          ? 'linear-gradient(135deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)'
          : 'linear-gradient(135deg, rgba(255,255,255,0.035) 0%, rgba(255,255,255,0.015) 100%)',
        border:       `1px solid rgba(255,255,255,0.08)`,
        borderLeft:   `3px solid ${borderColor}`,
        backdropFilter: 'blur(12px)',
        boxShadow: expanded
          ? `0 4px 24px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.06), 0 0 20px ${glowColor}`
          : 'inset 0 1px 0 rgba(255,255,255,0.04)',
      }}
    >
      <div
        className="flex items-start gap-3 p-3 cursor-pointer select-none"
        onClick={() => setExpanded(!expanded)}
      >
        <SeverityIcon className={cn('w-4 h-4 mt-0.5 flex-shrink-0', issue.severity === 'high' ? 'text-red-400' : issue.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400')} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center flex-wrap gap-1.5 mb-1">
            <span className={cn('text-[10px] font-semibold px-1.5 py-0.5 rounded-md uppercase tracking-wider', issue.severity === 'high' ? 'severity-high' : issue.severity === 'medium' ? 'severity-medium' : 'severity-low')}>
              {issue.severity}
            </span>
            <span className={cn('text-[10px] font-medium flex items-center gap-0.5 px-1.5 py-0.5 rounded-md border', tc.color, tc.bg, tc.border)}>
              {tc.icon}{tc.label}
            </span>
            <CategoryTag category={issue.category} />
            {issue.line !== null && <span className="text-[10px] text-zinc-600 font-mono">L{issue.line}</span>}
            <div className="flex items-center gap-1.5 ml-auto flex-shrink-0">
              {/* blast radius dot */}
              {(issue as Issue & { blastRadius?: string }).blastRadius && (
                <span className="text-[8px] px-1 py-0.5 rounded font-bold uppercase" style={{
                  background: {critical:'rgba(239,68,68,0.15)',high:'rgba(245,158,11,0.12)',medium:'rgba(59,130,246,0.1)',low:'rgba(107,114,128,0.1)'}[(issue as Issue & {blastRadius?:string}).blastRadius!] ?? 'rgba(107,114,128,0.1)',
                  color: {critical:'#ef4444',high:'#f59e0b',medium:'#3b82f6',low:'#6b7280'}[(issue as Issue & {blastRadius?:string}).blastRadius!] ?? '#6b7280',
                  border: `1px solid ${{critical:'rgba(239,68,68,0.3)',high:'rgba(245,158,11,0.25)',medium:'rgba(59,130,246,0.2)',low:'rgba(107,114,128,0.2)'}[(issue as Issue & {blastRadius?:string}).blastRadius!] ?? 'rgba(107,114,128,0.2)'}`,
                }}>{(issue as Issue & {blastRadius?:string}).blastRadius}</span>
              )}
              <div className="flex items-center gap-1">
                <div className="w-10 h-1 rounded-full bg-white/5 overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${confidencePct}%`, background: confidencePct >= 80 ? '#22c55e' : confidencePct >= 60 ? '#facc15' : '#94a3b8' }} />
                </div>
                <span className="text-[9px] font-mono" style={{ color: confidencePct >= 80 ? '#22c55e' : confidencePct >= 60 ? '#facc15' : '#94a3b8' }}>{confidencePct}%</span>
              </div>
            </div>
          </div>
          <p className="text-xs font-medium text-zinc-200 leading-snug">{issue.title}</p>
        </div>
        <span className="flex-shrink-0 text-zinc-600 hover:text-zinc-400 transition-colors mt-0.5">
          {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </span>
      </div>

      {expanded && (
        <div className="px-3 pb-3 pt-2 border-t flex flex-col gap-3 fade-in-up" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>

          {/* v4: Escalation warning */}
          {(issue as Issue & { escalate?: boolean }).escalate && (
            <div className="flex items-center gap-2 rounded-lg p-2" style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.25)' }}>
              <TriangleAlert className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
              <p className="text-[10px] text-amber-400 font-medium">Escalated — roles disagreed. Manual expert review required before acting on this finding.</p>
            </div>
          )}

          {/* v4: Consensus + metrics row */}
          {((issue as Issue & { consensusScore?: number; exploitability?: number; reachability?: number; blastRadius?: string }).consensusScore !== undefined) && (
            <div className="flex flex-wrap gap-1.5">
              {['consensusScore','exploitability','reachability'].map(k => {
                const val = (issue as Record<string,unknown>)[k] as number | undefined;
                if (val === undefined) return null;
                const labels: Record<string,string> = { consensusScore:'Consensus', exploitability:'Exploit', reachability:'Reach' };
                const color = val >= 80 ? '#ef4444' : val >= 60 ? '#f59e0b' : '#22c55e';
                return (
                  <div key={k} className="flex items-center gap-1 rounded-md px-1.5 py-0.5" style={{ background: `${color}12`, border: `1px solid ${color}30` }}>
                    <span className="text-[9px] font-medium" style={{ color }}>{labels[k]}</span>
                    <span className="text-[10px] font-bold tabular-nums" style={{ color }}>{Math.round(val)}%</span>
                  </div>
                );
              })}
              {(issue as Issue & { blastRadius?: string }).blastRadius && (
                <div className="flex items-center gap-1 rounded-md px-1.5 py-0.5" style={{ background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.25)' }}>
                  <span className="text-[9px] text-violet-400 font-medium">Blast</span>
                  <span className="text-[10px] text-violet-300 font-bold uppercase">{(issue as Issue & { blastRadius?: string }).blastRadius}</span>
                </div>
              )}
              {(issue as Issue & { astPatched?: boolean; patchConfidence?: number }).astPatched && (
                <div className="flex items-center gap-1 rounded-md px-1.5 py-0.5" style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.25)' }}>
                  <Check className="w-2.5 h-2.5 text-green-400" />
                  <span className="text-[9px] text-green-400 font-medium">AST patched ({(issue as Issue & { patchConfidence?: number }).patchConfidence ?? 0}% conf.)</span>
                </div>
              )}
            </div>
          )}

          {issue.explanation && (
            <div>
              <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider mb-1.5">Why this matters</p>
              <p className="text-xs text-zinc-400 leading-relaxed">{issue.explanation}</p>
            </div>
          )}

          {/* v4: Exploit chain */}
          {issue.exploitChain && (
            <div className="rounded-xl p-3" style={{ background: 'rgba(239,68,68,0.05)', border: '1px solid rgba(239,68,68,0.18)' }}>
              <p className="text-[10px] font-semibold text-red-400 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                <FlaskConical className="w-3 h-3" />Attack Chain
              </p>
              <pre className="text-[10px] text-red-300/80 font-mono leading-relaxed whitespace-pre-wrap break-words">{issue.exploitChain}</pre>
            </div>
          )}

          {/* v4: Proof chain */}
          {(issue as Issue & { proofChain?: { payload: string; executionPath: string; blockedAt: string | null; observedResult: string; sinkReachable: boolean } }).proofChain && (
            <div className="rounded-xl p-3" style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.15)' }}>
              <p className="text-[10px] font-semibold text-red-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                <Shield className="w-3 h-3" />Exploit Proof
              </p>
              {(() => {
                const pc = (issue as Issue & { proofChain?: { payload: string; executionPath: string; blockedAt: string | null; observedResult: string; sinkReachable: boolean } }).proofChain!;
                return (
                  <div className="flex flex-col gap-1.5 text-[10px] font-mono">
                    {pc.payload && <div><span className="text-zinc-500">payload: </span><span className="text-orange-300">{pc.payload.slice(0,120)}</span></div>}
                    {pc.executionPath && <div><span className="text-zinc-500">path: </span><span className="text-zinc-300">{pc.executionPath.slice(0,120)}</span></div>}
                    {pc.blockedAt && <div><span className="text-zinc-500">blocked at: </span><span className="text-green-400">{pc.blockedAt}</span></div>}
                    {pc.observedResult && <div><span className="text-zinc-500">result: </span><span className={pc.sinkReachable ? 'text-red-400' : 'text-green-400'}>{pc.observedResult.slice(0,120)}</span></div>}
                    <div className="mt-1"><span className={cn('px-1.5 py-0.5 rounded-md text-[9px] font-medium', pc.sinkReachable ? 'bg-red-500/15 text-red-400 border border-red-500/25' : 'bg-green-500/15 text-green-400 border border-green-500/25')}>{pc.sinkReachable ? '⚠ Sink reachable — confirmed exploitable' : '✓ Sink unreachable — exploit blocked'}</span></div>
                  </div>
                );
              })()}
            </div>
          )}

          {/* v4: Role votes */}
          {(issue as Issue & { roleVotes?: Record<string,string> }).roleVotes && (
            <div className="rounded-lg p-2" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <p className="text-[9px] text-zinc-600 uppercase tracking-wider mb-1.5 flex items-center gap-1"><Users className="w-3 h-3" />Role Votes</p>
              <div className="flex flex-wrap gap-1">
                {Object.entries((issue as Issue & { roleVotes?: Record<string,string> }).roleVotes!).map(([role, vote]) => {
                  const voteColor = vote === 'confirmed' || vote === 'valid' ? '#22c55e' : vote === 'rejected' || vote === 'bypassable' ? '#ef4444' : '#6b7280';
                  return <span key={role} className="text-[9px] px-1.5 py-0.5 rounded font-mono" style={{ background: `${voteColor}15`, color: voteColor, border: `1px solid ${voteColor}30` }}>{role}: {vote}</span>;
                })}
              </div>
            </div>
          )}

          {issue.fix && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-1.5">
                  <p className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider">Production Fix</p>
                  {issue.category === 'security' ? (
                    <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-medium">⚠ Security fix — audit before deploy</span>
                  ) : (
                    <span className="text-[9px] px-1 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium">AI-generated — review before use</span>
                  )}
                </div>
                <button onClick={handleCopy} className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-200 transition-all duration-150 px-1.5 py-0.5 rounded-md hover:bg-white/5">
                  {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div className="rounded-xl p-3 border overflow-x-auto" style={{ background: 'rgba(0,0,0,0.6)', borderColor: 'rgba(255,255,255,0.08)', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.04)' }}>
                <pre className="text-xs text-zinc-300 font-mono leading-relaxed whitespace-pre-wrap break-words">{issue.fix}</pre>
              </div>
            </div>
          )}

          {!issue.fix && issue.fixRejectionReason && (
            <div className="rounded-xl p-3 border" style={{ background: 'rgba(239,68,68,0.04)', borderColor: 'rgba(239,68,68,0.2)' }}>
              <div className="flex items-center gap-1.5 mb-1">
                <ShieldAlert className="w-3 h-3 text-red-400 flex-shrink-0" />
                <p className="text-[10px] font-semibold text-red-400 uppercase tracking-wider">Auto-fix Rejected — Unsafe Pattern Detected</p>
              </div>
              <p className="text-[10px] text-zinc-500 leading-relaxed">{issue.fixRejectionReason}</p>
              <p className="text-[10px] text-zinc-600 mt-1.5 italic">A partial fix is worse than none. Implement a manually reviewed, production-safe alternative.</p>
            </div>
          )}

          {!issue.fix && !issue.fixRejectionReason && (
            <p className="text-[10px] text-zinc-600 italic">No code change required for this issue.</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Diff Tab ─────────────────────────────────────────────────────────────────

function DiffTab({
  original, optimized, isLoading, onApplyFix,
}: {
  original: string;
  optimized: string | undefined;
  isLoading: boolean;
  onApplyFix?: (code: string) => void;
}) {
  const [copied,  setCopied]  = useState(false);
  const [applied, setApplied] = useState(false);

  const handleCopy = useCallback(async () => {
    if (!optimized) return;
    await navigator.clipboard.writeText(optimized);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [optimized]);

  const handleApply = useCallback(() => {
    if (!optimized || !onApplyFix) return;
    onApplyFix(optimized);
    setApplied(true);
    setTimeout(() => setApplied(false), 2500);
  }, [optimized, onApplyFix]);

  if (isLoading) return <SkeletonList count={4} />;
  if (!optimized) return <EmptyState label="Run analysis to see optimized diff" />;

  const hunks = diffLines(original, optimized);

  type DiffRow = { text: string; status: 'added' | 'removed' | 'unchanged' };
  const rows: DiffRow[] = [];
  for (const hunk of hunks) {
    const lines  = hunk.value.replace(/\n$/, '').split('\n');
    const status: DiffRow['status'] = hunk.added ? 'added' : hunk.removed ? 'removed' : 'unchanged';
    for (const line of lines) rows.push({ text: line, status });
  }

  const added   = rows.filter(r => r.status === 'added').length;
  const removed = rows.filter(r => r.status === 'removed').length;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <p className="text-[10px] text-zinc-500 uppercase tracking-wider font-medium">Unified Diff</p>
          {added   > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/20 font-medium">+{added}</span>}
          {removed > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/20 font-medium">-{removed}</span>}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={handleCopy} leftIcon={copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}>
            {copied ? 'Copied!' : 'Copy'}
          </Button>
          {onApplyFix && (
            <Button
              variant={applied ? 'ghost' : 'accent'}
              size="sm"
              onClick={handleApply}
              leftIcon={applied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <ArrowLeftRight className="w-3.5 h-3.5" />}
            >
              {applied ? 'Applied!' : 'Apply to Editor'}
            </Button>
          )}
        </div>
      </div>

      {/* Diff legend */}
      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1 text-[10px] text-green-400"><span className="w-2 h-2 rounded-sm" style={{background:'rgba(34,197,94,0.3)',border:'1px solid #22c55e'}}/>Added</span>
        <span className="flex items-center gap-1 text-[10px] text-red-400"><span className="w-2 h-2 rounded-sm" style={{background:'rgba(239,68,68,0.3)',border:'1px solid #ef4444'}}/>Removed</span>
      </div>

      <div className="overflow-hidden rounded-2xl" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', backdropFilter: 'blur(12px)' }}>
        <div className="overflow-auto max-h-96">
          <pre className="text-[11px] font-mono leading-5 p-3">
            {rows.map((row, i) => (
              <div key={i} className={cn('flex gap-2 px-1 rounded', row.status === 'added' && 'diff-add', row.status === 'removed' && 'diff-remove')}>
                <span className="select-none w-4 flex-shrink-0 text-[10px] pt-0.5 text-zinc-700">
                  {row.status === 'added' ? '+' : row.status === 'removed' ? '-' : ' '}
                </span>
                <span className={cn('break-all whitespace-pre-wrap', row.status === 'added' ? 'text-green-300' : row.status === 'removed' ? 'text-red-300' : 'text-zinc-400')}>
                  {row.text || ' '}
                </span>
              </div>
            ))}
          </pre>
        </div>
      </div>
    </div>
  );
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

function LoadingState({ message }: { message: string }) {
  return (
    <div
      className="flex items-center gap-3 p-4 rounded-2xl"
      style={{ background: 'linear-gradient(135deg, rgba(124,58,237,0.08) 0%, rgba(37,99,235,0.05) 100%)', border: '1px solid rgba(124,58,237,0.15)', backdropFilter: 'blur(20px)', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06)' }}
    >
      <div className="relative w-6 h-6 flex-shrink-0">
        <div className="absolute inset-0 rounded-full border-2 border-violet-500/20" />
        <div className="absolute inset-0 rounded-full border-2 border-violet-500 border-t-transparent animate-spin" />
      </div>
      <p className="text-sm text-zinc-400 fade-in-up" key={message}>{message}</p>
    </div>
  );
}

function SkeletonBlock({ height }: { height: number }) {
  return <div className="skeleton rounded-xl" style={{ height }} />;
}

function SkeletonList({ count }: { count: number }) {
  return (
    <div className="flex flex-col gap-3">
      {Array.from({ length: count }).map((_, i) => <SkeletonBlock key={i} height={72} />)}
    </div>
  );
}

function EmptyState({ label, positive = false }: { label: string; positive?: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16">
      <div className={cn('w-10 h-10 rounded-xl flex items-center justify-center', positive ? 'bg-green-500/10 border border-green-500/20 text-green-400' : 'bg-white/5 border border-white/10 text-zinc-600')}>
        {positive ? <Check className="w-5 h-5" /> : <Info className="w-5 h-5" />}
      </div>
      <p className={cn('text-sm', positive ? 'text-green-400' : 'text-zinc-600')}>{label}</p>
    </div>
  );
}

// ─── Visual Security Tab (v1.3) ───────────────────────────────────────────────

function VisualSecurityTab({ result, isLoading }: { result: ReviewResult | null; isLoading: boolean }) {
  if (isLoading) return <div className="flex flex-col gap-4"><LoadingState message="Building attack-chain graph..." /><SkeletonList count={2} /></div>;
  if (!result)   return <EmptyState label="Run analysis to see visual security graph" />;

  const meta = result.pipelineMetadata;
  const issues = result.issues;

  // Severity distribution data
  const high   = issues.filter(i => i.severity === 'high').length;
  const medium = issues.filter(i => i.severity === 'medium').length;
  const low    = issues.filter(i => i.severity === 'low').length;
  const total  = issues.length;

  // Category breakdown
  const byCat: Record<string, number> = {};
  for (const i of issues) { byCat[i.category] = (byCat[i.category] ?? 0) + 1; }
  const catEntries = Object.entries(byCat).sort((a,b) => b[1] - a[1]);

  // Attack chain issues (those with exploitChain)
  const chainIssues = issues.filter(i => i.exploitChain || i.proofChain);

  // v1.3 stats
  const dominance = (meta as any)?.deterministicDominance;
  const fp        = (meta as any)?.fpMinimizer;
  const delta     = (meta as any)?.deltaAnalysis;
  // v1.4
  const graph     = (meta as any)?.incrementalGraph;
  const policy    = (meta as any)?.policyLayer;
  const modelSpec = (meta as any)?.modelSpecialization;
  const memRef    = (meta as any)?.memoryRefinement;
  const bench     = (meta as any)?.benchmarkStats;

  return (
    <div className="flex flex-col gap-4">

      {/* Severity heatmap */}
      <div className="rounded-2xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
        <p className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider mb-3">🌡️ Severity Heatmap</p>
        <div className="flex gap-2 h-16 items-end">
          {high > 0 && (
            <div className="flex flex-col items-center gap-1 flex-1">
              <div className="w-full rounded-t-lg" style={{ height: `${Math.max(8, (high / Math.max(total, 1)) * 60)}px`, background: 'rgba(239,68,68,0.6)', border: '1px solid rgba(239,68,68,0.4)' }} />
              <span className="text-[9px] text-red-400 font-bold">{high} HIGH</span>
            </div>
          )}
          {medium > 0 && (
            <div className="flex flex-col items-center gap-1 flex-1">
              <div className="w-full rounded-t-lg" style={{ height: `${Math.max(8, (medium / Math.max(total, 1)) * 60)}px`, background: 'rgba(245,158,11,0.6)', border: '1px solid rgba(245,158,11,0.4)' }} />
              <span className="text-[9px] text-amber-400 font-bold">{medium} MED</span>
            </div>
          )}
          {low > 0 && (
            <div className="flex flex-col items-center gap-1 flex-1">
              <div className="w-full rounded-t-lg" style={{ height: `${Math.max(8, (low / Math.max(total, 1)) * 60)}px`, background: 'rgba(100,116,139,0.6)', border: '1px solid rgba(100,116,139,0.4)' }} />
              <span className="text-[9px] text-zinc-400 font-bold">{low} LOW</span>
            </div>
          )}
          {total === 0 && <p className="text-xs text-zinc-600 self-center w-full text-center">No issues — clean scan ✓</p>}
        </div>
      </div>

      {/* Category breakdown */}
      {catEntries.length > 0 && (
        <div className="rounded-2xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <p className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider mb-3">📂 Category Breakdown</p>
          <div className="flex flex-col gap-2">
            {catEntries.map(([cat, count]) => (
              <div key={cat} className="flex items-center gap-2">
                <span className="text-[10px] text-zinc-400 w-24 flex-shrink-0 capitalize">{cat}</span>
                <div className="flex-1 h-2 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                  <div className="h-full rounded-full" style={{ width: `${(count / total) * 100}%`, background: 'linear-gradient(90deg, rgba(124,58,237,0.8), rgba(37,99,235,0.6))' }} />
                </div>
                <span className="text-[10px] text-zinc-500 w-4 text-right">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Attack chain map */}
      {chainIssues.length > 0 && (
        <div className="rounded-2xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <p className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider mb-3">⛓️ Attack Chain Map</p>
          <div className="flex flex-col gap-3">
            {chainIssues.slice(0, 4).map((issue, i) => (
              <div key={i} className="flex flex-col gap-1">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${issue.severity === 'high' ? 'bg-red-500' : issue.severity === 'medium' ? 'bg-amber-500' : 'bg-zinc-500'}`} />
                  <span className="text-[10px] font-medium text-zinc-300">{issue.title}</span>
                  {issue.exploitVerified && (
                    <span className="text-[8px] px-1 py-0.5 rounded" style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)', color: '#f87171' }}>VERIFIED</span>
                  )}
                </div>
                {issue.exploitChain && (
                  <p className="text-[9px] text-zinc-600 pl-4 leading-relaxed font-mono truncate">{issue.exploitChain.slice(0, 120)}</p>
                )}
                {issue.proofChain && (
                  <p className="text-[9px] text-violet-500/70 pl-4 font-mono truncate">{issue.proofChain.payload} → {issue.proofChain.observedResult.slice(0, 60)}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* v1.3/v1.4 engine telemetry */}
      <div className="rounded-2xl p-4" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)' }}>
        <p className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider mb-3">🔬 Engine Telemetry (v1.4)</p>
        <div className="grid grid-cols-2 gap-2">
          {dominance && (
            <>
              <TelemetryCell label="Hallucinations killed" value={String(dominance.hallucinationsKilled)} accent="red" />
              <TelemetryCell label="Det. confirmed" value={String(dominance.confirmed)} accent="green" />
              <TelemetryCell label="AI annotated" value={String(dominance.annotated)} accent="yellow" />
              <TelemetryCell label="Pure deterministic" value={String(dominance.deterministic)} accent="blue" />
            </>
          )}
          {fp && (
            <>
              <TelemetryCell label="Framework safe" value={String(fp.frameworkSafe)} accent="green" />
              <TelemetryCell label="Sanitizer certain" value={String(fp.sanitizerCertain)} accent="green" />
              <TelemetryCell label="Dead code" value={String(fp.deadCode)} accent="gray" />
              <TelemetryCell label="Test code" value={String(fp.testCode)} accent="gray" />
            </>
          )}
          {delta && (
            <>
              <TelemetryCell label="Delta mode" value={delta.mode.toUpperCase()} accent="blue" />
              <TelemetryCell label="Delta regressions" value={String(delta.regressions)} accent={delta.regressions > 0 ? 'red' : 'green'} />
              {delta.newTrustBoundaries.length > 0 && (
                <div className="col-span-2">
                  <p className="text-[9px] text-amber-400/70 font-medium mb-1">New unauth endpoints:</p>
                  {delta.newTrustBoundaries.slice(0, 3).map((b: string, i: number) => (
                    <p key={i} className="text-[9px] text-zinc-600 font-mono">{b}</p>
                  ))}
                </div>
              )}
            </>
          )}
          {graph && (
            <>
              <TelemetryCell label="Graph attack paths" value={String(graph.attackPaths)} accent="red" />
              <TelemetryCell label="Nodes recomputed" value={`${graph.recomputed}/${graph.totalNodes}`} accent="blue" />
              <TelemetryCell label="Service deps" value={String(graph.serviceDeps)} accent="yellow" />
              <TelemetryCell label="Async bridges" value={String(graph.asyncBridges)} accent="gray" />
            </>
          )}
          {policy && (
            <>
              <TelemetryCell label="Policy suppressed" value={String(policy.suppressed)} accent="gray" />
              <TelemetryCell label="Must-fix (CI gate)" value={String(policy.requireFix)} accent={policy.requireFix > 0 ? 'red' : 'green'} />
              <div className="col-span-2 rounded-lg p-2" style={{ background: policy.ciGate ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${policy.ciGate ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'}` }}>
                <p className="text-[9px] text-zinc-500 mb-0.5">CI Gate</p>
                <p className={`text-sm font-bold ${policy.ciGate ? 'text-green-400' : 'text-red-400'}`}>
                  {policy.ciGate ? '✓ PASS' : '⛔ BLOCKED'}
                </p>
                {!policy.ciGate && policy.ciBlockReason && (
                  <p className="text-[8px] text-red-400/70 mt-0.5 font-mono leading-tight">{policy.ciBlockReason.slice(0, 80)}</p>
                )}
              </div>
            </>
          )}
          {modelSpec && (
            <>
              <TelemetryCell label="Cost saving" value={`~${modelSpec.estimatedCostSavingPct}%`} accent="green" />
              <TelemetryCell label="Security model" value={modelSpec.securityModel.split('/')[1] ?? modelSpec.securityModel} accent="blue" />
            </>
          )}
          {memRef && (
            <>
              <TelemetryCell label="Active vulns (hist)" value={String(memRef.activeVulns)} accent="red" />
              <TelemetryCell label="Resolved (hist)" value={String(memRef.resolvedVulns)} accent="green" />
              {memRef.escalatingDrifts > 0 && (
                <TelemetryCell label="Confidence escalating" value={String(memRef.escalatingDrifts)} accent="yellow" />
              )}
              {memRef.volatileDrifts > 0 && (
                <TelemetryCell label="Volatile drifts" value={String(memRef.volatileDrifts)} accent="red" />
              )}
            </>
          )}
          {bench && (
            <>
              <TelemetryCell label="Benchmark precision" value={`${Math.round(bench.precision * 100)}%`} accent={bench.precision >= 0.8 ? 'green' : 'yellow'} />
              <TelemetryCell label="Benchmark recall" value={`${Math.round(bench.recall * 100)}%`} accent={bench.recall >= 0.8 ? 'green' : 'yellow'} />
              <TelemetryCell label="F1 score" value={`${Math.round(bench.f1 * 100)}%`} accent={bench.f1 >= 0.8 ? 'green' : 'yellow'} />
              <TelemetryCell label="Bench regressions" value={String(bench.regressions)} accent={bench.regressions > 0 ? 'red' : 'green'} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function TelemetryCell({ label, value, accent }: { label: string; value: string; accent: 'red' | 'green' | 'yellow' | 'blue' | 'gray' }) {
  const colors: Record<string, string> = {
    red:    'text-red-400',
    green:  'text-green-400',
    yellow: 'text-amber-400',
    blue:   'text-blue-400',
    gray:   'text-zinc-500',
  };
  return (
    <div className="rounded-lg p-2" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
      <p className="text-[9px] text-zinc-600 mb-0.5">{label}</p>
      <p className={`text-sm font-bold ${colors[accent]}`}>{value}</p>
    </div>
  );
}
