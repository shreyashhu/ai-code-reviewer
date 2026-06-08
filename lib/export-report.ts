import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { ReviewResult } from './utils';

export function exportToJson(result: ReviewResult, originalCode: string) {
  if (!result) return; // Safety guard for old localStorage scans

  const payload = {
    generated_at: new Date().toISOString(),
    engine_version: result.pipelineMetadata?.engineVersion || 'v1.4.2',
    score: result.score,
    audit_passed: result.auditPassed,
    summary: result.summary,
    language: result.language,
    issues: result.issues,
    pipeline_metadata: result.pipelineMetadata,
    original_code: originalCode,
    optimized_code: result.optimized_code
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `security-audit-${result.score}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportToPdf(result: ReviewResult, originalCode?: string) {
  if (!result) return; // Safety guard for old localStorage scans

  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const meta = (result.pipelineMetadata || {}) as any;

  let yPos = 20;

  const checkPageBreak = (requiredSpace: number) => {
    if (yPos + requiredSpace > pageHeight - 25) {
      doc.addPage();
      yPos = 20;
    }
  };

  const cleanText = (text: string) => text.replace(/[^\x00-\x7F]/g, "");

  doc.setFillColor(9, 9, 11); 
  doc.rect(0, 0, pageWidth, 45, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(24);
  doc.setFont('helvetica', 'bold');
  doc.text('AI Code Review', 14, 20);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(161, 161, 170);
  doc.text('Production-Grade Security Audit Report', 14, 28);
  doc.text(`Generated: ${date}`, 14, 34);
  doc.text(`Engine: v1.4.2 | 31-Stage Pipeline`, 14, 40);

  const scoreColor = result.score >= 80 ? [34, 197, 94] : result.score >= 50 ? [234, 179, 8] : [239, 68, 68];
  doc.setFillColor(scoreColor[0], scoreColor[1], scoreColor[2]);
  doc.roundedRect(pageWidth - 50, 10, 35, 25, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text(`${result.score}`, pageWidth - 32.5, 22, { align: 'center' });
  doc.setFontSize(8);
  doc.text('/ 100', pageWidth - 32.5, 28, { align: 'center' });
  doc.setFontSize(7);
  doc.text(result.auditPassed ? 'PASSED' : 'FAILED', pageWidth - 32.5, 33, { align: 'center' });

  yPos = 55;

  doc.setTextColor(24, 24, 27);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('1. Executive Summary', 14, yPos);
  yPos += 8;
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(82, 82, 91);
  const summaryLines = doc.splitTextToSize(cleanText(result.summary || 'No summary provided.'), pageWidth - 28);
  doc.text(summaryLines, 14, yPos);
  yPos += summaryLines.length * 5 + 5;

  doc.setFontSize(10);
  doc.setTextColor(24, 24, 27);
  doc.setFont('helvetica', 'bold');
  doc.text('Language: ', 14, yPos);
  doc.setFont('helvetica', 'normal');
  doc.text(result.language || 'Unknown', 35, yPos);
  yPos += 15;

  checkPageBreak(40);
  doc.setTextColor(24, 24, 27);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('2. Vulnerability Analysis', 14, yPos);
  yPos += 8;

  if (result.issues.length > 0) {
    const tableColumn = ['Severity', 'Type', 'Line', 'Category', 'Title'];
    const tableRows = result.issues.map(issue => {
      const sevText = issue.severity === 'high' ? 'HIGH' : issue.severity === 'medium' ? 'MEDIUM' : 'LOW';
      return [sevText, issue.type.toUpperCase(), issue.line ? `L${issue.line}` : '-', issue.category, cleanText(issue.title)];
    });

    autoTable(doc, {
      head: [tableColumn],
      body: tableRows,
      startY: yPos,
      styles: { fontSize: 8, cellPadding: 3 },
      headStyles: { fillColor: [24, 24, 27], textColor: [255, 255, 255] },
      alternateRowStyles: { fillColor: [244, 244, 245] },
      columnStyles: {
        0: { cellWidth: 20, fontStyle: 'bold' },
        1: { cellWidth: 20 },
        2: { cellWidth: 15 },
        3: { cellWidth: 25 },
        4: { cellWidth: 'auto' }
      },
      didParseCell: function(data: any) {
        if (data.section === 'body' && data.column.index === 0) {
          if (data.cell.raw === 'HIGH') data.cell.styles.textColor = [220, 38, 38];
          else if (data.cell.raw === 'MEDIUM') data.cell.styles.textColor = [234, 88, 12];
          else if (data.cell.raw === 'LOW') data.cell.styles.textColor = [202, 138, 4];
        }
      }
    });
    yPos = (doc as any).lastAutoTable.finalY + 10;

    result.issues.forEach((issue, index) => {
      checkPageBreak(40);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(24, 24, 27);
      doc.text(`${index + 1}. ${cleanText(issue.title)} ${issue.line ? `(Line ${issue.line})` : ''}`, 14, yPos);
      yPos += 6;

      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(82, 82, 91);
      const expLines = doc.splitTextToSize(cleanText(issue.explanation), pageWidth - 28);
      doc.text(expLines, 14, yPos);
      yPos += expLines.length * 4 + 4;

      if (issue.fix) {
        checkPageBreak(20);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(22, 163, 74); 
        doc.text('Recommended Remediation:', 14, yPos);
        yPos += 4;
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(24, 24, 27);
        const fixLines = doc.splitTextToSize(cleanText(issue.fix), pageWidth - 28);
        doc.text(fixLines, 14, yPos);
        yPos += fixLines.length * 4 + 6;
      }
    });
  } else {
    doc.setFillColor(240, 253, 244); 
    doc.setDrawColor(34, 197, 94);   
    doc.roundedRect(14, yPos, pageWidth - 28, 20, 2, 2, 'FD');
    doc.setTextColor(21, 128, 61);   
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('VERIFIED CLEAN: No actionable vulnerabilities found.', pageWidth / 2, yPos + 12, { align: 'center' });
    yPos += 30;
  }

  doc.addPage(); 
  yPos = 20;
  doc.setTextColor(24, 24, 27);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('3. Pipeline Telemetry & Engine Stats', 14, yPos);
  yPos += 8;

  const telemetryData = [];
  telemetryData.push(['Taint Sources', `${meta.taintSources ?? 0} tracked variables`]);
  telemetryData.push(['Call Graph Nodes', `${meta.callGraphNodes ?? 0} mapped functions`]);
  telemetryData.push(['AST Patches Applied', `${meta.astPatchesApplied ?? 0} syntax-preserving fixes`]);
  
  if (meta.decayStats) {
    const active = meta.decayStats.active ?? 0;
    const suppressed = meta.decayStats.suppressed ?? 0;
    telemetryData.push(['Confidence Decay Engine', `[OK] ${active} active | [X] ${suppressed} suppressed`]);
  }
  
  if (meta.rootCauseGraph) {
    const surfaces = meta.rootCauseGraph.uniqueSurfaces ?? 0;
    const total = meta.rootCauseGraph.totalInput ?? 0;
    telemetryData.push(['Root-Cause Graph', `${surfaces} exploit surfaces (${total} raw collapsed)`]);
  }

  if (meta.clusterStats && meta.clusterStats.families) {
    const familyCount = meta.clusterStats.familyCount ?? 0;
    const familyStr = meta.clusterStats.families.map((f: any) => `${f.family} (x${f.count})`).join(', ');
    telemetryData.push(['Vuln Family Clustering', `${familyCount} families: ${familyStr || 'None'}`]);
  }

  if (meta.constraintChains && meta.constraintChains.fullyValidated > 0) {
    const validated = meta.constraintChains.fullyValidated;
    const cvss = meta.constraintChains.highestCvss ?? 'N/A';
    telemetryData.push(['Constraint-Valid Attack Chains', `${validated} proven (Highest CVSS: ${cvss})`]);
  }

  autoTable(doc, {
    body: telemetryData,
    startY: yPos,
    styles: { fontSize: 9, cellPadding: 4 },
    columnStyles: {
      0: { cellWidth: 60, fontStyle: 'bold', textColor: [24, 24, 27] },
      1: { cellWidth: 'auto', textColor: [82, 82, 91] }
    },
    theme: 'plain',
    alternateRowStyles: { fillColor: [244, 244, 245] }
  });
  yPos = (doc as any).lastAutoTable.finalY + 15;

  checkPageBreak(40);
  doc.setTextColor(24, 24, 27);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('4. Risk & Compliance Posture', 14, yPos);
  yPos += 8;

  const riskData = [];
  if (meta.adaptiveRoute) {
    riskData.push(['Analysis Tier', `${meta.adaptiveRoute.tier} (${meta.adaptiveRoute.reason})`]);
  }
  if (meta.policyLayer) {
    riskData.push(['CI/CD Gate', meta.policyLayer.ciGate ? 'PASS (Ready to Merge)' : `BLOCKED (${meta.policyLayer.ciBlockReason || 'Policy Violation'})`]);
    riskData.push(['Policy Suppressions', `${meta.policyLayer.suppressed} findings hidden by org policy`]);
  }
  if (meta.benchmarkStats) {
    riskData.push(['Engine Precision', `${(meta.benchmarkStats.precision * 100).toFixed(1)}% (Recall: ${(meta.benchmarkStats.recall * 100).toFixed(1)}%)`]);
  }

  if (riskData.length > 0) {
    autoTable(doc, {
      body: riskData,
      startY: yPos,
      styles: { fontSize: 9, cellPadding: 4 },
      columnStyles: {
        0: { cellWidth: 60, fontStyle: 'bold', textColor: [24, 24, 27] },
        1: { cellWidth: 'auto', textColor: [82, 82, 91] }
      },
      theme: 'plain',
      alternateRowStyles: { fillColor: [244, 244, 245] }
    });
    yPos = (doc as any).lastAutoTable.finalY + 15;
  }

  checkPageBreak(40);
  doc.setTextColor(24, 24, 27);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('5. Observability & Performance', 14, yPos);
  yPos += 8;

  const obsData = [];
  if (meta.observability) {
    obsData.push(['Total Duration', `${(meta.observability.totalDurationMs / 1000).toFixed(2)}s`]);
    obsData.push(['Total Tokens', `${meta.observability.totalTokens} tokens`]);
    obsData.push(['Estimated Cost', `$${meta.observability.estimatedCostUsd.toFixed(4)}`]);
    obsData.push(['Slowest Stage', meta.observability.slowestStage || 'N/A']);
    obsData.push(['Cache Hit Rate', `${(meta.observability.cacheHitRate * 100).toFixed(1)}%`]);
  }

  if (obsData.length > 0) {
    autoTable(doc, {
      body: obsData,
      startY: yPos,
      styles: { fontSize: 9, cellPadding: 4 },
      columnStyles: {
        0: { cellWidth: 60, fontStyle: 'bold', textColor: [24, 24, 27] },
        1: { cellWidth: 'auto', textColor: [82, 82, 91] }
      },
      theme: 'plain',
      alternateRowStyles: { fillColor: [244, 244, 245] }
    });
    yPos = (doc as any).lastAutoTable.finalY + 15;
  }

  if (originalCode && originalCode.trim().length > 0) {
    doc.addPage();
    yPos = 20;
    doc.setTextColor(24, 24, 27);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Appendix: Analyzed Source Code (Excerpt)', 14, yPos);
    yPos += 8;

    doc.setFontSize(7);
    doc.setFont('courier', 'normal');
    doc.setTextColor(82, 82, 91);
    
    const codeLines = originalCode.split('\n').slice(0, 60);
    const numberedCode = codeLines.map((line, i) => {
      const lineNum = String(i + 1).padStart(3, ' ');
      const cleanLine = cleanText(line);
      const truncatedLine = cleanLine.substring(0, 95); 
      return `${lineNum} | ${truncatedLine}`;
    });
    
    doc.text(numberedCode, 14, yPos);
  }

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(161, 161, 170);
    doc.text(
      `AI Code Review v1.4.2 | 31-Stage Pipeline | Page ${i} of ${pageCount}`,
      pageWidth / 2,
      pageHeight - 10,
      { align: 'center' }
    );
  }

  doc.save(`security-audit-${result.score}-${Date.now()}.pdf`);
}