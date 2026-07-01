// ============================================================
// CyberINTEL-AI — PDF Report Generator
// Matches professional security audit report format.
// NO emoji — jsPDF can't render them, causing garbled text.
// All severity indicators use plain ASCII text + color only.
// ============================================================

import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ScanResult, Severity, Vulnerability } from '../types/index';

// ─── Color palette ────────────────────────────────────────
const C = {
  bg:       [8,  13, 15]  as [number,number,number],
  accent:   [0,  200,150] as [number,number,number],
  white:    [255,255,255] as [number,number,number],
  dark:     [20, 20, 30]  as [number,number,number],
  gray:     [100,110,120] as [number,number,number],
  lightgray:[230,235,238] as [number,number,number],
  critical: [220, 53, 43] as [number,number,number],
  high:     [220,130,  0] as [number,number,number],
  medium:   [200,170,  0] as [number,number,number],
  low:      [40, 180, 90] as [number,number,number],
  info:     [60, 160,230] as [number,number,number],
  gradeA:   [40, 190, 80] as [number,number,number],
  gradeB:   [80, 200, 90] as [number,number,number],
  gradeC:   [220,180,  0] as [number,number,number],
  gradeD:   [220,140,  0] as [number,number,number],
  gradeF:   [220, 50, 50] as [number,number,number],
};

function severityRGB(s: Severity): [number,number,number] {
  switch (s) {
    case Severity.CRITICAL: return C.critical;
    case Severity.HIGH:     return C.high;
    case Severity.MEDIUM:   return C.medium;
    case Severity.LOW:      return C.low;
    default:                return C.info;
  }
}

function gradeRGB(g: string): [number,number,number] {
  switch (g) {
    case 'A': return C.gradeA;
    case 'B': return C.gradeB;
    case 'C': return C.gradeC;
    case 'D': return C.gradeD;
    case 'E': return C.gradeD;
    default:  return C.gradeF;
  }
}

function wrap(doc: jsPDF, text: string, maxWidth: number): string[] {
  return doc.splitTextToSize(text, maxWidth);
}

export function generatePDFReport(scan: ScanResult): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const PW  = doc.internal.pageSize.getWidth();   // 210
  const PH  = doc.internal.pageSize.getHeight();  // 297
  const ML  = 15; // margin left
  const MR  = 15; // margin right
  const CW  = PW - ML - MR; // content width = 180

  // ── PAGE 1: Cover ─────────────────────────────────────────

  // Full dark header band
  doc.setFillColor(...C.bg);
  doc.rect(0, 0, PW, 60, 'F');

  // Accent left bar
  doc.setFillColor(...C.accent);
  doc.rect(0, 0, 4, 60, 'F');

  // Tool name
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(26);
  doc.setTextColor(...C.accent);
  doc.text('CyberINTEL-AI', ML + 4, 24);

  // Subtitle
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(11);
  doc.setTextColor(...C.white);
  doc.text('Security Audit Report', ML + 4, 33);
  doc.text(`Generated: ${new Date(scan.scannedAt).toLocaleString()}`, ML + 4, 40);
  doc.text('Assessment Type: Penetration Testing & SOC Analysis', ML + 4, 47);

  // Grade badge (top right)
  const gc = gradeRGB(scan.grade);
  doc.setFillColor(...gc);
  doc.roundedRect(PW - 38, 8, 24, 24, 3, 3, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(...C.white);
  doc.text(scan.grade, PW - 29, 24, { align: 'center' });
  doc.setFontSize(7);
  doc.text('GRADE', PW - 29, 30, { align: 'center' });

  // Score circle next to grade
  doc.setFillColor(...C.bg);
  doc.setDrawColor(...gc);
  doc.setLineWidth(2);
  doc.circle(PW - 45, 24, 10, 'FD');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...gc);
  doc.text(String(scan.securityScore), PW - 45, 27, { align: 'center' });

  let y = 70;

  // ── Scan Target box ───────────────────────────────────────
  doc.setFillColor(...C.lightgray);
  doc.roundedRect(ML, y, CW, 34, 2, 2, 'F');
  doc.setDrawColor(...C.accent);
  doc.setLineWidth(0.5);
  doc.rect(ML, y, 3, 34, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(...C.gray);
  doc.text('SCAN TARGET', ML + 6, y + 7);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...C.dark);
  doc.text(scan.domain, ML + 6, y + 15);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(...C.gray);
  const col2 = ML + CW / 2;
  doc.text(`URL:`, ML + 6, y + 22);
  doc.setTextColor(...C.dark);
  doc.text(scan.url.length > 55 ? scan.url.slice(0, 55) + '...' : scan.url, ML + 20, y + 22);

  doc.setTextColor(...C.gray);
  doc.text(`Scan ID:`, ML + 6, y + 28);
  doc.setTextColor(...C.dark);
  doc.text(scan.id, ML + 25, y + 28);

  doc.setTextColor(...C.gray);
  doc.text(`Duration:`, col2, y + 22);
  doc.setTextColor(...C.dark);
  doc.text(`${scan.scanDurationMs}ms`, col2 + 22, y + 22);

  doc.setTextColor(...C.gray);
  doc.text(`Score:`, col2, y + 28);
  doc.setTextColor(...gc);
  doc.setFont('helvetica', 'bold');
  doc.text(`${scan.securityScore}/100 — Grade ${scan.grade}`, col2 + 18, y + 28);

  y += 42;

  // ── Executive Summary ─────────────────────────────────────
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(...C.dark);
  doc.text('Executive Summary', ML, y);
  doc.setDrawColor(...C.accent);
  doc.setLineWidth(0.4);
  doc.line(ML, y + 2, ML + CW, y + 2);
  y += 8;

  const totalVulns = scan.vulnerabilities.length;
  const summaryText = totalVulns === 0
    ? `No vulnerabilities were detected during this automated scan of ${scan.domain}. The site passed all rule-based checks for security headers, cookie configuration, SSL/TLS, and sensitive file exposure.`
    : `The automated security assessment of ${scan.domain} identified ${totalVulns} finding${totalVulns > 1 ? 's' : ''} across ${Object.values(scan.counts).filter(v => v > 0).length} severity categories. The overall security score is ${scan.securityScore}/100 (Grade ${scan.grade}). Immediate attention is recommended for ${scan.counts.critical > 0 ? scan.counts.critical + ' critical' : scan.counts.high > 0 ? scan.counts.high + ' high' : 'the identified'} issue${totalVulns > 1 ? 's' : ''} detailed below.`;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(...C.gray);
  const summaryLines = wrap(doc, summaryText, CW);
  doc.text(summaryLines, ML, y);
  y += summaryLines.length * 5.5 + 8;

  // ── Findings Summary table ────────────────────────────────
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(...C.dark);
  doc.text('Findings Summary', ML, y);
  doc.setDrawColor(...C.accent);
  doc.line(ML, y + 2, ML + CW, y + 2);
  y += 6;

  const summaryRows: [string, string, string][] = [
    ['CRITICAL', scan.counts.critical.toString(), 'Immediate action required — active exploitation risk'],
    ['HIGH',     scan.counts.high.toString(),     'Serious risk — address within 7 days'],
    ['MEDIUM',   scan.counts.medium.toString(),   'Moderate risk — address within 30 days'],
    ['LOW',      scan.counts.low.toString(),      'Minor risk — address in next maintenance cycle'],
    ['INFO',     scan.counts.info.toString(),     'Informational — review and document'],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Severity', 'Count', 'Priority']],
    body: summaryRows,
    theme: 'grid',
    headStyles: {
      fillColor: C.bg,
      textColor: C.accent,
      fontStyle: 'bold',
      fontSize: 9,
      halign: 'left',
    },
    bodyStyles: { fontSize: 9, cellPadding: 3 },
    columnStyles: {
      0: { cellWidth: 30, fontStyle: 'bold' },
      1: { cellWidth: 18, halign: 'center' },
      2: { cellWidth: CW - 48 },
    },
    margin: { left: ML, right: MR },
    didDrawCell: (data) => {
      if (data.section === 'body' && data.column.index === 0) {
        const labels = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
        const colors = [C.critical, C.high, C.medium, C.low, C.info];
        const idx    = labels.indexOf(data.cell.text[0]);
        if (idx >= 0) {
          doc.setFillColor(...colors[idx]);
          doc.rect(data.cell.x, data.cell.y, 2, data.cell.height, 'F');
        }
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  // ── Page break if needed before vulnerability details ─────
  if (y > PH - 60) {
    doc.addPage();
    y = 20;
  }

  // ── Vulnerability Details ─────────────────────────────────
  if (scan.vulnerabilities.length > 0) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(...C.dark);
    doc.text('Vulnerability Details', ML, y);
    doc.setDrawColor(...C.accent);
    doc.line(ML, y + 2, ML + CW, y + 2);
    y += 6;

    // Each vulnerability gets its own detailed block
    scan.vulnerabilities.forEach((v: Vulnerability, i: number) => {
      const blockH = 42;

      // Page break check
      if (y + blockH > PH - 20) {
        doc.addPage();
        y = 20;
      }

      const sev = v.severity as Severity;
      const sevRGB = severityRGB(sev);

      // Severity accent bar
      doc.setFillColor(...sevRGB);
      doc.rect(ML, y, 3, blockH - 2, 'F');

      // Finding number + title
      doc.setFillColor(245, 247, 249);
      doc.rect(ML + 3, y, CW - 3, blockH - 2, 'F');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(...C.dark);
      doc.text(`#${i + 1}  ${v.title}`, ML + 7, y + 7);

      // Severity badge
      doc.setFillColor(...sevRGB);
      doc.roundedRect(PW - MR - 28, y + 2, 26, 7, 1, 1, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(...C.white);
      doc.text(sev, PW - MR - 15, y + 7, { align: 'center' });

      // Category
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(...C.gray);
      doc.text(`Category: ${v.category}   |   Detection: ${v.detectedBy.toUpperCase()}   |   ${new Date(v.detectedAt).toLocaleString()}`, ML + 7, y + 13);

      // Description
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(50, 55, 70);
      const descLines = wrap(doc, v.description, CW - 15);
      doc.text(descLines.slice(0, 2), ML + 7, y + 19);

      // Evidence
      if (v.evidence) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(7.5);
        doc.setTextColor(...C.gray);
        doc.text('Evidence:', ML + 7, y + 29);
        doc.setFont('courier', 'normal');
        doc.setFontSize(7);
        doc.setTextColor(30, 80, 160);
        const evText = v.evidence.length > 100 ? v.evidence.slice(0, 100) + '...' : v.evidence;
        doc.text(evText, ML + 24, y + 29);
      }

      // Remediation
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(...C.gray);
      doc.text('Fix:', ML + 7, y + 35);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(30, 120, 60);
      const remText = v.remediation.length > 130 ? v.remediation.slice(0, 130) + '...' : v.remediation;
      doc.text(remText, ML + 17, y + 35);

      // Location
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(...C.gray);
      doc.text('Location:', ML + 7, y + 41);
      doc.setFont('courier', 'normal');
      doc.setTextColor(100, 60, 160);
      const locText = v.location.length > 110 ? v.location.slice(0, 110) + '...' : v.location;
      doc.text(locText, ML + 25, y + 41);

      y += blockH + 2;
    });

    y += 6;
  }

  // ── ML Analysis (if available) ────────────────────────────
  if (scan.mlPredictions.length > 0) {
    if (y + 40 > PH - 20) { doc.addPage(); y = 20; }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(...C.dark);
    doc.text('AI/ML Analysis', ML, y);
    doc.setDrawColor(...C.accent);
    doc.line(ML, y + 2, ML + CW, y + 2);
    y += 6;

    autoTable(doc, {
      startY: y,
      head: [['Model', 'Result', 'Confidence', 'Inference Time']],
      body: scan.mlPredictions.map(p => [
        p.modelName.toUpperCase() + ' Detection',
        p.isMalicious ? 'MALICIOUS' : 'BENIGN',
        `${(p.confidence * 100).toFixed(1)}%`,
        `${p.inferenceTimeMs.toFixed(1)}ms`,
      ]),
      theme: 'grid',
      headStyles: { fillColor: C.bg, textColor: C.accent, fontStyle: 'bold', fontSize: 9 },
      bodyStyles: { fontSize: 9 },
      columnStyles: { 1: { fontStyle: 'bold' } },
      margin: { left: ML, right: MR },
      didDrawCell: (data) => {
        if (data.section === 'body' && data.column.index === 1) {
          const isMal = data.cell.text[0] === 'MALICIOUS';
          doc.setTextColor(...(isMal ? C.critical : C.low));
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 10;
  }

  // ── Recommendations section ───────────────────────────────
  if (scan.vulnerabilities.length > 0) {
    if (y + 50 > PH - 20) { doc.addPage(); y = 20; }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(...C.dark);
    doc.text('Remediation Priority', ML, y);
    doc.setDrawColor(...C.accent);
    doc.line(ML, y + 2, ML + CW, y + 2);
    y += 6;

    const priorities: string[][] = [];
    const criticalVulns = scan.vulnerabilities.filter(v => v.severity === Severity.CRITICAL);
    const highVulns     = scan.vulnerabilities.filter(v => v.severity === Severity.HIGH);
    const medVulns      = scan.vulnerabilities.filter(v => v.severity === Severity.MEDIUM);

    if (criticalVulns.length > 0) priorities.push(['Immediate (This Week)', criticalVulns.map(v => v.title).join(', ')]);
    if (highVulns.length > 0)     priorities.push(['Short-Term (30 Days)', highVulns.map(v => v.title).join(', ')]);
    if (medVulns.length > 0)      priorities.push(['Medium-Term (90 Days)', medVulns.map(v => v.title).join(', ')]);

    if (priorities.length > 0) {
      autoTable(doc, {
        startY: y,
        head: [['Timeline', 'Findings to Address']],
        body: priorities,
        theme: 'striped',
        headStyles: { fillColor: C.bg, textColor: C.accent, fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 9, cellPadding: 3 },
        columnStyles: { 0: { cellWidth: 45, fontStyle: 'bold' }, 1: { cellWidth: CW - 45 } },
        margin: { left: ML, right: MR },
      });
      y = (doc as any).lastAutoTable.finalY + 10;
    }
  }

  // ── Footer on every page ──────────────────────────────────
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);

    // Footer bar
    doc.setFillColor(...C.bg);
    doc.rect(0, PH - 12, PW, 12, 'F');
    doc.setFillColor(...C.accent);
    doc.rect(0, PH - 12, 4, 12, 'F');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(...C.white);
    doc.text('CyberINTEL-AI  |  Automated Security Assessment', ML + 4, PH - 5);
    doc.text(`Page ${i} of ${totalPages}`, PW - MR, PH - 5, { align: 'right' });
    doc.setTextColor(...C.gray);
    doc.text('For authorized security testing only. Results may vary from manual assessment.', ML + 4, PH - 1.5);
  }

  const filename = `cyberintel-report-${scan.domain}-${Date.now()}.pdf`;
  doc.save(filename);
}

// ─── JSON Export ──────────────────────────────────────────
export function exportJSON(scan: ScanResult): void {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `cyberintel-scan-${scan.domain}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
