'use strict';
/**
 * MiniBurp Report Generator v2
 * ============================
 * Generates professional bug-bounty-grade reports:
 *  - JSON (structured)
 *  - Markdown (GitHub / HackerOne style)
 *  - PDF (pdfkit)
 *  - CVSS v3.1 score per finding
 */

const PDFDocument = require('pdfkit');
const { getCVSS }  = require('./cvssCalculator');
const db = require('../database');


// ── In-memory store ────────────────────────────────────────────
const _findings = [];

// ── CVSS helpers ───────────────────────────────────────────────
function enrichWithCVSS(finding) {
  const cvss = getCVSS(finding.type || finding.vulnerability_type || '');
  return {
    ...finding,
    cvss_score:    finding.cvss_score    || cvss.score,
    cvss_severity: finding.cvss_severity || cvss.severity,
    cvss_vector:   finding.cvss_vector   || cvss.vector,
  };
}

// ── Build finding object ────────────────────────────────────────
function buildFinding(opts) {
  const {
    reqId, method = 'GET', url = '', param, type,
    payload, severity, evidence, explanation,
    prevention, reproduction_steps,
    cvss_score, cvss_severity, cvss_vector,
    behavior_change, exploit_result, chain,
    raw_request, raw_response, confidence_score = 100,
    detection_type,
  } = opts;

  const urlObj = (() => { try { return new URL(url); } catch { return null; } })();
  const cvss   = getCVSS(type || '');

  return {
    id:            `${Date.now()}-${Math.random().toString(36).slice(2,6)}`,
    vulnerability_name: type || 'Unknown Vulnerability',
    reqId,
    host:          urlObj?.host || '',
    endpoint:      urlObj ? urlObj.pathname : url,
    fullUrl:       url,
    method,
    parameter:     param,
    type,
    detection_type: detection_type || type || 'Pattern Match',
    severity:      severity || cvss.severity,
    payload,
    evidence:      evidence || '',
    explanation:   explanation || cvss.description,
    prevention:    prevention || getDefaultPrevention(type),
    reproduction_steps: reproduction_steps || buildReproduction(method, url, param, payload),
    cvss_score:    cvss_score  || cvss.score,
    cvss_severity: cvss_severity || cvss.severity,
    cvss_vector:   cvss_vector  || cvss.vector,
    behavior_change: behavior_change || null,
    exploit_result:  exploit_result  || null,
    chain:           chain           || null,
    timestamp:       new Date().toISOString(),
    raw_request:     raw_request || `[${method}] ${url}`,
    raw_response:    raw_response || '',
    confidence_score: confidence_score,
    confidence_tier: opts.confidence_tier || 'SUSPICIOUS',
    impact:          opts.impact || 'Highly likely to lead to system compromise or unauthorized data disclosure.',
    proof:           opts.proof || 'Heuristic anomaly detected.',
  };
}

function buildReproduction(method, url, param, payload) {
  return [
    `1. Send ${method} request to: ${url}`,
    `2. Set parameter '${param}' to: ${payload}`,
    `3. Observe the behavioral difference in the response`,
    `4. Verify the response differs from the baseline (status, length, content)`,
  ];
}

function getDefaultPrevention(type = '') {
  const map = {
    'sql':         'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Use an ORM.',
    'xss':         'HTML-encode all user output. Implement Content-Security-Policy headers. Use DOMPurify on client.',
    'ssrf':        'Validate and allowlist URLs. Block private/internal IP ranges. Use a dedicated egress proxy.',
    'idor':        'Implement server-side authorization on every resource. Use indirect references (UUIDs).',
    'traversal':   'Resolve canonical paths and validate against a whitelist directory. Reject ".." sequences.',
    'ssti':        'Never render user input as template syntax. Use sandbox or logic-less template engines.',
    'command':     'Use parameterized OS APIs. Never pass user input to shell=True. Escape all shell metacharacters.',
    'auth bypass': 'Use parameterized queries. Implement account lockout. Log all failed authentication attempts.',
  };
  const k = Object.keys(map).find(k => type.toLowerCase().includes(k));
  return map[k] || 'Validate all inputs server-side using an allowlisting approach.';
}

let _io = null;
function setIO(io) { _io = io; }

// ── API ──────────────────────────────────────────────────────
async function addFinding(opts) {
  const f = buildFinding(opts);
  // Deduplicate by type+param+endpoint
  const all = db.getFindings();
  const dup = all.find(x => x.type === f.type && (x.parameter === f.parameter || x.param === f.parameter) && (x.endpoint === f.endpoint || x.fullUrl === f.fullUrl));
  
  if (!dup) {
      console.log(`[PassiveDiscovery] Found ${f.vulnerability_name || f.type} on ${f.fullUrl || f.endpoint} (Confidence: ${f.confidence_score}%)`);
      db.saveFinding(f);
      if (_io) _io.emit('finding:new', f);

      // ASYNC AI ENRICHMENT (Task 6)
      try {
        const aiModel = require('./aiModel');
        const enriched = await aiModel.generateReportDetails(f);
        if (enriched) {
          f.explanation = enriched.explanation;
          f.impact = enriched.impact;
          f.reproduction_steps = enriched.reproduction_steps;
          f.prevention = enriched.fix;
          db.updateFinding(f.id, f);
          if (_io) _io.emit('finding:update', f);
        }
      } catch (e) {
        console.warn('[Report] AI Enrichment failed:', e.message);
      }
  }
  return f;
}


function getFindings()  { return db.getFindings(); }
function clearFindings(){ db.clearFindings(); }


// ── JSON Export ─────────────────────────────────────────────────
function generateJSON() {
  const all = getFindings();
  const summary = buildSummary(all);
  return JSON.stringify({ meta: summary, findings: all }, null, 2);
}

function buildSummary(allFindings = []) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of allFindings) {
    const sev = f.cvss_severity || f.severity || 'Info';
    counts[sev] = (counts[sev] || 0) + 1;
  }
  const maxScore = allFindings.reduce((m, f) => Math.max(m, f.cvss_score || 0), 0);
  return {
    generated:       new Date().toISOString(),
    tool:            'MiniBurp v2 — AI Vulnerability Testing Engine',
    total_findings:  allFindings.length,
    severity_counts: counts,
    max_cvss:        maxScore,
    risk_rating:     maxScore >= 9 ? 'CRITICAL' : maxScore >= 7 ? 'HIGH' : maxScore >= 4 ? 'MEDIUM' : 'LOW',
  };
}

// ── Markdown Export (Bug Bounty Style) ────────────────────────
function generateMarkdown() {
  const all = getFindings();
  const summary = buildSummary(all);
  const lines = [];

  lines.push('# 🔴 MiniBurp Security Assessment Report');
  lines.push('');
  lines.push(`> **Tool:** MiniBurp v2 — AI-Powered Vulnerability Testing Engine`);
  lines.push(`> **Generated:** ${summary.generated}`);
  lines.push(`> **Risk Rating:** ${summary.risk_rating}`);
  lines.push(`> **Max CVSS Score:** ${summary.max_cvss}`);
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Executive Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  for (const [sev, count] of Object.entries(summary.severity_counts)) {
    if (count > 0) lines.push(`| ${sev} | ${count} |`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');

  const sevOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  for (const sev of sevOrder) {
    const group = all.filter(f => (f.cvss_severity || f.severity) === sev);
    if (!group.length) continue;

    const icon = { Critical: '☠️', High: '🔴', Medium: '🟠', Low: '🟡', Info: '🔵' }[sev] || '⚪';
    lines.push(`## ${icon} ${sev} Severity Findings (${group.length})`);
    lines.push('');

    for (const f of group) {
      lines.push(`### ${f.type} — \`${f.endpoint || f.fullUrl}\``);
      lines.push('');
      lines.push('#### Overview');
      lines.push('');
      lines.push(`| Field | Value |`);
      lines.push(`|-------|-------|`);
      lines.push(`| **Host** | \`${f.host}\` |`);
      lines.push(`| **Endpoint** | \`${f.endpoint}\` |`);
      lines.push(`| **Method** | \`${f.method}\` |`);
      lines.push(`| **Parameter** | \`${f.parameter}\` |`);
      lines.push(`| **Payload** | \`${f.payload}\` |`);
      lines.push(`| **CVSS Score** | **${f.cvss_score}** (${f.cvss_severity}) |`);
      lines.push(`| **CVSS Vector** | \`${f.cvss_vector}\` |`);
      lines.push(`| **Timestamp** | ${f.timestamp} |`);
      lines.push('');
      lines.push('#### Vulnerability Description');
      lines.push('');
      lines.push(f.explanation || f.evidence || 'See evidence below.');
      lines.push('');
      lines.push('#### Evidence (Behavioral Proof)');
      lines.push('```');
      lines.push(typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : (f.evidence || 'N/A'));
      lines.push('```');
      if (f.behavior_change) {
        lines.push('');
        lines.push('#### Response Comparison');
        lines.push('```json');
        lines.push(JSON.stringify(f.behavior_change, null, 2));
        lines.push('```');
      }
      if (f.exploit_result) {
        lines.push('');
        lines.push('#### Exploitation Result');
        lines.push('```');
        lines.push(typeof f.exploit_result === 'object' ? JSON.stringify(f.exploit_result, null, 2) : f.exploit_result);
        lines.push('```');
      }
      lines.push('');
      lines.push('#### Reproduction Steps');
      lines.push('');
      (f.reproduction || []).forEach((s, i) => lines.push(`${i+1}. ${s}`));
      lines.push('');
      lines.push('#### Remediation');
      lines.push('');
      lines.push(f.prevention || 'Apply input validation and use parameterized queries.');
      lines.push('');
      lines.push('---');
      lines.push('');
    }
  }

  lines.push('*Report generated by MiniBurp — AI-Powered Penetration Testing Platform*');
  return lines.join('\n');
}

// ── PDF Export ──────────────────────────────────────────────────
function generatePDF(outputStream) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    doc.pipe(outputStream);

    const BG = '#0d0d12', FG = '#e2e8f0', ACC = '#f97316', RED = '#ef4444', GRN = '#22c55e';
    const sevColors = { Critical: '#f43f5e', High: '#ef4444', Medium: '#f97316', Low: '#eab308', Info: '#3b82f6' };

    // Cover
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(BG);
    doc.fill(RED).fontSize(32).text('MiniBurp', 50, 60, { continued: true });
    doc.fill(FG).text(' Security Report');
    doc.fill('#64748b').fontSize(11).text('AI-Powered Vulnerability Testing Engine', 50, 100);

    const summary = buildSummary(getFindings());
    doc.fill(ACC).fontSize(13).text(`Risk Rating: ${summary.risk_rating}`, 50, 130);
    doc.fill(FG).fontSize(10).text(`Generated: ${summary.generated}`, 50, 148);
    doc.fill(FG).text(`Total Findings: ${summary.total_findings} | Max CVSS: ${summary.max_cvss}`, 50, 162);

    // Horizontal rule
    doc.moveTo(50, 185).lineTo(doc.page.width - 50, 185).strokeColor('#1e2535').lineWidth(1).stroke();
    doc.moveDown(4);

    const all = getFindings();
    if (all.length === 0) {
      doc.fill('#64748b').fontSize(14).text('No confirmed vulnerabilities in this session.', 50, 210);
    } else {
      for (const f of all) {
        const color = sevColors[f.cvss_severity] || '#64748b';
        // Ensure we don't overflow page (simple check)
        if (doc.y > doc.page.height - 200) doc.addPage().rect(0,0,doc.page.width,doc.page.height).fill(BG);


        doc.fill(color).fontSize(14).text(`[${f.cvss_severity}] ${f.type}`, 50);
        doc.fill(FG).fontSize(10).text(`${f.method} ${f.fullUrl || f.endpoint || f.host}`, 50);
        doc.fill('#94a3b8').fontSize(9)
          .text(`Parameter: ${f.parameter}   Payload: ${f.payload}`, 50);
        doc.fill('#64748b')
          .text(`CVSS: ${f.cvss_score} (${f.cvss_vector})`, 50);
        doc.fill(FG).fontSize(9)
          .text(`Evidence: ${typeof f.evidence === 'object' ? JSON.stringify(f.evidence) : (f.evidence||'').slice(0,200)}`, 50);
        if (f.prevention) {
          doc.fill(GRN).fontSize(8).text(`Fix: ${f.prevention.slice(0,180)}`, 50);
        }
        doc.moveTo(50, doc.y+4).lineTo(doc.page.width-50, doc.y+4).strokeColor('#1e2535').stroke();
        doc.moveDown(0.8);
      }
    }

    doc.end();
    outputStream.on('finish', resolve);
    outputStream.on('error', reject);
  });
}

// ── HTML Export ─────────────────────────────────────────────────
function generateHTML() {
  const all = getFindings();
  const summary = buildSummary(all);
  let html = `<!DOCTYPE html><html><head><title>MiniBurp Scan Report</title><style>
    body { background: #0f172a; color: #e2e8f0; font-family: sans-serif; padding: 40px; }
    .card { background: #1e293b; border: 1px solid #334155; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    .Critical { color: #f43f5e; } .High { color: #ef4444; } .Medium { color: #f97316; } .Low { color: #eab308; }
    pre { background: #000; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 11px; }
    h1, h2 { color: #f97316; }
  </style></head><body><h1>🔴 MiniBurp Security Assessment</h1>`;
  
  html += `<h2>Summary</h2><div class="card"><p><b>Total Findings:</b> ${summary.total_findings}</p><p><b>Risk Level:</b> ${summary.risk_rating}</p></div>`;
  
  all.forEach(f => {
    html += `<div class="card"><h3 class="${f.cvss_severity}">${f.type} [${f.cvss_severity}]</h3>
    <p><b>URL:</b> ${f.fullUrl || f.endpoint}</p>
    <p><b>Parameter:</b> ${f.parameter} | <b>Payload:</b> <code>${f.payload}</code></p>
    <p><b>Evidence:</b></p><pre>${typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : f.evidence}</pre>
    <p><b>Remediation:</b> ${f.prevention}</p>
    </div>`;
  });
  
  html += `</body></html>`;
  return html;
}

// ── CSV Export ──────────────────────────────────────────────────
function generateCSV() {
  const all = getFindings();
  let csv = 'ID,Type,Severity,Score,URL,Method,Parameter,Payload,Confidence\n';
  all.forEach(f => {
    const row = [
      f.id, f.type, f.cvss_severity, f.cvss_score, f.fullUrl || f.endpoint,
      f.method, f.parameter, `"${(f.payload || '').replace(/"/g, '""')}"`, f.confidence_score
    ];
    csv += row.join(',') + '\n';
  });
  return csv;
}

module.exports = {
  setIO, addFinding, getFindings, clearFindings,
  generateJSON, generateMarkdown, generatePDF, generateHTML, generateCSV,
  buildFinding,
};

