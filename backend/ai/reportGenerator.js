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
    confidence_score: opts.score || confidence_score,
    confidence:      opts.confidence || opts.confidence_tier || 'INFORMATIONAL',
    confidence_tier: opts.confidence || opts.confidence_tier || 'INFORMATIONAL',
    impact:          opts.impact || 'Highly likely to lead to system compromise or unauthorized data disclosure.',
    proof:           opts.proof || 'Heuristic anomaly detected.',
    score:           opts.score || cvss.score * 10
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
  const confCounts = { VERIFIED: 0, LIKELY: 0, INFORMATIONAL: 0 };
  const breakdown = {};

  for (const f of allFindings) {
    const sev = f.cvss_severity || f.severity || 'Info';
    counts[sev] = (counts[sev] || 0) + 1;

    const conf = f.confidence || f.confidence_tier || 'INFORMATIONAL';
    confCounts[conf] = (confCounts[conf] || 0) + 1;

    const type = f.type || 'Unknown';
    breakdown[type] = (breakdown[type] || 0) + 1;
  }

  const maxScore = allFindings.reduce((m, f) => Math.max(m, f.cvss_score || f.score || 0), 0);
  const endpointStats = db.getEndpointStats();

  return {
    generated:       new Date().toISOString(),
    tool:            'MiniBurp v2 — AI-Powered Behavioral Verification Platform',
    total_findings:  allFindings.length,
    severity_counts: counts,
    confidence_counts: confCounts,
    vulnerability_breakdown: breakdown,
    endpoint_statistics: endpointStats,
    max_cvss:        maxScore,
    risk_rating:     maxScore >= 9 ? 'CRITICAL' : maxScore >= 7 ? 'HIGH' : maxScore >= 4 ? 'MEDIUM' : 'LOW',
  };
}

// ── Markdown Export (Bug Bounty Style) ────────────────────────
function generateMarkdown() {
  const all = getFindings();
  const summary = buildSummary(all);
  const lines = [];

  lines.push('# 🔴 MiniBurp Security Assessment & Verification Report');
  lines.push('');
  lines.push(`> **Tool:** MiniBurp v2 — AI-Powered Behavioral Verification Platform`);
  lines.push(`> **Generated:** ${summary.generated}`);
  lines.push(`> **Risk Rating:** ${summary.risk_rating} (Max CVSS Score: ${summary.max_cvss})`);
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('## Executive Summary');
  lines.push('');
  lines.push('### Endpoint Statistics');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| **Total Captured Requests** | ${summary.endpoint_statistics.totalRequests} |`);
  lines.push(`| **Distinct Targets Scanned** | ${summary.endpoint_statistics.distinctUrls} |`);
  lines.push(`| **Discovered Endpoints** | ${summary.endpoint_statistics.discovered} |`);
  lines.push(`| **Tested Endpoints** | ${summary.endpoint_statistics.tested} |`);
  lines.push('');
  lines.push('### Severity & Confidence Distribution');
  lines.push('');
  lines.push('| Severity | Count | Confidence Tier | Count |');
  lines.push('|----------|-------|-----------------|-------|');
  const sevs = Object.keys(summary.severity_counts);
  const confs = Object.keys(summary.confidence_counts);
  for (let i = 0; i < Math.max(sevs.length, confs.length); i++) {
    const sev = sevs[i] || '';
    const sevCnt = sev ? summary.severity_counts[sev] : '';
    const conf = confs[i] || '';
    const confCnt = conf ? summary.confidence_counts[conf] : '';
    lines.push(`| ${sev} | ${sevCnt} | ${conf} | ${confCnt} |`);
  }
  lines.push('');
  lines.push('### Vulnerability Type Breakdown');
  lines.push('');
  lines.push('| Vulnerability Type | Count |');
  lines.push('|--------------------|-------|');
  for (const [type, cnt] of Object.entries(summary.vulnerability_breakdown)) {
    lines.push(`| ${type} | ${cnt} |`);
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
      lines.push(`| **Confidence Level** | **${f.confidence || f.confidence_tier}** (${f.cvss_score || f.score}%) |`);
      lines.push(`| **CVSS Vector** | \`${f.cvss_vector}\` |`);
      lines.push(`| **Timestamp** | ${f.timestamp} |`);
      lines.push('');
      lines.push('#### AI-Assisted Behavioral Reasoning');
      lines.push('');
      lines.push(f.reasoning || f.explanation || 'Analyzed automatically via behavioral verification heuristics.');
      lines.push('');
      if (f.aiAnalysis) {
        lines.push('#### AI Explanation');
        lines.push('');
        lines.push(typeof f.aiAnalysis === 'string' ? f.aiAnalysis : f.aiAnalysis.explanation || 'N/A');
        lines.push('');
      }
      lines.push('#### Evidence (Behavioral Proof)');
      lines.push('```json');
      lines.push(typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : (f.evidence || 'N/A'));
      lines.push('```');
      if (f.behavior_change) {
        lines.push('');
        lines.push('#### Response Comparison');
        lines.push('```json');
        lines.push(JSON.stringify(f.behavior_change, null, 2));
        lines.push('```');
      }
      lines.push('');
      lines.push('#### Reproduction Steps');
      lines.push('');
      const steps = f.reproduction_steps || f.reproduction || buildReproduction(f.method, f.fullUrl || f.endpoint, f.parameter, f.payload);
      steps.forEach((s, i) => lines.push(`${i+1}. ${s}`));
      lines.push('');
      lines.push('#### Remediation Recommendations');
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
// ── PDF Export ──────────────────────────────────────────────────
function generatePDF(outputStream) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    doc.pipe(outputStream);

    const BG = '#0d0d12', FG = '#e2e8f0', ACC = '#f97316', RED = '#ef4444', GRN = '#22c55e';
    const sevColors = { Critical: '#f43f5e', High: '#ef4444', Medium: '#f97316', Low: '#eab308', Info: '#3b82f6' };

    // Cover Page
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(BG);
    doc.fill(RED).fontSize(32).text('MiniBurp', 50, 60, { continued: true });
    doc.fill(FG).text(' Security Assessment');
    doc.fill('#64748b').fontSize(11).text('AI-Powered Behavioral Verification Platform', 50, 100);

    const summary = buildSummary(getFindings());
    doc.fill(ACC).fontSize(14).text(`Overall Risk Rating: ${summary.risk_rating}`, 50, 130);
    doc.fill(FG).fontSize(10).text(`Generated: ${summary.generated}`, 50, 148);
    
    // Stats Grid on Cover
    doc.fill('#94a3b8').fontSize(11).text('Assessment Summary:', 50, 175);
    doc.fill(FG).fontSize(10)
      .text(`Total Discovered Findings: ${summary.total_findings}`, 70, 195)
      .text(`Max CVSS Score: ${summary.max_cvss}`, 70, 210)
      .text(`Total Crawler Requests: ${summary.endpoint_statistics.totalRequests}`, 70, 225)
      .text(`Distinct Tested Targets: ${summary.endpoint_statistics.distinctUrls}`, 70, 240);

    // Severity Breakdown list
    doc.fill('#94a3b8').fontSize(11).text('Severity Distribution:', 50, 270);
    let yPos = 290;
    for (const [sev, count] of Object.entries(summary.severity_counts)) {
      doc.fill(sevColors[sev] || FG).fontSize(10).text(`${sev}: ${count}`, 70, yPos);
      yPos += 15;
    }

    // Horizontal rule
    doc.moveTo(50, 420).lineTo(doc.page.width - 50, 420).strokeColor('#1e2535').lineWidth(1).stroke();

    // Start findings page
    doc.addPage();
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(BG);
    doc.y = 50;

    const all = getFindings();
    if (all.length === 0) {
      doc.fill('#64748b').fontSize(14).text('No verified vulnerabilities found in this session.', 50, doc.y);
    } else {
      for (const f of all) {
        const color = sevColors[f.cvss_severity || f.severity] || '#64748b';
        if (doc.y > doc.page.height - 180) {
          doc.addPage();
          doc.rect(0, 0, doc.page.width, doc.page.height).fill(BG);
          doc.y = 50;
        }

        doc.fill(color).fontSize(14).text(`[${f.cvss_severity || f.severity}] ${f.type || f.vulnerability_name}`, 50);
        doc.fill(FG).fontSize(10).text(`${f.method} ${f.fullUrl || f.endpoint || f.host}`, 50);
        doc.fill('#94a3b8').fontSize(9).text(`Parameter: ${f.parameter}   Payload: ${f.payload}`, 50);
        doc.fill('#64748b').text(`CVSS: ${f.cvss_score || f.score} (${f.cvss_vector || 'N/A'})   Confidence: ${f.confidence || f.confidence_tier}`, 50);
        
        const evidenceSnippet = typeof f.evidence === 'object' ? JSON.stringify(f.evidence) : (f.evidence || '');
        doc.fill('#cbd5e1').fontSize(9).text(`Reasoning: ${f.reasoning || f.explanation || 'N/A'}`, 50);
        doc.fill('#64748b').fontSize(8).text(`Evidence Proof: ${evidenceSnippet.slice(0, 150)}...`, 50);
        
        if (f.prevention || f.remediation) {
          doc.fill(GRN).fontSize(9).text(`Remediation: ${f.prevention || f.remediation}`, 50);
        }
        
        doc.moveTo(50, doc.y + 6).lineTo(doc.page.width - 50, doc.y + 6).strokeColor('#1e2535').stroke();
        doc.moveDown(1.5);
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
  let html = `<!DOCTYPE html>
<html>
<head>
  <title>MiniBurp Scan Report</title>
  <style>
    body { background: #0b0b0f; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; margin: 0; }
    .container { max-width: 1000px; margin: 0 auto; }
    h1 { color: #ef4444; border-bottom: 2px solid #1e2535; padding-bottom: 10px; font-weight: 800; letter-spacing: -0.5px; }
    h2 { color: #f97316; margin-top: 30px; font-weight: 700; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .stat-card { background: #12121a; border: 1px solid #1e2535; padding: 20px; border-radius: 8px; text-align: center; }
    .stat-val { font-size: 28px; font-weight: 800; color: #f97316; margin-bottom: 5px; }
    .stat-lbl { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
    .card { background: #12121a; border: 1px solid #1e2535; padding: 24px; border-radius: 8px; margin-bottom: 25px; border-left: 4px solid #3b82f6; }
    .card.Critical { border-left-color: #f43f5e; }
    .card.High { border-left-color: #ef4444; }
    .card.Medium { border-left-color: #f97316; }
    .card.Low { border-left-color: #eab308; }
    .badge { display: inline-block; padding: 2px 8px; font-size: 10px; font-weight: 700; border-radius: 4px; text-transform: uppercase; margin-right: 10px; }
    .badge.Critical { background: rgba(244,63,94,0.15); color: #f43f5e; }
    .badge.High { background: rgba(239,68,68,0.15); color: #ef4444; }
    .badge.Medium { background: rgba(249,115,22,0.15); color: #f97316; }
    .badge.Low { background: rgba(234,179,8,0.15); color: #eab308; }
    pre { background: #050508; border: 1px solid #1a1a24; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; font-family: monospace; color: #a78bfa; }
    .meta-line { font-size: 13px; margin: 6px 0; color: #94a3b8; }
    .meta-line strong { color: #f8fafc; }
    .remediation { background: rgba(34,197,94,0.05); border: 1px dashed rgba(34,197,94,0.3); padding: 15px; border-radius: 6px; color: #4ade80; margin-top: 15px; font-size: 13px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔴 MiniBurp Security Assessment Report</h1>
    <div style="color: #64748b; font-size: 13px; margin-bottom: 30px;">
      AI-Powered Behavioral Verification Platform &bull; Generated: ${summary.generated}
    </div>

    <h2>Executive Overview</h2>
    <div class="grid">
      <div class="stat-card">
        <div class="stat-val" style="color: #ef4444;">${summary.risk_rating}</div>
        <div class="stat-lbl">Risk Rating</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">${summary.total_findings}</div>
        <div class="stat-lbl">Total Findings</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #3b82f6;">${summary.endpoint_statistics.discovered}</div>
        <div class="stat-lbl">Discovered URLs</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #10b981;">${summary.endpoint_statistics.tested}</div>
        <div class="stat-lbl">Tested Endpoints</div>
      </div>
    </div>

    <h2>Verified Findings</h2>`;
  
  all.forEach(f => {
    const sev = f.cvss_severity || f.severity || 'Medium';
    const scoreVal = f.cvss_score || f.score || 0;
    const evidenceStr = typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : f.evidence;
    
    html += `
    <div class="card ${sev}">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px;">
        <span style="font-size: 18px; font-weight: 700; color: #f8fafc;">
          <span class="badge ${sev}">${sev}</span> ${f.type || f.vulnerability_name}
        </span>
        <span style="font-size: 12px; color: #64748b;">CVSS Score: <strong>${scoreVal}</strong> | Confidence: <strong>${f.confidence || f.confidence_tier}</strong></span>
      </div>
      <div class="meta-line"><strong>Target URL:</strong> <code>${f.method || 'GET'} ${f.fullUrl || f.endpoint}</code></div>
      <div class="meta-line"><strong>Parameter:</strong> <code>${f.parameter}</code> &bull; <strong>Payload:</strong> <code>${f.payload}</code></div>
      <div class="meta-line" style="margin-top: 15px;"><strong>Behavioral Verification Reasoning:</strong></div>
      <p style="font-size: 14px; line-height: 1.6; color: #cbd5e1; margin-top: 5px;">${f.reasoning || f.explanation || 'N/A'}</p>
      
      <div class="meta-line" style="margin-top: 15px;"><strong>Evidence Proof:</strong></div>
      <pre>${evidenceStr}</pre>

      <div class="remediation">
        <strong>Remediation:</strong> ${f.prevention || f.remediation || 'Enforce robust input validation and server-side parameterized sanitization.'}
      </div>
    </div>`;
  });
  
  html += `
  </div>
</body>
</html>`;
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

