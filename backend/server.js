'use strict';

require('dotenv').config();
const express = require('express');
const http = require('http');
const net = require('net');
const { Server: SocketIOServer } = require('socket.io');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const os = require('os');

// Database & Core
const db = require('./database');
const interceptor = require('./intercept/interceptor');
const { startProxy, setInterceptor, setDatabase, setIO: setProxyIO, getProxyPort } = require('./proxy-core/proxyServer');
const { initCA, getRootCACert, CA_CERT_PATH } = require('./proxy-core/caManager');
const { sendRawRequest } = require('./core/repeater');
const { runIntruder, stopIntruder } = require('./core/intruder');
const systemState = require('./core/systemState');

// AI & Pentesting
const insightEngine = require('./ai/insightEngine');
const agentEngine = require('./ai/agentEngine');
const scanEngine = require('./scanner/scanEngine');
const reportGenerator = require('./ai/reportGenerator');
const memoryDB = require('./ai/memoryDB');
const autoAI = require('./ai/autoAI');

const API_PORT_START = 3000;
const PORT_FILE = path.join(os.homedir(), '.miniburp', 'api.port');

function findAvailablePort(start) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(start, '0.0.0.0', () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') resolve(findAvailablePort(start + 1));
      else reject(err);
    });
  });
}

async function main() {
  console.log('[Server] Startup sequence initiated...');
  
  await initCA();

  // Initialize AI system
  await autoAI.init();
  console.log(`[Server] AI Mode Active: ${autoAI.getMode()}`);

  await db.getDB();
  const removedCount = db.removeDuplicateFindings();
  console.log(`[Server] Cleaned up ${removedCount} duplicate findings.`);

  // 2. Setup Networking
  const API_PORT = await findAvailablePort(API_PORT_START);
  const mbDir = path.join(os.homedir(), '.miniburp');
  if (!fs.existsSync(mbDir)) fs.mkdirSync(mbDir, { recursive: true });
  fs.writeFileSync(PORT_FILE, String(API_PORT));

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '50mb' }));
  
  // ── Serve Frontend ───────────────────────────────────────────
  const distDir = path.join(__dirname, '..', 'frontend', 'dist');
  if (fs.existsSync(distDir)) {
     app.use(express.static(distDir));
     console.log(`[Server] Serving frontend from ${distDir}`);
  } else {
     console.warn('[Server] Frontend dist not found! Please build it first.');
  }
  
  const httpServer = http.createServer(app);
  const io = new SocketIOServer(httpServer, { cors: { origin: '*' } });

  // 3. Initialization
  interceptor.setIO(io);
  insightEngine.setIO(io);
  agentEngine.setIO(io);
  reportGenerator.setIO(io);
  systemState.setIO(io);
  
  if (typeof scanEngine.setIO === 'function') {
    scanEngine.setIO(io);
  } else {
    console.warn('[Server] [WARN] scanEngine.setIO missing or not a function');
  }

  setInterceptor(interceptor);
  setDatabase(db);
  setProxyIO(io);  // ← FIX: give proxy access to socket.io so request:resolved events work
  
  // Engine initializations removed for standalone auto-scanner.

  // projectManager.init() removed

  // 4. Shared Listeners
  insightEngine.onConfirmed((f) => {
    db.saveFinding(f);
    reportGenerator.addFinding(f);
    io.emit('finding:new', f);
  });

  // 5. API Routes
  app.get('/api/status', (req, res) => res.json({ ok: true, version: 'GOD MODE v1.1' }));
  
  // Interceptor
  app.get('/api/intercept-status', (req, res) => res.json(interceptor.getStatus()));
  app.post('/api/intercept/toggle', (req, res) => {
    interceptor.interceptOn = !!req.body.on;
    io.emit('intercept:state', { on: interceptor.interceptOn });
    res.json({ ok: true });
  });

  // History, Repeater & Diff
  app.get('/api/history', (req, res) => {
    const { limit, offset, search } = req.query;
    console.log(`[API] GET /api/history | search: "${search || ''}"`);
    const rows = db.getHistory({ 
      limit: parseInt(limit) || 200, 
      offset: parseInt(offset) || 0,
      search: search || ''
    });
    console.log(`[API] Returning ${rows.length} rows.`);
    res.json({ 
      success: true,
      rows: rows, 
      total: db.getCount() 
    });
  });

  app.get('/api/search', (req, res) => {
    const { q } = req.query;
    const rows = db.searchAll(q || '');
    res.json({ success: true, rows, total: rows.length });
  });

  app.delete('/api/history', (req, res) => {
    db.clearHistory();
    res.json({ success: true });
  });

  app.get('/api/request/:id', (req, res) => res.json(db.getRequestById(req.params.id)));
  
  // Session Manager API
  app.get('/api/session', (req, res) => {
    const sessionManager = require('./core/sessionManager');
    res.json(sessionManager.exportSnapshot());
  });

  app.delete('/api/session', (req, res) => {
    const sessionManager = require('./core/sessionManager');
    sessionManager.cookies.clear();
    sessionManager.tokens.clear();
    res.json({ success: true });
  });

  app.get('/api/diff/:id1/:id2', (req, res) => {
    const r1 = db.getRequestById(req.params.id1);
    const r2 = db.getRequestById(req.params.id2);
    if (!r1 || !r2) return res.status(404).json({ success: false, error: 'Request not found' });
    res.json({ success: true, r1, r2 });
  });
  app.post('/api/repeater/send', async (req, res) => {
     try {
       const response = await sendRawRequest(req.body);
       res.json({ success: true, response: response.toString('utf8') });
     } catch (e) { res.status(500).json({ success: false, error: e.message }); }
  });

  // Intruder
  app.post('/api/intruder/start', async (req, res) => {
     const { rawRequest, host, port, useSSL, payloads, attackType, grepRegex } = req.body;
     runIntruder({ rawRequest, host, port, useSSL, payloads, attackType, io, grepRegex }).catch(console.error);
     res.json({ success: true });
  });
  app.post('/api/intruder/stop', (req, res) => {
     stopIntruder();
     res.json({ ok: true });
  });

  // Scanner
  app.get('/api/scanner/status', (req, res) => res.json({ success: true, ...scanEngine.getScanStatus() }));
  app.post('/api/scanner/start', async (req, res) => {
    const { url, targetUrl, ...options } = req.body;
    const finalUrl = url || targetUrl;
    if (!finalUrl) return res.status(400).json({ success: false, error: 'URL is required' });
    
    scanEngine.startScan(finalUrl, options || {}, (update) => io.emit('scanner:update', update));
    res.json({ success: true });
  });
  app.post('/api/scanner/stop', (req, res) => {
    scanEngine.stopScan();
    res.json({ success: true });
  });

  app.post('/api/scanner/run-test', async (req, res) => {
    const { reqId } = req.body;
    if (!reqId) return res.status(400).json({ success: false, error: 'Request ID is required' });
    
    // Asynchronous triggering of individual tests disabled in favor of automated full-sweep crawler.
    res.json({ success: true, message: 'Active Scan initiated (handled by auto-scanner queue)' });
  });

  // AI & Agent
  app.get('/api/agent/state', (req, res) => res.json({ success: true, ...agentEngine.getAgentState() }));
  app.post('/api/ai/mode', (req, res) => {
    const { mode } = req.body;
    agentEngine.setMode(mode);
    res.json({ success: true, mode });
  });
  app.post('/api/agent/config', (req, res) => {
    const { mode } = req.body;
    if (mode) agentEngine.setMode(mode);
    res.json({ success: true });
  });
  app.post('/api/agent/confirm', (req, res) => {
    // Stub: agent confirm is a no-op in MVP
    res.json({ success: true });
  });
  app.post('/api/ai/attack', (req, res) => {
    // Stub: manual attack trigger — scanner handles automated testing
    res.json({ success: true, message: 'Attack queued (use Scanner tab for full scans)' });
  });

  // AI Insights per request — returns passive findings for a specific request ID
  app.get('/api/ai/insights/:id', (req, res) => {
    const { id } = req.params;
    const allFindings = db.getFindings();
    const reqFindings = allFindings.filter(f => f.reqId === id);
    res.json({
      success: true,
      findings: reqFindings.map(f => ({
        type: f.type || f.vulnerability_name,
        severity: f.cvss_severity || f.severity || 'Medium',
        parameter: f.parameter || '-',
        message: f.explanation || f.evidence || '',
      })),
      attackResults: [],
    });
  });

  app.get('/api/ai/graph', (req, res) => {
    res.json({ success: true, nodes: [], edges: [] });
  });

  // AI Status & Test
  app.get('/api/ai/status', async (req, res) => {
    try {
      if (autoAI.getMode() === 'rule-based' && (process.env.AI_PROVIDER || '').toLowerCase() === 'ollama') {
        await autoAI.init();
      }
      res.json({ success: true, level: autoAI.getMode() });
    } catch (e) {
      res.json({ success: false, error: e.message });
    }
  });

  app.post('/api/ai/test', async (req, res) => {
    try {
      const result = await autoAI.analyzeFinding({ type: 'sqli', endpoint: 'test' });
      res.json({ success: true, response: result });
    } catch (e) {
      res.json({ success: false, error: e.message });
    }
  });

  app.post('/api/ai/pull', async (req, res) => {
    res.json({ success: true, message: 'Auto-AI system initialized.', level: autoAI.getMode() });
  });


  // Exploit Chain
  app.post('/api/exploit/chain', async (req, res) => {
    const { url, cookies } = req.body;
    const { runExploitChain } = require('./ai/exploitChain');
    
    io.emit('exploit:progress', { phase: 'START', message: `Skull Chain initiated on ${url}` });
    const result = await runExploitChain({ url, cookies: cookies || {} }, (progress) => {
      io.emit('exploit:progress', progress);
    });
    
    io.emit('exploit:complete', { url, report: result });
    res.json({ success: true, result });
  });

  app.get('/api/report/findings', (req, res) => {
    // Sync RAM with persistent DB to survive server reloads
    const dbFindings = db.getFindings();
    const ramFindings = reportGenerator.getFindings();
    
    // De-dupe based on ID
    const merged = new Map();
    dbFindings.forEach(f => merged.set(f.id, f));
    ramFindings.forEach(f => merged.set(f.id, f));
    
    let rows = Array.from(merged.values()).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    const confidenceFilter = req.query.confidence;
    if (confidenceFilter && confidenceFilter !== 'ALL') {
      rows = rows.filter(f => f.confidence === confidenceFilter);
    }

    console.log(`[API] Returning ${rows.length} findings as 'rows'.`);
    res.json({ success: true, rows });
  });

  // Clear all findings (for demo reset)
  app.delete('/api/report/findings/clear', (req, res) => {
    db.clearFindings();
    reportGenerator.clearFindings();
    res.json({ success: true, message: 'All findings cleared.' });
  });
  app.get('/api/report/download', (req, res) => {
    const type = req.query.type || 'json';
    try {
      if (type === 'pdf') {
         res.setHeader('Content-Type', 'application/pdf');
         res.setHeader('Content-Disposition', 'attachment; filename="miniburp_findings.pdf"');
         reportGenerator.generatePDF(res).catch(console.error); 
      } else if (type === 'markdown') {
         res.setHeader('Content-Type', 'text/markdown');
         res.setHeader('Content-Disposition', 'attachment; filename="miniburp_findings.md"');
         res.send(reportGenerator.generateMarkdown());
      } else {
         res.setHeader('Content-Type', 'application/json');
         res.setHeader('Content-Disposition', 'attachment; filename="miniburp_findings.json"');
         res.send(reportGenerator.generateJSON());
      }
    } catch (err) {
      console.error('[Export Error]', err);
      res.status(500).send('Export failed');
    }
  });

  // Project export/import disabled for MVP
  // 6. Catch-all for React (SPA)
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api')) return;
    const indexFile = path.join(__dirname, '..', 'frontend', 'dist', 'index.html');
    if (fs.existsSync(indexFile)) res.sendFile(indexFile);
    else res.status(404).send('Not Found');
  });

  // Start
  httpServer.listen(API_PORT, '0.0.0.0', () => {
    console.log(`[Server] MiniBurp God Mode listening on port ${API_PORT}`);
  });

  await startProxy();
  console.log('[Server] MiniBurp backend ready.');
}

main().catch((err) => {
  console.error('[Server] Fatal Error:', err);
  process.exit(1);
});
