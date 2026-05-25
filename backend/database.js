'use strict';

/**
 * SQLite database layer using better-sqlite3.
 * v3: High performance, zero-blocking sync writes using WAL mode.
 */

const path = require('path');
const os = require('os');
const fs = require('fs');
const Database = require('better-sqlite3');

const DB_DIR = path.join(os.homedir(), '.miniburp');
const DB_PATH = path.join(DB_DIR, 'miniburp.db');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

let db = null;
let stmts = {};

async function getDB() {
  if (db) return db;

  // better-sqlite3 is synchronous
  db = new Database(DB_PATH);
  
  // Enable Write-Ahead Logging for high-concurrency lock-free reads/writes
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');

  // Must keep id as TEXT to maintain compatibility with nanoid tracking from proxyServer
  db.exec(`
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY,
      method TEXT,
      url TEXT,
      status INTEGER DEFAULT 0,
      request_headers TEXT,
      request_body TEXT,
      response_headers TEXT,
      response_body TEXT,
      size INTEGER DEFAULT 0,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      reqId TEXT,
      type TEXT,
      parameter TEXT,
      payload TEXT,
      severity TEXT,
      score REAL,
      evidence TEXT,
      endpoint TEXT,
      method TEXT,
      data TEXT,
      source TEXT DEFAULT 'scanner',
      confidence TEXT DEFAULT '',
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS scan_sessions (
      id TEXT PRIMARY KEY,
      target_url TEXT,
      status TEXT,
      discovered INTEGER DEFAULT 0,
      tested INTEGER DEFAULT 0,
      findings INTEGER DEFAULT 0,
      options TEXT,
      started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS ai_insights (
      id TEXT PRIMARY KEY,
      reqId TEXT,
      type TEXT,
      detail TEXT,
      confidence REAL,
      generated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS exploit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_url TEXT,
      vulnerability_type TEXT,
      parameter TEXT,
      module_used VARCHAR(255),
      success BOOLEAN DEFAULT 0,
      confidence REAL DEFAULT 0,
      execution_time INTEGER,
      output TEXT,
      evidence TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_ts ON requests(timestamp);
    CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(timestamp);
    CREATE INDEX IF NOT EXISTS idx_scan_sessions ON scan_sessions(started_at);
    CREATE INDEX IF NOT EXISTS idx_exploit_log_ts ON exploit_log(timestamp);
  `);

  // Migrate legacy findings table if needed
  const existingColumns = db.prepare(`PRAGMA table_info(findings)`).all().map(r => r.name);
  if (existingColumns.length > 0) {
    if (!existingColumns.includes('source')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN source TEXT DEFAULT 'scanner'`).run();
    }
    if (!existingColumns.includes('confidence')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT ''`).run();
    }
    // Add exploit-related columns
    if (!existingColumns.includes('exploited')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN exploited BOOLEAN DEFAULT 0`).run();
    }
    if (!existingColumns.includes('exploit_proof')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN exploit_proof TEXT`).run();
    }
    if (!existingColumns.includes('metasploit_module')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN metasploit_module VARCHAR(255)`).run();
    }
    if (!existingColumns.includes('exploitation_timestamp')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN exploitation_timestamp DATETIME`).run();
    }
    if (!existingColumns.includes('ai_verified')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN ai_verified BOOLEAN DEFAULT 0`).run();
    }
    if (!existingColumns.includes('ai_verification_data')) {
      db.prepare(`ALTER TABLE findings ADD COLUMN ai_verification_data TEXT`).run();
    }
  }

  stmts.save = db.prepare(`
    INSERT OR REPLACE INTO requests
      (id, method, url, status, request_headers, request_body, response_headers, response_body, size, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `);
  
  stmts.saveFinding = db.prepare(`
    INSERT OR REPLACE INTO findings (id, reqId, type, parameter, payload, severity, score, evidence, endpoint, method, data, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `);

  stmts.getFindings = db.prepare(`SELECT * FROM findings ORDER BY timestamp DESC`);
  stmts.getById = db.prepare(`SELECT * FROM requests WHERE id = ?`);
  stmts.getCount = db.prepare(`SELECT COUNT(*) as count FROM requests`);
  stmts.clear = db.prepare(`DELETE FROM requests`);
  stmts.clearFindings = db.prepare(`DELETE FROM findings`);
  stmts.saveScanSession = db.prepare(`
    INSERT OR REPLACE INTO scan_sessions
      (id, target_url, status, discovered, tested, findings, options, started_at, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmts.saveAiInsight = db.prepare(`
    INSERT OR REPLACE INTO ai_insights
      (id, reqId, type, detail, confidence, generated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  return db;
}

// Initialize eagerly at startup
getDB().catch((e) => console.error('[DB] init error:', e.message));

function saveRequest({ id, method, url, status, requestHeaders, requestBody, responseHeaders, responseBody, size }) {
  if (!db) return;
  try {
    console.log(`[DB] [CAPTURE] Captured Request: ${id} | ${method} ${url}`);
    stmts.save.run(
      id,
      method,
      url,
      status || 0,
      typeof requestHeaders === 'string' ? requestHeaders : JSON.stringify(requestHeaders || {}),
      requestBody || '',
      typeof responseHeaders === 'string' ? responseHeaders : JSON.stringify(responseHeaders || {}),
      responseBody || '',
      size || 0
    );
    console.log(`[DB] [SUCCESS] Saved Request ${id} to database.`);
  } catch (e) {
    console.error('[DB] [ERROR] saveRequest failed:', e.message);
  }
}

function saveFinding(f) {
  if (!db) return;
  const evidenceStr = typeof f.evidence === 'object' && f.evidence !== null ? JSON.stringify(f.evidence) : (f.evidence || '');
  const args = [
    f.id, f.reqId || '', f.type || '', f.parameter || '', f.payload || '',
    f.severity || '', f.cvss_score || 0, evidenceStr, f.endpoint || f.url || '',
    f.method || '', JSON.stringify(f)
  ];
  try {
    console.log(`[DB] [FINDING] Saving Finding: ${f.id} | ${f.type} on ${f.endpoint || f.url}`);
    stmts.saveFinding.run(...args);
    console.log(`[DB] [SUCCESS] Saved Finding ${f.id} to database.`);
  } catch (e) {
    console.error('[DB] [ERROR] saveFinding failed:', e.message);
    console.error('[DB] [ERROR] Args count:', args.length);
    console.error('[DB] [ERROR] Args:', JSON.stringify(args));
  }
}

function getHistory({ limit = 100, offset = 0, search = '', searchFields = 'url,method' } = {}) {
  if (!db) return [];
  try {
    if (search) {
      const term = `%${search}%`;
      const fields = searchFields.split(',');
      const conditions = fields.map(f => {
        const colMap = {
          url: 'url',
          method: 'method',
          status: 'CAST(status AS TEXT)',
          headers: 'request_headers',
          body: 'request_body',
          response: 'response_body',
        };
        return colMap[f.trim()] ? `${colMap[f.trim()]} LIKE ?` : null;
      }).filter(Boolean);

      const whereClause = conditions.length > 0 ? conditions.join(' OR ') : 'url LIKE ?';
      const stmt = db.prepare(
        `SELECT id, method, url, status, size, timestamp FROM requests
         WHERE ${whereClause}
         ORDER BY timestamp DESC LIMIT ? OFFSET ?`
      );
      
      const params = conditions.map(() => term);
      params.push(limit, offset);
      return stmt.all(...params);
    } else {
      const stmt = db.prepare(
        `SELECT id, method, url, status, size, timestamp FROM requests
         ORDER BY timestamp DESC LIMIT ? OFFSET ?`
      );
      return stmt.all(limit, offset);
    }
  } catch (e) {
    console.error('[DB] getHistory error:', e.message);
    return [];
  }
}

function searchAll(q) {
  if (!db || !q) return [];
  try {
    const term = `%${q}%`;
    const stmt = db.prepare(
      `SELECT id, method, url, status, size, timestamp,
              request_headers, request_body, response_headers, response_body
       FROM requests
       WHERE url LIKE ?
          OR method LIKE ?
          OR CAST(status AS TEXT) LIKE ?
          OR request_headers LIKE ?
          OR request_body LIKE ?
          OR response_headers LIKE ?
          OR response_body LIKE ?
       ORDER BY timestamp DESC
       LIMIT 200`
    );
    
    // better-sqlite3 all() array spread for args
    const rows = stmt.all(term, term, term, term, term, term, term);
    
    for (const row of rows) {
      row.matchFields = [];
      const lq = q.toLowerCase();
      if ((row.url || '').toLowerCase().includes(lq)) row.matchFields.push('url');
      if ((row.method || '').toLowerCase().includes(lq)) row.matchFields.push('method');
      if (String(row.status || '').includes(lq)) row.matchFields.push('status');
      if ((row.request_headers || '').toLowerCase().includes(lq)) row.matchFields.push('request_headers');
      if ((row.request_body || '').toLowerCase().includes(lq)) row.matchFields.push('request_body');
      if ((row.response_headers || '').toLowerCase().includes(lq)) row.matchFields.push('response_headers');
      if ((row.response_body || '').toLowerCase().includes(lq)) row.matchFields.push('response_body');
    }
    return rows;
  } catch (e) {
    console.error('[DB] searchAll error:', e.message);
    return [];
  }
}

function getRequestById(id) {
  if (!db) return null;
  try {
    const row = stmts.getById.get(id);
    if (row) {
      try { row.request_headers = JSON.parse(row.request_headers); } catch (_) {}
      try { row.response_headers = JSON.parse(row.response_headers); } catch (_) {}
    }
    return row || null;
  } catch (e) {
    console.error('[DB] getById error:', e.message);
    return null;
  }
}

function getCount() {
  if (!db) return 0;
  try {
    const row = stmts.getCount.get();
    return row ? row.count : 0;
  } catch (e) {
    return 0;
  }
}

function clearHistory() {
  if (!db) return;
  try {
    stmts.clear.run();
  } catch (e) {
    console.error('[DB] clearHistory error:', e.message);
  }
}

/** Called by projectManager before file swap */
function close() {
  if (!db) return;
  try { db.close(); } catch (_) {}
  db = null;
  stmts = {};
  console.log('[DB] Connection closed for project switch.');
}

/** Called by projectManager after file swap to re-open the new DB */
async function reinit() {
  db = null;
  stmts = {};
  await getDB();
  console.log('[DB] Re-initialized from new project file.');
}



function findingExists(type, endpoint, method, parameter) {
  if (!db) return false;
  try {
    const row = db.prepare(`
      SELECT id FROM findings 
      WHERE type = ? AND endpoint = ? AND method = ? AND parameter = ?
      LIMIT 1
    `).get(type, endpoint, method, parameter);
    return !!row;
  } catch (e) {
    console.error('[DB] findingExists error:', e.message);
    return false;
  }
}

function removeDuplicateFindings() {
  if (!db) return 0;
  try {
    const info = db.prepare(`
      DELETE FROM findings WHERE id NOT IN (
        SELECT MIN(id) FROM findings 
        GROUP BY type, endpoint, method, parameter
      )
    `).run();
    return info.changes;
  } catch (e) {
    console.error('[DB] removeDuplicateFindings error:', e.message);
    return 0;
  }
}

function getFindings() {
  if (!db) return [];
  try {
    const rows = stmts.getFindings.all();
    return rows.map(r => ({ ...JSON.parse(r.data), timestamp: r.timestamp }));
  } catch (e) {
    console.error('[DB] getFindings error:', e.message);
    return [];
  }
}

function clearFindings() {
  if (!db) return;
  try { stmts.clearFindings.run(); } catch(e) {}
}

function saveScanSession(session) {
  if (!db || !session || !session.id) return;
  try {
    stmts.saveScanSession.run(
      session.id,
      session.target_url || session.url || '',
      session.status || 'unknown',
      session.discovered || 0,
      session.tested || 0,
      session.findings || 0,
      JSON.stringify(session.options || {}),
      session.started_at || new Date().toISOString(),
      session.completed_at || null
    );
  } catch (e) {
    console.error('[DB] saveScanSession error:', e.message);
  }
}

function saveAiInsight(insight) {
  if (!db || !insight || !insight.id) return;
  try {
    stmts.saveAiInsight.run(
      insight.id,
      insight.reqId || '',
      insight.type || '',
      insight.detail || '',
      insight.confidence || 0,
      insight.generated_at || new Date().toISOString()
    );
  } catch (e) {
    console.error('[DB] saveAiInsight error:', e.message);
  }
}

function updateFinding(id, f) {
  if (!db) return;
  try {
    const stmt = db.prepare(`UPDATE findings SET data = ? WHERE id = ?`);
    stmt.run(JSON.stringify(f), id);
  } catch (e) { console.error('[DB] updateFinding error:', e.message); }
}

function saveExploitLog(logEntry) {
  if (!db || !logEntry) return;
  try {
    const stmt = db.prepare(`
      INSERT INTO exploit_log
        (target_url, vulnerability_type, parameter, module_used, success, confidence, execution_time, output, evidence, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `);
    stmt.run(
      logEntry.targetUrl || '',
      logEntry.vulnerabilityType || '',
      logEntry.parameter || '',
      logEntry.moduleUsed || '',
      logEntry.success ? 1 : 0,
      logEntry.confidence || 0,
      logEntry.executionTime || 0,
      logEntry.output || '',
      logEntry.evidence || ''
    );
    console.log(`[DB] Saved exploit log for ${logEntry.vulnerabilityType} on ${logEntry.targetUrl}`);
  } catch (e) {
    console.error('[DB] saveExploitLog error:', e.message);
  }
}

function getEndpointStats() {
  if (!db) return { totalRequests: 0, distinctUrls: 0, discovered: 0, tested: 0 };
  try {
    const totalRequests = db.prepare(`SELECT COUNT(*) as count FROM requests`).get().count;
    const distinctUrls = db.prepare(`SELECT COUNT(DISTINCT url) as count FROM requests`).get().count;
    const latestSession = db.prepare(`SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT 1`).get();
    return {
      totalRequests,
      distinctUrls,
      discovered: latestSession ? latestSession.discovered : 0,
      tested: latestSession ? latestSession.tested : 0,
    };
  } catch (e) {
    console.error('[DB] getEndpointStats error:', e.message);
    return { totalRequests: 0, distinctUrls: 0, discovered: 0, tested: 0 };
  }
}

module.exports = { 
  getDB, saveRequest, getHistory, getRequestById, getCount, clearHistory, searchAll, close, reinit,
  saveFinding, getFindings, clearFindings, updateFinding, saveScanSession, saveAiInsight, saveExploitLog,
  findingExists, removeDuplicateFindings, getEndpointStats
};

