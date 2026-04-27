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
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_ts ON requests(timestamp);
    CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(timestamp);

  `);

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
  try {
    console.log(`[DB] [FINDING] Saving Finding: ${f.id} | ${f.type} on ${f.endpoint || f.url}`);
    stmts.saveFinding.run(
      f.id, f.reqId || '', f.type || '', f.parameter || '', f.payload || '',
      f.severity || '', f.cvss_score || 0, f.evidence || '', f.endpoint || f.url || '',
      f.method || '', JSON.stringify(f)
    );
    console.log(`[DB] [SUCCESS] Saved Finding ${f.id} to database.`);
  } catch (e) { console.error('[DB] [ERROR] saveFinding failed:', e.message); }
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

function updateFinding(id, f) {
  if (!db) return;
  try {
    const stmt = db.prepare(`UPDATE findings SET data = ? WHERE id = ?`);
    stmt.run(JSON.stringify(f), id);
  } catch (e) { console.error('[DB] updateFinding error:', e.message); }
}

module.exports = { 
  getDB, saveRequest, getHistory, getRequestById, getCount, clearHistory, searchAll, close, reinit,
  saveFinding, getFindings, clearFindings, updateFinding
};

