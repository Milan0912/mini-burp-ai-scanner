'use strict';

const Database = require('better-sqlite3');
const path = require('path');

let db;

function initDB() {
  if (db) return;
  const dbPath = path.resolve(__dirname, '../ai-memory.sqlite');
  db = new Database(dbPath, { fileMustExist: false });
  // Set PRAGMAs for performance and reliability
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  
  db.exec(`
    CREATE TABLE IF NOT EXISTS memory_cache (
      route_key TEXT NOT NULL,
      payload TEXT NOT NULL,
      type TEXT NOT NULL,
      success INTEGER NOT NULL DEFAULT 0,
      failure_count INTEGER NOT NULL DEFAULT 0,
      usage_count INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      last_used INTEGER NOT NULL,
      UNIQUE(route_key, payload, type)
    );
    CREATE INDEX IF NOT EXISTS idx_route ON memory_cache(route_key);
    CREATE INDEX IF NOT EXISTS idx_last_used ON memory_cache(last_used);
  `);
}

/**
 * Loads the most recent valid payloads from SQLite into the native Map.
 */
function loadTop(limit = 1000) {
  if (!db) initDB();
  const stmt = db.prepare(`
    SELECT * FROM memory_cache 
    ORDER BY last_used DESC 
    LIMIT ?
  `);
  return stmt.all(limit);
}

/**
 * Batch Upsert Queue into SQLite using a solitary transaction to prevent locking
 */
function batchUpsert(items) {
  if (!db) initDB();
  if (!items || items.length === 0) return;

  const stmt = db.prepare(`
    INSERT INTO memory_cache (
      route_key, payload, type, success, failure_count, usage_count, created_at, last_used
    ) VALUES (
      @route_key, @payload, @type, @success, @failure_count, @usage_count, @created_at, @last_used
    )
    ON CONFLICT(route_key, payload, type) DO UPDATE SET
      success = CASE WHEN excluded.success = 1 THEN 1 ELSE memory_cache.success END,
      failure_count = excluded.failure_count,
      usage_count = excluded.usage_count,
      last_used = excluded.last_used
  `);

  const transaction = db.transaction((batch) => {
    for (const item of batch) {
       stmt.run(item);
    }
  });

  transaction(items);
}

/**
 * Cleanup job to delete organic stragglers
 * > 1 hour old OR > 100 uses
 */
function deleteExpired() {
  if (!db) initDB();
  const oneHourAgo = Date.now() - (60 * 60 * 1000);
  const stmt = db.prepare(`
    DELETE FROM memory_cache 
    WHERE last_used < ? OR usage_count > 100
  `);
  const info = stmt.run(oneHourAgo);
  return info.changes;
}

function flushAndClose() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = {
  initDB,
  loadTop,
  batchUpsert,
  deleteExpired,
  flushAndClose
};
