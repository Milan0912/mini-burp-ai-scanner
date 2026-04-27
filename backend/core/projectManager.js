'use strict';

/**
 * Project Manager
 *
 * Handles safe Export (zip) and Import (unzip + hot-swap) of the full
 * MiniBurp session following the SAFE MODE SWITCH protocol:
 *
 *   STEP 1: pause    → systemState.pause()
 *   STEP 2: flush    → memoryEngine write queue + pending interceptor drains
 *   STEP 3: close DB → db.closeAll(), memoryDB.flushAndClose()
 *   STEP 4: swap     → overwrite .db files from zip
 *   STEP 5: resume   → re-init DB + memoryEngine, systemState.resume()
 */

const archiver = require('archiver');
const unzipper  = require('unzipper');
const fs        = require('fs');
const path      = require('path');
const os        = require('os');
const stream    = require('stream');

const MB_DIR    = path.join(os.homedir(), '.miniburp');
const MAIN_DB   = path.join(MB_DIR, 'miniburp.db');
const MEM_DB    = path.join(__dirname, '..', 'ai-memory.sqlite');

// Lazily acquired references injected by server.js at startup
let _db          = null;
let _memoryDB    = null;
let _interceptor  = null;
let _systemState = null;
let _importInProgress = false;

function init({ db, memoryDB, systemState, interceptor }) {
  _db           = db;
  _memoryDB     = memoryDB;
  _systemState  = systemState;
  _interceptor   = interceptor;
}

// ── EXPORT ─────────────────────────────────────────────────────────────────

/**
 * Streams a .zip archive containing both databases into `res` (Express response).
 */
async function exportProject(res) {

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="miniburp-project.zip"');

  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', (err) => { console.error('[Project] Archive error:', err.message); });
  archive.pipe(res);

  // Add meta file
  archive.append(JSON.stringify({ version: 2, exported: new Date().toISOString() }), { name: 'meta.json' });

  const mainExists = fs.existsSync(MAIN_DB);
  const memExists  = fs.existsSync(MEM_DB);
  console.log(`[Project] Exporting: mainline=${mainExists} (${MAIN_DB}), ai-mem=${memExists} (${MEM_DB})`);

  if (mainExists) archive.file(MAIN_DB, { name: 'miniburp.db' });
  if (memExists)  archive.file(MEM_DB,  { name: 'ai-memory.sqlite' });

  return new Promise((resolve, reject) => {
    res.on('finish', resolve);
    res.on('error', reject);
    archive.finalize().catch(reject);
  });
}

// ── IMPORT ─────────────────────────────────────────────────────────────────

/**
 * Safe import using the 5-step PAUSED protocol.
 * `zipBuffer` is a Buffer containing the uploaded .zip bytes.
 */
async function importProject(zipBuffer) {
  if (!_systemState) throw new Error('projectManager not initialized');
  if (_importInProgress) throw new Error('Another import is already in progress');

  _importInProgress = true;
  _systemState.pause('Switching project...');

  try {
    // ── STEP 2: drain pending interceptor queue ───────
    if (_interceptor && typeof _interceptor._flushAll === 'function') {
      _interceptor._flushAll();             // Forward all queued/paused requests
    }
    
    // Give any in-flight async DB writes a moment to complete
    await new Promise(r => setTimeout(r, 200));

    // ── STEP 3: Close SQLite connections ─────────────────────────────────
    if (_memoryDB && typeof _memoryDB.flushAndClose === 'function') {
      _memoryDB.flushAndClose();
    }
    if (_db && typeof _db.close === 'function') {
      _db.close();
    }

    // ── STEP 4: Extract zip and replace .db files ─────────────────────────
    const extractedFiles = await _extractZip(zipBuffer);
    console.log('[Project] Extracted files:', Object.keys(extractedFiles));

    if (extractedFiles['miniburp.db']) {
      fs.writeFileSync(MAIN_DB, extractedFiles['miniburp.db']);
      console.log('[Project] miniburp.db replaced.');
    }
    if (extractedFiles['ai-memory.sqlite']) {
      fs.writeFileSync(MEM_DB, extractedFiles['ai-memory.sqlite']);
      console.log('[Project] ai-memory.sqlite replaced.');
    }

    // ── STEP 5: Re-initialize in specific order: database -> memoryDB -> memoryEngine ──────────
    console.log('[Project] Re-initializing database...');
    if (_db && typeof _db.reinit === 'function') {
      await _db.reinit();
    }
    
    console.log('[Project] Re-initializing memoryDB...');
    if (_memoryDB && typeof _memoryDB.initDB === 'function') {
      _memoryDB.initDB();
    } else if (_memoryDB && typeof _memoryDB.init === 'function') {
       // Support either naming convention
       _memoryDB.init();
    }

    // Re-initialization complete

    // ── STEP 6: Clear and rebuild report findings ──
    try {
      const reportGenerator = require('../ai/reportGenerator');
      reportGenerator.clearFindings();
    } catch (e) {
      console.warn('[Project] Could not clear report generator findings:', e.message);
    }

    // Give modules a moment to fully hydrate
    await new Promise(r => setTimeout(r, 300));

  } catch (err) {
    console.error('[Project Import] Failed:', err.message);
    throw err;
  } finally {
    _importInProgress = false;
    _systemState.resume();
  }
}

/**
 * Extracts zip buffer contents into a plain object { filename: Buffer }.
 */
function _extractZip(zipBuffer) {
  return new Promise((resolve, reject) => {
    unzipper.Open.buffer(zipBuffer)
      .then(d => {
        const files = {};
        const promises = d.files.map(file => {
          return file.buffer().then(buf => {
            files[path.basename(file.path)] = buf;
          });
        });
        Promise.all(promises).then(() => resolve(files)).catch(reject);
      })
      .catch(reject);
  });
}

module.exports = { init, exportProject, importProject };
