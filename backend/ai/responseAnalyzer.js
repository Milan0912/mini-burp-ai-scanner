'use strict';
// AI HOOK — Phase 2: Response Analyzer

const insightEngine = require('./insightEngine');

/**
 * Analyzes responses for vulnerabilities synchronously/fast.
 * @param {Object} ctx 
 */
async function responseAnalyzer(ctx) {
  setImmediate(() => analyze(ctx));
  return null;
}

function analyze(ctx) {
  if (!ctx.id) return;

  insightEngine.setResponse(ctx.id, ctx);

  const status = parseInt(ctx.statusCode || ctx.status || 0);
  const body = (ctx.bodyPreview || ctx.rawResponse || '').toString();

  // 1. Detect HTTP 500
  if (status >= 500) {
    insightEngine.addResponseInsight(ctx.id, {
      id: 'http_500',
      type: 'HTTP 500 Error',
      parameter: 'Status Code',
      confidence: 'Medium',
      message: `Server returned an internal error (${status}). Check for unhandled exceptions or hidden debug dumps.`
    });
  }

  // 2. Detect SQL Errors
  const sqlErrorRegex = /(SQL syntax|mysql_fetch_array|ORA-[0-9]{5}|PostgreSQL query failed|SQLite3::SQLException|unclosed quotation mark after the character string)/i;
  if (sqlErrorRegex.test(body)) {
    insightEngine.addResponseInsight(ctx.id, {
      id: 'sql_error',
      type: 'SQL Error Leaked',
      parameter: 'Response Body',
      confidence: 'High',
      message: 'A database error was detected in the response body! High likelihood of SQL Injection.'
    });
  }

  // 3. Detect Reflection (We can just check if url parameters exist in the response body)
  const reqInsight = insightEngine.getOrCreate(ctx.id);
  if (reqInsight.request && reqInsight.request.url) {
      try {
          const u = new URL(reqInsight.request.url);
          for (const [key, val] of u.searchParams.entries()) {
              if (val.length > 3 && body.includes(val)) {
                  // Only report it if it looks like XSS is possible (HTML ctx)
                  const contentType = ctx.headers ? (ctx.headers['content-type'] || '') : '';
                  if (contentType.toLowerCase().includes('text/html')) {
                      insightEngine.addResponseInsight(ctx.id, {
                          id: `reflected_${key}`,
                          type: 'Reflected Input (XSS Risk)',
                          parameter: key,
                          confidence: 'Medium',
                          message: `The value for '${key}' is reflected in the HTML response without obvious filtering.`
                      });
                  }
              }
          }
      } catch (e) {}
  }
}

module.exports = { responseAnalyzer };
