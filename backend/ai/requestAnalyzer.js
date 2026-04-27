'use strict';
const { analyzeProxyRequest } = require('./proxyAssistant');
const insightEngine = require('./insightEngine');

async function requestAnalyzer(ctx) {
  // Fire and forget (async, non-blocking)
  setImmediate(async () => {
    try {
      insightEngine.setRequest(ctx.id, {
        method: ctx.method,
        url: ctx.url,
        headers: ctx.headers || {},
        body: ctx.body || '',
        raw: ctx.raw || ''
      });

      const aiResult = await analyzeProxyRequest(ctx);
      if (aiResult) {
         insightEngine.addRequestInsight(ctx.id, {
            id: `ai_${Date.now()}`,
            type: 'AI Assistant Analysis',
            parameter: aiResult.risky_parameters ? aiResult.risky_parameters.join(', ') : 'N/A',
            confidence: 'Medium',
            message: `Possible Vulns: ${aiResult.possible_vulnerabilities?.join(', ')}. Reasoning: ${aiResult.reasoning}`
         });
         
         if (aiResult.payload_suggestions && aiResult.payload_suggestions.length > 0) {
            insightEngine.addRequestInsight(ctx.id, {
               id: `ai_payloads_${Date.now()}`,
               type: 'AI Payload Suggestions',
               parameter: 'Payloads',
               confidence: 'High',
               message: JSON.stringify(aiResult.payload_suggestions)
            });
         }
      }
    } catch (e) {
      console.error("[RequestAnalyzer] Error:", e.message);
    }
  });
  return null;
}

module.exports = { requestAnalyzer };
