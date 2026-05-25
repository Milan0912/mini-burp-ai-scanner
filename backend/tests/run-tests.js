const fs = require('fs');
const path = require('path');
const endpointStore = require('../scanner/endpointStore');
const paramClassifier = require('../scanner/paramClassifier');
const autoAI = require('../ai/autoAI');
const http = require('http');
const os = require('os');

// Start Express server for API tests
let server;
async function startServer() {
  const serverModule = require('../server');
  return new Promise((resolve) => {
    server = serverModule.listen ? serverModule : require('http').createServer();
    // Give server 1 second to fully initialize
    setTimeout(resolve, 1000);
  });
}

// Kill server after all tests
async function stopServer() {
  if (server && server.close) {
    return new Promise((resolve) => {
      server.close(resolve);
    });
  }
}

let passed = 0;
const total = 20;
const results = [];

function assert(condition, message) {
  if (condition) {
    console.log(`✅ ${message}`);
    passed++;
    results.push({ test: message, status: 'pass' });
  } else {
    console.log(`❌ ${message}`);
    results.push({ test: message, status: 'fail' });
  }
}

async function runTests() {
  await startServer();
  console.log('Running Tests...\n');

  // GROUP 1 - EndpointStore
  endpointStore.clear();
  endpointStore.add('http://test.com/api', 'GET', { a: 1 });
  assert(endpointStore.endpoints.size === 1, "add() stores a new endpoint");

  endpointStore.add('http://test.com/api', 'GET', { a: 1 });
  assert(endpointStore.endpoints.size === 1, "deduplicates exact same endpoint");

  const stats = endpointStore.getStats();
  assert(stats.total === 1 && stats.tested === 0 && stats.untested === 1, "getStats() returns total/tested/untested");

  const untested = endpointStore.getUntested();
  assert(untested && untested.url === 'http://test.com/api', "getUntested() returns untested endpoint");

  endpointStore.markTested(untested.id);
  const statsAfter = endpointStore.getStats();
  assert(statsAfter.tested === 1, "markTested() marks endpoint as tested");

  endpointStore.clear();
  assert(endpointStore.endpoints.size === 0, "clear() empties the store");

  endpointStore.add('http://test.com/api', 'POST', {});
  assert(endpointStore.endpoints.size === 1, "handles endpoint with no params");

  endpointStore.add('http://test.com/api2', 'GET', { b: 2 });
  assert(endpointStore.endpoints.size === 2, "handles multiple different endpoints");

  // GROUP 2 - ParamClassifier
  assert(paramClassifier.classifyParameter('id') === 'id', "classifies 'id' correctly");
  assert(paramClassifier.classifyParameter('redirect') === 'redirect', "classifies 'redirect' correctly");
  assert(paramClassifier.classifyParameter('file') === 'file', "classifies 'file' correctly");
  
  let unknownClass;
  try {
    unknownClass = paramClassifier.classifyParameter('xyz123');
  } catch (e) {}
  assert(unknownClass === 'misc', "classifies unknown param without crashing");

  // GROUP 3 - AutoAI
  await autoAI.init();
  assert(autoAI.getMode() === 'ollama' || autoAI.getMode() === 'rule-based', "init() returns 'ollama' or 'rule-based'");

  const sqliAnalysis = autoAI.ruleBasedAnalysis({ type: 'sqli' });
  assert(sqliAnalysis.exploitability === 'High' && sqliAnalysis.cvss === 8.8, "ruleBasedAnalysis() returns sqli analysis");

  const xssAnalysis = autoAI.ruleBasedAnalysis({ type: 'xss' });
  assert(xssAnalysis.exploitability === 'Medium' && xssAnalysis.cvss === 6.1, "ruleBasedAnalysis() returns xss analysis");

  const fpCheck = await autoAI.checkFalsePositive({ type: 'sqli' }, 'error syntax');
  assert(typeof fpCheck.is_false_positive === 'boolean', "checkFalsePositive() returns boolean result");

  const summaryLow = await autoAI.generateScanSummary([]);
  assert(summaryLow.overallRisk === 'Low', "generateScanSummary([]) returns Low risk");

  const summaryCritical = await autoAI.generateScanSummary([{ severity: 'Critical' }]);
  assert(summaryCritical.overallRisk === 'Critical', "generateScanSummary([CRITICAL]) returns Critical risk");

  // GROUP 4 - API
  let port = 3000;
  try {
    const portFile = path.join(os.homedir(), '.miniburp', 'api.port');
    if (fs.existsSync(portFile)) port = parseInt(fs.readFileSync(portFile, 'utf8'), 10);
  } catch (e) {}

  const apiTest1 = await new Promise((resolve) => {
    http.get(`http://localhost:${port}/api/scanner/status`, (res) => {
      resolve(res.statusCode === 200);
    }).on('error', () => resolve(false));
  });
  assert(apiTest1, "GET /api/scanner/status returns 200");

  const apiTest2 = await new Promise((resolve) => {
    http.get(`http://localhost:${port}/api/report/findings`, (res) => {
      resolve(res.statusCode === 200);
    }).on('error', () => resolve(false));
  });
  assert(apiTest2, "GET /api/report/findings returns 200");

  console.log(`\n${passed}/${total} passed`);

  const resultsDir = path.join(__dirname, '../test-results');
  if (!fs.existsSync(resultsDir)) {
    fs.mkdirSync(resultsDir, { recursive: true });
  }
  const timestamp = Date.now();
  fs.writeFileSync(path.join(resultsDir, `report-${timestamp}.json`), JSON.stringify({ passed, total, results }, null, 2));

  await stopServer();
  process.exit(0);
}

runTests();
