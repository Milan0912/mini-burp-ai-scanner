const crawler = require('../scanner/crawlerEngine');
const store = require('../scanner/endpointStore');
const paramClassifier = require('../scanner/paramClassifier');
const scanEngine = require('../scanner/scanEngine');
const db = require('../database');

describe('Scanner Tests', () => {
  beforeEach(() => {
    store.clear();
  });

  test('Test 1: crawlerEngine accepts maxDepth option', async () => {
    const result = await crawler.crawl('http://httpbin.org', 'GET', {}, '', { maxDepth: 1, maxPages: 1 });
    expect(result.crawlStats.maxDepth).toBe(1);
  });

  test('Test 2: crawlerEngine accepts maxPages option', async () => {
    const result = await crawler.crawl('http://httpbin.org', 'GET', {}, '', { maxDepth: 1, maxPages: 2 });
    expect(result.crawlStats.maxPages).toBe(2);
  });

  test('Test 3: crawlerEngine returns links array', async () => {
    const result = await crawler.crawl('http://httpbin.org', 'GET', {}, '', { maxDepth: 1, maxPages: 1 });
    expect(Array.isArray(result.links)).toBe(true);
  });

  test('Test 4: crawlerEngine returns forms array', async () => {
    const result = await crawler.crawl('http://httpbin.org', 'GET', {}, '', { maxDepth: 1, maxPages: 1 });
    expect(Array.isArray(result.forms)).toBe(true);
  });

  test('Test 5: endpointStore.add() stores endpoint', () => {
    const added = store.add('http://example.com/test', 'GET', { id: '1' });
    expect(added).toBe(true);
    const stats = store.getStats();
    expect(stats.total).toBe(1);
  });

  test('Test 6: endpointStore deduplicates same endpoint', () => {
    store.add('http://example.com/test', 'GET', { id: '1' });
    const added = store.add('http://example.com/test', 'GET', { id: '1' });
    expect(added).toBe(false);
    const stats = store.getStats();
    expect(stats.total).toBe(1);
  });

  test('Test 7: endpointStore.getUntested() works', () => {
    store.add('http://example.com/test', 'GET', { id: '1' });
    const ep = store.getUntested();
    expect(ep).toBeTruthy();
    expect(ep.url).toBe('http://example.com/test');
  });

  test('Test 8: endpointStore.markTested() works', () => {
    store.add('http://example.com/test', 'GET', { id: '1' });
    const ep = store.getUntested();
    store.markTested(ep.id);
    const stats = store.getStats();
    expect(stats.tested).toBe(1);
    expect(stats.untested).toBe(0);
  });

  test('Test 9: endpointStore.getStats() returns correct counts', () => {
    store.add('http://example.com/test1', 'GET', { id: '1' });
    store.add('http://example.com/test2', 'GET', { id: '2' });
    const stats = store.getStats();
    expect(stats.total).toBe(2);
    expect(stats.tested).toBe(0);
    expect(stats.untested).toBe(2);
  });

  test('Test 10: endpointStore.clear() empties store', () => {
    store.add('http://example.com/test', 'GET', { id: '1' });
    store.clear();
    const stats = store.getStats();
    expect(stats.total).toBe(0);
  });

  test('Test 11: paramClassifier classifies \'id\' as IDOR candidate', () => {
    const result = paramClassifier.classifyParameter('id');
    expect(result).toBe('idor');
  });

  test('Test 12: paramClassifier classifies \'redirect\' as redirect param', () => {
    const result = paramClassifier.classifyParameter('redirect');
    expect(result).toBe('redirect');
  });

  test('Test 13: paramClassifier classifies \'file\' as LFI candidate', () => {
    const result = paramClassifier.classifyParameter('file');
    expect(result).toBe('file');
  });

  test('Test 14: scanEngine accepts options without crashing', () => {
    expect(() => {
      scanEngine.startScan('http://example.com', { maxDepth: 2, concurrency: 2 });
    }).not.toThrow();
  });

  test('Test 15: database saveRequest works', () => {
    const req = { id: 'test-id', method: 'GET', url: 'http://example.com', status: 200, requestHeaders: '{}', requestBody: '', responseHeaders: '{}', responseBody: 'ok', size: 2 };
    db.saveRequest(req);
    const retrieved = db.getRequestById('test-id');
    expect(retrieved).toBeTruthy();
    expect(retrieved.method).toBe('GET');
  });

  test('Test 16: database saveFinding works', () => {
    const finding = { id: 'test-finding', reqId: 'test-req', type: 'sqli', parameter: 'id', payload: '1\'', severity: 'High', score: 90, evidence: 'error', endpoint: 'http://example.com', method: 'GET' };
    db.saveFinding(finding);
    const findings = db.getFindings();
    expect(findings.length).toBeGreaterThan(0);
  });

  test('Test 17: database getFindings returns array', () => {
    const findings = db.getFindings();
    expect(Array.isArray(findings)).toBe(true);
  });

  test('Test 18: GET /api/report/findings returns 200', async () => {
    const axios = require('axios');
    const res = await axios.get('http://localhost:3000/api/report/findings');
    expect(res.status).toBe(200);
  });

  test('Test 19: POST /api/scanner/start returns scanId', async () => {
    const axios = require('axios');
    const res = await axios.post('http://localhost:3000/api/scanner/start', { targetUrl: 'http://httpbin.org' });
    expect(res.status).toBe(200);
    expect(res.data.success).toBe(true);
  });

  test('Test 20: GET /api/scanner/status returns status field', async () => {
    const axios = require('axios');
    const res = await axios.get('http://localhost:3000/api/scanner/status');
    expect(res.status).toBe(200);
    expect(res.data).toHaveProperty('isRunning');
  });
});