'use strict';

/**
 * SiteMap Engine
 * Tracks all discovered endpoints and prevents infinite crawling loops.
 */

// Track unique nodes: METHOD:PATH:PARAMS (e.g. GET:http://example.com/api:id,name)
const visitedNodes = new Set();
const discoveryTree = new Map(); // Domain -> Array of Endpoints

function _buildNodeKey(method, url, queryParams) {
  if (!url) return `${method.toUpperCase()}:INVALID_URL:${Date.now()}`;
  try {
    const urlObj = new URL(url);
    const baseURL = `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`;
    const paramKeys = Object.keys(queryParams || {}).sort().join(',');
    return `${method.toUpperCase()}:${baseURL}:${paramKeys}`;
  } catch (e) {
    return `${method.toUpperCase()}:INVALID_URL:${url}:${Date.now()}`;
  }
}

function hasVisited(method, url, queryParams) {
  return visitedNodes.has(_buildNodeKey(method, url, queryParams));
}

function markVisited(method, url, queryParams) {
  const key = _buildNodeKey(method, url, queryParams);
  visitedNodes.add(key);

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    if (!discoveryTree.has(domain)) {
       discoveryTree.set(domain, []);
    }
    discoveryTree.get(domain).push({
       method: method.toUpperCase(),
       url: url,
       path: urlObj.pathname,
       params: Object.keys(queryParams || {}),
       timestamp: Date.now()
    });
  } catch (e) {
    // skip tree node for invalid URL, already added to visited via buildNodeKey fallback
  }
}

function getTree() {
  const result = {};
  for (const [domain, endpoints] of discoveryTree.entries()) {
     result[domain] = endpoints;
  }
  return result;
}

function resetSiteMap() {
  visitedNodes.clear();
  discoveryTree.clear();
}

module.exports = {
  hasVisited,
  markVisited,
  getTree,
  resetSiteMap
};
