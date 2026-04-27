'use strict';

/**
 * proxyAssistant.js
 * Proxy-intercept AI analysis — delegates to ollamaClient.
 */

const { analyzeProxyRequest } = require('./ollamaClient');

module.exports = { analyzeProxyRequest };
