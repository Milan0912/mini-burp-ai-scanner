'use strict';

/**
 * Repeater — executes raw HTTP requests manually.
 * Supports both HTTP and HTTPS targets.
 */

const net = require('net');
const tls = require('tls');

/**
 * Send a raw HTTP request string to a target host/port.
 * Returns the full raw HTTP response as a string.
 */
function sendRawRequest({ rawRequest, host, port, useSSL, timeoutMs = 30000 }) {
  return new Promise((resolve, reject) => {
    let socket;
    const timeout = setTimeout(() => {
      if (socket) socket.destroy();
      reject(new Error('Repeater: connection timeout'));
    }, timeoutMs);

    const connectOptions = { host, port: port || (useSSL ? 443 : 80) };
    socket = useSSL
      ? tls.connect({ ...connectOptions, rejectUnauthorized: false, servername: host })
      : net.connect(connectOptions);

    const chunks = [];

    socket.on('connect', () => {
      // Ensure Connection: close for manual repeater probes to avoid hangs
      let finalReq = rawRequest;
      if (!rawRequest.toLowerCase().includes('connection:')) {
        finalReq = rawRequest.replace('\r\n\r\n', '\r\nConnection: close\r\n\r\n');
      }
      socket.write(finalReq);
    });

    socket.on('secureConnect', () => {
      let finalReq = rawRequest;
      if (!rawRequest.toLowerCase().includes('connection:')) {
        finalReq = rawRequest.replace('\r\n\r\n', '\r\nConnection: close\r\n\r\n');
      }
      socket.write(finalReq);
    });

    socket.on('data', (chunk) => {
      chunks.push(chunk);
    });

    socket.on('end', () => {
      clearTimeout(timeout);
      resolve(Buffer.concat(chunks));
    });

    socket.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    socket.on('close', () => {
      clearTimeout(timeout);
      if (chunks.length > 0) {
        resolve(Buffer.concat(chunks));
      }
    });

  });
}

module.exports = { sendRawRequest };
