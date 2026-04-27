'use strict';

/**
 * CA Manager — generates a Root CA and signs per-domain certificates dynamically.
 * Uses node-forge for all crypto operations.
 */

const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CA_DIR = path.join(os.homedir(), '.miniburp');
const CA_CERT_PATH = path.join(CA_DIR, 'ca.crt');
const CA_KEY_PATH = path.join(CA_DIR, 'ca.key');

// In-memory certificate cache: hostname → {cert, key} PEM strings
const certCache = new Map();

let rootCA = null; // { cert: forge.pki.Certificate, key: forge.pki.PrivateKey, certPem, keyPem }

/**
 * Initialize the Root CA — generate if missing, load from disk otherwise.
 */
async function initCA() {
  if (rootCA) return rootCA;

  // Ensure directory exists
  if (!fs.existsSync(CA_DIR)) {
    fs.mkdirSync(CA_DIR, { recursive: true });
  }

  if (fs.existsSync(CA_CERT_PATH) && fs.existsSync(CA_KEY_PATH)) {
    // Load existing CA
    const certPem = fs.readFileSync(CA_CERT_PATH, 'utf8');
    const keyPem = fs.readFileSync(CA_KEY_PATH, 'utf8');
    rootCA = {
      cert: forge.pki.certificateFromPem(certPem),
      key: forge.pki.privateKeyFromPem(keyPem),
      certPem,
      keyPem,
    };
    console.log('[CA] Loaded existing Root CA from', CA_DIR);
  } else {
    // Generate new CA
    console.log('[CA] Generating new Root CA...');
    rootCA = generateRootCA();
    fs.writeFileSync(CA_CERT_PATH, rootCA.certPem);
    fs.writeFileSync(CA_KEY_PATH, rootCA.keyPem);
    console.log('[CA] Root CA saved to', CA_DIR);
  }

  return rootCA;
}

/**
 * Generate a self-signed Root CA certificate.
 */
function generateRootCA() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName', value: 'MiniBurp Root CA' },
    { name: 'organizationName', value: 'MiniBurp Security' },
    { name: 'countryName', value: 'US' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
      critical: true,
    },
    {
      name: 'subjectKeyIdentifier',
    },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    cert,
    key: keys.privateKey,
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

/**
 * Generate a certificate for a given hostname, signed by our Root CA.
 * Results are cached in memory.
 */
async function getCertForHost(hostname) {
  // Strip port if present
  const host = hostname.split(':')[0];

  if (certCache.has(host)) {
    return certCache.get(host);
  }

  const ca = await initCA();

  // 1024-bit: fast generation (~30ms vs ~300ms for 2048-bit)
  // Sufficient for interception proxy — certs are ephemeral, not long-lived
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date();
  cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 2);

  const attrs = [
    { name: 'commonName', value: host },
    { name: 'organizationName', value: 'MiniBurp Intercepted' },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(ca.cert.subject.attributes);

  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: host },
        { type: 2, value: '*.' + host },
      ],
    },
    {
      name: 'subjectKeyIdentifier'
    },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier: ca.cert.generateSubjectKeyIdentifier().getBytes()
    }
  ]);

  cert.sign(ca.key, forge.md.sha256.create());

  const result = {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };

  certCache.set(host, result);
  return result;
}


/**
 * Get the root CA PEM (for export/installation).
 */
async function getRootCACert() {
  const ca = await initCA();
  return ca.certPem;
}

module.exports = { initCA, getCertForHost, getRootCACert, CA_CERT_PATH };
