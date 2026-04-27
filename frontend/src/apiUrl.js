/**
 * apiUrl.js — Dynamic API URL discovery.
 * 
 * The backend writes its actual port to ~/.miniburp/api.port.
 * Since we can't read the filesystem from the browser, we probe
 * a range of ports and use whichever responds to /api/status.
 */

const PORT_RANGE = [3000, 3001, 3002, 3003, 3004, 3005];
let resolvedBase = null;

async function probePort(port) {
  try {
    const res = await fetch(`http://localhost:${port}/api/status`, {
      signal: AbortSignal.timeout(1500),
    });
    if (res.ok) {
      const data = await res.json();
      if (data.ok) return `http://localhost:${port}`;
    }
  } catch (_) {}
  return null;
}

export async function getApiBase() {
  if (resolvedBase) return resolvedBase;

  for (const port of PORT_RANGE) {
    const base = await probePort(port);
    if (base) {
      resolvedBase = base;
      console.log(`[API] Discovered backend at ${base}`);
      return base;
    }
  }

  // Fallback to default
  console.warn('[API] Could not discover backend port, using :3000');
  resolvedBase = 'http://localhost:3000';
  return resolvedBase;
}

export function getSocketUrl() {
  // Same base URL for Socket.IO
  return resolvedBase || 'http://localhost:3000';
}
