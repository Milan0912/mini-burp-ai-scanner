import { useState, useEffect, useRef } from 'react';

export default function IntruderTab({ socket, apiBase }) {
  const [raw, setRaw]           = useState('');
  const [host, setHost]         = useState('');
  const [port, setPort]         = useState('80');
  const [useSSL, setUseSSL]     = useState(false);
  const [payloadText, setPayloadText] = useState('admin\nguest\ntest\npassword\n123456');
  const [attackType, setAttackType]   = useState('sniper');
  const [grepRegex, setGrepRegex]     = useState('');
  const [running, setRunning]         = useState(false);
  const [results, setResults]         = useState([]);
  const [stats, setStats]             = useState(null);
  const [selectedResult, setSelectedResult] = useState(null);
  const resultsEndRef = useRef(null);

  // Listen for "Send to Intruder" from other tabs
  useEffect(() => {
    const handler = (e) => {
      const { raw: r, host: h, port: p, useSSL: ssl } = e.detail;
      if (r) setRaw(r);
      if (h) setHost(h);
      if (p) setPort(String(p));
      if (ssl !== undefined) { setUseSSL(ssl); setPort(ssl ? '443' : '80'); }
    };
    window.addEventListener('send-to-intruder', handler);
    return () => window.removeEventListener('send-to-intruder', handler);
  }, []);

  // Socket.IO listeners for real-time attack results
  useEffect(() => {
    if (!socket) return;
    const onStarted = (d) => { setStats({ total: d.total, done: 0 }); setResults([]); };
    const onResult  = (r) => { 
       setResults((prev) => [...prev, r]);
       setStats((prev) => prev ? { ...prev, done: (prev.done || 0) + 1 } : prev); 
    };
    const onFinished = ({ total }) => { setRunning(false); setStats(p => ({ ...p, done: total, finished: true })); };

    socket.on('intruder:started', onStarted);
    socket.on('intruder:result',  onResult);
    socket.on('intruder:finished', onFinished);
    return () => {
      socket.off('intruder:started', onStarted);
      socket.off('intruder:result',  onResult);
      socket.off('intruder:finished', onFinished);
    };
  }, [socket]);

  useEffect(() => { resultsEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [results]);

  const generatePayloads = (type) => {
    let list = [];
    if (type === 'numbers') for (let i = 1; i <= 20; i++) list.push(i.toString());
    else if (type === 'sqli') list = ["' OR 1=1--", "'\"--", "') OR ('1'='1", "admin'--", "1' ORDER BY 1--"];
    else if (type === 'xss') list = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "\"><script>alert(1)</script>"];
    setPayloadText(list.join('\n'));
  };

  const startAttack = async () => {
    if (!raw || !host) return;
    const payloads = payloadText.split('\n').map((p) => p.trim()).filter(Boolean);
    if (payloads.length === 0) return;

    setRunning(true);
    setResults([]);
    setStats(null);

    try {
      await fetch(`${apiBase}/api/intruder/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawRequest: raw, host, port: parseInt(port), useSSL, payloads, attackType, grepRegex }),
      });
    } catch (e) {
      console.error('[Intruder] start error:', e);
      setRunning(false);
    }
  };

  const stopAttack = async () => {
    try {
      await fetch(`${apiBase}/api/intruder/stop`, { method: 'POST' });
    } catch (_) {}
    setRunning(false);
  };

  const insertMarkers = () => {
    // Wrap selected text in §§ markers
    const ta = document.getElementById('intruder-raw');
    if (!ta) return;
    const start = ta.selectionStart;
    const end   = ta.selectionEnd;
    const selected = raw.slice(start, end) || 'PAYLOAD';
    const newRaw = raw.slice(0, start) + `§${selected}§` + raw.slice(end);
    setRaw(newRaw);
  };

  function statusClass(s) {
    if (!s) return 's0';
    if (s >= 500) return 's5xx';
    if (s >= 400) return 's4xx';
    if (s >= 300) return 's3xx';
    return 's2xx';
  }

  const progress = stats ? Math.round(((stats.done || 0) / (stats.total || 1)) * 100) : 0;

  return (
    <div className="repeater-tab">
      {/* Target bar */}
      <div className="repeater-target-bar">
        <span className="target-label">Target:</span>
        <input className="target-input" value={host} onChange={(e) => setHost(e.target.value)} placeholder="hostname" style={{ width: 140 }} />
        <span className="target-label">:</span>
        <input className="target-input" value={port} onChange={(e) => setPort(e.target.value)} style={{ width: 45 }} />
        <label className="ssl-toggle">
          <input type="checkbox" checked={useSSL} onChange={(e) => { setUseSSL(e.target.checked); setPort(e.target.checked ? '443' : '80'); }} />
          HTTPS
        </label>

        <div className="divider" style={{ margin: '0 6px' }} />

        <select className="target-input" value={attackType} onChange={(e) => setAttackType(e.target.value)} style={{ width: 110 }}>
          <option value="sniper">Sniper</option>
          <option value="battering_ram">Battering Ram</option>
          <option value="pitchfork">Pitchfork</option>
        </select>

        <div className="divider" style={{ margin: '0 6px' }} />
        <input className="target-input" style={{ width: 130 }} placeholder="Grep Regex (Extract)" value={grepRegex} onChange={(e) => setGrepRegex(e.target.value)} />

        <div style={{ flex: 1 }} />

        <button className="btn btn-ghost" onClick={insertMarkers} disabled={running} title="Wrap selection in §...§">
          § Mark §
        </button>

        {!running ? (
          <button className="btn btn-danger" onClick={startAttack} disabled={!raw || !host}>
            ▶ Start Attack
          </button>
        ) : (
          <button className="btn btn-ghost" onClick={stopAttack}>
            ■ Stop
          </button>
        )}
      </div>

      {/* Progress bar */}
      {stats && (
        <div style={{ height: 3, background: 'var(--border)' }}>
          <div style={{
            height: '100%',
            width: `${progress}%`,
            background: stats.finished ? 'var(--green)' : 'var(--accent)',
            transition: 'width 0.3s ease',
          }} />
        </div>
      )}

      {/* Main split: request editor | payloads | results */}
      <div className="split-h" style={{ flex: 1, overflow: 'hidden' }}>
        {/* Request template */}
        <div className="pane" style={{ flex: 1, borderRight: '1px solid var(--border)' }}>
          <div className="section-header">
            Request Template
            <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 6 }}>
              — wrap payload positions with §value§
            </span>
          </div>
          <textarea
            id="intruder-raw"
            className="raw-editor"
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
            style={{ flex: 1, borderRadius: 0, border: 'none' }}
            placeholder="Paste a raw HTTP request here. Select text and click § Mark § to add payload positions."
          />
        </div>

        {/* Payloads */}
        <div className="pane" style={{ width: 220, borderRight: '1px solid var(--border)' }}>
          <div className="section-header">Payloads</div>
          <div style={{ display: 'flex', gap: 4, padding: 4, background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)', flexWrap: 'wrap' }}>
            <button className="btn btn-ghost" style={{ fontSize: 9, padding: '2px 6px' }} onClick={() => generatePayloads('numbers')}>1-20</button>
            <button className="btn btn-ghost" style={{ fontSize: 9, padding: '2px 6px' }} onClick={() => generatePayloads('sqli')}>SQLi</button>
            <button className="btn btn-ghost" style={{ fontSize: 9, padding: '2px 6px' }} onClick={() => generatePayloads('xss')}>XSS</button>
          </div>
          <textarea
            className="raw-editor"
            value={payloadText}
            onChange={(e) => setPayloadText(e.target.value)}
            spellCheck={false}
            style={{ flex: 1, borderRadius: 0, border: 'none', fontSize: 11 }}
            placeholder="One payload per line"
          />
          <div style={{ padding: '6px 8px', fontSize: 10, color: 'var(--text-muted)', borderTop: '1px solid var(--border)' }}>
            {payloadText.split('\n').filter((p) => p.trim()).length} payloads
          </div>
        </div>

        {/* Results */}
        <div className="pane" style={{ flex: 1 }}>
          <div className="panel-toolbar">
            <span className="panel-title">
              Results {stats ? `(${stats.done || 0}/${stats.total || 0})` : ''}
            </span>
          </div>
          <div className="history-table-wrap">
            {results.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-icon">⚔️</div>
                <span>{running ? 'Attack in progress...' : 'Start an attack to see results'}</span>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 30 }}>#</th>
                    <th>Payload</th>
                    <th style={{ width: 60 }}>Status</th>
                    <th style={{ width: 70 }}>Length</th>
                    <th style={{ width: 60 }}>Time</th>
                    <th>Grep Match</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={i} className={selectedResult === i ? 'selected' : ''} onClick={() => setSelectedResult(i)}>
                      <td style={{ color: 'var(--text-muted)' }}>{r.index + 1}</td>
                      <td style={{ color: 'var(--text-primary)', maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {r.error ? <span style={{ color: 'var(--red)' }}>ERR: {r.error}</span> : r.payload}
                      </td>
                      <td><span className={`status-badge-cell ${statusClass(r.status)}`}>{r.status || '-'}</span></td>
                      <td style={{ color: 'var(--text-muted)' }}>{r.length ? `${r.length}B` : '-'}</td>
                      <td style={{ color: 'var(--text-muted)' }}>{r.elapsed}ms</td>
                      <td style={{ color: 'var(--accent)', fontSize: 10 }}>{r.grepMatch || ''}</td>
                    </tr>
                  ))}
                  <tr ref={resultsEndRef} />
                </tbody>
              </table>
            )}
          </div>
          {/* Response preview for selected result */}
          {selectedResult !== null && results[selectedResult] && (
            <div style={{ height: 150, borderTop: '1px solid var(--border)', overflow: 'auto', padding: '8px 12px' }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>RESPONSE PREVIEW</div>
              <pre style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                {results[selectedResult].responsePreview || '(no preview)'}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
