import { useState, useEffect, useCallback, useRef } from 'react';

const PAGE_SIZE = 100;

export default function HistoryTab({ socket, apiBase }) {
  const [rows, setRows]           = useState([]);
  const [search, setSearch]       = useState('');
  const [selected, setSelected]   = useState(null);
  const [detail, setDetail]       = useState(null);
  const [total, setTotal]         = useState(0);
  const [loading, setLoading]     = useState(false);
  // Viewer tabs
  const [viewerPane, setViewerPane] = useState('request');   // 'request' | 'response'
  const [reqTab, setReqTab]         = useState('raw');        // 'raw' | 'headers' | 'pretty'
  const [resTab, setResTab]         = useState('raw');
  const [aiData, setAiData]         = useState({ findings: [], attackResults: [] });
  const [agentMode, setAgentMode]   = useState('Suggest');
  const [agentPending, setAgentPending] = useState(0);
  const searchRef = useRef(null);

  // ── Load/search ─────────────────────────────────────────────
  const loadHistory = useCallback(async (q = '') => {
    setLoading(true);
    try {
      let url;
      if (q) {
        // Full-text search across all fields using the new backend capability
        url = `${apiBase}/api/history?limit=${PAGE_SIZE}&offset=0&search=${encodeURIComponent(q)}`;
      } else {
        url = `${apiBase}/api/history?limit=${PAGE_SIZE}&offset=0`;
      }
      const r = await fetch(url);
      const data = await r.json();
      setRows(data.rows || []);
      setTotal(data.total || data.rows?.length || 0);
    } catch (e) { console.error('[History]', e); }
    finally { setLoading(false); }
  }, [apiBase]);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  // Real-time update on new requests
  useEffect(() => {
    if (!socket) return;
    const onUpdate = () => { if (!search) loadHistory(); };
    socket.on('request:resolved', onUpdate);
    return () => socket.off('request:resolved', onUpdate);
  }, [socket, search, loadHistory]);

  useEffect(() => {
    if (!socket) return;
    fetch(`${apiBase}/api/agent/state`).then(r => r.json()).then(d => setAgentMode(d.mode)).catch(()=>{});

    const onAiUpdate = (data) => {
      if (data.id === selected) setAiData(data);
    };
    const onAgentConfirm = (data) => {
      if (data.reqId === selected) setAgentPending(data.taskCount);
    };

    socket.on('ai:insights:update', onAiUpdate);
    socket.on('agent:require_confirm', onAgentConfirm);

    return () => {
      socket.off('ai:insights:update', onAiUpdate);
      socket.off('agent:require_confirm', onAgentConfirm);
    };
  }, [socket, selected, apiBase]);

  // Debounced search
  useEffect(() => {
    const t = setTimeout(() => loadHistory(search), 300);
    return () => clearTimeout(t);
  }, [search, loadHistory]);

  const selectRow = async (row) => {
    setSelected(row.id);
    setDetail(null);
    setViewerPane('request');
    setReqTab('raw');
    setResTab('raw');
    setAiData({ findings: [], attackResults: [] });
    try {
      const r = await fetch(`${apiBase}/api/request/${row.id}`);
      const d = await r.json();
      setDetail(d);
      
      const aiR = await fetch(`${apiBase}/api/ai/insights/${row.id}`);
      if (aiR.ok) {
        const data = await aiR.json();
        if (!data) return;
        if (!data.findings) data.findings = [];
        setAiData(data);
      }
    } catch (e) { console.error('[History] detail error:', e); }
  };

  const clearHistory = async () => {
    if (!confirm('Clear all history?')) return;
    await fetch(`${apiBase}/api/history`, { method: 'DELETE' });
    setRows([]); setDetail(null); setSelected(null); setTotal(0);
  };

  const [compareId, setCompareId] = useState(null);

  const formatRawForTool = (det) => {
    const h = typeof det.request_headers === 'object' ? det.request_headers : {};
    let u;
    try { u = new URL(det.url); } catch { u = { pathname: det.url, hostname: 'localhost' }; }
    
    let raw = `${det.method} ${u.pathname || '/'} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(h)) {
      if (k.toLowerCase() === 'host' && !v) continue;
      raw += `${k}: ${v}\r\n`;
    }
    if (!h.host && !h.Host) raw += `Host: ${u.hostname || 'localhost'}\r\n`;
    raw += '\r\n';
    if (det.request_body) raw += det.request_body;
    return { raw, host: u.hostname || 'localhost', port: det.url.startsWith('https') ? 443 : 80, useSSL: det.url.startsWith('https') };
  };

  const sendToRepeater = () => {
    if (!detail) return;
    const info = formatRawForTool(detail);
    window.dispatchEvent(new CustomEvent('send-to-repeater', { detail: info }));
    window.dispatchEvent(new CustomEvent('switch-tab', { detail: { tab: 'repeater' } }));
  };

  const startDiff = () => {
    if (!compareId) {
      setCompareId(selected);
    } else {
      window.dispatchEvent(new CustomEvent('open-diff', { detail: { id1: compareId, id2: selected } }));
      window.dispatchEvent(new CustomEvent('switch-tab', { detail: { tab: 'diff' } }));
      setCompareId(null);
    }
  };

  const sendToScanner = async () => {
    if (!selected) return;
    if (!confirm('Run full active scan (SQLi, XSS, etc) on this request?')) return;
    try {
      await fetch(`${apiBase}/api/scanner/run-test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reqId: selected })
      });
      alert('Active Scan Queued!');
    } catch(e) { console.error('Scan failed', e); }
  };

  const sendToIntruder = () => {
    if (!detail) return;
    const info = formatRawForTool(detail);
    window.dispatchEvent(new CustomEvent('send-to-intruder', { detail: info }));
    window.dispatchEvent(new CustomEvent('switch-tab', { detail: { tab: 'intruder' } }));
  };

  const toggleAgentMode = async () => {
    const newMode = agentMode === 'Suggest' ? 'Auto' : 'Suggest';
    setAgentMode(newMode);
    await fetch(`${apiBase}/api/agent/config`, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ mode: newMode }) });
  };

  const approveAgentRun = async () => {
    if (!selected) return;
    setAgentPending(0);
    await fetch(`${apiBase}/api/agent/confirm`, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ reqId: selected }) });
  };

  const runAttack = async (type, parameter) => {
    if (!selected) return;
    if (!confirm(`This will send multiple test requests to check for ${type}.\n\nDo you want to proceed?`)) return;
    try {
      await fetch(`${apiBase}/api/ai/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reqId: selected, type, parameter })
      });
    } catch(e) { console.error('Attack failed to start', e); }
  };

  // ── Render detail panel ──────────────────────────────────────
  const renderRequestPane = () => {
    if (!detail) return null;
    const headers = typeof detail.request_headers === 'object' ? detail.request_headers : {};
    if (reqTab === 'headers') {
      const u = (() => { try { return new URL(detail.url); } catch { return null; } })();
      return (
        <div className="detail-body">
          <div style={{ color: 'var(--accent)', fontWeight: 600, marginBottom: 6 }}>
            {detail.method} {u?.pathname || detail.url} HTTP/1.1
          </div>
          {Object.entries(headers).map(([k, v]) => (
            <div key={k}>
              <span style={{ color: 'var(--accent)' }}>{k}</span>
              <span style={{ color: 'var(--text-muted)' }}>: </span>
              <span>{String(v)}</span>
            </div>
          ))}
        </div>
      );
    }
    if (reqTab === 'pretty') {
      return <div className="detail-body"><PrettyView content={detail.request_body || ''} /></div>;
    }
    // Raw
    const u = (() => { try { return new URL(detail.url); } catch { return null; } })();
    let raw = `${detail.method} ${u?.pathname || '/'} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(headers)) raw += `${k}: ${v}\r\n`;
    raw += '\r\n';
    if (detail.request_body) raw += detail.request_body;
    return <div className="detail-body">{raw}</div>;
  };

  const renderResponsePane = () => {
    if (!detail) return null;
    const headers = typeof detail.response_headers === 'object' ? detail.response_headers : {};
    if (resTab === 'headers') {
      return (
        <div className="detail-body">
          <div style={{ color: 'var(--blue)', fontWeight: 600, marginBottom: 6 }}>
            HTTP/1.1 {detail.status}
          </div>
          {Object.entries(headers).map(([k, v]) => (
            <div key={k}>
              <span style={{ color: 'var(--blue)' }}>{k}</span>
              <span style={{ color: 'var(--text-muted)' }}>: </span>
              <span>{String(v)}</span>
            </div>
          ))}
        </div>
      );
    }
    if (resTab === 'pretty') {
      return <div className="detail-body"><PrettyView content={detail.response_body || ''} /></div>;
    }
    // Raw
    let raw = `HTTP/1.1 ${detail.status}\r\n`;
    for (const [k, v] of Object.entries(headers)) raw += `${k}: ${v}\r\n`;
    raw += '\r\n';
    if (detail.response_body) raw += detail.response_body;
    return <div className="detail-body">{raw}</div>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
      {/* ── Global Search Bar ─────────────────────────────────── */}
      <div className="global-search-bar">
        <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>🔍</span>
        <input
          ref={searchRef}
          className="search-input"
          style={{ flex: 1, fontSize: 13 }}
          placeholder="Search URL, headers, request body, response body…  (live filter)"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {search && (
          <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={() => setSearch('')}>✕ Clear</button>
        )}
        {loading && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Searching…</span>}
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{total} requests</span>
        <button className="btn btn-ghost" onClick={() => loadHistory(search)}>↻</button>
        <button className="btn btn-danger" onClick={clearHistory}>Clear All</button>
      </div>

      {/* ── Burp-style split: request list | viewer ─────────────── */}
      <div className="split-h" style={{ flex: 1, overflow: 'hidden' }}>
        {/* Left: History List */}
        <div className="pane" style={{ flex: 1, borderRight: '1px solid var(--border)' }}>
          <div className="history-table-wrap">
            {rows.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-icon">📋</div>
                <span>{search ? 'No results for "' + search + '"' : 'No requests captured yet'}</span>
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 60 }}>Method</th>
                    <th>URL</th>
                    <th style={{ width: 60 }}>Status</th>
                    <th style={{ width: 70 }}>Size</th>
                    <th style={{ width: 80 }}>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr key={row.id}
                      className={selected === row.id ? 'selected' : ''}
                      onClick={() => selectRow(row)}
                    >
                      <td>
                        <span className={`method-badge ${(row.method || '').toUpperCase()}`}>
                          {search ? highlight(row.method || '', search) : row.method}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-primary)', maxWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {search ? highlight(row.url || '', search) : (row.url || '')}
                      </td>
                      <td>
                        <span className={`status-badge-cell ${statusClass(row.status)}`}>
                          {search ? highlight(String(row.status || '-'), search) : (row.status || '-')}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>{formatSize(row.size)}</td>
                      <td style={{ color: 'var(--text-muted)' }}>{formatTime(row.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Right: Burp-style Request/Response Viewer */}
        <div className="pane" style={{ width: 520, flexShrink: 0, display: 'flex', flexDirection: 'column' }}>
          {detail ? (
            <>
              {/* Action bar */}
              <div className="panel-toolbar" style={{ padding: '5px 10px' }}>
                <button className="btn btn-blue" style={{ fontSize: 11 }} onClick={sendToRepeater}>↗ Repeater</button>
                <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={sendToIntruder}>⚔ Intruder</button>
                <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={sendToScanner}>🧪 Scan</button>
                <button className={`btn ${compareId ? 'btn-red' : 'btn-ghost'}`} style={{ fontSize: 11 }} onClick={startDiff}>
                  ⚖️ {compareId ? (compareId === selected ? 'Mark Second...' : 'Compare!') : 'Mark for Compare'}
                </button>
                <div style={{ flex: 1 }} />
                {/* Request / Response switcher */}
                <button className={`tab-btn ${viewerPane === 'request' ? 'active' : ''}`}
                  style={{ fontSize: 11 }} onClick={() => setViewerPane('request')}>Request</button>
                <button className={`tab-btn ${viewerPane === 'response' ? 'active' : ''}`}
                  style={{ fontSize: 11 }} onClick={() => setViewerPane('response')}>Response</button>
              </div>

              {/* Sub-tabs: Raw / Headers / Pretty */}
              <div className="panel-toolbar" style={{ padding: '3px 10px', borderTop: '1px solid var(--surface)' }}>
                {(viewerPane === 'request' ? ['raw','headers','pretty'] : ['raw','headers','pretty']).map((t) => (
                  <button
                    key={t}
                    className={`tab-btn ${(viewerPane === 'request' ? reqTab : resTab) === t ? 'active' : ''}`}
                    style={{ fontSize: 11, padding: '2px 8px' }}
                    onClick={() => viewerPane === 'request' ? setReqTab(t) : setResTab(t)}
                  >
                    {t.charAt(0).toUpperCase() + t.slice(1)}
                  </button>
                ))}
              </div>

              {/* Content */}
              <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                {viewerPane === 'request' ? renderRequestPane() : renderResponsePane()}
              </div>

              <div className="ai-panel" style={{ height: 320, borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', flexShrink: 0, background: 'var(--surface)' }}>
                <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 12px', background: 'var(--surface-light)', borderBottom: '1px solid var(--border)' }}>
                  <span style={{ fontWeight: 600 }}>💡 AI Insights & Agent</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ fontSize: 11, color: agentMode === 'Auto' ? 'var(--accent)' : 'var(--blue)', fontWeight: 600 }}>Mode: {agentMode}</span>
                    <button className="btn btn-ghost" style={{ fontSize: 10, padding: '2px 6px', border: '1px solid var(--border)' }} onClick={toggleAgentMode}>
                      Toggle Mode
                    </button>
                  </div>
                </div>
                
                {agentMode === 'Auto' && agentPending > 0 && (
                  <div style={{ padding: '8px 12px', background: 'rgba(245, 158, 11, 0.1)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>⚠️ Agent has {agentPending} task(s) queued. Waiting for approval.</span>
                    <button className="btn" style={{ fontSize: 11, padding: '3px 12px', background: 'var(--accent)', color: '#fff' }} onClick={approveAgentRun}>
                      Approve Run
                    </button>
                  </div>
                )}

                <div style={{ padding: '8px 12px', overflow: 'auto', flex: 1 }}>
                  {aiData.findings.length === 0 && <span style={{fontSize: 11, color:'var(--text-muted)'}}>(No vulnerabilities detected)</span>}
                  {aiData.findings.map((f, i) => {
                    const sevColors = { 'Critical': '#f43f5e', 'High': 'var(--red)', 'Medium': 'var(--accent)', 'Low': 'var(--blue)' };
                    const c = sevColors[f.severity || 'Low'];
                    return (
                    <div key={i} style={{ marginBottom: 12, padding: '10px 12px', background: 'var(--background)', borderLeft: `4px solid ${c}`, borderRadius: 4, boxShadow: '0 1px 3px rgba(0,0,0,0.2)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <strong>{f.severity === 'Critical' ? '☠️' : f.severity === 'High' ? '🔥' : f.severity === 'Medium' ? '⚠️' : 'ℹ️'} {f.type} <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 6 }}>({f.severity} Severity)</span></strong>
                        <button className="btn btn-ghost" style={{ fontSize: 11, padding: '3px 8px', border: '1px solid var(--border)' }} onClick={() => runAttack(f.type, f.parameter)}>
                          ▶ Run Test
                        </button>
                      </div>
                      <div style={{ fontSize: 12, marginTop: 6 }}>
                        <span style={{ color: 'var(--text-muted)' }}>Parameter:</span> <span style={{ color: 'var(--blue)', fontWeight: 600 }}>{f.parameter}</span>
                        <div style={{ color: 'var(--text-secondary)', marginTop: 4 }}>{f.message}</div>
                      </div>
                      {aiData.attackResults.filter(r => r.type === f.type && r.param === f.parameter).map((res, j) => {
                        const confirmed = res.result.includes('CONFIRMED');
                        const likely = res.result.includes('Likely');
                        return (
                          <div key={j} style={{ marginTop: 8, fontSize: 12, padding: '6px 8px', background: confirmed ? 'rgba(239, 68, 68, 0.1)' : likely ? 'rgba(245, 158, 11, 0.1)' : 'var(--surface)', borderLeft: `2px solid ${confirmed ? 'var(--red)' : likely ? 'var(--accent)' : 'var(--green)'}`, color: confirmed ? '#fca5a5' : likely ? '#fcd34d' : 'var(--text-primary)' }}>
                            {res.result}
                          </div>
                        );
                      })}
                    </div>
                    );
                  })}
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              <div className="empty-state-icon">👆</div>
              <span>Click a request to inspect</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Helpers ─────────────────────────────────────────────────────

function PrettyView({ content }) {
  try {
    return <pre style={{ color: 'var(--green)', fontSize: 11.5, overflow: 'auto' }}>{JSON.stringify(JSON.parse(content), null, 2)}</pre>;
  } catch {
    return <pre style={{ fontSize: 11.5, color: 'var(--text-secondary)', overflow: 'auto' }}>{content || '(no body)'}</pre>;
  }
}

function highlight(text, query) {
  if (!query) return text;
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const parts = String(text).split(new RegExp(`(${escaped})`, 'gi'));
  return (
    <span>
      {parts.map((part, i) =>
        part.toLowerCase() === query.toLowerCase() ? (
          <mark key={i} className="search-highlight">{part}</mark>
        ) : (
          part
        )
      )}
    </span>
  );
}

function statusClass(s) {
  if (!s) return 's0';
  if (s >= 500) return 's5xx';
  if (s >= 400) return 's4xx';
  if (s >= 300) return 's3xx';
  return 's2xx';
}

function formatSize(b) {
  if (!b) return '-';
  if (b < 1024) return `${b}B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)}KB`;
  return `${(b / 1048576).toFixed(1)}MB`;
}

function formatTime(ts) {
  if (!ts) return '-';
  try { return new Date(ts + 'Z').toLocaleTimeString(); } catch { return ts; }
}
