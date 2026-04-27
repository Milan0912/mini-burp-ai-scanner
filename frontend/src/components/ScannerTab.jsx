import { useState, useEffect, useRef } from 'react';
import { useStore } from '../StoreContext';

const CVSS_COLOR = { Critical: '#f43f5e', High: '#ef4444', Medium: '#f97316', Low: '#eab308', Info: '#3b82f6' };
const PHASE_COLOR = {
  BASELINE: '#8b5cf6', TESTING: '#f97316', FINDING: '#ef4444', DONE: '#22c55e',
  ERROR: '#ef4444', CRAWLING: '#3b82f6', EXPLOIT: '#8b5cf6', VERIFIED: '#22c55e',
  STEALTH: '#64748b', PIVOT: '#f43f5e', CHAIN: '#ef4444'
};

export default function ScannerTab({ socket, apiBase }) {
  const { state, dispatch } = useStore();
  const [targetUrl, setTargetUrl] = useState('http://testphp.vulnweb.com');
  const [maxDepth, setMaxDepth] = useState(3);
  const [exploitUrl, setExploitUrl] = useState('');
  const [exploitRunning, setExploitRunning] = useState(false);
  const [exploitLog, setExploitLog] = useState([]);
  const [activeTab, setActiveTab] = useState('scanner');
  const [attackGraph, setAttackGraph] = useState({ nodes: [], edges: [] });
  const [validationResults, setValidationResults] = useState(null);

  const status = state?.scannerState || {};
  const vulnerabilities = state?.vulnerabilities || [];

  useEffect(() => {
    if (!socket) return;
    const onExploitProgress = (data) => {
      setExploitLog(prev => [{ text: `${data.phase}: ${data.message}`, color: PHASE_COLOR[data.phase] || '#64748b', ts: Date.now() }, ...prev]);
    };
    const onExploitComplete = (data) => {
      setExploitRunning(false);
      setExploitLog(prev => [{ text: `✅ Exploit Chain Complete. Findings: ${data.report?.findings.length}`, color: '#22c55e', ts: Date.now() }, ...prev]);
    };
    const onScanLog = (data) => {
      dispatch({ type: 'ADD_LOG', payload: { phase: data.state, message: data.message, timestamp: new Date().toISOString() } });
    };
    const onIntelLog = (data) => {
      dispatch({ type: 'ADD_LOG', payload: { ...data, timestamp: new Date().toISOString() } });
    };

    socket.on('exploit:progress', onExploitProgress);
    socket.on('exploit:complete', onExploitComplete);
    socket.on('graph:update', (data) => setAttackGraph(data));
    socket.on('validation:results', (data) => setValidationResults(data));
    socket.on('scan:log', onScanLog);
    socket.on('intel:log', onIntelLog);

    fetch(`${apiBase}/api/ai/graph`).then(r => r.json()).then(data => setAttackGraph(data)).catch(() => {});
    fetch(`${apiBase}/api/report/findings`)
      .then(r => r.json())
      .then(data => {
        if (data.rows) data.rows.forEach(f => dispatch({ type: 'ADD_VULNERABILITY', payload: f }));
      }).catch(console.error);

    return () => {
      socket.off('exploit:progress', onExploitProgress);
      socket.off('exploit:complete', onExploitComplete);
      socket.off('graph:update');
      socket.off('validation:results');
      socket.off('scan:log', onScanLog);
      socket.off('intel:log', onIntelLog);
    };
  }, [socket, apiBase]);

  const startScan = async () => {
    if (!targetUrl) return;
    await fetch(`${apiBase}/api/scanner/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl, maxDepth, stealth: state.scannerMode === 'ultimate' }),
    });
  };

  const stopScan = async () => {
    await fetch(`${apiBase}/api/scanner/stop`, { method: 'POST' });
  };

  return (
    <div className="tab-pane active" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* Progress Bar */}
      <div style={{ padding: '10px 16px', background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, fontWeight: 700, marginBottom: 5 }}>
          <span style={{ color: status.isRunning ? 'var(--accent)' : '#444' }}>
            {status.isRunning ? `🔍 SCANNING: ${status.currentUrl?.slice(0, 50)}...` : '⚪ SCANNER IDLE'}
          </span>
          <span style={{ color: 'var(--text-muted)' }}>
            Progress: {status.scanned || 0} / {status.discovered || 1} endpoints ({status.progress || 0}%)
          </span>
        </div>
        <div style={{ height: 3, background: '#111', borderRadius: 2 }}>
          <div style={{ height: '100%', width: `${status.progress || 0}%`, background: 'var(--accent)', transition: 'width 0.4s' }} />
        </div>
      </div>

      {/* Sub-tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)', flexShrink: 0 }}>
        {[['scanner', '🔍 Crawler'], ['findings', '🎯 Findings']].map(([id, label]) => (
          <button key={id} onClick={() => setActiveTab(id)} className={`tab-btn ${activeTab === id ? 'active' : ''}`} style={{ padding: '8px 20px', fontSize: 11 }}>
            {label} {id === 'findings' && vulnerabilities.length > 0 && <span style={{ marginLeft: 6, opacity: 0.7 }}>({vulnerabilities.length})</span>}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div style={{ flex: 1, minHeight: 0, overflow: 'hidden', display: 'flex' }}>

        {/* ── SCANNER TAB ── */}
        {activeTab === 'scanner' && (
          <div style={{ display: 'flex', flex: 1, padding: 15, gap: 15, overflow: 'hidden' }}>
            {/* Left config column */}
            <div style={{ width: 280, display: 'flex', flexDirection: 'column', gap: 15, flexShrink: 0 }}>
              <div className="panel">
                <h3 className="panel-title">Target Config</h3>
                <div style={{ marginBottom: 15 }}>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 5, fontWeight: 700 }}>EXPLOITATION MODE</div>
                  <div style={{ display: 'flex', background: '#0a0a0f', borderRadius: 4, padding: 2, border: '1px solid #222' }}>
                    {[['auto','AUTO','#238636'],['elite','ELITE','#8957e5'],['ultimate','STEALTH','#f43f5e']].map(([mode, label, activeColor]) => (
                      <button key={mode}
                        onClick={() => {
                          dispatch({ type: 'SET_SCANNER_MODE', payload: mode });
                          fetch(`${apiBase}/api/ai/mode`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ mode }) });
                        }}
                        style={{
                          flex: 1, padding: '6px 0', fontSize: 10, fontWeight: 700, border: 'none', cursor: 'pointer',
                          background: (state.scannerMode || 'auto') === mode ? activeColor : 'transparent',
                          color: (state.scannerMode || 'auto') === mode ? '#fff' : '#666'
                        }}>{label}</button>
                    ))}
                  </div>
                </div>
                <div className="config-grid">
                  <label>Base URL</label>
                  <input type="text" placeholder="http://example.com" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} />
                </div>
                <button className="btn btn-primary" style={{ width: '100%', marginTop: 10 }} onClick={status.isRunning ? stopScan : startScan}>
                  {status.isRunning ? '⏹ Stop Scan' : '🚀 Start Full Scan'}
                </button>
              </div>

              {status.isRunning && (
                <div className="panel" style={{ background: 'rgba(139,92,246,0.05)', border: '1px solid rgba(139,92,246,0.2)' }}>
                  <h3 className="panel-title" style={{ color: 'var(--accent)' }}>📊 Detailed Progress</h3>
                  <div style={{ fontSize: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <div>Parameters: <span style={{ color: '#fff' }}>{status.stats?.testedParams || 0}</span></div>
                    <div>Payloads: <span style={{ color: '#fff' }}>{status.stats?.testedPayloads || 0}</span></div>
                  </div>
                  <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: 9 }}>CURRENT TEST</div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--orange)' }}>{status.currentTest || 'Analyzing...'}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: 9, marginTop: 8 }}>PARAMETER</div>
                    <div style={{ fontSize: 10, color: 'var(--blue)' }}>{status.currentParam || '-'}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: 9, marginTop: 8 }}>PAYLOAD</div>
                    <div style={{ fontSize: 9, color: '#666', overflow: 'hidden', textOverflow: 'ellipsis' }}>{status.currentPayload || '-'}</div>
                  </div>
                </div>
              )}
            </div>

            {/* Right stats + live log */}
            <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', background: '#020205', minWidth: 400, minHeight: 0 }}>
              <h3 className="panel-title">📊 Scan Statistics</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 1, background: '#111', border: '1px solid #222', margin: '0 10px 10px' }}>
                {[['Discovered', status.discovered || 0, '#3b82f6'], ['Tested', status.scanned || 0, '#8b5cf6'], ['Findings', vulnerabilities.length, '#f43f5e']].map(([label, val, color]) => (
                  <div key={label} style={{ textAlign: 'center', padding: '12px 0', background: '#020205' }}>
                    <div style={{ fontSize: 24, fontWeight: 900, color, fontFamily: 'var(--font-mono)' }}>{val}</div>
                    <div style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: 1 }}>{label}</div>
                  </div>
                ))}
              </div>
              {status.currentUrl && (
                <div style={{ margin: '0 10px 10px', padding: '8px 10px', background: '#0a0a0f', border: '1px solid #1a1a2e', borderRadius: 4 }}>
                  <div style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>Currently Testing</div>
                  <div style={{ fontSize: 10, color: '#8b5cf6', fontFamily: 'monospace', wordBreak: 'break-all' }}>{status.currentUrl}</div>
                </div>
              )}
              <div style={{ flex: 1, minHeight: 0, padding: '0 10px 10px', display: 'flex', flexDirection: 'column' }}>
                <h3 className="panel-title" style={{ fontSize: 9, marginBottom: 6 }}>📡 Scanner Live Log</h3>
                <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, background: '#010108', padding: '8px', borderRadius: 4, border: '1px solid #111' }}>
                  {(state.logs || []).length === 0
                    ? <div style={{ color: '#333', fontStyle: 'italic', textAlign: 'center', marginTop: 20 }}>Start a scan to see live activity...</div>
                    : (state.logs || []).slice(0, 30).map((l, i) => (
                      <div key={i} style={{ marginBottom: 2, color: PHASE_COLOR[l.phase] || '#555' }}>
                        [{new Date(l.timestamp).toLocaleTimeString()}] {l.message}
                      </div>
                    ))
                  }
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── FINDINGS TAB ── */}
        {activeTab === 'findings' && (
          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

            {/* Button bar — fixed, does not scroll */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, padding: '10px 15px', flexShrink: 0, borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)' }}>
              <button onClick={async () => {
                if (!confirm('Clear all findings from database?')) return;
                await fetch(`${apiBase}/api/report/findings/clear`, { method: 'DELETE' });
                dispatch({ type: 'CLEAR_VULNERABILITIES' });
              }} className="btn" style={{ fontSize: 10, padding: '4px 10px', background: '#1c1c1c', border: '1px solid #444', color: '#888' }}>
                🗑 Clear
              </button>
              <button onClick={() => window.open(`${apiBase}/api/report/download?type=json`)} className="btn" style={{ fontSize: 10, padding: '4px 10px', background: '#1c1c1c', border: '1px solid #444', color: '#ccc' }}>
                📄 EXPORT JSON
              </button>
              <button onClick={() => window.open(`${apiBase}/api/report/download?type=markdown`)} className="btn" style={{ fontSize: 10, padding: '4px 10px', background: '#1c1c1c', border: '1px solid #444', color: '#ccc' }}>
                📝 EXPORT MARKDOWN
              </button>
              <button onClick={() => window.open(`${apiBase}/api/report/download?type=pdf`)} className="btn" style={{ fontSize: 10, padding: '4px 10px', background: '#f43f5e', border: 'none', color: '#fff', fontWeight: 'bold' }}>
                📑 EXPORT PDF
              </button>
            </div>

            {/* Two-column body */}
            {vulnerabilities.length === 0 ? (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#555' }}>No verified findings yet.</div>
            ) : (
              <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'row', overflow: 'hidden' }}>

                {/* LEFT — findings list, independently scrollable */}
                <div style={{
                  width: 360, flexShrink: 0,
                  overflowY: 'auto', overflowX: 'hidden',
                  borderRight: '1px solid var(--border)',
                  padding: '10px 10px 10px 15px',
                }}>
                  {vulnerabilities.map((f, i) => {
                    const color = f.status === 'EXPLOITED' || f.status === 'VERIFIED_ELITE' ? '#8957e5' : (CVSS_COLOR[f.severity] || '#f97316');
                    const isSelected = state.selectedFinding?.id === f.id;
                    const displayTitle = f.title || f.type || f.vulnerability_name || 'Unknown';
                    const displayUrl = f.url || f.endpoint || f.fullUrl || '';
                    return (
                      <div key={i} onClick={() => dispatch({ type: 'SELECT_FINDING', payload: f })}
                        style={{
                          marginBottom: 8, padding: 12, borderRadius: 5, cursor: 'pointer',
                          background: isSelected ? 'rgba(139,92,246,0.15)' : 'var(--bg-elevated)',
                          border: isSelected ? '1px solid var(--accent)' : '1px solid var(--border)',
                          borderLeft: `4px solid ${color}`
                        }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ fontWeight: 700, fontSize: 11, color, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{displayTitle}</div>
                          <span style={{ fontSize: 9, color: CVSS_COLOR[f.severity] || '#666', fontWeight: 900, marginLeft: 6, flexShrink: 0 }}>{f.severity?.toUpperCase()}</span>
                        </div>
                        <div style={{ fontSize: 10, marginTop: 4, color: '#888' }}>{f.method} {displayUrl.slice(0, 45)}</div>
                      </div>
                    );
                  })}
                </div>

                {/* RIGHT — detail panel, independently scrollable */}
                <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', background: '#05050a', padding: 20 }}>
                  {!state.selectedFinding ? (
                    <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#444' }}>
                      Select a finding to view details.
                    </div>
                  ) : (() => {
                    const f = state.selectedFinding;
                    const title = f.title || f.type || f.vulnerability_name || 'Unknown';
                    const url   = f.url || f.endpoint || f.fullUrl || '-';
                    const desc  = f.description || f.explanation || '';
                    const evid  = f.evidence || f.proof || desc || '-';
                    const sev   = f.cvss_severity || f.severity || 'Medium';
                    const conf  = f.confidence || 'DETECTED';
                    const color = CVSS_COLOR[sev] || '#f97316';
                    return (
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #222', paddingBottom: 10 }}>
                          <h2 style={{ margin: 0, fontSize: 18, color }}>{title}</h2>
                          <span style={{ background: color + '22', color, padding: '4px 12px', borderRadius: 4, fontSize: 10, fontWeight: 700 }}>{sev.toUpperCase()}</span>
                        </div>
                        <div style={{ marginTop: 20, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, fontSize: 11, color: '#aaa' }}>
                          <div>
                            <div style={{ marginBottom: 5 }}><strong style={{ color: '#fff' }}>Endpoint:</strong> {url}</div>
                            <div style={{ marginBottom: 5 }}><strong style={{ color: '#fff' }}>Method:</strong> {f.method || 'GET'}</div>
                            <div style={{ marginBottom: 5 }}><strong style={{ color: '#fff' }}>Confidence:</strong> {conf}</div>
                          </div>
                          <div>
                            <div style={{ marginBottom: 5 }}><strong style={{ color: '#fff' }}>Severity:</strong> <span style={{ color }}>{sev}</span></div>
                            <div style={{ marginBottom: 5 }}><strong style={{ color: '#fff' }}>CVSS:</strong> {f.cvss_score || f.score || 'N/A'}</div>
                            <div style={{ marginBottom: 5 }}><strong style={{ color: '#fff' }}>Detected:</strong> {new Date(f.timestamp || Date.now()).toLocaleString()}</div>
                          </div>
                        </div>
                        <div style={{ marginTop: 20 }}>
                          <h4 style={{ color: 'var(--blue)', fontSize: 12, marginBottom: 8 }}>📖 DESCRIPTION</h4>
                          <div style={{ fontSize: 11, color: '#ccc', lineHeight: 1.6 }}>{desc || 'No description available.'}</div>
                        </div>
                        <div style={{ marginTop: 20 }}>
                          <h4 style={{ color: 'var(--orange)', fontSize: 12, marginBottom: 8 }}>🏹 EVIDENCE / PROOF</h4>
                          <div style={{ background: '#0a0a1f', padding: 10, borderRadius: 4, border: '1px solid #1a1a3a' }}>
                            <div style={{ fontSize: 11, color: '#aaa', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{evid}</div>
                            {f.payload && f.payload !== 'N/A' && (
                              <div style={{ marginTop: 10, background: '#000', padding: 8, border: '1px dotted #333', color: 'var(--orange)', fontSize: 10, fontFamily: 'var(--font-mono)' }}>
                                <strong>PAYLOAD:</strong> {f.payload}
                              </div>
                            )}
                          </div>
                        </div>
                        <div style={{ marginTop: 20, borderTop: '1px solid #222', paddingTop: 15 }}>
                          <h4 style={{ color: '#888', fontSize: 11, marginBottom: 8 }}>🔐 FIX RECOMMENDATION</h4>
                          <div style={{ fontSize: 11, color: '#22c55e' }}>{f.prevention || f.remediation || 'Apply input validation and enforce secure coding practices.'}</div>
                        </div>
                      </div>
                    );
                  })()}
                </div>

              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
}
