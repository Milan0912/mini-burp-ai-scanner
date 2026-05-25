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
  const [aiStatus, setAiStatus] = useState('unknown');
  const [confidenceFilter, setConfidenceFilter] = useState('ALL');

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
    fetch(`${apiBase}/api/report/findings?confidence=ALL`)
      .then(r => r.json())
      .then(data => {
        if (data.rows) data.rows.forEach(f => dispatch({ type: 'ADD_VULNERABILITY', payload: f }));
      }).catch(console.error);
    fetch(`${apiBase}/api/ai/status`).then(r => r.json()).then(data => setAiStatus(data.level || 'unknown')).catch(() => {});

    const aiStatusInterval = setInterval(() => {
      fetch(`${apiBase}/api/ai/status`).then(r => r.json()).then(data => setAiStatus(data.level || 'unknown')).catch(() => {});
    }, 5000);

    return () => {
      clearInterval(aiStatusInterval);
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

      {/* AI Mode Indicator */}
      <div style={{ padding: '5px 16px', background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)', flexShrink: 0, fontSize: '12px', color: '#666', display: 'flex', alignItems: 'center', gap: '6px' }}>
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: aiStatus === 'ollama' ? '#22c55e' : '#64748b' }} />
        <span style={{ fontWeight: 600, color: '#ccc' }}>
          {aiStatus === 'ollama' ? 'AI: Online' : 'AI: Offline Mode'}
        </span>
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
                    <div style={{ color: 'var(--text-muted)', fontSize: 9, marginTop: 8 }}>CURRENT TEST</div>
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
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr 1fr', gap: 1, background: '#111', border: '1px solid #222', margin: '0 10px 10px' }}>
                <div style={{ textAlign: 'center', padding: '12px 0', background: '#020205' }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: '#3b82f6', fontFamily: 'var(--font-mono)' }}>{status.discovered || 0}</div>
                  <div style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: 1 }}>Discovered</div>
                </div>
                <div style={{ textAlign: 'center', padding: '12px 0', background: '#020205' }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: '#8b5cf6', fontFamily: 'var(--font-mono)' }}>{status.scanned || 0}</div>
                  <div style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: 1 }}>Tested</div>
                </div>
                <div style={{ textAlign: 'center', padding: '12px 0', background: '#020205' }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: '#22c55e', fontFamily: 'var(--font-mono)' }}>{vulnerabilities.filter(f => f.confidence === 'VERIFIED').length}</div>
                  <div style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: 1 }}>✅ VERIFIED</div>
                </div>
                <div style={{ textAlign: 'center', padding: '12px 0', background: '#020205' }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: '#eab308', fontFamily: 'var(--font-mono)' }}>{vulnerabilities.filter(f => f.confidence === 'LIKELY').length}</div>
                  <div style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: 1 }}>⚠️ LIKELY</div>
                </div>
                <div style={{ textAlign: 'center', padding: '12px 0', background: '#020205' }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: '#64748b', fontFamily: 'var(--font-mono)' }}>{vulnerabilities.filter(f => f.confidence === 'INFORMATIONAL').length}</div>
                  <div style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: 1 }}>ℹ️ INFO</div>
                </div>
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 15px', flexShrink: 0, borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)' }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={() => setConfidenceFilter('ALL')} className={`btn ${confidenceFilter === 'ALL' ? 'active' : ''}`} style={{ fontSize: 10, padding: '4px 10px', background: confidenceFilter === 'ALL' ? '#333' : '#1c1c1c', border: '1px solid #444', color: '#ccc' }}>All</button>
                <button onClick={() => setConfidenceFilter('VERIFIED')} className={`btn ${confidenceFilter === 'VERIFIED' ? 'active' : ''}`} style={{ fontSize: 10, padding: '4px 10px', background: confidenceFilter === 'VERIFIED' ? '#22c55e' : '#1c1c1c', border: '1px solid #444', color: confidenceFilter === 'VERIFIED' ? '#000' : '#ccc' }}>✅ Verified Only</button>
                <button onClick={() => setConfidenceFilter('LIKELY')} className={`btn ${confidenceFilter === 'LIKELY' ? 'active' : ''}`} style={{ fontSize: 10, padding: '4px 10px', background: confidenceFilter === 'LIKELY' ? '#eab308' : '#1c1c1c', border: '1px solid #444', color: confidenceFilter === 'LIKELY' ? '#000' : '#ccc' }}>⚠️ Likely</button>
                <button onClick={() => setConfidenceFilter('INFORMATIONAL')} className={`btn ${confidenceFilter === 'INFORMATIONAL' ? 'active' : ''}`} style={{ fontSize: 10, padding: '4px 10px', background: confidenceFilter === 'INFORMATIONAL' ? '#3b82f6' : '#1c1c1c', border: '1px solid #444', color: confidenceFilter === 'INFORMATIONAL' ? '#000' : '#ccc' }}>ℹ️ Info</button>
              </div>

              <div style={{ display: 'flex', gap: 10 }}>
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
            </div>

            {/* Two-column body */}
            {vulnerabilities.filter(f => confidenceFilter === 'ALL' ? true : f.confidence === confidenceFilter).length === 0 ? (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#555' }}>No findings match the current filter.</div>
            ) : (
              <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'row', overflow: 'hidden' }}>

                {/* LEFT — findings list, independently scrollable */}
                <div style={{
                  width: 360, flexShrink: 0,
                  overflowY: 'auto', overflowX: 'hidden',
                  borderRight: '1px solid var(--border)',
                  padding: '10px 10px 10px 15px',
                }}>
                  {vulnerabilities.filter(f => confidenceFilter === 'ALL' ? true : f.confidence === confidenceFilter).map((f, i) => {
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
                          borderLeft: `4px ${f.confidence === 'LIKELY' ? 'dashed' : (f.confidence === 'INFORMATIONAL' ? 'dotted' : 'solid')} ${color}`,
                          opacity: f.confidence === 'LIKELY' ? 0.85 : (f.confidence === 'INFORMATIONAL' ? 0.6 : 1)
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
                    const conf  = f.confidence || 'INFORMATIONAL';
                    const color = CVSS_COLOR[sev] || '#f97316';
                    
                    // Parse structured evidence if present
                    let evidenceObj = null;
                    if (f.evidence) {
                      if (typeof f.evidence === 'object') {
                        evidenceObj = f.evidence;
                      } else if (typeof f.evidence === 'string') {
                        try {
                          evidenceObj = JSON.parse(f.evidence);
                        } catch (e) {
                          // Plain string fallback
                        }
                      }
                    }

                    // Confidence styling mapping
                    const confColorMap = {
                      VERIFIED: { text: '#22c55e', bg: 'rgba(34, 197, 94, 0.1)', border: 'rgba(34, 197, 94, 0.2)' },
                      LIKELY: { text: '#eab308', bg: 'rgba(234, 179, 8, 0.1)', border: 'rgba(234, 179, 8, 0.2)' },
                      INFORMATIONAL: { text: '#3b82f6', bg: 'rgba(59, 130, 246, 0.1)', border: 'rgba(59, 130, 246, 0.2)' }
                    };
                    const cStyle = confColorMap[conf] || confColorMap.INFORMATIONAL;
                    
                    const score = f.score || (f.cvss_score ? f.cvss_score * 10 : 50);

                    return (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                        {/* Header Section */}
                        <div style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'flex-start',
                          borderBottom: '1px solid var(--border)',
                          paddingBottom: '16px',
                          gap: '12px'
                        }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                              <span style={{
                                fontSize: '10px',
                                fontWeight: 800,
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: cStyle.bg,
                                color: cStyle.text,
                                border: `1px solid ${cStyle.border}`,
                                letterSpacing: '0.5px'
                              }}>
                                {conf}
                              </span>
                              <span style={{
                                fontSize: '10px',
                                fontWeight: 800,
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: color + '15',
                                color: color,
                                border: `1px solid ${color}33`,
                                letterSpacing: '0.5px'
                              }}>
                                {sev.toUpperCase()} SEVERITY
                              </span>
                            </div>
                            <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#fff', lineHeight: 1.3 }}>
                              {title.replace(/^\[.*?\]\s*/, '')}
                            </h2>
                          </div>
                          
                          <div style={{ textAlign: 'right', flexShrink: 0 }}>
                            <div style={{ fontSize: '20px', fontWeight: 900, color: color, fontFamily: 'var(--font-mono)' }}>
                              {(f.cvss_score || score / 10 || 0).toFixed(1)}
                            </div>
                            <div style={{ fontSize: '9px', color: 'var(--text-secondary)', fontWeight: 700, letterSpacing: '0.5px' }}>CVSS SCORE</div>
                          </div>
                        </div>

                        {/* Metadata Grid */}
                        <div style={{
                          display: 'grid',
                          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                          gap: '12px',
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border)',
                          borderRadius: 'var(--radius)',
                          padding: '14px',
                          fontSize: '11.5px'
                        }}>
                          <div>
                            <div style={{ marginBottom: '6px' }}><strong style={{ color: 'var(--text-secondary)' }}>Method:</strong> <span style={{ color: '#fff', fontWeight: 600, marginLeft: '4px' }}>{f.method || 'GET'}</span></div>
                            <div style={{ marginBottom: '6px', wordBreak: 'break-all' }}><strong style={{ color: 'var(--text-secondary)' }}>Endpoint:</strong> <span style={{ color: '#fff', fontFamily: 'var(--font-mono)', marginLeft: '4px' }}>{url}</span></div>
                          </div>
                          <div>
                            <div style={{ marginBottom: '6px' }}><strong style={{ color: 'var(--text-secondary)' }}>Parameter:</strong> <span style={{ color: 'var(--accent)', fontWeight: 600, fontFamily: 'var(--font-mono)', marginLeft: '4px' }}>{f.parameter || 'N/A'}</span></div>
                            <div style={{ marginBottom: '6px' }}><strong style={{ color: 'var(--text-secondary)' }}>Detected:</strong> <span style={{ color: '#fff', marginLeft: '4px' }}>{new Date(f.timestamp || Date.now()).toLocaleString()}</span></div>
                          </div>
                        </div>

                        {/* Confidence Gauge Panel */}
                        <div style={{
                          background: 'var(--bg-surface)',
                          borderRadius: 'var(--radius)',
                          border: '1px solid var(--border)',
                          padding: '16px'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                            <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: '0.5px' }}>VERIFICATION CONFIDENCE</span>
                            <span style={{ fontSize: '13px', fontWeight: 900, color: cStyle.text }}>{score}% Confidence</span>
                          </div>
                          <div style={{ height: '8px', background: '#0a0a0f', borderRadius: '4px', overflow: 'hidden', display: 'flex', border: '1px solid var(--border)' }}>
                            <div style={{
                              width: `${score}%`,
                              background: `linear-gradient(90deg, ${cStyle.text}88, ${cStyle.text})`,
                              boxShadow: `0 0 8px ${cStyle.text}55`,
                              borderRadius: '4px',
                              transition: 'width 0.8s cubic-bezier(0.4, 0, 0.2, 1)'
                            }} />
                          </div>
                          {f.reasoning && (
                            <div style={{ marginTop: '12px', fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
                              <span style={{ color: cStyle.text }}>🛡️</span>
                              <div>
                                <strong style={{ color: '#fff' }}>Behavioral Proof:</strong> {f.reasoning}
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Payload Section */}
                        {f.payload && f.payload !== 'N/A' && (
                          <div style={{
                            background: 'rgba(249, 115, 22, 0.02)',
                            border: '1px dashed rgba(249, 115, 22, 0.2)',
                            borderRadius: 'var(--radius)',
                            padding: '12px 16px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '6px'
                          }}>
                            <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--accent)', letterSpacing: '0.5px' }}>ACTIVE PAYLOAD</div>
                            <code style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: '#fff', wordBreak: 'break-all', display: 'block', background: '#00000044', padding: '6px', borderRadius: '4px' }}>
                              {f.payload}
                            </code>
                          </div>
                        )}

                        {/* Evidence Dashboard Grid */}
                        <div>
                          <h4 style={{ color: 'var(--text-secondary)', fontSize: '11.5px', fontWeight: 700, marginBottom: '10px', letterSpacing: '0.5px' }}>🏹 VERIFICATION EVIDENCE PROFILE</h4>
                          {evidenceObj && (evidenceObj.diffResult || evidenceObj.timingResult || evidenceObj.contextResult) ? (
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                              {/* Diff Profile */}
                              {evidenceObj.diffResult && (
                                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#3b82f6', borderBottom: '1px solid var(--border)', paddingBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>📊</span> DIFF PROFILE
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>Similarity:</span>
                                    <span style={{ fontWeight: 600, color: '#fff' }}>
                                      {typeof evidenceObj.diffResult.similarityScore === 'number' ? `${evidenceObj.diffResult.similarityScore}%` : 'N/A'}
                                    </span>
                                  </div>
                                  {evidenceObj.diffResult.anomalies && evidenceObj.diffResult.anomalies.length > 0 && (
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
                                      <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>Anomalies:</span>
                                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                                        {evidenceObj.diffResult.anomalies.map((anom, idx) => (
                                          <span key={idx} style={{ fontSize: '9px', background: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.15)', padding: '2px 6px', borderRadius: '3px', fontWeight: 600 }}>
                                            {anom}
                                          </span>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}

                              {/* Timing Profile */}
                              {evidenceObj.timingResult && (
                                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#f97316', borderBottom: '1px solid var(--border)', paddingBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>⏱️</span> TIMING PROFILE
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>Delay Detected:</span>
                                    <span style={{ fontWeight: 600, color: '#fff' }}>
                                      {evidenceObj.timingResult.delay ? `${evidenceObj.timingResult.delay} ms` : '0 ms'}
                                    </span>
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>Timing Anomaly:</span>
                                    <span style={{ fontWeight: 600, color: evidenceObj.timingResult.significant ? '#ef4444' : '#22c55e' }}>
                                      {evidenceObj.timingResult.significant ? 'YES' : 'NO'}
                                    </span>
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>Confidence:</span>
                                    <span style={{ fontWeight: 600, color: '#fff' }}>{evidenceObj.timingResult.confidence}%</span>
                                  </div>
                                </div>
                              )}

                              {/* Reflection Profile */}
                              {evidenceObj.contextResult && (
                                <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                  <div style={{ fontSize: '11px', fontWeight: 700, color: '#8b5cf6', borderBottom: '1px solid var(--border)', paddingBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <span>🔮</span> REFLECTION PROFILE
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>Reflected:</span>
                                    <span style={{ fontWeight: 600, color: evidenceObj.contextResult.reflected ? '#ef4444' : '#22c55e' }}>
                                      {evidenceObj.contextResult.reflected ? 'YES' : 'NO'}
                                    </span>
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>Context:</span>
                                    <span style={{ fontWeight: 600, color: '#fff', fontFamily: 'var(--font-mono)' }}>
                                      {evidenceObj.contextResult.context || 'unknown'}
                                    </span>
                                  </div>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                                    <span style={{ color: 'var(--text-secondary)' }}>Sanitized:</span>
                                    <span style={{ fontWeight: 600, color: evidenceObj.contextResult.sanitized ? '#22c55e' : '#ef4444' }}>
                                      {evidenceObj.contextResult.sanitized ? 'YES' : 'NO'}
                                    </span>
                                  </div>
                                </div>
                              )}
                            </div>
                          ) : (
                            <div style={{ background: '#0a0a0f', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '12px', overflowX: 'auto' }}>
                              <pre style={{ margin: 0, color: '#a78bfa', fontFamily: 'var(--font-mono)', fontSize: '11px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                                {evid}
                              </pre>
                            </div>
                          )}
                        </div>

                        {/* AI Insights Card */}
                        {f.aiAnalysis && (
                          <div style={{
                            background: 'rgba(30, 35, 48, 0.3)',
                            backdropFilter: 'blur(12px)',
                            border: '1px solid rgba(255, 255, 255, 0.06)',
                            boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.2)',
                            borderRadius: 'var(--radius)',
                            padding: '16px',
                            position: 'relative',
                            overflow: 'hidden'
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
                              <span style={{ fontSize: '15px' }}>🤖</span>
                              <span style={{ fontSize: '12px', fontWeight: 700, letterSpacing: '0.5px', color: '#fff' }}>AI-ASSISTED SCANNER ANALYSIS</span>
                            </div>
                            
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px' }}>
                              {f.aiAnalysis.owasp && (
                                <span style={{ fontSize: '9.5px', fontWeight: 600, background: 'rgba(139, 92, 246, 0.1)', color: '#c084fc', border: '1px solid rgba(139, 92, 246, 0.15)', padding: '3px 8px', borderRadius: '4px' }}>
                                  {f.aiAnalysis.owasp}
                                </span>
                              )}
                              {f.aiAnalysis.exploitability && (
                                <span style={{ fontSize: '9.5px', fontWeight: 600, background: 'rgba(239, 68, 68, 0.1)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.15)', padding: '3px 8px', borderRadius: '4px' }}>
                                  Exploitability: {f.aiAnalysis.exploitability}
                                </span>
                              )}
                            </div>

                            <div style={{ fontSize: '11.5px', color: '#cbd5e1', lineHeight: '1.6', background: 'rgba(0,0,0,0.15)', padding: '10px 12px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.02)' }}>
                              <strong>Security Impact:</strong> {f.aiAnalysis.explanation || (typeof f.aiAnalysis === 'string' ? f.aiAnalysis : 'N/A')}
                            </div>
                          </div>
                        )}

                        {/* Remediation Card */}
                        <div style={{
                          background: 'rgba(34, 197, 94, 0.02)',
                          border: '1px solid rgba(34, 197, 94, 0.15)',
                          borderRadius: 'var(--radius)',
                          padding: '16px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '8px'
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#4ade80', fontSize: '11.5px', fontWeight: 700, letterSpacing: '0.5px' }}>
                            <span>🛡️</span> ACTIONABLE REMEDIATION RECOMMENDATION
                          </div>
                          <div style={{ fontSize: '11.5px', color: '#a7f3d0', lineHeight: '1.5' }}>
                            {f.prevention || f.remediation || (f.aiAnalysis && f.aiAnalysis.remediation) || 'Enforce robust input validation and server-side parameterized sanitization.'}
                          </div>
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
