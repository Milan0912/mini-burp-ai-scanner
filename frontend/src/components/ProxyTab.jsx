import { useState, useEffect, useCallback } from 'react';
import { useStore } from '../StoreContext';

/**
 * ProxyTab — Professional Interception & Manual Testing UI
 * ========================================================
 * 1. Fixed "Blank Request" issue by ensuring selectedRequest synchronization.
 * 2. Implemented formatRaw() for Burp-like display.
 * 3. Dedicated Manual vs AI mode separation.
 */

export default function ProxyTab({ socket, apiBase }) {
  const { state, dispatch } = useStore();
  const [interceptOn, setInterceptOn] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState(null);
  const [interceptedRes, setInterceptedRes] = useState(null);
  const [editedRaw, setEditedRaw] = useState('');
  const [editedResRaw, setEditedResRaw] = useState('');
  const [viewMode, setViewMode] = useState('request');
  const [reqTab, setReqTab] = useState('raw');
  const [resTab, setResTab] = useState('raw');
  const [resInterceptScheduled, setResInterceptScheduled] = useState(false);
  const [aiInsights, setAiInsights] = useState({ findings: [], attackResults: [] });

  const queue = state?.interceptQueue || [];
  const logs = state?.logs || [];
  const [testLog, setTestLog] = useState([]);
  const [testRunning, setTestRunning] = useState(false);
  const [showScope, setShowScope] = useState(false);
  const [scopeText, setScopeText] = useState('');
  const [onlyInScope, setOnlyInScope] = useState(false);

  const saveScope = () => {
    socket.emit('scope:set', { scope: scopeText.split('\n').filter(Boolean), onlyInScope });
    setShowScope(false);
  };

  // ── Auto-selection mechanism ───────────────────────────────────
  useEffect(() => {
    if (queue.length > 0 && !selectedRequest) {
      setSelectedRequest(queue[0]);
    } else if (queue.length === 0 && selectedRequest) {
      setSelectedRequest(null);
    } else if (selectedRequest && !queue.find(r => r.id === selectedRequest.id)) {
      // Current selected request was forwarded/dropped
      setSelectedRequest(queue[0] || null);
    }
  }, [queue, selectedRequest]);

  // ── Synchronization of edited state ───────────────────────────
  useEffect(() => {
    if (selectedRequest) {
      setEditedRaw(selectedRequest.raw || formatRaw(selectedRequest));
      // Fetch insights for this specific request
      fetch(`${apiBase}/api/ai/insights/${selectedRequest.id}`)
        .then(r => r.json())
        .then(data => setAiInsights(data || { findings: [], attackResults: [] }))
        .catch(() => {});
    } else {
      setEditedRaw('');
      setAiInsights({ findings: [], attackResults: [] });
    }
  }, [selectedRequest, apiBase]);

  // ── Socket listeners ──────────────────────────────────────────
  useEffect(() => {
    if (!socket) return;

    socket.on('intercept:state', ({ on, onlyInScope: scopeOn, scope }) => {
      setInterceptOn(on);
      setOnlyInScope(!!scopeOn);
      if (scope) setScopeText(scope.join('\n'));
    });

    socket.on('response:intercepted', (res) => {
      setInterceptedRes(res);
      setEditedResRaw(res.rawResponse || formatResRaw(res));
      setViewMode('response');
    });

    socket.on('response:resolved', ({ id }) => {
      if (interceptedRes?.id === id) {
        setInterceptedRes(null);
        setEditedResRaw('');
        setViewMode('request');
      }
    });

    socket.on('test:progress', (data) => {
      if (!selectedRequest || data.reqId !== selectedRequest.id) return;
      const color = data.phase === 'FINDING' ? '🔴' : '🔹';
      setTestLog(prev => [{ text: `${color} [${data.phase}] ${data.message}`, ts: Date.now() }, ...prev]);
    });

    socket.on('test:complete', (data) => {
      if (!selectedRequest || data.reqId !== selectedRequest.id) return;
      setTestRunning(false);
      setTestLog(prev => [{ text: `✅ Testing complete: ${data.findingCount} findings.`, ts: Date.now() }, ...prev]);
    });

    return () => {
      socket.off('intercept:state');
      socket.off('response:intercepted');
      socket.off('response:resolved');
      socket.off('test:progress');
      socket.off('test:complete');
    };
  }, [socket, selectedRequest, interceptedRes]);

  // ── Actions ───────────────────────────────────────────────────
  const handleToggle = () => {
    const newVal = !interceptOn;
    setInterceptOn(newVal);
    socket.emit('intercept:set', { on: newVal });
  };

  const doForward = () => {
    if (!selectedRequest) return;
    socket.emit('action:forward', { id: selectedRequest.id, editedRaw });
    dispatch({ type: 'REMOVE_INTERCEPT_QUEUE', payload: selectedRequest.id });
  };

  const doDrop = () => {
    if (!selectedRequest) return;
    socket.emit('action:drop', { id: selectedRequest.id });
    dispatch({ type: 'REMOVE_INTERCEPT_QUEUE', payload: selectedRequest.id });
  };

  const runFullTest = async () => {
    if (!selectedRequest || testRunning) return;
    setTestRunning(true);
    setTestLog([{ text: '🚀 Starting multi-vector behavioral test...', ts: Date.now() }]);
    await fetch(`${apiBase}/api/ai/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reqId: selectedRequest.id })
    });
  };

  // ── Rendering ─────────────────────────────────────────────────
  const renderRequestContent = () => {
    if (!selectedRequest) return <div className="no-intercept-msg">Waiting for traffic...</div>;
    if (reqTab === 'headers') return <pre className="detail-body">{JSON.stringify(selectedRequest.headers, null, 2)}</pre>;
    return (
      <textarea
        className="raw-editor"
        value={editedRaw}
        onChange={(e) => setEditedRaw(e.target.value)}
        spellCheck={false}
      />
    );
  };

  return (
    <div className="proxy-tab">
      <div className="intercept-bar">
        <button className={`btn ${interceptOn ? 'btn-red' : 'btn-ghost'}`} onClick={handleToggle}>
          {interceptOn ? '🔴 Intercept ON' : '⚪ Intercept OFF'}
        </button>
        {queue.length > 0 && <span className="queue-badge">{queue.length} held</span>}
        <div className="divider" />
        
        <button className={`btn ${showScope ? 'btn-blue' : 'btn-ghost'}`} onClick={() => setShowScope(!showScope)}>
           🎯 Scope
        </button>

        <div className="divider" />

        {viewMode === 'request' && selectedRequest && (
          <>
            <button className="btn btn-success" onClick={doForward}>▶ Forward</button>
            <button className="btn btn-danger" onClick={doDrop}>✕ Drop</button>
            <div className="divider" />
            <button className={`btn ${resInterceptScheduled ? 'btn-red' : 'btn-ghost'}`} 
                    onClick={() => {
                      const id = selectedRequest.id;
                      socket.emit('action:intercept-response', { id });
                      setResInterceptScheduled(true);
                    }}>
              {resInterceptScheduled ? '📥 Intercepting Response...' : '🔽 Intercept Response'}
            </button>
            <div className="divider" />
            <button className="btn btn-primary" onClick={runFullTest} disabled={testRunning}>
              {testRunning ? '⟳ Testing...' : '🧪 Run Full Test'}
            </button>
          </>
        )}

        {viewMode === 'response' && interceptedRes && (
          <>
            <button className="btn btn-blue" onClick={() => {
              socket.emit('response:forward', { id: interceptedRes.id, editedRaw: editedResRaw });
              setInterceptedRes(null);
              setEditedResRaw('');
              setViewMode('request');
            }}>▶ Forward Response</button>
            <button className="btn btn-danger" onClick={() => {
              socket.emit('response:drop', { id: interceptedRes.id });
              setInterceptedRes(null);
              setEditedResRaw('');
              setViewMode('request');
            }}>✕ Drop Response</button>
            <div style={{ flex: 1 }} />
            <span style={{ color: 'var(--accent)', fontWeight: 600 }}>PAUSED RESPONSE: {interceptedRes.url}</span>
          </>
        )}
      </div>

      {showScope && (
         <div className="scope-config-panel" style={{ padding: 15, background: 'var(--surface)', borderBottom: '1px solid var(--border)', display: 'flex', gap: 20 }}>
            <div style={{ flex: 1 }}>
               <div className="section-header" style={{ marginBottom: 8 }}>Target Scope Definition</div>
               <textarea 
                  style={{ width: '100%', height: 80, background: 'var(--bg-elevated)', color: 'white', border: '1px solid var(--border)', padding: 8, fontSize: 11, fontFamily: 'monospace' }} 
                  placeholder="Enter domains or regex patterns (one per line). Example: domain.com or /.*api.*/"
                  value={scopeText}
                  onChange={(e) => setScopeText(e.target.value)}
               />
               <button className="btn btn-blue" style={{ marginTop: 8, fontSize: 11 }} onClick={saveScope}>Save Scope</button>
            </div>
            <div style={{ width: 300, display: 'flex', flexDirection: 'column', gap: 10, justifyContent: 'center' }}>
               <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, cursor: 'pointer' }}>
                  <input type="checkbox" checked={onlyInScope} onChange={(e) => {
                     setOnlyInScope(e.target.checked);
                     socket.emit('scope:set', { scope: scopeText.split('\n').filter(Boolean), onlyInScope: e.target.checked });
                  }} />
                  Intercept ONLY in-scope requests
               </label>
               <div style={{ padding: 10, background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.3)', borderRadius: 4, fontSize: 10.5, color: '#94a3b8' }}>
                  Requests matching these patterns will be logged and intercepted. Out-of-scope traffic will be auto-forwarded.
               </div>
            </div>
         </div>
      )}

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Left: Queue List */}
        <div style={{ width: 300, borderRight: '1px solid var(--border)', overflowY: 'auto', background: 'var(--bg-elevated)' }}>
          <div className="section-header" style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Interception Queue</div>
          {queue.map((req, i) => (
            <div
              key={req.id}
              className={`req-item ${selectedRequest?.id === req.id ? 'active' : ''}`}
              onClick={() => { setSelectedRequest(req); setViewMode('request'); }}
            >
              <span className={`method-badge ${req.method?.toLowerCase()}`}>{req.method}</span>
              <span className="url-snippet">{shortenUrl(req.url)}</span>
            </div>
          ))}
          {interceptedRes && (
             <div className={`req-item active-res`} style={{ borderLeft: '4px solid var(--accent)', background: 'rgba(249,115,22,0.1)' }}>
                <span className="method-badge res" style={{ background: 'var(--accent)' }}>RES</span>
                <span className="url-snippet" style={{ color: 'var(--accent)' }}>{shortenUrl(interceptedRes.url)}</span>
             </div>
          )}
          {queue.length === 0 && !interceptedRes && <div style={{ padding: 20, color: '#555', fontSize: 11 }}>No intercepted requests.</div>}
        </div>

        {/* Right: Detail Panel */}
        <div className="request-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
          <div className="panel-toolbar">
            <div className="tabs">
              {viewMode === 'request' ? (
                 <>
                   <button className={reqTab === 'raw' ? 'active' : ''} onClick={() => setReqTab('raw')}>Raw Request</button>
                   <button className={reqTab === 'headers' ? 'active' : ''} onClick={() => setReqTab('headers')}>Headers</button>
                 </>
              ) : (
                 <>
                   <button className={resTab === 'raw' ? 'active' : ''} onClick={() => setResTab('raw')}>Raw Response</button>
                   <button className={resTab === 'headers' ? 'active' : ''} onClick={() => setResTab('headers')}>Headers</button>
                 </>
              )}
            </div>
          </div>
          
          <div className="editor-container" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            {viewMode === 'request' ? (
              selectedRequest ? (
                reqTab === 'headers' ? (
                  <pre className="detail-body">{JSON.stringify(selectedRequest.headers, null, 2)}</pre>
                ) : (
                  <textarea
                    className="raw-editor"
                    value={editedRaw}
                    onChange={(e) => setEditedRaw(e.target.value)}
                    spellCheck={false}
                  />
                )
              ) : <div className="no-intercept-msg">Waiting for traffic...</div>
            ) : (
              interceptedRes ? (
                resTab === 'headers' ? (
                  <pre className="detail-body">{JSON.stringify(interceptedRes.headers, null, 2)}</pre>
                ) : (
                  <textarea
                    className="raw-editor"
                    value={editedResRaw}
                    onChange={(e) => setEditedResRaw(e.target.value)}
                    spellCheck={false}
                  />
                )
              ) : <div className="no-intercept-msg">No response intercepted.</div>
            )}
          </div>
          
          {/* Behavioral Log removed — editor takes full height */}
        </div>
      </div>
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────
function formatRaw(req) {
  if (!req) return "";
  let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
  if (req.headers) {
    for (const [k, v] of Object.entries(req.headers)) {
      raw += `${k}: ${v}\r\n`;
    }
  }
  raw += `\r\n${req.body || ""}`;
  return raw;
}

function formatResRaw(res) {
  let raw = `HTTP/1.1 ${res.statusCode} ${res.statusMessage}\r\n`;
  if (res.headers) {
    for (const [k, v] of Object.entries(res.headers)) {
      raw += `${k}: ${v}\r\n`;
    }
  }
  raw += `\r\n${res.bodyPreview || ""}`;
  return raw;
}

function shortenUrl(url) {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}
