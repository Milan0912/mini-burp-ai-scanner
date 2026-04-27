import { useState, useEffect } from 'react';

const DEFAULT_RAW = `GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: MiniBurp/2.0\r\nAccept: */*\r\n\r\n`;

export default function RepeaterTab({ apiBase }) {
  const [raw, setRaw]         = useState(DEFAULT_RAW);
  const [host, setHost]       = useState('example.com');
  const [port, setPort]       = useState('80');
  const [useSSL, setUseSSL]   = useState(false);
  const [response, setResponse] = useState('');
  const [sending, setSending]   = useState(false);
  const [elapsed, setElapsed]   = useState(null);
  const [resTab, setResTab]     = useState('raw');

  useEffect(() => {
    const handler = (e) => {
      const { raw: r, host: h, port: p, useSSL: ssl } = e.detail;
      if (r) setRaw(r);
      if (h) setHost(h);
      if (p) setPort(String(p));
      if (ssl !== undefined) { setUseSSL(ssl); setPort(ssl ? '443' : '80'); }
    };
    window.addEventListener('send-to-repeater', handler);
    return () => window.removeEventListener('send-to-repeater', handler);
  }, []);

  const syncHostFromRaw = (rawText) => {
    setRaw(rawText);
    const match = rawText.match(/^Host:\s*(.+)$/im);
    if (match) {
      const [h, p] = match[1].trim().split(':');
      setHost(h);
      if (p) setPort(p);
    }
  };

  const sendRequest = async () => {
    setSending(true);
    setResponse('');
    const start = Date.now();
    try {
      const res = await fetch(`${apiBase}/api/repeater/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rawRequest: raw, host, port: parseInt(port) || (useSSL ? 443 : 80), useSSL }),
      });
      const data = await res.json();
      setElapsed(Date.now() - start);
      setResponse(data.success ? (data.response || '(empty)') : `Error: ${data.error}`);
      setResTab('raw');
    } catch (e) {
      setResponse(`Network error: ${e.message}`);
      setElapsed(null);
    } finally {
      setSending(false);
    }
  };

  const renderResponse = () => {
    if (!response) return null;
    if (resTab === 'headers') {
      const headerEnd = response.indexOf('\r\n\r\n');
      const headers = headerEnd > -1 ? response.slice(0, headerEnd) : response;
      return (
        <div className="detail-body">
          {headers.split('\r\n').map((line, i) => {
            if (i === 0) return <div key={i} style={{ color: 'var(--accent)', fontWeight: 600 }}>{line}</div>;
            const ci = line.indexOf(':');
            if (ci < 0) return <div key={i}>{line}</div>;
            return (
              <div key={i}>
                <span style={{ color: 'var(--blue)' }}>{line.slice(0, ci)}</span>
                <span style={{ color: 'var(--text-muted)' }}>:</span>
                <span style={{ color: 'var(--text-primary)' }}>{line.slice(ci + 1)}</span>
              </div>
            );
          })}
        </div>
      );
    }
    if (resTab === 'pretty') {
      const headerEnd = response.indexOf('\r\n\r\n');
      const body = headerEnd > -1 ? response.slice(headerEnd + 4) : response;
      return <div className="detail-body"><PrettyView content={body} /></div>;
    }
    return <div className="detail-body">{response}</div>;
  };

  return (
    <div className="repeater-tab">
      <div className="repeater-target-bar">
        <span className="target-label">Target:</span>
        <input className="target-input" value={host} onChange={(e) => setHost(e.target.value)} style={{ width: 200 }} />
        <span className="target-label">:</span>
        <input className="target-input" value={port} onChange={(e) => setPort(e.target.value)} style={{ width: 60 }} />
        <label className="ssl-toggle">
          <input type="checkbox" checked={useSSL} onChange={(e) => { setUseSSL(e.target.checked); setPort(e.target.checked ? '443' : '80'); }} />
          HTTPS
        </label>
        <div style={{ flex: 1 }} />
        <button className="btn btn-primary" onClick={sendRequest} disabled={sending} title="Ctrl+Enter">
          {sending ? '⏳ Sending…' : '▶ Send'}
        </button>
        {elapsed !== null && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{elapsed}ms</span>}
      </div>

      <div className="split-h" style={{ flex: 1, overflow: 'hidden' }}>
        {/* Request editor */}
        <div className="pane" style={{ flex: 1, borderRight: '1px solid var(--border)' }}>
          <div className="section-header">Request  <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(Ctrl+Enter)</span></div>
          <textarea
            className="raw-editor"
            value={raw}
            onChange={(e) => syncHostFromRaw(e.target.value)}
            onKeyDown={(e) => e.ctrlKey && e.key === 'Enter' && sendRequest()}
            spellCheck={false}
            style={{ flex: 1, borderRadius: 0, border: 'none' }}
          />
        </div>

        {/* Response viewer */}
        <div className="pane" style={{ flex: 1 }}>
          <div className="section-header" style={{ display: 'flex', alignItems: 'center' }}>
            <span>Response</span>
            {elapsed !== null && <span style={{ color: 'var(--green)', marginLeft: 8, fontWeight: 400 }}>{elapsed}ms</span>}
            <div style={{ flex: 1 }} />
            {response && ['raw','headers','pretty'].map((t) => (
              <button key={t} className={`tab-btn ${resTab === t ? 'active' : ''}`}
                style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setResTab(t)}>
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
          {response ? renderResponse() : (
            <div className="empty-state" style={{ flex: 1 }}>
              <div className="empty-state-icon">📡</div><span>Send a request to see response</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function PrettyView({ content }) {
  try { return <pre style={{ color: 'var(--green)', fontSize: 11.5 }}>{JSON.stringify(JSON.parse(content), null, 2)}</pre>; }
  catch { return <pre style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{content || '(no body)'}</pre>; }
}
