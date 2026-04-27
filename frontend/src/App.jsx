import { useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { getApiBase } from './apiUrl';
import { StoreProvider, useStore } from './StoreContext';
import ProxyTab    from './components/ProxyTab';
import HistoryTab  from './components/HistoryTab';
import RepeaterTab from './components/RepeaterTab';
import IntruderTab from './components/IntruderTab';
import ScannerTab  from './components/ScannerTab';
import './index.css';

// ── Inner app — has access to StoreContext ─────────────────────
function AppContent() {
  const [tab, setTab]     = useState('proxy');
  const [apiBase, setApiBase] = useState('http://localhost:3000');
  const { state, dispatch } = useStore();
  const socketRef = useRef(null);

  // Stable dispatch reference — never changes
  const stableDispatch = useCallback(dispatch, []);

  useEffect(() => {
    let s = null;
    let timer = null;

    (async () => {
      const base = await getApiBase();
      setApiBase(base);

      s = io(base, {
        transports: ['websocket', 'polling'],
        reconnectionDelay: 1000,
        reconnectionAttempts: Infinity,
      });
      socketRef.current = s;

      s.on('connect', () => {
        stableDispatch({ type: 'SET_CONNECTED', payload: true });
        console.log('[App] Socket connected:', s.id);

        // Initial hydration
        fetch(`${base}/api/intercept-status`).then(r => r.json()).then(d => {
          stableDispatch({ type: 'UPDATE_INTERCEPT_QUEUE', payload: d.queue || [] });
        }).catch(() => {});

        fetch(`${base}/api/agent/state`).then(r => r.json()).then(d => {
          if (d.mode) stableDispatch({ type: 'SET_AGENT_MODE', payload: d.mode });
        }).catch(() => {});

        fetch(`${base}/api/scanner/status`).then(r => r.json()).then(d => {
          stableDispatch({ type: 'UPDATE_SCANNER', payload: d });
        }).catch(() => {});
      });

      s.on('disconnect', () => stableDispatch({ type: 'SET_CONNECTED', payload: false }));

      // Forward intercept:state as a browser event so ProxyTab can listen
      s.on('intercept:state', ({ on }) => {
        window.dispatchEvent(new CustomEvent('intercept:state', { detail: { on } }));
      });

      // Intercept queue updates — use functional updater to avoid stale state
      s.on('request:intercepted', (req) => {
        stableDispatch({ type: 'APPEND_INTERCEPT_QUEUE', payload: req });
      });

      s.on('request:resolved', ({ id }) => {
        stableDispatch({ type: 'REMOVE_INTERCEPT_QUEUE', payload: id });
      });

      // AI / Agent updates
      s.on('ai:insights:update', (data) => {
        (data.attackResults || []).forEach(r => {
          if (r.result && r.result.includes('CONFIRMED')) {
            stableDispatch({ type: 'ADD_VULNERABILITY', payload: {
              id: `${Date.now()}-${Math.random()}`,
              reqId: data.id,
              param: r.param,
              type: r.type,
              evidence: r.result,
              timestamp: new Date().toISOString()
            }});
          }
        });
      });

      s.on('agent:queue:update', (data) => {
        stableDispatch({ type: 'UPDATE_AGENT_QUEUE', payload: { reqId: data.reqId, queue: data.queue } });
      });

      // Scanner & Pentesting
      s.on('scanner:update', (update) => {
        stableDispatch({ type: 'UPDATE_SCANNER', payload: update });
      });

      s.on('test:progress', (data) => {
        if (data.phase === 'TESTING' || data.phase === 'VERIFY' || data.phase === 'EXPLOIT') {
          stableDispatch({ type: 'UPDATE_SCANNER', payload: {
            currentTest: data.currentTest,
            currentParam: data.currentParam,
            currentPayload: data.currentPayload
          }});
        }
        // Also log to behavioral log
        stableDispatch({ type: 'ADD_LOG', payload: { ...data, message: `[${data.phase}] ${data.message}`, timestamp: new Date().toISOString() } });
      });

      s.on('finding:new', (finding) => {
        stableDispatch({ type: 'ADD_VULNERABILITY', payload: finding });
      });

      // Attack logs (legacy support)
      s.on('attack:log', (entry) => {
        stableDispatch({ type: 'ADD_LOG', payload: { ...entry, message: `[${entry.phase}] ${entry.message}`, timestamp: new Date().toISOString() } });
      });

      // Fallback polling — keep intercept queue in sync
      timer = setInterval(() => {
        fetch(`${base}/api/intercept-status`).then(r => r.json()).then(d => {
          stableDispatch({ type: 'UPDATE_INTERCEPT_QUEUE', payload: d.queue || [] });
        }).catch(() => {});
      }, 1500);
    })();

    return () => {
      if (s) {
        s.off('scanner:update');
        s.off('test:progress');
        s.off('finding:new');
        s.off('attack:log');
        s.off('intercept:state');
        s.off('request:intercepted');
        s.off('request:resolved');
        s.disconnect();
      }
      if (timer) clearInterval(timer);
    };

  }, []); // Run only once on mount

  // Cross-tab navigation event
  useEffect(() => {
    const handler = (e) => setTab(e.detail?.tab);
    window.addEventListener('switch-tab', handler);
    return () => window.removeEventListener('switch-tab', handler);
  }, []);

  const tabs = [
    { id: 'proxy',    icon: '🕵️', label: 'Proxy'       },
    { id: 'history',  icon: '📋', label: 'HTTP History' },
    { id: 'repeater', icon: '🔁', label: 'Repeater'     },
    { id: 'intruder', icon: '⚔️', label: 'Intruder'     },
    { id: 'scanner',  icon: '🤖', label: 'Scanner'      },
  ];

  return (
    <div className="app">
      {/* ── Top Bar ───────────────────────────────────────────── */}
      <div className="topbar">
        <div className="topbar-logo">Mini<span>Burp</span></div>
        <div className="topbar-tabs">
          {tabs.map((t) => (
            <button key={t.id} className={`tab-btn ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
              {t.icon} {t.label}
            </button>
          ))}
        </div>
        <div className="status-badge" style={{ display: 'flex', alignItems: 'center' }}>
          <span className={`status-dot ${state.connected ? 'connected' : ''}`} />
          {state.connected ? 'Connected' : 'Disconnected'}
          {state.connected && <span style={{ color: 'var(--text-muted)', marginLeft: 4 }}>· :8080</span>}
          {(state.interceptQueue?.length > 0) && (
            <span className="intercept-pip req">{state.interceptQueue.length} held</span>
          )}
        </div>
      </div>

      {/* ── Tab Content ─────────────────────────────────────────── */}
      <div className="tab-content">
        <div style={{ display: tab === 'proxy' ? 'flex' : 'none', flex: 1, minHeight: 0, flexDirection: 'column' }}>
          <ProxyTab socket={socketRef.current} apiBase={apiBase} />
        </div>
        <div style={{ display: tab === 'history' ? 'flex' : 'none', flex: 1, minHeight: 0, flexDirection: 'column' }}>
          <HistoryTab socket={socketRef.current} apiBase={apiBase} />
        </div>
        <div style={{ display: tab === 'repeater' ? 'flex' : 'none', flex: 1, minHeight: 0, flexDirection: 'column' }}>
          <RepeaterTab apiBase={apiBase} />
        </div>
        <div style={{ display: tab === 'intruder' ? 'flex' : 'none', flex: 1, minHeight: 0, flexDirection: 'column' }}>
          <IntruderTab socket={socketRef.current} apiBase={apiBase} />
        </div>
        <div style={{ display: tab === 'scanner' ? 'flex' : 'none', flex: 1, minHeight: 0, flexDirection: 'column' }}>
          <ScannerTab socket={socketRef.current} apiBase={apiBase} />
        </div>
      </div>
    </div>
  );
}

// ── Root app — provides the store ──────────────────────────────
export default function App() {
  return (
    <StoreProvider>
      <AppContent />
    </StoreProvider>
  );
}
