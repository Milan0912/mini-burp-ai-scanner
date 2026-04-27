import React, { createContext, useContext, useReducer } from 'react';

const initialState = {
  connected: false,
  interceptQueue: [],
  agentQueue: {},
  agentMode: 'Suggest',
  scannerState: {
    isRunning: false,
    discovered: 0,
    scanned: 0,
    maxLimit: 100,
    tree: {},
    progress: 0,
    currentUrl: '',
  },
  vulnerabilities: [],
  selectedFinding: null,
  logs: [],
  scannerMode: 'auto',
};

function reducer(state, action) {
  switch (action.type) {
    case 'SET_CONNECTED':      return { ...state, connected: !!action.payload };
    case 'SET_AGENT_MODE':     return { ...state, agentMode: action.payload };
    case 'SET_SCANNER_MODE':   return { ...state, scannerMode: action.payload };
    case 'UPDATE_INTERCEPT_QUEUE': return { ...state, interceptQueue: action.payload || [] };
    case 'APPEND_INTERCEPT_QUEUE': {
      // Add request to intercept queue if not already present
      if (state.interceptQueue.some(r => r.id === action.payload?.id)) return state;
      return { ...state, interceptQueue: [...state.interceptQueue, action.payload] };
    }
    case 'REMOVE_INTERCEPT_QUEUE': return { ...state, interceptQueue: state.interceptQueue.filter(r => r.id !== action.payload) };
    case 'UPDATE_AGENT_QUEUE': return { ...state, agentQueue: { ...state.agentQueue, [action.payload.reqId]: action.payload.queue } };
    case 'UPDATE_SCANNER':     return { ...state, scannerState: { ...state.scannerState, ...action.payload } };
    case 'ADD_VULNERABILITY': {
      if (state.vulnerabilities.some(v => v.id === action.payload?.id)) return state;
      return { ...state, vulnerabilities: [action.payload, ...state.vulnerabilities] };
    }
    case 'SELECT_FINDING': return { ...state, selectedFinding: action.payload };
    case 'CLEAR_VULNERABILITIES': return { ...state, vulnerabilities: [], selectedFinding: null };
    case 'ADD_LOG':            return { ...state, logs: [action.payload, ...state.logs].slice(0, 200) };

    case 'CLEAR_LOGS':         return { ...state, logs: [] };
    default: return state;
  }
}

const StoreContext = createContext(null);
export function StoreProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  return <StoreContext.Provider value={{ state, dispatch }}>{children}</StoreContext.Provider>;
}
export function useStore() { return useContext(StoreContext); }
