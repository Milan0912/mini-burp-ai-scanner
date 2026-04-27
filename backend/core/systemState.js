'use strict';

/**
 * SystemState — Global RUNNING / PAUSED sentinel
 *
 * Any module that touches the DB or the proxy traffic pipeline should
 * check `systemState.isRunning()` before doing work.
 *
 * During a project import the control flow is:
 *   1. pause()         — blocks new proxy traffic with HTTP 503
 *   2. flush()         — drains write queues
 *   3. swap databases  — swap .db files safely
 *   4. resume()        — restores normal operation
 */

const EventEmitter = require('events');
const emitter = new EventEmitter();

let _state = 'RUNNING'; // 'RUNNING' | 'PAUSED'
let _io = null;

function setIO(io) { _io = io; }

function getState()    { return _state; }
function isRunning()   { return _state === 'RUNNING'; }
function isPaused()    { return _state === 'PAUSED';  }

function pause(reason = 'Switching project...') {
  if (_state === 'PAUSED') return;
  _state = 'PAUSED';
  console.log(`[SystemState] PAUSED — ${reason}`);
  emitter.emit('paused', reason);
  if (_io) _io.emit('system:state', { state: 'PAUSED', reason });
}

function resume() {
  if (_state === 'RUNNING') return;
  _state = 'RUNNING';
  console.log('[SystemState] RUNNING');
  emitter.emit('resumed');
  if (_io) _io.emit('system:state', { state: 'RUNNING' });
}

module.exports = { setIO, getState, isRunning, isPaused, pause, resume, emitter };
