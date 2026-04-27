'use strict';

/**
 * Attack Graph — Exploitation Path Tracking
 * =========================================
 * Maintains a lightweight directed graph of the attack surface and success.
 * Path: Entry -> Vuln -> Exploit -> Result
 */

class AttackGraph {
  constructor(io) {
    this.io = io;
    this.nodes = [];
    this.edges = [];
    this.findingMap = new Map();
  }

  /**
   * Add a node to the graph.
   */
  addNode(data) {
    const id = `node_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
    const node = { id, ...data };
    this.nodes.push(node);
    this.emitUpdate();
    return id;
  }

  /**
   * Connect two nodes.
   */
  addEdge(fromId, toId, label = '') {
    this.edges.push({ from: fromId, to: toId, label });
    this.emitUpdate();
  }

  /**
   * Records a transition from discovery to exploitation.
   */
  recordTransition(finding, resultData, phase = 'EXPLOIT') {
    let parentId = this.findingMap.get(finding.id);
    
    if (!parentId) {
      // Create initial discovery node if it doesn't exist
      parentId = this.addNode({
        type: 'discovery',
        label: finding.type,
        detail: finding.endpoint,
        status: finding.status
      });
      this.findingMap.set(finding.id, parentId);
    }

    const childId = this.addNode({
      type: phase.toLowerCase(),
      label: phase,
      detail: typeof resultData === 'string' ? resultData : JSON.stringify(resultData).substring(0, 50),
      status: 'success'
    });

    this.addEdge(parentId, childId, phase);
    return childId;
  }

  emitUpdate() {
    if (this.io) {
      this.io.emit('attack:graph:update', {
        nodes: this.nodes,
        edges: this.edges
      });
    }
  }

  getGraph() {
    return { nodes: this.nodes, edges: this.edges };
  }
}

module.exports = AttackGraph;
