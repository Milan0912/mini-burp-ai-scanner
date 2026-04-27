'use strict';

const db = require('../core/db');

/**
 * ProjectManager.js
 * =================
 * Handles persistence of scans and findings.
 * Fulfills Task 5.
 */

class ProjectManager {
    static async saveScan(projectId, data) {
        const stmt = db.prepare('INSERT INTO projects (id, data, timestamp) VALUES (?, ?, ?)');
        stmt.run(projectId, JSON.stringify(data), Date.now());
    }

    static async loadScan(projectId) {
        const stmt = db.prepare('SELECT data FROM projects WHERE id = ?');
        const row = stmt.get(projectId);
        return row ? JSON.parse(row.data) : null;
    }

    static async listScans() {
        const stmt = db.prepare('SELECT id, timestamp FROM projects ORDER BY timestamp DESC');
        return stmt.all();
    }
}

module.exports = ProjectManager;
