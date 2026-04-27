'use strict';

/**
 * AppModel.js
 * ===========
 * Builds a cognitive model of the target application.
 * Tracks: Endpoints, Auth Flow, Parameters, and Dependencies.
 */

class AppModel {
    constructor() {
        this.nodes = new Map(); // url -> { method, params, type, authRequired }
        this.edges = [];        // links between nodes
        this.authEntry = null;
        this.sessionEstablished = false;
    }

    addEndpoint(url, method, params, headers) {
        if (!this.nodes.has(url)) {
            const type = this.classify(url, params);
            this.nodes.set(url, { method, params, type, authRequired: false });
            if (type === 'auth') this.authEntry = url;
        }
    }

    classify(url, params) {
        const u = url.toLowerCase();
        if (u.includes('login') || u.includes('auth')) return 'auth';
        if (u.includes('admin') || u.includes('panel')) return 'admin';
        if (u.includes('api')) return 'api';
        if (u.includes('profile') || u.includes('user')) return 'profile';
        return 'generic';
    }

    setAuthRequired(url, required) {
        if (this.nodes.has(url)) {
            this.nodes.get(url).authRequired = required;
        }
    }

    getNeighbors(url) {
        return this.edges.filter(e => e.from === url).map(e => e.to);
    }
}

module.exports = new AppModel();
