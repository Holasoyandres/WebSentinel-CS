/**
 * WebSentinel-CS :: Native SQLite Storage & Forensics Engine
 * Powered by Node.js 24 Native DatabaseSync (Zero external npm packages)
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'sentinel.sqlite');
const db = new DatabaseSync(DB_PATH);

// Initialize Enterprise SQL Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    target TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    failed_attempts INTEGER DEFAULT 0,
    is_blocked INTEGER DEFAULT 0,
    block_expires_at DATETIME,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS endpoint_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    status_code INTEGER,
    security_score INTEGER,
    missing_headers_count INTEGER,
    latency_ms INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
  CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
`);

module.exports = {
  db,

  // Insert Incident
  insertIncident(event) {
    try {
      const stmt = db.prepare(`
        INSERT INTO incidents (id, timestamp, severity, type, rule_id, source_ip, target, action, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        event.id,
        event.timestamp,
        event.severity,
        event.type,
        event.ruleId || 'RULE-GENERIC',
        event.sourceIp,
        event.target,
        event.action,
        event.details
      );
    } catch (err) {
      console.error('[DB Error] Failed to insert incident:', err.message);
    }
  },

  // Retrieve Incidents
  getIncidents(limit = 100, severity = 'ALL') {
    try {
      if (severity === 'ALL') {
        const stmt = db.prepare(`SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?`);
        return stmt.all(limit);
      } else {
        const stmt = db.prepare(`SELECT * FROM incidents WHERE severity = ? ORDER BY timestamp DESC LIMIT ?`);
        return stmt.all(severity, limit);
      }
    } catch (err) {
      console.error('[DB Error] Failed to query incidents:', err.message);
      return [];
    }
  },

  // Save Scan Result
  saveScanResult(scan) {
    try {
      const stmt = db.prepare(`
        INSERT INTO endpoint_scans (target_url, status_code, security_score, missing_headers_count, latency_ms)
        VALUES (?, ?, ?, ?, ?)
      `);
      stmt.run(
        scan.url,
        scan.statusCode || 0,
        scan.securityScore || 0,
        scan.missingHeadersCount || 0,
        scan.latencyMs || 0
      );
    } catch (err) {
      console.error('[DB Error] Failed to save scan:', err.message);
    }
  },

  // Aggregated SQL Analytics
  getAnalyticsSummary() {
    try {
      const totalIncidents = db.prepare(`SELECT COUNT(*) as count FROM incidents`).get().count;
      const criticalCount = db.prepare(`SELECT COUNT(*) as count FROM incidents WHERE severity IN ('CRITICAL', 'HIGH')`).get().count;
      const blockedIps = db.prepare(`SELECT COUNT(*) as count FROM ip_reputation WHERE is_blocked = 1`).get().count;
      
      const topIps = db.prepare(`
        SELECT source_ip, COUNT(*) as hits 
        FROM incidents 
        GROUP BY source_ip 
        ORDER BY hits DESC 
        LIMIT 5
      `).all();

      const severityDistribution = db.prepare(`
        SELECT severity, COUNT(*) as count 
        FROM incidents 
        GROUP BY severity
      `).all();

      return {
        totalIncidents,
        criticalCount,
        blockedIps,
        topIps,
        severityDistribution
      };
    } catch (err) {
      console.error('[DB Error] Analytics failed:', err.message);
      return { totalIncidents: 0, criticalCount: 0, blockedIps: 0, topIps: [], severityDistribution: [] };
    }
  },

  // Read-only SQL Query Runner for Forensic Analyst
  runReadOnlyQuery(sql) {
    const cleanSql = sql.trim();
    // Enforce read-only constraint
    if (!/^\s*SELECT\b/i.test(cleanSql) && !/^\s*WITH\b/i.test(cleanSql)) {
      throw new Error('Solo se permiten consultas SQL de lectura (SELECT)');
    }
    const stmt = db.prepare(cleanSql);
    return stmt.all();
  }
};
