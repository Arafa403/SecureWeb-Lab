
"use strict";

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";

const db = new Database(path.join(__dirname, "secureweb.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
      CHECK (role IN ('user', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    username TEXT,
    ip_address TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS siem_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    severity TEXT NOT NULL
      CHECK (severity IN ('low','medium','high','critical')),
    source_ip TEXT,
    description TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open'
      CHECK (status IN ('open','investigating','resolved')),
    first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_events_type_time
    ON security_events(event_type, created_at);

  CREATE INDEX IF NOT EXISTS idx_events_ip_time
    ON security_events(ip_address, created_at);

  CREATE INDEX IF NOT EXISTS idx_incidents_status_time
    ON siem_incidents(status, last_seen);
`);

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));

const sessionSecret = process.env.SESSION_SECRET;

if (isProduction && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error(
    "Set SESSION_SECRET (at least 32 characters) in production."
  );
}

app.use(session({
  name: "secureweb.sid",
  secret: sessionSecret ||
    "local-only-secret-change-this-before-deployment",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: isProduction,
    maxAge: 15 * 60 * 1000
  }
}));

// ==================== IP NORMALIZATION ====================

function normalizeIp(ip) {
  if (typeof ip !== "string" || !ip.trim()) return null;

  let normalized = ip.trim();

  if (normalized.toLowerCase().startsWith("::ffff:")) {
    normalized = normalized.slice(7);
  }

  if (normalized === "::1") {
    return "127.0.0.1";
  }

  return normalized.toLowerCase();
}

function getIpAliases(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return [];

  if (normalized === "127.0.0.1") {
    return ["127.0.0.1", "::1", "::ffff:127.0.0.1"];
  }

  return [normalized];
}

// ==================== SIEM CORRELATION ====================

const correlationRules = [
  {
    eventType: "LOGIN_FAILED",
    minutes: 10,
    threshold: 5,
    key: "BRUTE_FORCE",
    severity: "high",
    title: "Possible brute-force login activity",
    description:
      "At least 5 failed login attempts from one IP within 10 minutes."
  },
  {
    eventType: "WAF_DETECTION",
    minutes: 5,
    threshold: 3,
    key: "REPEATED_WAF",
    severity: "high",
    title: "Repeated WAF detections from one IP",
    description:
      "At least 3 WAF detections from one IP within 5 minutes."
  }
];

const countMatchingEvents = db.prepare(`
  SELECT COUNT(*) AS total
  FROM security_events
  WHERE event_type = ?
    AND ip_address IN (SELECT value FROM json_each(?))
    AND created_at >= datetime('now', ?)
`);

const findMatchingIncident = db.prepare(`
  SELECT *
  FROM siem_incidents
  WHERE title = ?
    AND source_ip IN (SELECT value FROM json_each(?))
  ORDER BY
    CASE status
      WHEN 'open' THEN 0
      WHEN 'investigating' THEN 1
      ELSE 2
    END,
    last_seen DESC,
    id DESC
  LIMIT 1
`);

const insertIncident = db.prepare(`
  INSERT INTO siem_incidents (
    dedupe_key, title, severity, source_ip, description,
    event_count, first_seen, last_seen
  )
  VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`);

const updateIncident = db.prepare(`
  UPDATE siem_incidents
  SET source_ip = ?,
      severity = ?,
      description = ?,
      event_count = ?,
      last_seen = CURRENT_TIMESTAMP,
      status = CASE
        WHEN status = 'resolved' THEN 'open'
        ELSE status
      END,
      resolved_at = NULL
  WHERE id = ?
`);

function correlateSecurityEvent(eventType, rawIp) {
  const ipAddress = normalizeIp(rawIp);
  if (!ipAddress) return;

  const rule = correlationRules.find(
    item => item.eventType === eventType
  );

  if (!rule) return;

  const aliases = getIpAliases(ipAddress);

  const count = countMatchingEvents.get(
    rule.eventType,
    JSON.stringify(aliases),
    `-${rule.minutes} minutes`
  ).total;

  if (count < rule.threshold) return;

  const description =
    `${rule.description} Current matching events: ${count}.`;

  const existing = findMatchingIncident.get(
    rule.title,
    JSON.stringify(aliases)
  );

  if (existing) {
    updateIncident.run(
      ipAddress,
      rule.severity,
      description,
      count,
      existing.id
    );
    return;
  }

  const dedupeKey = `${rule.key}:${ipAddress}`;

  try {
    insertIncident.run(
      dedupeKey,
      rule.title,
      rule.severity,
      ipAddress,
      description,
      count
    );
  } catch (error) {
    if (!String(error.code || "").includes("CONSTRAINT")) {
      throw error;
    }

    const sameKey = db.prepare(`
      SELECT id
      FROM siem_incidents
      WHERE dedupe_key = ?
    `).get(dedupeKey);

    if (sameKey) {
      updateIncident.run(
        ipAddress,
        rule.severity,
        description,
        count,
        sameKey.id
      );
    } else {
      throw error;
    }
  }
}

// ==================== SECURITY EVENT LOGGER ====================

const insertSecurityEvent = db.prepare(`
  INSERT INTO security_events (
    event_type, username, ip_address, details
  )
  VALUES (?, ?, ?, ?)
`);

function logSecurityEvent(eventType, req, username, details) {
  try {
    const ipAddress = normalizeIp(req.ip);

    const serializedDetails = typeof details === "string"
      ? details.slice(0, 4000)
      : JSON.stringify(details ?? {}).slice(0, 4000);

    db.transaction(() => {
      insertSecurityEvent.run(
        eventType,
        username || null,
        ipAddress,
        serializedDetails
      );

      correlateSecurityEvent(eventType, ipAddress);
    })();
  } catch (error) {
    console.error(
      "Security event logging/correlation failed:",
      error.message
    );
  }
}

// ==================== WEB APPLICATION FIREWALL ====================

const wafRules = [
  {
    id: "WAF-SQLI-01",
    name: "Possible SQL injection",
    pattern:
      /\bUNION\s+(?:ALL\s+)?SELECT\b|\bSELECT\b[\s\S]{0,100}\bFROM\b|\bOR\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/i
  },
  {
    id: "WAF-XSS-01",
    name: "Possible cross-site scripting",
    pattern: /<\s*script\b|javascript\s*:|on(?:error|load)\s*=/i
  },
  {
    id: "WAF-TRAVERSAL-01",
    name: "Possible path traversal",
    pattern: /\.\.(?:\/|\\|%2f|%5c)|%2e%2e(?:%2f|%5c)/i
  },
  {
    id: "WAF-CMD-01",
    name: "Possible command injection",
    pattern: /(?:;|\||&&)\s*(?:whoami|cat|id|uname|ping|curl|wget)\b/i
  }
];

function inspectWafValue(value, findings, location, depth = 0) {
  if (depth > 5 || findings.length >= 10 || value == null) return;

  if (typeof value === "string" || typeof value === "number") {
    const input = String(value).slice(0, 2000);

    for (const rule of wafRules) {
      if (rule.pattern.test(input)) {
        findings.push({
          rule: rule.id,
          name: rule.name,
          location
        });

        if (findings.length >= 10) break;
      }
    }

    return;
  }

  if (Array.isArray(value)) {
    value.slice(0, 30).forEach((item, index) => {
      inspectWafValue(item, findings, `${location}[${index}]`, depth + 1);
    });
    return;
  }

  if (typeof value === "object") {
    Object.entries(value).slice(0, 50).forEach(([key, item]) => {
      inspectWafValue(item, findings, `${location}.${key}`, depth + 1);
    });
  }
}

app.use((req, res, next) => {
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    return next();
  }

  const findings = [];

  inspectWafValue(req.path, findings, "path");
  inspectWafValue(req.query, findings, "query");
  inspectWafValue(req.body, findings, "body");

  if (findings.length) {
    logSecurityEvent(
      "WAF_DETECTION",
      req,
      req.session?.user?.username,
      {
        method: req.method,
        path: req.path,
        findings
      }
    );

    console.log(
      `[WAF] ${findings.length} finding(s) on ${req.method} ${req.path}`
    );
  }

  next();
});

// ==================== RATE LIMITING ====================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Too many login attempts. Try again in 15 minutes."
  }
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Too many registration attempts. Try again in 15 minutes."
  }
});

// ==================== VALIDATION HELPERS ====================

function isValidUsername(username) {
  return typeof username === "string" &&
    /^[a-zA-Z0-9_]{3,24}$/.test(username);
}

function isValidEmail(email) {
  return typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPassword(password) {
  return typeof password === "string" &&
    password.length >= 8 &&
    Buffer.byteLength(password, "utf8") <= 72;
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => err ? reject(err) : resolve());
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(err => err ? reject(err) : resolve());
  });
}

// ==================== AUTHORIZATION ====================

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please sign in first." });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please sign in first." });
  }

  if (req.session.user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator access required."
    });
  }

  next();
}

// ==================== WAF STATUS ====================

app.get("/api/waf/status", (req, res) => {
  const total = db.prepare(`
    SELECT COUNT(*) AS total
    FROM security_events
    WHERE event_type = 'WAF_DETECTION'
  `).get().total;

  res.json({
    wafMode: "detection",
    detectedEvents: total
  });
});

// ==================== AUTH: CURRENT USER ====================

app.get("/api/auth/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// ==================== REGISTER ====================

app.post("/api/auth/register", registerLimiter, async (req, res) => {
  try {
    const { username, email, password } = req.body || {};

    if (!isValidUsername(username)) {
      return res.status(400).json({
        error: "Username must be 3-24 characters using English letters, numbers, or underscores."
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({
        error: "Password must be 8-72 bytes and at least 8 characters."
      });
    }

    const normalizedUsername = username.trim();
    const normalizedEmail = email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (username, email, password_hash, role)
      VALUES (?, ?, ?, 'user')
    `).run(normalizedUsername, normalizedEmail, passwordHash);

    await regenerateSession(req);

    req.session.user = {
      id: Number(result.lastInsertRowid),
      username: normalizedUsername,
      email: normalizedEmail,
      role: "user"
    };

    await saveSession(req);

    res.status(201).json({ user: req.session.user });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({
        error: "That username or email is already registered."
      });
    }

    console.error("Registration failed:", err.message);
    res.status(500).json({ error: "Could not create account." });
  }
});

// ==================== LOGIN ====================

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      username.length > 254 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({ error: "Invalid input." });
    }

    const identifier = username.trim();

    const user = db.prepare(`
      SELECT id, username, email, password_hash, role
      FROM users
      WHERE username = ? COLLATE NOCASE
         OR email = ? COLLATE NOCASE
    `).get(identifier, identifier);

    const validPassword = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!user || !validPassword) {
      logSecurityEvent(
        "LOGIN_FAILED",
        req,
        identifier.slice(0, 254),
        "Invalid username/email or password"
      );

      return res.status(401).json({
        error: "Invalid username/email or password."
      });
    }

    await regenerateSession(req);

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    await saveSession(req);

    logSecurityEvent("LOGIN_SUCCESS", req, user.username, "Successful login");

    res.json({ user: req.session.user });
  } catch (err) {
    console.error("Login failed:", err.message);
    res.status(500).json({ error: "Could not sign in." });
  }
});

// ==================== LOGOUT ====================

app.post("/api/auth/logout", requireLogin, (req, res) => {
  const username = req.session.user.username;

  logSecurityEvent("LOGOUT", req, username, "User signed out");

  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: "Could not sign out." });
    }

    res.clearCookie("secureweb.sid", {
      httpOnly: true,
      sameSite: "strict",
      secure: isProduction
    });

    res.json({ message: "Signed out successfully." });
  });
});

// ==================== USER DASHBOARD ====================

app.get("/api/dashboard", requireLogin, (req, res) => {
  res.json({
    user: req.session.user,
    stats: {
      labs: 4,
      completed: 0,
      securityScore: "Training mode"
    }
  });
});

// ==================== SECURITY SUMMARY ====================

app.get("/api/security/summary", requireAdmin, (req, res) => {
  try {
    const failedLogins = db.prepare(`
      SELECT COUNT(*) AS total
      FROM security_events
      WHERE event_type = 'LOGIN_FAILED'
    `).get().total;

    const recentEvents = db.prepare(`
      SELECT COUNT(*) AS total
      FROM security_events
      WHERE created_at >= datetime('now', '-24 hours')
    `).get().total;

    const wafEvents = db.prepare(`
      SELECT COUNT(*) AS total
      FROM security_events
      WHERE event_type = 'WAF_DETECTION'
        AND created_at >= datetime('now', '-24 hours')
    `).get().total;

    res.json({ failedLogins, recentEvents, wafEvents });
  } catch (err) {
    console.error("Security summary failed:", err.message);
    res.status(500).json({
      error: "Could not load security summary."
    });
  }
});

// ==================== SECURITY EVENTS ====================

app.get("/api/security/events", requireAdmin, (req, res) => {
  try {
    const events = db.prepare(`
      SELECT id, event_type, username, ip_address, details, created_at
      FROM security_events
      ORDER BY id DESC
      LIMIT 50
    `).all();

    res.json({ events });
  } catch (err) {
    console.error("Security events failed:", err.message);
    res.status(500).json({
      error: "Could not load security events."
    });
  }
});

// ==================== ADMIN BOOTSTRAP ====================

app.post("/api/admin/bootstrap", (req, res) => {
  const expectedToken = process.env.ADMIN_BOOTSTRAP_TOKEN;
  const suppliedToken = req.get("x-admin-bootstrap-token");

  if (!expectedToken || expectedToken.length < 24) {
    return res.status(404).json({ error: "Not found." });
  }

  if (typeof suppliedToken !== "string") {
    return res.status(403).json({ error: "Invalid bootstrap token." });
  }

  const expected = Buffer.from(expectedToken);
  const supplied = Buffer.from(suppliedToken);

  if (
    expected.length !== supplied.length ||
    !crypto.timingSafeEqual(expected, supplied)
  ) {
    return res.status(403).json({ error: "Invalid bootstrap token." });
  }

  const { username } = req.body || {};

  if (!isValidUsername(username)) {
    return res.status(400).json({
      error: "Provide a valid existing username."
    });
  }

  const user = db.prepare(`
    SELECT id, username
    FROM users
    WHERE username = ? COLLATE NOCASE
  `).get(username.trim());

  if (!user) {
    return res.status(404).json({
      error: "User not found. Register that user first, then retry."
    });
  }

  db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(user.id);

  logSecurityEvent(
    "ADMIN_BOOTSTRAP",
    req,
    user.username,
    "Local bootstrap token used to grant admin role"
  );

  res.json({
    message: "Admin role granted. Sign in again to refresh your session.",
    username: user.username
  });
});

// ==================== SIEM SUMMARY API ====================

app.get("/api/siem/summary", requireAdmin, (req, res) => {
  try {
    const openIncidents = db.prepare(`
      SELECT COUNT(*) AS n
      FROM siem_incidents
      WHERE status = 'open'
    `).get().n;

    const highSeverity = db.prepare(`
      SELECT COUNT(*) AS n
      FROM siem_incidents
      WHERE severity IN ('high', 'critical')
        AND status != 'resolved'
    `).get().n;

    const events24h = db.prepare(`
      SELECT COUNT(*) AS n
      FROM security_events
      WHERE created_at >= datetime('now', '-24 hours')
    `).get().n;

    // Explicit count for failed login attempts in the last 24 hours.
    const failedLogins = db.prepare(`
      SELECT COUNT(*) AS n
      FROM security_events
      WHERE event_type = 'LOGIN_FAILED'
        AND created_at >= datetime('now', '-24 hours')
    `).get().n;

    // Explicit count for WAF detections in the last 24 hours.
    const wafEvents = db.prepare(`
      SELECT COUNT(*) AS n
      FROM security_events
      WHERE event_type = 'WAF_DETECTION'
        AND created_at >= datetime('now', '-24 hours')
    `).get().n;

    const eventTypes = db.prepare(`
      SELECT event_type, COUNT(*) AS count
      FROM security_events
      WHERE created_at >= datetime('now', '-24 hours')
      GROUP BY event_type
      ORDER BY count DESC
      LIMIT 8
    `).all();

    res.json({
      openIncidents,
      highSeverity,
      events24h,
      failedLogins,
      wafEvents,
      eventTypes
    });
  } catch (error) {
    console.error("SIEM summary failed:", error.message);
    res.status(500).json({
      error: "Could not load SIEM summary."
    });
  }
});

// ==================== SIEM INCIDENTS API ====================

app.get("/api/siem/incidents", requireAdmin, (req, res) => {
  try {
    const status = ["open", "investigating", "resolved"].includes(
      req.query.status
    ) ? req.query.status : null;

    const incidents = status
      ? db.prepare(`
          SELECT *
          FROM siem_incidents
          WHERE status = ?
          ORDER BY last_seen DESC
          LIMIT 100
        `).all(status)
      : db.prepare(`
          SELECT *
          FROM siem_incidents
          ORDER BY
            CASE status
              WHEN 'open' THEN 0
              WHEN 'investigating' THEN 1
              ELSE 2
            END,
            last_seen DESC
          LIMIT 100
        `).all();

    res.json({ incidents });
  } catch (error) {
    console.error("SIEM incidents failed:", error.message);
    res.status(500).json({
      error: "Could not load SIEM incidents."
    });
  }
});

// ==================== UPDATE INCIDENT STATUS ====================

app.patch("/api/siem/incidents/:id/status", requireAdmin, (req, res) => {
  const { status } = req.body || {};

  if (!["open", "investigating", "resolved"].includes(status)) {
    return res.status(400).json({
      error: "Status must be open, investigating, or resolved."
    });
  }

  const incidentId = Number(req.params.id);

  if (!Number.isSafeInteger(incidentId) || incidentId < 1) {
    return res.status(400).json({ error: "Invalid incident ID." });
  }

  const result = db.prepare(`
    UPDATE siem_incidents
    SET status = ?,
        resolved_at = CASE
          WHEN ? = 'resolved' THEN CURRENT_TIMESTAMP
          ELSE NULL
        END
    WHERE id = ?
  `).run(status, status, incidentId);

  if (!result.changes) {
    return res.status(404).json({ error: "Incident not found." });
  }

  logSecurityEvent(
    "SIEM_INCIDENT_STATUS_CHANGED",
    req,
    req.session.user.username,
    { incidentId, status }
  );

  res.json({
    message: "Incident status updated.",
    id: incidentId,
    status
  });
});

// ==================== STATIC FILES ====================

app.use(express.static(path.join(__dirname, "public")));

// ==================== START SERVER ====================

const server = app.listen(PORT, () => {
  console.log(`SecureWeb Lab running at http://localhost:${PORT}`);
  console.log("WAF mode: DETECTION (requests are not blocked)");
  console.log(
    "Admin bootstrap: disabled unless ADMIN_BOOTSTRAP_TOKEN is set."
  );
});

// ==================== GRACEFUL SHUTDOWN ====================

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
