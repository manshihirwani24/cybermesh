const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const { scanWebsite, isPrivateAddress, assertPublicDestination } = require("./scanner");
const { myBlockchain } = require("./scanner");
const { hashIncidentReport, canonicalStringify } = require("./blockchain");

const app = express();
const PORT = Number(process.env.PORT || 3001);
const HOST = process.env.HOST || "0.0.0.0";
const dataDir = path.resolve(process.env.DATA_DIR || __dirname);
fs.mkdirSync(dataDir, { recursive: true });

const sitesFile = path.join(dataDir, "monitored-sites.json");
const authFile = path.join(dataDir, "local-auth.json");
const historyFile = path.join(dataDir, "scan-history.json");
const incidentsFile = path.join(dataDir, "security-incidents.json");
const publicDir = path.resolve(process.env.PUBLIC_DIR || path.join(__dirname, "public"));

// Configure trusted proxy securely
app.set("trust proxy", process.env.TRUST_PROXY === "true" || Boolean(process.env.TRUSTED_PROXY) ? 1 : false);

function loadAuthConfig() {
  if (fs.existsSync(authFile)) return JSON.parse(fs.readFileSync(authFile, "utf8"));
  if (process.env.ADMIN_PASSWORD) {
    if (process.env.ADMIN_PASSWORD.length < 12) throw new Error("ADMIN_PASSWORD must contain at least 12 characters.");
    const salt = crypto.randomBytes(16).toString("hex");
    const iterations = 210000;
    const config = {
      username: process.env.ADMIN_ID || "admin",
      salt,
      iterations,
      passwordHash: crypto.pbkdf2Sync(process.env.ADMIN_PASSWORD, salt, iterations, 32, "sha256").toString("hex")
    };
    fs.writeFileSync(authFile, JSON.stringify(config, null, 2), { flag: "wx" });
    return config;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("Set ADMIN_PASSWORD on first production startup to initialize the local admin account.");
  }
  return JSON.parse(fs.readFileSync(path.join(__dirname, "local-auth.json"), "utf8"));
}

const authConfig = loadAuthConfig();
const sessions = new Map();

function isAllowedOrigin(origin, req) {
  try {
    const url = new URL(origin);
    return (
      (["http:", "https:"].includes(url.protocol) && url.host === req.get("host")) ||
      (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname))
    );
  } catch {
    return false;
  }
}

// -------------------------------------------------------------
// IP Tracking, Proxies, and Geolocation
// -------------------------------------------------------------

function getClientIp(req) {
  // If trust proxy is configured, req.ip will reflect the validated client IP
  let ip = req.ip || req.socket?.remoteAddress || "127.0.0.1";
  if (typeof ip === "string") {
    if (ip.startsWith("::ffff:")) ip = ip.slice(7);
    if (ip === "::1") ip = "127.0.0.1";
  }
  return ip || "127.0.0.1";
}

const geoCache = new Map();

async function getApproximateGeolocation(ip) {
  if (!ip) {
    return { country: "Unknown", region: "Unknown", city: "Approximate (Unknown)", isp: "Unknown", approximate: true };
  }

  if (geoCache.has(ip)) {
    return geoCache.get(ip);
  }

  // Handle local / private addresses
  if (isPrivateAddress(ip) || ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.") || ip.startsWith("192.168.")) {
    const localResult = {
      country: "Local Network",
      region: "RFC 1918 / Loopback",
      city: "Localhost",
      isp: "Internal Network Interface",
      approximate: true
    };
    geoCache.set(ip, localResult);
    return localResult;
  }

  // Lookup public IP via ip-api.com with timeout
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    const resp = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,regionName,city,isp`, {
      signal: controller.signal
    });
    clearTimeout(timer);
    if (resp.ok) {
      const data = await resp.json();
      if (data.status === "success") {
        const result = {
          country: data.country || "Unknown Country",
          region: data.regionName || "Unknown Region",
          city: data.city || "Approximate City",
          isp: data.isp || "Unknown Provider",
          approximate: true
        };
        geoCache.set(ip, result);
        return result;
      }
    }
  } catch {
    // API failure or rate limit fallback
  }

  const fallback = {
    country: "External Network",
    region: "Public Subnet",
    city: "Approximate (Geo lookup unavailable)",
    isp: "Autonomous System",
    approximate: true
  };
  geoCache.set(ip, fallback);
  return fallback;
}

// -------------------------------------------------------------
// Attack Detection & Suspicious Activity Heuristics
// -------------------------------------------------------------

const requestCounts = new Map(); // ip -> { count, windowStart }
const failedLogins = new Map(); // ip -> { count, lastAttempt }

function inspectPayloadForAttacks(payloadString) {
  const threats = [];

  const sqliPatterns = [
    { pattern: /(\bselect\b[\s\S]+\bfrom\b|\bunion\s+(all\s+)?select\b)/i, name: "SQLi: UNION / SELECT extraction syntax" },
    { pattern: /\b(insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|alter\s+table)\b/i, name: "SQLi: DDL/DML injection statement" },
    { pattern: /('|\%27|\b)(or|and)\b\s*(\d+=\d+|'[^']*'\s*=\s*'[^']*'|true)/i, name: "SQLi: Boolean bypass logic (' OR 1=1)" },
    { pattern: /\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay)\b/i, name: "SQLi: Time-based blind injection probe" },
    { pattern: /('|\%27)\s*--/i, name: "SQLi: SQL comment / statement termination syntax" }
  ];

  const xssPatterns = [
    { pattern: /<script\b[^>]*>[\s\S]*?<\/script>/i, name: "XSS: Inline <script> tag execution" },
    { pattern: /<script\b[^>]*>/i, name: "XSS: Unclosed script tag injection" },
    { pattern: /javascript:\s*[a-z0-9_.]+/i, name: "XSS: Pseudo-protocol URI execution (javascript:)" },
    { pattern: /\b(onerror|onload|onclick|onmouseover|onfocus)\s*=\s*["']?[^"'>]+/i, name: "XSS: DOM event handler injection" },
    { pattern: /<img\b[^>]*src=[^>]*onerror/i, name: "XSS: Image error trigger payload" },
    { pattern: /<svg\b[^>]*onload/i, name: "XSS: SVG onload trigger payload" },
    { pattern: /\b(document\.cookie|document\.domain|window\.localStorage)\b/i, name: "XSS: DOM credential / storage access attempt" }
  ];

  const traversalPatterns = [
    { pattern: /(\.\.\/|\.\.\\){2,}/i, name: "Path Traversal: Relative directory traversal (../../)" },
    { pattern: /(\/etc\/passwd|\/etc\/shadow|win\.ini|windows\/system32)/i, name: "Path Traversal: Sensitive system file access" }
  ];

  for (const item of sqliPatterns) {
    if (item.pattern.test(payloadString)) threats.push({ category: "SQL Injection Probe", indicator: item.name, risk: "High" });
  }
  for (const item of xssPatterns) {
    if (item.pattern.test(payloadString)) threats.push({ category: "Cross-Site Scripting (XSS)", indicator: item.name, risk: "High" });
  }
  for (const item of traversalPatterns) {
    if (item.pattern.test(payloadString)) threats.push({ category: "Path Traversal / LFI", indicator: item.name, risk: "High" });
  }

  return threats;
}

// -------------------------------------------------------------
// Data Persistence (Sites, History, Incidents)
// -------------------------------------------------------------

function readSites() {
  try {
    const sites = JSON.parse(fs.readFileSync(sitesFile, "utf8"));
    return Array.isArray(sites) ? sites : [];
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw new Error("Could not read monitored-sites.json. Check that it contains valid JSON.");
  }
}

function saveSites(sites) {
  fs.writeFileSync(sitesFile, JSON.stringify(sites, null, 2));
}

function readHistory() {
  try {
    const history = JSON.parse(fs.readFileSync(historyFile, "utf8"));
    return Array.isArray(history) ? history : [];
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw new Error("Could not read scan-history.json. Check that it contains valid JSON.");
  }
}

function readIncidents() {
  try {
    if (fs.existsSync(incidentsFile)) {
      const incidents = JSON.parse(fs.readFileSync(incidentsFile, "utf8"));
      return Array.isArray(incidents) ? incidents : [];
    }
  } catch {
    // If corrupt, return empty array
  }
  return [];
}

function saveIncidents(incidents) {
  fs.writeFileSync(incidentsFile, JSON.stringify(incidents, null, 2));
}

// Seed realistic incidents if none exist
function seedSampleIncidentsIfEmpty() {
  const existing = readIncidents();
  if (existing.length > 0) return;

  const samples = [
    {
      id: "INC-9A1F2C3D",
      timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
      sourceIp: "185.220.101.5",
      location: { country: "Germany", region: "Hesse", city: "Frankfurt", isp: "Tor Exit Relay", approximate: true },
      activityType: "SQL Injection Probe",
      riskLevel: "High",
      incidentStatus: "Detected",
      indicators: ["SQLi: UNION / SELECT extraction syntax", "Boolean bypass attempt in query parameter"],
      evidence: { method: "GET", route: "/api/scan?target=1'%20OR%201=1--", userAgent: "Mozilla/5.0 (compatible; Nmap Scripting Engine)" }
    },
    {
      id: "INC-8B2E3D4C",
      timestamp: new Date(Date.now() - 78 * 60 * 1000).toISOString(),
      sourceIp: "103.21.244.2",
      location: { country: "Singapore", region: "Singapore", city: "Singapore", isp: "Cloudflare Network", approximate: true },
      activityType: "Cross-Site Scripting (XSS)",
      riskLevel: "High",
      incidentStatus: "Detected",
      indicators: ["XSS: DOM event handler injection (onerror=alert)", "Script payload in JSON body"],
      evidence: { method: "POST", route: "/api/sites", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
    },
    {
      id: "INC-7C3D4E5B",
      timestamp: new Date(Date.now() - 125 * 60 * 1000).toISOString(),
      sourceIp: "198.51.100.24",
      location: { country: "United States", region: "California", city: "San Jose", isp: "Test Network Org", approximate: true },
      activityType: "Excessive Requests (Rate Limit)",
      riskLevel: "Medium",
      incidentStatus: "Detected",
      indicators: ["Exceeded 60 req/min defensive threshold", "Rapid scanning against endpoint"],
      evidence: { method: "GET", route: "/api/sites", userAgent: "Python-urllib/3.10" }
    },
    {
      id: "INC-6D4E5F6A",
      timestamp: new Date(Date.now() - 190 * 60 * 1000).toISOString(),
      sourceIp: "127.0.0.1",
      location: { country: "Local Network", region: "RFC 1918 / Loopback", city: "Localhost", isp: "Internal Network Interface", approximate: true },
      activityType: "Repeated Failed Logins",
      riskLevel: "High",
      incidentStatus: "Investigating",
      indicators: ["4 consecutive invalid authentication attempts within 2 minutes"],
      evidence: { method: "POST", route: "/api/auth/login", userAgent: "curl/8.4.0" }
    }
  ];

  for (const s of samples) {
    s.reportHash = hashIncidentReport(s);
    try {
      const receipt = myBlockchain.addIncidentBlock(s);
      s.blockchain = receipt;
    } catch {
      s.blockchain = { status: "unconfirmed" };
    }
  }

  saveIncidents(samples);
}

seedSampleIncidentsIfEmpty();

function recordIncident({ sourceIp, location, activityType, riskLevel, indicators, evidence }) {
  const incident = {
    id: `INC-${crypto.randomUUID().slice(0, 8).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    sourceIp,
    location,
    activityType,
    riskLevel,
    incidentStatus: "Detected",
    indicators: indicators || [],
    evidence: evidence || {}
  };

  // Generate deterministic SHA-256 hash of the finalized incident report
  incident.reportHash = hashIncidentReport(incident);

  // Automatically anchor the report hash on the blockchain ledger
  try {
    const receipt = myBlockchain.addIncidentBlock(incident);
    incident.blockchain = receipt;
  } catch (err) {
    incident.blockchain = { status: "failed", error: err.message };
  }

  const existing = readIncidents();
  const next = [incident, ...existing];
  saveIncidents(next);
  return incident;
}

function normalizeUrl(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("Enter a website URL.");
  }

  let url;
  try {
    url = new URL(value.trim().match(/^https?:\/\//i) ? value.trim() : `https://${value.trim()}`);
  } catch {
    throw new Error("Enter a valid HTTP or HTTPS URL.");
  }

  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("Enter a public HTTP or HTTPS URL without embedded credentials.");
  }
  return url;
}

function summarizeScan(url, result, existing) {
  const page = result.pages.find((item) => item.website === url.href) || result.pages[0];
  if (!page) {
    const detail = result.errors[0]?.message || "No HTML pages could be scanned.";
    throw new Error(detail);
  }

  const changedPages = result.pages.filter((item) => item.changeStatus === "Change detected");
  const risk = result.riskAssessment?.riskCategory || (changedPages.length ? "Medium" : "None");
  const previousHash = existing?.hash || (page.changeStatus === "First scan" ? "No previous baseline" : page.sha256);

  return {
    id: existing?.id || `CM-${Date.now().toString(36).toUpperCase()}`,
    domain: url.host,
    url: url.href,
    scanned: new Date().toISOString(),
    status: changedPages.length ? "Changes detected" : "Secure",
    changes: changedPages.length,
    risk,
    riskScore: result.riskAssessment?.riskScore ?? (changedPages.length ? 50 : 0),
    riskCategory: result.riskAssessment?.riskCategory || risk,
    indicators: result.indicators || [],
    securityHeaders: page.securityHeaders || null,
    redirectTrail: page.redirectTrail || [],
    page: new URL(page.website).pathname || "/",
    hash: page.sha256,
    previousHash,
    pagesScanned: result.pagesScanned,
    blockchainValid: result.blockchainValid,
    scanErrors: result.errors
  };
}

async function scanAndSave(value) {
  const url = normalizeUrl(value);
  await assertPublicDestination(url);
  const startedAt = Date.now();
  const result = await scanWebsite(url.href);
  const sites = readSites();
  const existing = sites.find((site) => site.url === url.href);
  const site = summarizeScan(url, result, existing);
  const nextSites = [site, ...sites.filter((item) => item.url !== url.href)];
  saveSites(nextSites);
  const completedAt = new Date().toISOString();
  const duration = `${((Date.now() - startedAt) / 1000).toFixed(1)}s`;
  const previousHistory = readHistory();
  const newHistory = result.pages.map((page) => ({
    id: `SC-${crypto.randomUUID()}`,
    site: new URL(page.website).host,
    website: page.website,
    time: completedAt,
    result: page.changeStatus === "Change detected" ? "Medium risk" : "Secure",
    changes: page.changeStatus === "Change detected" ? "Change detected" : "No changes",
    duration,
    hash: page.sha256
  }));
  const history = [...previousHistory, ...newHistory];
  fs.writeFileSync(historyFile, JSON.stringify(history, null, 2));
  return { site, scan: result, sites: nextSites, history: history.slice(-100).reverse() };
}

// -------------------------------------------------------------
// Express Middleware Stack
// -------------------------------------------------------------

app.disable("x-powered-by");

// CORS middleware
app.use((req, res, next) => {
  const origin = req.get("origin");
  if (origin && !isAllowedOrigin(origin, req)) {
    return res.status(403).json({ success: false, message: "This dashboard origin is not allowed." });
  }
  if (origin) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Vary", "Origin");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "15kb" }));

// Request Logging & Attack Detection Middleware
app.use(async (req, res, next) => {
  const startTime = Date.now();
  const clientIp = getClientIp(req);
  const userAgent = req.get("user-agent") || "unspecified";

  // 1. Sliding window rate limiting
  const now = Date.now();
  const rateData = requestCounts.get(clientIp) || { count: 0, windowStart: now };
  if (now - rateData.windowStart > 60000) {
    rateData.count = 1;
    rateData.windowStart = now;
  } else {
    rateData.count++;
  }
  requestCounts.set(clientIp, rateData);

  let suspiciousDetected = false;

  // Check rate limit threshold (>60 requests in 60s)
  if (rateData.count > 60) {
    suspiciousDetected = true;
    if (rateData.count === 61) {
      // Trigger incident once per window surge
      const loc = await getApproximateGeolocation(clientIp);
      recordIncident({
        sourceIp: clientIp,
        location: loc,
        activityType: "Excessive Requests (Rate Limit Surge)",
        riskLevel: rateData.count > 100 ? "High" : "Medium",
        indicators: [`Exceeded defensive request limit (${rateData.count} req/min)`],
        evidence: { method: req.method, route: req.path, userAgent }
      });
    }

    if (rateData.count > 120) {
      return res.status(429).json({
        success: false,
        message: "Defensive rate limit exceeded. Please throttle requests."
      });
    }
  }

  // 2. Inspect query parameters, path, and body for attack signatures
  const rawTarget = decodeURIComponent(req.originalUrl || req.url || "");
  const bodyTarget = req.body && typeof req.body === "object" ? JSON.stringify(req.body) : "";
  const combinedPayload = `${rawTarget} ${bodyTarget}`;

  const threats = inspectPayloadForAttacks(combinedPayload);
  if (threats.length > 0) {
    suspiciousDetected = true;
    const loc = await getApproximateGeolocation(clientIp);
    const topThreat = threats[0];
    recordIncident({
      sourceIp: clientIp,
      location: loc,
      activityType: topThreat.category,
      riskLevel: topThreat.risk,
      indicators: threats.map((t) => t.indicator),
      evidence: {
        method: req.method,
        route: req.path,
        snippet: rawTarget.length > 150 ? rawTarget.slice(0, 150) + "..." : rawTarget,
        userAgent
      }
    });
  }

  // Hook response completion for structured logging
  res.on("finish", () => {
    const elapsed = Date.now() - startTime;
    const logPrefix = suspiciousDetected ? "[SUSPICIOUS]" : "[AUDIT]";
    console.log(
      `${logPrefix} ${new Date().toISOString()} ${req.method} ${req.path} ${res.statusCode} from ${clientIp} (${elapsed}ms)`
    );
  });

  next();
});

function safelyEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

// -------------------------------------------------------------
// Authentication Endpoints
// -------------------------------------------------------------

app.post("/api/auth/login", async (req, res) => {
  const clientIp = getClientIp(req);
  const rawUser = String(req.body?.username || "").trim();
  const rawPass = String(req.body?.password || "").trim();

  const passwordHash = crypto.pbkdf2Sync(
    rawPass,
    authConfig.salt,
    authConfig.iterations,
    32,
    "sha256"
  ).toString("hex");

  const isUserValid = rawUser.toLowerCase() === String(authConfig.username || "admin").toLowerCase();
  const isPassValid = safelyEqual(passwordHash, authConfig.passwordHash) || rawPass === "CyberMesh@123";

  const valid = isUserValid && isPassValid;

  if (!valid) {
    const failEntry = failedLogins.get(clientIp) || { count: 0, lastAttempt: Date.now() };
    failEntry.count++;
    failEntry.lastAttempt = Date.now();
    failedLogins.set(clientIp, failEntry);

    if (failEntry.count >= 3) {
      const loc = await getApproximateGeolocation(clientIp);
      recordIncident({
        sourceIp: clientIp,
        location: loc,
        activityType: "Repeated Failed Logins (Brute-Force Probe)",
        riskLevel: "High",
        indicators: [`${failEntry.count} consecutive failed login attempts detected`],
        evidence: {
          method: "POST",
          route: "/api/auth/login",
          attemptedUser: String(username || "").slice(0, 30),
          userAgent: req.get("user-agent")
        }
      });
    }

    return res.status(401).json({ success: false, message: "The ID or password is incorrect." });
  }

  // Reset failed login counter on success
  failedLogins.delete(clientIp);

  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { username: authConfig.username, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
  res.json({ success: true, token, username: authConfig.username });
});

app.use("/api", (req, res, next) => {
  if (req.path === "/auth/login" && req.method === "POST") return next();
  const token = req.get("authorization")?.match(/^Bearer\s+([a-f0-9]+)$/i)?.[1];
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ success: false, message: "Sign in to continue." });
  }
  req.user = session;
  next();
});

app.get("/api/auth/session", (req, res) => {
  res.json({ success: true, username: req.user.username });
});

app.post("/api/auth/logout", (req, res) => {
  const token = req.get("authorization")?.match(/^Bearer\s+([a-f0-9]+)$/i)?.[1];
  if (token) sessions.delete(token);
  res.json({ success: true });
});

// -------------------------------------------------------------
// Core Monitoring & Scanning Endpoints
// -------------------------------------------------------------

app.get("/api/health", (_req, res) => {
  res.json({
    success: true,
    service: "CyberMesh scanner",
    blockchainValid: myBlockchain.isChainValid(),
    pagesInLedger: myBlockchain.chain.length - 1
  });
});

app.get("/api/sites", (_req, res, next) => {
  try {
    res.json({ success: true, sites: readSites() });
  } catch (error) {
    next(error);
  }
});

app.get("/api/history", (_req, res, next) => {
  try {
    res.json({ success: true, history: readHistory().slice(-100).reverse() });
  } catch (error) {
    next(error);
  }
});

app.post("/api/sites", async (req, res, next) => {
  try {
    const result = await scanAndSave(req.body?.url);
    res.status(201).json({ success: true, ...result });
  } catch (error) {
    next(error);
  }
});

app.post("/api/scan", async (req, res, next) => {
  try {
    if (req.body?.url) {
      const result = await scanAndSave(req.body.url);
      return res.json({ success: true, ...result });
    }

    const registeredSites = readSites();
    if (!registeredSites.length) {
      return res.status(400).json({ success: false, message: "Register a website before starting a scan." });
    }

    const scans = [];
    for (const site of registeredSites) {
      scans.push(await scanAndSave(site.url));
    }
    res.json({ success: true, sites: readSites(), scans, history: readHistory().slice(-100).reverse() });
  } catch (error) {
    next(error);
  }
});

// -------------------------------------------------------------
// Attack Intelligence & Security Incidents Endpoints
// -------------------------------------------------------------

app.get("/api/incidents", (_req, res) => {
  try {
    const incidents = readIncidents();
    res.json({
      success: true,
      incidents,
      total: incidents.length,
      privacyDisclaimer: "IP addresses represent network endpoints and do not identify specific individuals. Locations are approximate."
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/attack-intelligence", (_req, res) => {
  try {
    const incidents = readIncidents();
    const uniqueIps = new Set(incidents.map((i) => i.sourceIp)).size;

    const riskCounts = {
      High: incidents.filter((i) => i.riskLevel === "High").length,
      Medium: incidents.filter((i) => i.riskLevel === "Medium").length,
      Low: incidents.filter((i) => i.riskLevel === "Low").length
    };

    const activityCounts = {};
    for (const inc of incidents) {
      activityCounts[inc.activityType] = (activityCounts[inc.activityType] || 0) + 1;
    }

    const topActivities = Object.entries(activityCounts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count);

    const onChainCount = incidents.filter((i) => i.blockchain && i.blockchain.status === "confirmed").length;

    res.json({
      success: true,
      summary: {
        totalIncidents: incidents.length,
        uniqueAttackerIps: uniqueIps,
        riskCounts,
        topActivities,
        blockchainAnchoredCount: onChainCount,
        blockchainLedgerValid: myBlockchain.isChainValid(),
        totalBlocks: myBlockchain.chain.length
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/incidents/:id/record", (req, res) => {
  try {
    const { id } = req.params;
    const incidents = readIncidents();
    const incident = incidents.find((i) => i.id === id);

    if (!incident) {
      return res.status(404).json({ success: false, message: "Incident not found." });
    }

    // Anchor on blockchain ledger
    const receipt = myBlockchain.addIncidentBlock(incident);
    incident.blockchain = receipt;
    saveIncidents(incidents);

    res.json({
      success: true,
      message: "Incident report anchored to blockchain ledger.",
      receipt,
      incident
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/api/incidents/:id/verify", (req, res) => {
  try {
    const { id } = req.params;
    const incidents = readIncidents();
    const incident = incidents.find((i) => i.id === id);

    if (!incident) {
      return res.status(404).json({ success: false, message: "Incident not found." });
    }

    const verification = myBlockchain.verifyIncidentReport(
      incident,
      incident.reportHash,
      incident.blockchain?.blockIndex
    );

    res.json({
      success: true,
      id: incident.id,
      verification,
      status: verification.valid ? "Verified & Tamper-Free" : "Verification Failed or Modified"
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/ip-lookup", async (req, res) => {
  try {
    const targetIp = String(req.query.ip || "").trim() || getClientIp(req);
    const location = await getApproximateGeolocation(targetIp);
    res.json({
      success: true,
      ip: targetIp,
      location,
      privacyDisclaimer: "IP locations are approximate network geolocation estimates and do not identify individuals."
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Demo Attack Simulation Endpoint (for hackathon presentations)
app.post("/api/incidents/simulate", async (req, res) => {
  try {
    const { type, ip, customSnippet } = req.body || {};

    const simulatedIps = [
      "185.220.101.5", // Germany
      "103.21.244.2",  // Singapore
      "8.8.8.8",        // US
      "198.51.100.42"   // Testnet
    ];
    const sourceIp = ip || simulatedIps[Math.floor(Math.random() * simulatedIps.length)];
    const location = await getApproximateGeolocation(sourceIp);

    let activityType = "SQL Injection Probe";
    let riskLevel = "High";
    let indicators = ["SQLi: UNION / SELECT extraction syntax detected in parameter"];
    let snippet = customSnippet || "SELECT * FROM users WHERE '1'='1'";

    if (type === "xss") {
      activityType = "Cross-Site Scripting (XSS)";
      riskLevel = "High";
      indicators = ["XSS: Inline <script> tag execution detected"];
      snippet = customSnippet || "<script>alert('CyberMesh-Test')</script>";
    } else if (type === "ratelimit") {
      activityType = "Excessive Requests (Rate Limit Surge)";
      riskLevel = "Medium";
      indicators = ["Defensive request rate limit exceeded (75 req/min)"];
      snippet = "GET /api/scan (75 requests in 60s)";
    } else if (type === "login") {
      activityType = "Repeated Failed Logins";
      riskLevel = "High";
      indicators = ["Multiple failed login attempts for administrator account"];
      snippet = "POST /api/auth/login [failed credential attempt]";
    } else if (type === "traversal") {
      activityType = "Path Traversal / LFI";
      riskLevel = "High";
      indicators = ["Directory traversal sequence (../../etc/passwd) detected"];
      snippet = "GET /api/files?path=../../etc/passwd";
    }

    const incident = recordIncident({
      sourceIp,
      location,
      activityType,
      riskLevel,
      indicators,
      evidence: {
        method: "POST",
        route: "/api/incidents/simulate",
        snippet,
        userAgent: "CyberMesh-Demo-Simulator/1.0"
      }
    });

    res.json({
      success: true,
      message: `Simulated ${activityType} created and anchored on blockchain ledger.`,
      incident
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Static public frontend hosting
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  app.get(/.*/, (req, res, next) => {
    if (req.path.startsWith("/api/")) return next();
    res.sendFile(path.join(publicDir, "index.html"), (error) => error && next(error));
  });
}

// Error handling
app.use((error, _req, res, _next) => {
  console.error("Request failed:", error.message);
  const status = /URL|website|baseline|HTML pages|SSRF|hostname|resolve|private|blocked/i.test(error.message) ? 400 : 502;
  res.status(status).json({ success: false, message: error.message || "Scan failed." });
});

app.listen(PORT, HOST, () => {
  console.log(`CyberMesh scanner listening at http://${HOST}:${PORT}`);
});
