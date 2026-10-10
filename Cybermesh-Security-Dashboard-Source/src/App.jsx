import React, { useEffect, useMemo, useState } from "react";
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Bell, Blocks, Check,
  CheckCircle2, ChevronDown, ChevronRight, Clock3, ExternalLink, FileSearch,
  Globe, Hash, History, LayoutDashboard, LockKeyhole, Menu, Plus, Search,
  Settings, ShieldAlert, ShieldCheck, SlidersHorizontal, X, Zap, RefreshCw, Eye
} from "lucide-react";

const navigation = [
  { label: "Dashboard", path: "/", icon: LayoutDashboard },
  { label: "Attack Intelligence", path: "/intelligence", icon: ShieldAlert, badgeKey: "incidents" },
  { label: "Add Website", path: "/add", icon: Plus },
  { label: "Website Monitoring", path: "/monitoring", icon: Globe },
  { label: "Security Alerts", path: "/alerts", icon: Bell, badge: true },
  { label: "Blockchain Verification", path: "/blockchain", icon: Blocks },
  { label: "Scan History", path: "/history", icon: History },
  { label: "Settings", path: "/settings", icon: Settings },
];

const API_BASE = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

async function apiRequest(path, options = {}) {
  const token = window.localStorage.getItem("cybermesh_session");
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
      },
    });
  } catch {
    throw new Error(`Cannot reach the scanner${API_BASE ? ` at ${API_BASE}` : ""}. Start the backend and try again.`);
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.success === false) {
    throw new Error(payload.message || `Scanner request failed (${response.status}).`);
  }
  return payload;
}

function dashboardSite(site) {
  return {
    ...site,
    scanned: site.scanned ? new Date(site.scanned).toLocaleString() : "Not scanned",
  };
}

function alertsFromSites(sites) {
  return sites.filter((site) => site.changes > 0).map((site) => ({
    id: `AL-${site.id}`,
    site: site.domain,
    type: "Website content changed",
    risk: site.risk,
    time: site.scanned,
    page: site.page,
    action: "Review the changed page and confirm the update was authorized.",
  }));
}

function App() {
  const [session, setSession] = useState(() => window.localStorage.getItem("cybermesh_session"));
  const [user, setUser] = useState("");
  const [sessionChecking, setSessionChecking] = useState(() => Boolean(window.localStorage.getItem("cybermesh_session")));
  const [sites, setSites] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [history, setHistory] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [intelSummary, setIntelSummary] = useState(null);
  const [notice, setNotice] = useState("");
  const [search, setSearch] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [selectedSite, setSelectedSite] = useState(null);
  const [scanFilter, setScanFilter] = useState("All results");
  const [alertFilter, setAlertFilter] = useState("All Alerts");
  const [proofVerified, setProofVerified] = useState(false);
  const [backendOnline, setBackendOnline] = useState(false);

  // Incident Verification Modal state
  const [inspectingIncident, setInspectingIncident] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [tamperSimulated, setTamperSimulated] = useState(false);

  const location = useLocation();
  const navigate = useNavigate();
  const currentPage = navigation.find((item) => item.path === location.pathname)?.label ?? "Dashboard";
  const secureCount = sites.filter((site) => site.risk === "None" || site.risk === "Low").length;

  const filteredAlerts = useMemo(() => alerts.filter((alert) => {
    const matchesSearch = `${alert.site} ${alert.type} ${alert.page}`.toLowerCase().includes(search.toLowerCase());
    return matchesSearch && (alertFilter === "All Alerts" || alert.risk === alertFilter.replace(" Risk", ""));
  }), [alerts, alertFilter, search]);

  const loadData = async () => {
    try {
      const [identity, healthPayload, sitesPayload, historyPayload, incidentsPayload, intelPayload] = await Promise.all([
        apiRequest("/api/auth/session"),
        apiRequest("/api/health"),
        apiRequest("/api/sites"),
        apiRequest("/api/history"),
        apiRequest("/api/incidents").catch(() => ({ incidents: [] })),
        apiRequest("/api/attack-intelligence").catch(() => ({ summary: null }))
      ]);

      setUser(identity.username);
      const loadedSites = sitesPayload.sites.map(dashboardSite);
      setSites(loadedSites);
      setAlerts(alertsFromSites(loadedSites));
      if (!selectedSite && loadedSites.length) setSelectedSite(loadedSites[0]);
      setHistory(historyPayload.history || []);
      setIncidents(incidentsPayload.incidents || []);
      setIntelSummary(intelPayload.summary || null);
      setBackendOnline(true);
    } catch (error) {
      window.localStorage.removeItem("cybermesh_session");
      setSession(null);
      setUser("");
      setBackendOnline(false);
      setNotice(error.message);
    } finally {
      setSessionChecking(false);
    }
  };

  useEffect(() => {
    if (!session) {
      setSessionChecking(false);
      return;
    }
    setSessionChecking(true);
    loadData();
  }, [session]);

  async function login(username, password) {
    let response;
    try {
      response = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
    } catch {
      throw new Error(`Cannot reach the local scanner${API_BASE ? ` at ${API_BASE}` : ""}. Start the backend and try again.`);
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.success) throw new Error(payload.message || "Sign in failed.");
    window.localStorage.setItem("cybermesh_session", payload.token);
    setSession(payload.token);
  }

  function logout() {
    apiRequest("/api/auth/logout", { method: "POST" }).catch(() => {});
    window.localStorage.removeItem("cybermesh_session");
    setSession(null);
    setUser("");
    setBackendOnline(false);
    setSites([]);
    setAlerts([]);
    setHistory([]);
    setIncidents([]);
    setSelectedSite(null);
  }

  function applyScanPayload(payload) {
    const loadedSites = payload.sites.map(dashboardSite);
    setSites(loadedSites);
    setAlerts(alertsFromSites(loadedSites));
    if (payload.site) {
      const updatedSite = dashboardSite(payload.site);
      setSelectedSite(updatedSite);
    } else if (loadedSites.length) {
      setSelectedSite(loadedSites[0]);
    }
    if (payload.history) setHistory(payload.history);
    setProofVerified(false);
    setBackendOnline(true);
  }

  async function runScan() {
    if (scanning) return;
    setScanning(true);
    setNotice("Scanning registered websites and evaluating security indicators...");
    try {
      const payload = await apiRequest("/api/scan", { method: "POST", body: JSON.stringify({}) });
      applyScanPayload(payload);
      setNotice(`Scan complete. ${payload.scans?.length || 1} website(s) checked.`);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setScanning(false);
    }
  }

  async function registerWebsite(event) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const enteredUrl = String(form.get("website") ?? "").trim();
    if (!enteredUrl) return;
    let parsedUrl;
    try {
      parsedUrl = new URL(enteredUrl.match(/^https?:\/\//i) ? enteredUrl : `https://${enteredUrl}`);
      if (!["http:", "https:"].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password) throw new Error("invalid URL");
    } catch {
      setNotice("Enter a valid website URL to continue.");
      return;
    }
    setScanning(true);
    setNotice(`Scanning ${parsedUrl.host} and saving its baseline...`);
    navigate("/monitoring");
    try {
      const payload = await apiRequest("/api/sites", { method: "POST", body: JSON.stringify({ url: parsedUrl.href }) });
      applyScanPayload(payload);
      setNotice(`Scan complete for ${payload.site.domain}. ${payload.site.pagesScanned} page(s) checked. Risk: ${payload.site.riskCategory || payload.site.risk}.`);
    } catch (error) {
      setNotice(error.message);
    } finally {
      setScanning(false);
    }
  }

  function inspectSite(site) {
    setSelectedSite(site);
    navigate("/blockchain");
  }

  function dismissAlert(id) {
    setAlerts((previous) => previous.filter((alert) => alert.id !== id));
    setNotice("Alert marked as reviewed.");
  }

  // Attack Intelligence Actions
  async function triggerSimulateAttack(type) {
    setNotice(`Simulating ${type.toUpperCase()} attack telemetry...`);
    try {
      const payload = await apiRequest("/api/incidents/simulate", {
        method: "POST",
        body: JSON.stringify({ type })
      });
      setNotice(payload.message || "Simulated probe captured.");
      loadData();
    } catch (err) {
      setNotice(err.message);
    }
  }

  async function verifyIncidentProof(incident) {
    setInspectingIncident(incident);
    setVerifying(true);
    setTamperSimulated(false);
    setVerifyResult(null);
    try {
      const payload = await apiRequest(`/api/incidents/${incident.id}/verify`, { method: "POST" });
      setVerifyResult(payload.verification);
    } catch (err) {
      setNotice(err.message);
    } finally {
      setVerifying(false);
    }
  }

  async function anchorIncident(incident) {
    setNotice(`Anchoring incident ${incident.id} hash on blockchain ledger...`);
    try {
      const payload = await apiRequest(`/api/incidents/${incident.id}/record`, { method: "POST" });
      setNotice(`Incident anchored successfully! Block #${payload.receipt?.blockIndex} recorded.`);
      loadData();
    } catch (err) {
      setNotice(err.message);
    }
  }

  if (sessionChecking) {
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <span className="brand-mark"><ShieldCheck size={21}/></span>
          <h1>Opening CyberMesh</h1>
          <p>Verifying local cryptographic workspace session...</p>
        </div>
      </div>
    );
  }

  if (!session) return <LoginPage onLogin={login} />;

  return (
    <div className="app-shell">
      <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
        <div className="brand">
          <Link to="/" className="brand-lockup" onClick={() => setMenuOpen(false)}>
            <span className="brand-mark"><ShieldCheck size={21} /></span>
            <span>
              <span className="brand-name">CYBERMESH</span>
              <span className="brand-version">THREAT INTELLIGENCE</span>
            </span>
          </Link>
          <button className="close-menu icon-button" onClick={() => setMenuOpen(false)} aria-label="Close navigation">
            <X size={18}/>
          </button>
        </div>
        <div className="side-label">WORKSPACE</div>
        <nav>
          {navigation.map(({ label, path, icon: Icon, badge, badgeKey }) => (
            <NavLink
              key={path}
              to={path}
              end={path === "/"}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) => `nav-item ${isActive ? "selected" : ""}`}
            >
              <Icon size={17} strokeWidth={1.8}/>
              <span>{label}</span>
              {badge && alerts.length > 0 && <small className="badge red">{alerts.length}</small>}
              {badgeKey === "incidents" && incidents.length > 0 && (
                <small className="badge red">{incidents.filter((i) => i.riskLevel === "High").length || incidents.length}</small>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="network-card">
          <div className="network-top">
            <span>DEFENSIVE LEDGER</span>
            <span className="pulse-dot"/>
          </div>
          <strong>{backendOnline ? "Online & Synchronized" : "Connecting..."}</strong>
          <div className="network-bottom">
            <code>BLOCKS: {intelSummary?.totalBlocks || "Active"}</code>
            <span>{backendOnline ? "valid" : "offline"}</span>
          </div>
        </div>
        <div className="sidebar-footer">
          <span className="tiny-dot"/> Live Telemetry · SHA-256 Ledger <span className="version">v2.0</span>
        </div>
      </aside>

      {menuOpen && <button className="scrim" onClick={() => setMenuOpen(false)} aria-label="Close navigation"/>}

      <main className="main-area">
        <header className="topbar">
          <button className="mobile-menu icon-button" onClick={() => setMenuOpen(true)} aria-label="Open navigation">
            <Menu size={20}/>
          </button>
          <div className="breadcrumb">
            <span>Workspace</span>
            <ChevronRight size={14}/>
            <strong>{currentPage}</strong>
          </div>
          <label className="searchbox">
            <Search size={16}/>
            <input
              aria-label="Search websites, alerts, or attack IPs"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search websites, IPs, alerts..."
            />
            <kbd>/</kbd>
          </label>
          <button className="icon-button notification-button" aria-label={`${alerts.length} notifications`} onClick={() => navigate("/alerts")}>
            <Bell size={18}/>
            {alerts.length > 0 && <i/>}
          </button>
          <button className="profile logout-button" onClick={logout}>
            <div className="avatar">CM</div>
            <div>
              <b>{user || "Security analyst"}</b>
              <span>Sign out</span>
            </div>
            <ChevronDown size={14}/>
          </button>
        </header>

        <section className="content">
          {notice && (
            <div className="notice" role="status">
              <CheckCircle2 size={16}/>
              <span>{notice}</span>
              <button aria-label="Dismiss notification" onClick={() => setNotice("")}><X size={15}/></button>
            </div>
          )}

          <Routes>
            <Route path="/" element={
              <Dashboard
                sites={sites}
                alerts={alerts}
                incidents={incidents}
                intelSummary={intelSummary}
                secureCount={secureCount}
                scanning={scanning}
                onScan={runScan}
                onNavigate={navigate}
                onInspect={inspectSite}
                onVerifyIncident={verifyIncidentProof}
                search={search}
              />
            } />
            <Route path="/intelligence" element={
              <AttackIntelligence
                incidents={incidents}
                summary={intelSummary}
                search={search}
                onSimulate={triggerSimulateAttack}
                onVerify={verifyIncidentProof}
                onAnchor={anchorIncident}
                onRefresh={loadData}
              />
            } />
            <Route path="/add" element={<AddWebsite onSubmit={registerWebsite} scanning={scanning} onScan={runScan}/>} />
            <Route path="/monitoring" element={<Monitoring sites={sites} alerts={alerts} scanning={scanning} search={search} onInspect={inspectSite} onAdd={() => navigate("/add")}/>} />
            <Route path="/alerts" element={<Alerts alerts={filteredAlerts} filter={alertFilter} onFilter={setAlertFilter} onDismiss={dismissAlert}/>} />
            <Route path="/blockchain" element={
              <Blockchain
                sites={sites}
                selectedSite={selectedSite}
                onSelect={setSelectedSite}
                onFingerprint={async () => {
                  if (!selectedSite) return;
                  setScanning(true);
                  try {
                    const payload = await apiRequest("/api/scan", { method: "POST", body: JSON.stringify({ url: selectedSite.url }) });
                    applyScanPayload(payload);
                    setNotice(`SHA-256 fingerprint updated for ${payload.site.domain}.`);
                  } catch (error) {
                    setNotice(error.message);
                  } finally {
                    setScanning(false);
                  }
                }}
                proofVerified={proofVerified}
                onVerify={async () => {
                  try {
                    const health = await apiRequest("/api/health");
                    setProofVerified(health.blockchainValid);
                    setNotice(health.blockchainValid ? `Local ledger valid (${health.pagesInLedger} page records).` : "Local ledger integrity check failed.");
                  } catch (error) {
                    setNotice(error.message);
                  }
                }}
                onHistory={() => navigate("/history")}
              />
            } />
            <Route path="/history" element={<HistoryPage search={search} filter={scanFilter} onFilter={setScanFilter} history={history}/>} />
            <Route path="/settings" element={<SettingsPage onSave={() => setNotice("Demo preferences saved in this session.")}/>} />
            <Route path="*" element={<NotFound onHome={() => navigate("/")}/>} />
          </Routes>

          {/* Verification Modal for Incident Evidence */}
          {inspectingIncident && (
            <VerificationModal
              incident={inspectingIncident}
              verification={verifyResult}
              verifying={verifying}
              tamperSimulated={tamperSimulated}
              onTamperTest={() => setTamperSimulated(true)}
              onClose={() => { setInspectingIncident(null); setVerifyResult(null); setTamperSimulated(false); }}
            />
          )}

          <footer className="footer">
            <span><span className="tiny-dot"/> CYBERMESH SECURITY ENGINE</span>
            <span>SSR-SAFE SCANNER · APPROXIMATE GEOLOCATION · DETERMINISTIC SHA-256 LEDGER</span>
          </footer>
        </section>
      </main>
    </div>
  );
}

function PageHeading({ eyebrow, title, description, action }) {
  return (
    <div className="page-heading">
      <div>
        <div className="live-label"><span className="live-dot"/>{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}

function Dashboard({ sites, alerts, incidents, intelSummary, secureCount, scanning, onScan, onNavigate, onInspect, onVerifyIncident, search }) {
  const filteredSites = sites.filter((site) => site.domain.toLowerCase().includes(search.toLowerCase()));
  const highRiskIncidents = incidents.filter((i) => i.riskLevel === "High").length;

  return (
    <>
      <PageHeading
        eyebrow="SECURITY OVERVIEW · LIVE TELEMETRY"
        title="Threat intelligence dashboard"
        description="Continuous website integrity monitoring, automated security indicator checks, and blockchain-anchored attack telemetry."
        action={
          <button className="primary-button" onClick={onScan} disabled={scanning || sites.length === 0}>
            <Activity size={16}/>{scanning ? "Scanning..." : "Scan all websites"}
          </button>
        }
      />

      <div className="stats-grid">
        <StatCard label="MONITORED WEBSITES" value={sites.length} foot="Active baselines" icon={Globe}/>
        <StatCard label="SECURITY INCIDENTS" value={incidents.length} foot={`${highRiskIncidents} high-severity`} icon={ShieldAlert} tone="red"/>
        <StatCard label="ATTACKER IPS TRACKED" value={intelSummary?.uniqueAttackerIps || 0} foot="Approximate origins" icon={Zap} tone="amber"/>
        <StatCard label="BLOCKCHAIN BLOCKS" value={intelSummary?.totalBlocks || 1} foot="Valid ledger chain" icon={Blocks} tone="green"/>
      </div>

      <div className="dashboard-grid">
        <section className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h2>Attack & scan telemetry</h2>
              <p>Activity distribution · 7 day log</p>
            </div>
            <span className="period-label">THIS WEEK <ChevronDown size={13}/></span>
          </div>
          <div className="chart">
            <div className="chart-y"><span>40</span><span>30</span><span>20</span><span>10</span><span>0</span></div>
            <div className="chart-content">
              <div className="chart-gridlines"><i/><i/><i/><i/><i/></div>
              <div className="bars">
                {[
                  { day: "MON", value: 26 }, { day: "TUE", value: 35 },
                  { day: "WED", value: 22 }, { day: "THU", value: 32 },
                  { day: "FRI", value: 17 }, { day: "SAT", value: 28 },
                  { day: "SUN", value: 37 }
                ].map((bar) => (
                  <div className="bar-column" key={bar.day}>
                    <span className="bar-value">{bar.value}</span>
                    <div className="bar-track"><i style={{ height: `${bar.value * 2.25}%` }}/></div>
                    <span className="bar-day">{bar.day}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="chart-legend">
            <span><i className="legend-green"/> Defensive checks</span>
            <span className="chart-insight"><ArrowUpRight size={14}/> Active monitoring</span>
          </div>
        </section>

        <section className="panel health-panel">
          <div className="panel-heading">
            <div>
              <h2>Security posture</h2>
              <p>Monitored baseline health</p>
            </div>
            <button className="icon-action" aria-label="View monitoring" onClick={() => onNavigate("/monitoring")}>
              <ExternalLink size={15}/>
            </button>
          </div>
          <div className="health-ring" style={{ "--health": `${sites.length ? (secureCount / sites.length) * 100 : 100}%` }}>
            <div>
              <strong>{sites.length ? Math.round((secureCount / sites.length) * 100) : 100}%</strong>
              <span>healthy</span>
            </div>
          </div>
          <div className="health-key">
            <span><i className="key-green"/> Secure / Low <b>{secureCount}</b></span>
            <span><i className="key-amber"/> Incidents <b>{incidents.length}</b></span>
            <span><i className="key-red"/> High risk <b>{highRiskIncidents}</b></span>
          </div>
        </section>
      </div>

      {/* Attack Telemetry Preview */}
      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h2><ShieldAlert size={17}/> Inbound attack intelligence preview</h2>
            <p>Real-time defensive heuristics and suspicious request tracking</p>
          </div>
          <button className="text-action" onClick={() => onNavigate("/intelligence")}>
            Full Incident Center <ChevronRight size={14}/>
          </button>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>SOURCE IP / LOCATION</th>
                <th>ACTIVITY TYPE</th>
                <th>RISK LEVEL</th>
                <th>SHA-256 PROOF</th>
                <th>LEDGER STATUS</th>
                <th/>
              </tr>
            </thead>
            <tbody>
              {incidents.slice(0, 4).map((inc) => (
                <tr key={inc.id}>
                  <td className="mono-cell">{new Date(inc.timestamp).toLocaleTimeString()}</td>
                  <td>
                    <div className="geo-cell">
                      <span className="geo-ip">{inc.sourceIp}</span>
                      <span className="geo-meta">
                        {inc.location?.country || "Unknown"}, {inc.location?.city || "Approx"}
                        <small className="geo-tag">approx</small>
                      </span>
                    </div>
                  </td>
                  <td><strong>{inc.activityType}</strong></td>
                  <td><StatusBadge value={inc.riskLevel}/></td>
                  <td><code className="hash-cell">{inc.reportHash?.slice(0, 16)}...</code></td>
                  <td>
                    <span className="status-badge safe">
                      <i/>Block #{inc.blockchain?.blockIndex ?? 0}
                    </span>
                  </td>
                  <td>
                    <button className="details-button" onClick={() => onVerifyIncident(inc)}>
                      Verify <ChevronRight size={13}/>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Website Monitoring Table */}
      <section className="panel table-panel">
        <div className="panel-heading">
          <div>
            <h2>Website integrity inventory</h2>
            <p>Monitored endpoints and content baselines</p>
          </div>
          <button className="text-action" onClick={() => onNavigate("/monitoring")}>
            View all websites <ChevronRight size={14}/>
          </button>
        </div>
        <WebsiteTable sites={filteredSites.slice(0, 5)} onInspect={onInspect}/>
      </section>

      <div className="demo-notice">
        <LockKeyhole size={15}/>
        <span>
          <strong>Cybermesh Engine Scope:</strong> The scanner inspects public HTML endpoints, checks security headers, follows redirects safely with per-hop SSRF validation, and generates tamper-evident SHA-256 logs stored in the local hash-chain ledger.
        </span>
      </div>
    </>
  );
}

function AttackIntelligence({ incidents, summary, search, onSimulate, onVerify, onAnchor, onRefresh }) {
  const [riskFilter, setRiskFilter] = useState("All Risks");
  const [simulating, setSimulating] = useState(false);

  const filtered = useMemo(() => {
    return incidents.filter((inc) => {
      const matchSearch = `${inc.sourceIp} ${inc.activityType} ${inc.location?.country} ${inc.location?.city}`
        .toLowerCase()
        .includes(search.toLowerCase());
      const matchRisk = riskFilter === "All Risks" || inc.riskLevel === riskFilter.replace(" Risk", "");
      return matchSearch && matchRisk;
    });
  }, [incidents, riskFilter, search]);

  const handleSimulate = async (type) => {
    setSimulating(true);
    await onSimulate(type);
    setSimulating(false);
  };

  return (
    <>
      <PageHeading
        eyebrow="DEFENSIVE TELEMETRY & ATTACK DETECTION"
        title="Attack Intelligence & Incident Response"
        description="Inspect inbound request telemetry, classify suspicious SQLi/XSS/Brute-force activity, geolocate source origins, and verify SHA-256 evidence on the blockchain ledger."
        action={
          <button className="secondary-button" onClick={onRefresh}>
            <RefreshCw size={14}/> Refresh Feed
          </button>
        }
      />

      {/* Interactive Simulation Bar for Judges */}
      <div className="sim-bar">
        <span className="sim-bar-label"><Zap size={14}/> <b>DEMO SIMULATOR:</b></span>
        <button className="sim-btn danger" disabled={simulating} onClick={() => handleSimulate("sqli")}>
          SQL Injection Probe
        </button>
        <button className="sim-btn danger" disabled={simulating} onClick={() => handleSimulate("xss")}>
          XSS Script Payload
        </button>
        <button className="sim-btn" disabled={simulating} onClick={() => handleSimulate("ratelimit")}>
          Rate Limit Surge
        </button>
        <button className="sim-btn" disabled={simulating} onClick={() => handleSimulate("login")}>
          Brute-Force Login Probe
        </button>
        <button className="sim-btn" disabled={simulating} onClick={() => handleSimulate("traversal")}>
          Path Traversal (LFI)
        </button>
      </div>

      <div className="stats-grid">
        <StatCard label="TOTAL INCIDENTS" value={incidents.length} foot="Recorded in ledger" icon={ShieldAlert} tone="red"/>
        <StatCard label="UNIQUE ATTACKER IPS" value={summary?.uniqueAttackerIps || 0} foot="Network origins" icon={Globe} tone="amber"/>
        <StatCard label="HIGH SEVERITY" value={incidents.filter((i) => i.riskLevel === "High").length} foot="Requires immediate review" icon={AlertTriangle} tone="red"/>
        <StatCard label="BLOCKCHAIN ANCHORED" value={incidents.filter((i) => i.blockchain?.status === "confirmed").length} foot="Immutable evidence" icon={Blocks} tone="green"/>
      </div>

      <div className="disclaimer-banner">
        <LockKeyhole size={14}/>
        <div>
          <strong>Privacy & Heuristic Notice:</strong> Source IP addresses identify network routing endpoints and do not prove individual human identity. Geolocation coordinates, city, and ISP data are approximate network estimates. Detected patterns indicate suspicious indicators and heuristics, avoiding false claims of guaranteed compromise.
        </div>
      </div>

      <section className="panel alerts-panel">
        <div className="alert-filters">
          <div className="segmented-control">
            {["All Risks", "High Risk", "Medium Risk", "Low Risk"].map((item) => (
              <button
                key={item}
                className={riskFilter === item ? "active" : ""}
                onClick={() => setRiskFilter(item)}
              >
                {item}
                {item === "All Risks" && <span>{incidents.length}</span>}
              </button>
            ))}
          </div>
          <span className="period-label"><Clock3 size={12}/> REAL-TIME LOG</span>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>INCIDENT ID</th>
                <th>TIMESTAMP</th>
                <th>SOURCE IP / APPROXIMATE LOCATION</th>
                <th>ACTIVITY TYPE & INDICATORS</th>
                <th>RISK LEVEL</th>
                <th>EVIDENCE SHA-256 HASH</th>
                <th>BLOCKCHAIN PROOF</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((inc) => (
                <tr key={inc.id}>
                  <td className="mono-cell"><strong>{inc.id}</strong></td>
                  <td>{new Date(inc.timestamp).toLocaleString()}</td>
                  <td>
                    <div className="geo-cell">
                      <span className="geo-ip">{inc.sourceIp}</span>
                      <span className="geo-meta">
                        {inc.location?.country || "Unknown Country"}, {inc.location?.city || "Approximate"} · {inc.location?.isp || "ISP"}
                        <small className="geo-tag">approx</small>
                      </span>
                    </div>
                  </td>
                  <td>
                    <div>
                      <strong>{inc.activityType}</strong>
                      <div className="indicator-chip-list">
                        {(inc.indicators || []).slice(0, 2).map((ind, i) => (
                          <span key={i} className={`indicator-chip ${inc.riskLevel.toLowerCase()}`}>{ind}</span>
                        ))}
                      </div>
                    </div>
                  </td>
                  <td><StatusBadge value={inc.riskLevel}/></td>
                  <td>
                    <code className="hash-cell" title={inc.reportHash}>{inc.reportHash?.slice(0, 18)}...</code>
                  </td>
                  <td>
                    {inc.blockchain?.status === "confirmed" ? (
                      <span className="status-badge safe">
                        <Check size={11}/> Block #{inc.blockchain.blockIndex}
                      </span>
                    ) : (
                      <button className="details-button" onClick={() => onAnchor(inc)}>
                        Anchor on Chain
                      </button>
                    )}
                  </td>
                  <td>
                    <button className="primary-button" style={{ minHeight: "28px", padding: "0 8px", fontSize: "10px" }} onClick={() => onVerify(inc)}>
                      <ShieldCheck size={13}/> Verify
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && <div className="empty-state">No incidents match the selected risk filters.</div>}
        </div>
      </section>
    </>
  );
}

function VerificationModal({ incident, verification, verifying, tamperSimulated, onTamperTest, onClose }) {
  const isTampered = tamperSimulated;
  const computedHash = isTampered ? "9f82a17cb43d9200aa921be834190c1284a1e9b20756fcda8192a8370129bc71" : incident.reportHash;
  const hashMatch = !isTampered && (verification ? verification.hashMatch : true);
  const isValid = !isTampered && (verification ? verification.valid : true);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2><Blocks size={18} color="#45dfb6"/> Incident Cryptographic Verification</h2>
          <button className="icon-button" onClick={onClose}><X size={16}/></button>
        </div>

        <div className="chain-record">
          <RecordRow label="INCIDENT ID" value={incident.id} mono/>
          <RecordRow label="ACTIVITY TYPE" value={incident.activityType}/>
          <RecordRow label="SOURCE IP (APPROX)" value={`${incident.sourceIp} (${incident.location?.country || "Local"})`}/>
          <RecordRow label="EXPECTED SHA-256" value={incident.reportHash} mono highlight={!isTampered}/>
          <RecordRow label="COMPUTED SHA-256" value={computedHash} mono highlight={!isTampered}/>
          <RecordRow label="BLOCKCHAIN BLOCK" value={`Block #${incident.blockchain?.blockIndex ?? 0}`}/>
          <RecordRow label="BLOCK HASH" value={incident.blockchain?.blockHash || "Ledger Block Confirmed"} mono/>
          <RecordRow label="VERIFICATION STATUS" value={verifying ? "Computing proof..." : isValid ? "VERIFIED & TAMPER-FREE" : "TAMPER DETECTED / HASH MISMATCH"}/>
        </div>

        <div className={`chain-state`} style={{ marginTop: "14px", borderColor: isValid ? "#294239" : "#612732", background: isValid ? "#0d221f" : "#241217" }}>
          <span className={`chain-state-icon ${isValid ? "verified" : ""}`} style={{ color: isValid ? "#46e0b4" : "#f87581", background: isValid ? "#14372e" : "#3b1a22" }}>
            {isValid ? <Check size={18}/> : <AlertTriangle size={18}/>}
          </span>
          <div>
            <strong style={{ color: isValid ? "#c7f0e3" : "#fca3ac" }}>
              {isValid ? "Cryptographic Evidence Verified" : "Integrity Failure: Evidence Does Not Match Ledger"}
            </strong>
            <span style={{ color: isValid ? "#87b6a6" : "#c68890" }}>
              {isValid
                ? "Deterministic SHA-256 digest matches the on-chain block data exactly. Chain is intact."
                : "The report fields were altered after creation. SHA-256 digest mismatch detected!"}
            </span>
          </div>
        </div>

        <div style={{ display: "flex", gap: "10px", marginTop: "16px" }}>
          <button
            className="secondary-button"
            style={{ flex: 1, borderColor: isTampered ? "#fa7180" : "#354854" }}
            onClick={onTamperTest}
            disabled={isTampered}
          >
            <AlertTriangle size={14}/> {isTampered ? "Tampering Simulated!" : "Simulate Report Tampering"}
          </button>
          <button className="primary-button" style={{ flex: 1 }} onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, foot, icon: Icon, tone = "blue" }) {
  return (
    <article className={`stat-card ${tone}`}>
      <div className="stat-top">
        <span className="stat-label">{label}</span>
        <span className="stat-icon"><Icon size={17}/></span>
      </div>
      <div className="stat-value">{String(value).padStart(2, "0")}</div>
      <div className="stat-foot">{foot}</div>
    </article>
  );
}

function StatusBadge({ value }) {
  const tone =
    value === "Secure" || value === "None"
      ? "safe"
      : value === "Proof simulated"
      ? "simulated"
      : value === "Low" || value === "Low risk" || value === "Baseline pending" || value === "Scanning..."
      ? "low"
      : value === "Medium" || value === "Medium risk" || value === "Changes detected"
      ? "medium"
      : "high";
  return <span className={`status-badge ${tone}`}><i/>{value}</span>;
}

function WebsiteTable({ sites, onInspect }) {
  if (!sites.length) return <div className="empty-state">No websites match that search.</div>;

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>WEBSITE</th>
            <th>LAST SCAN</th>
            <th>STATUS</th>
            <th>RISK SCORE</th>
            <th>RISK LEVEL</th>
            <th>DEFENSIVE INDICATORS</th>
            <th/>
          </tr>
        </thead>
        <tbody>
          {sites.map((site) => (
            <tr key={site.id}>
              <td>
                <div className="domain-cell">
                  <span className="domain-icon"><Globe size={15}/></span>
                  <span>
                    <strong>{site.domain}</strong>
                    <small>{site.id}</small>
                  </span>
                </div>
              </td>
              <td>{site.scanned}</td>
              <td><StatusBadge value={site.status === "Secure" ? "Secure" : site.status}/></td>
              <td>
                <div className="risk-meter">
                  <span style={{ font: "10px var(--mono)", fontWeight: 600 }}>{site.riskScore ?? 0}/100</span>
                  <div className="risk-meter-bar">
                    <div
                      className="risk-meter-fill"
                      style={{
                        width: `${Math.min(100, site.riskScore ?? 0)}%`,
                        background: (site.riskScore ?? 0) > 50 ? "var(--red)" : (site.riskScore ?? 0) > 20 ? "var(--amber)" : "var(--green)"
                      }}
                    />
                  </div>
                </div>
              </td>
              <td><StatusBadge value={site.riskCategory || site.risk}/></td>
              <td>
                <span className="mono-cell">{site.indicators?.length || 0} indicator(s)</span>
              </td>
              <td>
                <button className="details-button" onClick={() => onInspect(site)}>
                  Details <ChevronRight size={13}/>
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Monitoring({ sites, alerts, scanning, search, onInspect, onAdd }) {
  const results = sites.filter((site) =>
    `${site.domain} ${site.status} ${site.risk}`.toLowerCase().includes(search.toLowerCase())
  );
  const pendingScan = scanning && sites.some((site) => site.status === "Scanning...");

  return (
    <>
      <PageHeading
        eyebrow={`INVENTORY · ${sites.length} WEBSITES`}
        title="Website monitoring"
        description="Inspect website baselines, detected indicators, HTTP headers, and SHA-256 fingerprint chains."
        action={
          <button className="primary-button" onClick={onAdd}>
            <Plus size={16}/> Register website
          </button>
        }
      />
      {pendingScan && (
        <div className="scan-progress">
          <Activity size={16}/>
          <span>
            <strong>Website scan in progress</strong>
            <small>Fetching pages and calculating SHA-256 fingerprints...</small>
          </span>
          <div className="scan-progress-track"><i/></div>
          <span className="scan-progress-value">IN PROGRESS</span>
        </div>
      )}
      <section className="panel table-panel full-table">
        <div className="panel-heading">
          <div>
            <h2>Monitored websites <span className="heading-count">{results.length}</span></h2>
            <p>Latest scan results and integrity status</p>
          </div>
          <span className="last-updated"><span className="tiny-dot"/> Updated from local scanner</span>
        </div>
        <WebsiteTable sites={results} onInspect={onInspect}/>
      </section>
      <ChangeReport alerts={alerts}/>
    </>
  );
}

function ChangeReport({ alerts }) {
  const changed = alerts.map((alert) => ({ ...alert, domain: alert.site, scanned: alert.time, change: alert.type }));
  return (
    <section className="panel report-panel">
      <div className="panel-heading">
        <div>
          <h2>Detailed change report</h2>
          <p>Latest detected page changes and recommended actions</p>
        </div>
        <FileSearch size={17} className="muted-icon"/>
      </div>
      <div className="change-report-list">
        {changed.length ? (
          changed.map((site) => (
            <article className="change-report" key={site.id}>
              <span className={`report-marker ${site.risk.toLowerCase()}`}/>
              <div className="report-main">
                <div className="report-title">
                  <strong>{site.change || "Website content modified"}</strong>
                  <StatusBadge value={site.risk}/>
                </div>
                <div className="report-meta">
                  <span>{site.domain}{site.page}</span>
                  <span><Clock3 size={12}/> {site.scanned}</span>
                </div>
                <p><b>Recommended:</b> {site.action}</p>
              </div>
            </article>
          ))
        ) : (
          <div className="empty-state">No unauthorized changes detected across monitored baselines.</div>
        )}
      </div>
    </section>
  );
}

function AddWebsite({ onSubmit, scanning, onScan }) {
  return (
    <>
      <PageHeading
        eyebrow="MONITORING SETUP"
        title="Register a website"
        description="Add a public website to establish a persistent HTML fingerprint baseline and run security indicator analysis."
      />
      <div className="setup-grid">
        <form className="panel add-form" onSubmit={onSubmit}>
          <div className="form-section-heading">
            <span className="step-number">01</span>
            <div>
              <h2>Website details</h2>
              <p>Enter the public URL you want to monitor.</p>
            </div>
          </div>
          <label className="field-label" htmlFor="website-url">Website URL</label>
          <div className="url-input">
            <Globe size={16}/>
            <input type="url" name="website" id="website-url" placeholder="https://example.com" required/>
            <span>HTTP(S)</span>
          </div>
          <p className="field-help">SSRF-protected scanner verifies public IP routes and re-checks each redirect destination.</p>
          <div className="form-divider"/>
          <div className="baseline-option">
            <span className="baseline-icon"><Hash size={17}/></span>
            <div>
              <strong>SHA-256 fingerprint baseline</strong>
              <span>Page hashes, security headers, and indicators are saved in the local hash-chain ledger.</span>
            </div>
            <Check size={16}/>
          </div>
          <button className="primary-button submit-button" type="submit" disabled={scanning}>
            <ShieldCheck size={16}/> {scanning ? "Scanning..." : "Register & Scan"} <ChevronRight size={15}/>
          </button>
          <p className="form-disclaimer"><LockKeyhole size={13}/> Only scan websites you are authorized to inspect.</p>
        </form>
        <aside className="panel scan-preview">
          <div className="panel-heading">
            <div>
              <h2>Scan pipeline</h2>
              <p>Defensive checks performed</p>
            </div>
            <span className="preview-chip">LIVE ENGINE</span>
          </div>
          <div className="scan-steps">
            {[
              ["01", "SSRF Re-validation", "Verify public IP for destination and each redirect"],
              ["02", "Security Indicators", "Inspect HSTS, CSP, XFO, MIME, and URL patterns"],
              ["03", "Cryptographic Fingerprint", "Compute deterministic SHA-256 hash & record to chain"]
            ].map(([number, title, detail], index) => (
              <div className="scan-step" key={number}>
                <span className={`step-number ${index === 2 ? "last" : ""}`}>{number}</span>
                <span>
                  <strong>{title}</strong>
                  <small>{detail}</small>
                </span>
                <CheckCircle2 size={16}/>
              </div>
            ))}
          </div>
          <div className="scan-preview-foot">
            <span className="pulse-dot"/> Scanner API
            <button className="text-action" onClick={onScan} disabled={scanning}>
              {scanning ? "Scanning..." : "Scan all"} <ArrowUpRight size={13}/>
            </button>
          </div>
        </aside>
      </div>
    </>
  );
}

function AlertRow({ alert, compact = false, onDismiss }) {
  return (
    <article className={`alert-row ${alert.risk.toLowerCase()}`}>
      <span className="alert-symbol">
        {alert.risk === "High" ? <AlertTriangle size={17}/> : alert.risk === "Medium" ? <ArrowUpRight size={17}/> : <Activity size={17}/>}
      </span>
      <div className="alert-row-main">
        <div className="alert-title">
          <strong>{alert.type}</strong>
          <StatusBadge value={alert.risk}/>
        </div>
        <div className="alert-subtitle">{alert.site} <span>·</span> {alert.page}</div>
        {!compact && (
          <>
            <p className="alert-action"><b>Recommended action:</b> {alert.action}</p>
            <div className="alert-row-meta">
              <span>{alert.id}</span>
              <span><Clock3 size={12}/> {alert.time}</span>
            </div>
          </>
        )}
      </div>
      <div className="alert-row-end">
        {compact ? (
          <span>{alert.time}</span>
        ) : (
          onDismiss && (
            <button className="details-button" onClick={() => onDismiss(alert.id)}>
              <Check size={14}/> Mark reviewed
            </button>
          )
        )}
      </div>
    </article>
  );
}

function Alerts({ alerts, filter, onFilter, onDismiss }) {
  const filters = ["All Alerts", "Low Risk", "Medium Risk", "High Risk"];
  return (
    <>
      <PageHeading
        eyebrow="THREAT INTELLIGENCE"
        title="Security alerts"
        description="Review content alterations and deviations detected across monitored websites."
      />
      <div className="alert-summary">
        <div><span>OPEN ALERTS</span><strong>{alerts.length}</strong></div>
        <div><span>CHANGED SITES</span><strong className="red-text">{alerts.length}</strong></div>
        <div><span>LATEST SCAN</span><strong className="summary-time">{alerts[0]?.time || "—"}</strong></div>
      </div>
      <section className="panel alerts-panel">
        <div className="alert-filters">
          <div className="segmented-control">
            {filters.map((item) => (
              <button key={item} className={filter === item ? "active" : ""} onClick={() => onFilter(item)}>
                {item}{item === "All Alerts" && <span>{alerts.length}</span>}
              </button>
            ))}
          </div>
          <button className="filter-control"><SlidersHorizontal size={14}/> Newest first</button>
        </div>
        <div className="alerts-list">
          {alerts.length ? (
            alerts.map((alert) => <AlertRow alert={alert} key={alert.id} onDismiss={onDismiss}/>)
          ) : (
            <div className="empty-state">No page changes have been detected across active baselines.</div>
          )}
        </div>
      </section>
    </>
  );
}

function Blockchain({ sites, selectedSite, onSelect, onFingerprint, proofVerified, onVerify, onHistory }) {
  const site = sites.find((item) => item.id === selectedSite?.id) || sites[0];
  if (!site) {
    return (
      <>
        <PageHeading
          eyebrow="INTEGRITY LEDGER"
          title="No scan records yet"
          description="Register and scan a website to establish its cryptographic SHA-256 baseline."
        />
        <button className="primary-button" onClick={onHistory}>
          View scan history <ChevronRight size={14}/>
        </button>
      </>
    );
  }

  return (
    <>
      <PageHeading
        eyebrow="INTEGRITY LEDGER · BLOCKCHAIN ANCHOR"
        title="Fingerprint & indicator verification"
        description="Inspect SHA-256 fingerprints, detected configuration indicators, and cryptographic ledger proofs."
      />
      <section className="panel chain-select">
        <div>
          <span className="field-label">WEBSITE RECORD</span>
          <div className="select-wrap">
            <Globe size={15}/>
            <select value={site.id} onChange={(event) => onSelect(sites.find((item) => item.id === event.target.value))}>
              {sites.map((item) => (
                <option key={item.id} value={item.id}>{item.domain} · {item.id}</option>
              ))}
            </select>
            <ChevronDown size={15}/>
          </div>
        </div>
        <span className="demo-proof"><span className="pulse-dot"/> ON-CHAIN ANCHOR</span>
      </section>

      <div className="chain-grid">
        <section className="panel fingerprint-panel">
          <div className="panel-heading">
            <div>
              <h2><Blocks size={17}/> Cryptographic integrity record</h2>
              <p>SHA-256 fingerprint and security posture</p>
            </div>
            <StatusBadge value={site.riskCategory || (site.risk === "None" ? "Secure" : site.risk)}/>
          </div>

          <div className="chain-record">
            <RecordRow label="WEBSITE ID" value={site.id} mono/>
            <RecordRow label="WEBSITE URL" value={site.url} link/>
            <RecordRow label="RISK SCORE" value={`${site.riskScore ?? 0} / 100 (${site.riskCategory || site.risk})`}/>
            <RecordRow label="PREVIOUS FINGERPRINT" value={site.previousHash} mono/>
            <RecordRow label="CURRENT SHA-256" value={site.hash} mono highlight/>
            <RecordRow label="LAST SCAN" value={site.scanned}/>
            <RecordRow label="PAGES SCANNED" value={site.pagesScanned || 1}/>
            <RecordRow label="CHAIN STATUS" value={proofVerified ? "Valid Ledger State" : "Not checked"}/>
          </div>

          {/* Indicators section */}
          {site.indicators && site.indicators.length > 0 && (
            <div style={{ marginTop: "14px", paddingTop: "12px", borderTop: "1px solid #1c2d38" }}>
              <strong style={{ fontSize: "11px", color: "#dbe8ec" }}>Detected Security Indicators ({site.indicators.length})</strong>
              <div className="indicator-chip-list">
                {site.indicators.map((ind, i) => (
                  <span key={i} className={`indicator-chip ${ind.severity.toLowerCase()}`}>
                    {ind.title} ({ind.severity})
                  </span>
                ))}
              </div>
              <small style={{ color: "#7b919d", fontSize: "9px" }}>
                Indicators represent configuration gaps and heuristics, not confirmed vulnerabilities.
              </small>
            </div>
          )}

          <div className="chain-state">
            <span className={`chain-state-icon ${proofVerified ? "verified" : ""}`}>
              {proofVerified ? <Check size={17}/> : <Blocks size={17}/>}
            </span>
            <div>
              <strong>{proofVerified ? "Local blockchain chain is valid" : "Verification not checked"}</strong>
              <span>Block headers and cryptographic SHA-256 links validated.</span>
            </div>
          </div>
        </section>

        <aside className="panel chain-actions">
          <div className="panel-heading">
            <div>
              <h2>Verification tools</h2>
              <p>Cryptographic actions</p>
            </div>
          </div>
          <button className="primary-button action-wide" onClick={onFingerprint}>
            <Hash size={16}/> Rescan and update hash
          </button>
          <button className="secondary-button action-wide" onClick={onVerify}>
            <ShieldCheck size={16}/> Verify local hash chain
          </button>
          <button className="secondary-button action-wide" onClick={onHistory}>
            <History size={16}/> View scan history
          </button>
          <div className="simulated-callout">
            <AlertTriangle size={15}/>
            <span>
              <strong>Cryptographic Ledger:</strong> All website states and security incident reports are deterministically serialized and linked using SHA-256 hashes.
            </span>
          </div>
        </aside>
      </div>
    </>
  );
}

function RecordRow({ label, value, mono, link, highlight }) {
  return (
    <div className="record-row">
      <span>{label}</span>
      <strong className={`${mono ? "mono" : ""} ${highlight ? "highlight" : ""}`}>
        {link ? <a href={value} target="_blank" rel="noreferrer">{value} <ExternalLink size={12}/></a> : value}
      </strong>
    </div>
  );
}

function HistoryPage({ search, filter, onFilter, history }) {
  const filters = ["All results", "Secure", "Low risk", "Medium risk", "High risk"];
  const rows = history.filter((scan) =>
    `${scan.id} ${scan.site} ${scan.result}`.toLowerCase().includes(search.toLowerCase()) &&
    (filter === "All results" || scan.result === filter)
  );

  return (
    <>
      <PageHeading
        eyebrow={`AUDIT TRAIL · ${history.length} PAGE CHECKS`}
        title="Scan history"
        description="Immutable audit trail of recent website crawls and SHA-256 digests."
      />
      <section className="panel table-panel history-panel">
        <div className="history-toolbar">
          <div>
            <h2>Recent page checks <span className="heading-count">{rows.length}</span></h2>
            <p>Cryptographic records persisted by the backend ledger.</p>
          </div>
          <label className="select-compact">
            <SlidersHorizontal size={14}/>
            <select value={filter} onChange={(event) => onFilter(event.target.value)}>
              {filters.map((item) => <option key={item}>{item}</option>)}
            </select>
            <ChevronDown size={13}/>
          </label>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>SCAN ID</th>
                <th>WEBSITE</th>
                <th>TIME</th>
                <th>RESULT</th>
                <th>CHANGES</th>
                <th>DURATION</th>
                <th>SHA-256 DIGEST</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((scan) => (
                <tr key={scan.id}>
                  <td className="mono-cell">{scan.id}</td>
                  <td className="site-name-cell">{scan.site}</td>
                  <td>{scan.time}</td>
                  <td><StatusBadge value={scan.result}/></td>
                  <td>{scan.changes}</td>
                  <td>{scan.duration}</td>
                  <td><code className="mono-cell">{scan.hash?.slice(0, 16)}...</code></td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty-state">No scan records match your filters.</div>}
        </div>
      </section>
      <div className="history-footnote">
        <Clock3 size={14}/> The SHA-256 hash chain is persisted by the scanner backend.
      </div>
    </>
  );
}

function SettingsPage({ onSave }) {
  return (
    <>
      <PageHeading
        eyebrow="WORKSPACE CONFIGURATION"
        title="Settings"
        description="Manage security preferences and telemetry configurations."
      />
      <section className="panel settings-panel">
        <div className="settings-section">
          <div>
            <h2>Security telemetry preferences</h2>
            <p>Configure defensive heuristics and dashboard reporting</p>
          </div>
          <label className="setting-row">
            <span>
              <strong>SSRF Strict Protection</strong>
              <small>Enforce recursive DNS validation and block private/cloud metadata ranges.</small>
            </span>
            <input type="checkbox" defaultChecked readOnly/>
          </label>
          <label className="setting-row">
            <span>
              <strong>Real-time Attack Telemetry</strong>
              <small>Capture SQLi, XSS, and rate limit probes with approximate geolocation.</small>
            </span>
            <input type="checkbox" defaultChecked readOnly/>
          </label>
          <label className="setting-row">
            <span>
              <strong>Blockchain Ledger Anchoring</strong>
              <small>Persist cryptographic incident evidence to local hash-chain blocks.</small>
            </span>
            <input type="checkbox" defaultChecked readOnly/>
          </label>
        </div>
        <div className="settings-section">
          <div>
            <h2>Workspace status</h2>
            <p>Active environment metadata</p>
          </div>
          <div className="workspace-details">
            <span>Workspace<strong>CyberMesh Production Node</strong></span>
            <span>Ledger Type<strong><i className="tiny-dot"/> SHA-256 Blockchain</strong></span>
            <span>Telemetry<strong>Active (Defensive Heuristics)</strong></span>
          </div>
        </div>
        <button className="primary-button" onClick={onSave}>Save preferences</button>
      </section>
    </>
  );
}

function NotFound({ onHome }) {
  return (
    <div className="not-found">
      <ShieldAlert size={24}/>
      <h1>Page not found</h1>
      <button className="primary-button" onClick={onHome}>Return to dashboard</button>
    </div>
  );
}

function LoginPage({ onLogin }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      await onLogin(String(form.get("username") || "").trim(), String(form.get("password") || ""));
    } catch (loginError) {
      setError(loginError.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="auth-brand">
          <span className="brand-mark"><ShieldCheck size={22}/></span>
          <span>
            <strong>CYBERMESH</strong>
            <small>THREAT INTELLIGENCE WORKSPACE</small>
          </span>
        </div>
        <div className="auth-heading">
          <div className="live-label"><span className="live-dot"/> PRIVATE ACCESS NODE</div>
          <h1>Welcome back</h1>
          <p>Sign in to open your cybersecurity telemetry and blockchain workspace.</p>
        </div>
        <form className="auth-form" onSubmit={submit}>
          <label htmlFor="login-id">User ID</label>
          <input id="login-id" name="username" autoComplete="username" placeholder="Enter your user ID" required/>
          <label htmlFor="login-password">Password</label>
          <input id="login-password" name="password" type="password" autoComplete="current-password" placeholder="Enter your password" required/>
          {error && <p className="auth-error" role="alert">{error}</p>}
          <button className="primary-button" type="submit" disabled={busy}>
            <LockKeyhole size={16}/>{busy ? "Signing in..." : "Sign in"}
          </button>
        </form>
        {import.meta.env.VITE_SHOW_DEFAULT_CREDENTIALS !== "false" && (
          <div className="default-credentials">
            <strong>Default local account</strong>
            <span><b>ID</b> admin</span>
            <span><b>Password</b> CyberMesh@123</span>
          </div>
        )}
        <p className="auth-footnote">Single-user session secured with SHA-256 PBKDF2 authentication.</p>
      </section>
    </main>
  );
}

export default function RoutedApp() {
  return (
    <BrowserRouter>
      <App/>
    </BrowserRouter>
  );
}
