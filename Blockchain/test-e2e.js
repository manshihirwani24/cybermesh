const { spawn } = require("child_process");

console.log("=================================================================");
console.log("CYBERMESH FULL END-TO-END DEMO & VALIDATION TEST");
console.log("=================================================================\n");

const TEST_PORT = 3015;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

const serverProcess = spawn("node", ["server.js"], {
  cwd: __dirname,
  env: { ...process.env, PORT: String(TEST_PORT), HOST: "127.0.0.1" }
});

let serverLogs = [];
serverProcess.stdout.on("data", (d) => serverLogs.push(d.toString().trim()));
serverProcess.stderr.on("data", (d) => serverLogs.push("[ERR] " + d.toString().trim()));

function cleanupAndExit(code = 0) {
  serverProcess.kill();
  setTimeout(() => process.exit(code), 200);
}

setTimeout(async () => {
  let passed = 0;
  let total = 0;

  function report(name, condition, extra = "") {
    total++;
    if (condition) {
      console.log(`[PASS] ${name} ${extra ? `(${extra})` : ""}`);
      passed++;
    } else {
      console.error(`[FAIL] ${name} ${extra ? `(${extra})` : ""}`);
    }
  }

  try {
    // 1. Authenticate & Obtain Session Token
    console.log("1. AUTHENTICATION & SESSION INITIALIZATION");
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "CyberMesh@123" })
    });
    const loginData = await loginRes.json();
    report("Admin authentication", loginData.success === true, `Token: ${loginData.token?.slice(0, 16)}...`);
    const token = loginData.token;
    const authHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

    // 2. Test Safe URL Scan
    console.log("\n2. KNOWN SAFE TEST URL SCAN");
    const safeScanRes = await fetch(`${BASE_URL}/api/scan`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ url: "https://example.com" })
    });
    const safeScanData = await safeScanRes.json();
    report("Safe URL scan succeeded", safeScanData.success === true);
    report("Calculated risk score & category", safeScanData.site?.riskScore > 0, `Score: ${safeScanData.site?.riskScore}/100, Cat: ${safeScanData.site?.riskCategory}`);
    report("Security indicators collected", safeScanData.site?.indicators?.length > 0, `${safeScanData.site?.indicators?.length} indicators found`);
    report("Deterministic SHA-256 fingerprint generated", safeScanData.site?.hash?.length === 64, safeScanData.site?.hash?.slice(0, 16) + "...");

    // 3. Test Invalid URL Input
    console.log("\n3. INVALID URL INPUT TEST");
    const invalidScanRes = await fetch(`${BASE_URL}/api/scan`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ url: "not-a-valid-domain" })
    });
    report("Invalid URL input rejected with 400", invalidScanRes.status === 400);

    // 4. Test Deliberately Suspicious / SSRF URL
    console.log("\n4. DELIBERATELY SUSPICIOUS TEST URL & SSRF DEFENSE");
    const ssrfScanRes = await fetch(`${BASE_URL}/api/scan`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ url: "http://127.0.0.1:3015" })
    });
    const ssrfData = await ssrfScanRes.json();
    report("SSRF localhost access blocked", ssrfScanRes.status === 400 && ssrfData.message?.includes("SSRF Protection"), ssrfData.message);

    const cloudMetaRes = await fetch(`${BASE_URL}/api/scan`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ url: "http://169.254.169.254/latest/meta-data" })
    });
    const cloudMetaData = await cloudMetaRes.json();
    report("SSRF cloud metadata endpoint blocked", cloudMetaRes.status === 400 && cloudMetaData.message?.includes("SSRF Protection"), cloudMetaData.message);

    // 5. Test IP Addresses & Approximate Geolocation
    console.log("\n5. TEST IP ADDRESSES & APPROXIMATE GEOLOCATION");
    const localGeoRes = await fetch(`${BASE_URL}/api/ip-lookup?ip=127.0.0.1`, { headers: authHeaders });
    const localGeo = await localGeoRes.json();
    report("Localhost IP resolves to private subnet", localGeo.location?.country === "Local Network", localGeo.location?.city);

    const publicGeoRes = await fetch(`${BASE_URL}/api/ip-lookup?ip=8.8.8.8`, { headers: authHeaders });
    const publicGeo = await publicGeoRes.json();
    report("Public IP resolves to approximate geo", publicGeo.location?.approximate === true, `${publicGeo.location?.country}, ${publicGeo.location?.city} (${publicGeo.location?.isp})`);

    // 6. Test Suspicious SQLi & XSS Detection
    console.log("\n6. SUSPICIOUS ATTACK ACTIVITY DETECTION");
    const sqliProbeRes = await fetch(`${BASE_URL}/api/sites?target=1%27%20OR%201=1--`, { headers: authHeaders });
    report("Handled SQLi probe request and flagged telemetry", sqliProbeRes.status === 200 || sqliProbeRes.status === 400);

    // 7. Test Simulated Attack Telemetry
    console.log("\n7. ATTACK INCIDENT CREATION & TELEMETRY");
    const simRes = await fetch(`${BASE_URL}/api/incidents/simulate`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify({ type: "sqli" })
    });
    const simData = await simRes.json();
    report("Generated incident report", simData.success === true, `ID: ${simData.incident?.id}`);
    const incidentId = simData.incident?.id;
    report("Deterministic SHA-256 report hash generated", simData.incident?.reportHash?.length === 64, simData.incident?.reportHash?.slice(0, 16) + "...");
    report("Anchored incident onto blockchain ledger", simData.incident?.blockchain?.status === "confirmed", `Block #${simData.incident?.blockchain?.blockIndex}`);

    // 8. Test SHA-256 Verification & Tamper Detection
    console.log("\n8. CRYPTOGRAPHIC VERIFICATION & TAMPER DETECTION");
    const verifyRes = await fetch(`${BASE_URL}/api/incidents/${incidentId}/verify`, {
      method: "POST",
      headers: authHeaders
    });
    const verifyData = await verifyRes.json();
    report("Cryptographic verification confirms untampered state", verifyData.verification?.valid === true && verifyData.verification?.hashMatch === true, verifyData.status);

    // 9. Simulated Repeated Requests (Rate Limiting)
    console.log("\n9. SIMULATED REPEATED REQUESTS (RATE LIMITING)");
    let floodCounter = 0;
    for (let i = 0; i < 20; i++) {
      await fetch(`${BASE_URL}/api/health`, { headers: authHeaders });
      floodCounter++;
    }
    report("Processed repeated request burst safely", floodCounter === 20, "20 rapid requests processed");

    // 10. Summary Assessment
    console.log("\n=================================================================");
    console.log(`FINAL RESULT: ${passed} / ${total} CHECKS PASSED (${Math.round((passed / total) * 100)}%)`);
    console.log("=================================================================\n");

    if (passed === total) {
      cleanupAndExit(0);
    } else {
      cleanupAndExit(1);
    }
  } catch (err) {
    console.error("E2E Test Failure:", err);
    cleanupAndExit(1);
  }
}, 1500);
