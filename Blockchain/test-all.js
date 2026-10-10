const http = require("http");
const { scanWebsite, myBlockchain } = require("./scanner");
const { hashIncidentReport } = require("./blockchain");

async function runTests() {
  console.log("==================================================");
  console.log("CYBERMESH COMPREHENSIVE AUTOMATED VERIFICATION SUITE");
  console.log("==================================================\n");

  let passed = 0;
  let total = 0;

  function assert(title, condition, extra = "") {
    total++;
    if (condition) {
      console.log(`[PASS] ${title} ${extra ? `(${extra})` : ""}`);
      passed++;
    } else {
      console.error(`[FAIL] ${title} ${extra ? `(${extra})` : ""}`);
    }
  }

  // 1. SSRF & URL Validation Tests
  console.log("--- 1. SSRF Protection & URL Validation ---");
  try {
    await scanWebsite("http://127.0.0.1:3001");
    assert("SSRF blocks localhost (127.0.0.1)", false);
  } catch (err) {
    assert("SSRF blocks localhost (127.0.0.1)", true, err.message);
  }

  try {
    await scanWebsite("http://169.254.169.254/latest/meta-data");
    assert("SSRF blocks AWS/Cloud Metadata", false);
  } catch (err) {
    assert("SSRF blocks AWS/Cloud Metadata", true, err.message);
  }

  try {
    await scanWebsite("http://10.0.0.1/admin");
    assert("SSRF blocks RFC1918 Private Class A (10.0.0.1)", false);
  } catch (err) {
    assert("SSRF blocks RFC1918 Private Class A (10.0.0.1)", true, err.message);
  }

  try {
    await scanWebsite("ftp://evil.com/exploit");
    assert("Rejects non-HTTP protocols", false);
  } catch (err) {
    assert("Rejects non-HTTP protocols", true, err.message);
  }

  // 2. Safe Scan & Security Indicator Tests
  console.log("\n--- 2. Website Scan & Security Indicator Analysis ---");
  try {
    const scanResult = await scanWebsite("https://example.com");
    assert("Scans public safe website (example.com)", scanResult.pagesScanned > 0, `${scanResult.pagesScanned} page(s)`);
    assert("Computes SHA-256 fingerprint", scanResult.pages[0].sha256.length === 64, scanResult.pages[0].sha256.slice(0, 16) + "...");
    assert("Calculates numerical risk score (0-100)", typeof scanResult.riskAssessment.riskScore === "number", `Score: ${scanResult.riskAssessment.riskScore}`);
    assert("Assigns risk category", ["Low", "Medium", "High", "None"].includes(scanResult.riskAssessment.riskCategory), `Category: ${scanResult.riskAssessment.riskCategory}`);
    assert("Detects security header gaps", scanResult.indicators.length > 0, `${scanResult.indicators.length} indicators found`);
    assert("Taxonomy distinguishes indicators from vulnerabilities", scanResult.riskAssessment.taxonomy.type.includes("Indicators"), scanResult.riskAssessment.taxonomy.disclaimer.slice(0, 45) + "...");
  } catch (err) {
    assert("Scan public safe website", false, err.message);
  }

  // 3. SHA-256 Incident Report Hashing & Tamper Verification
  console.log("\n--- 3. SHA-256 Hashing & Tamper Detection ---");
  const sampleIncident = {
    id: "INC-TEST-99",
    timestamp: "2026-10-10T12:00:00.000Z",
    sourceIp: "198.51.100.77",
    activityType: "SQL Injection Probe",
    riskLevel: "High",
    indicators: ["SQLi: UNION / SELECT extraction syntax", "Boolean bypass attempt"],
    evidence: { method: "GET", route: "/api/scan?id=1' OR '1'='1" }
  };

  const hash1 = hashIncidentReport(sampleIncident);
  // Re-order object keys to test canonical determinism
  const sampleReordered = {
    evidence: { route: "/api/scan?id=1' OR '1'='1", method: "GET" },
    riskLevel: "High",
    indicators: ["SQLi: UNION / SELECT extraction syntax", "Boolean bypass attempt"],
    activityType: "SQL Injection Probe",
    sourceIp: "198.51.100.77",
    timestamp: "2026-10-10T12:00:00.000Z",
    id: "INC-TEST-99"
  };
  const hash2 = hashIncidentReport(sampleReordered);
  assert("Deterministic SHA-256 hashing across key orders", hash1 === hash2, `Hash: ${hash1.slice(0, 16)}...`);

  // 4. Blockchain Recording & Integrity Verification
  console.log("\n--- 4. Blockchain Recording & Ledger Verification ---");
  const blockReceipt = myBlockchain.addIncidentBlock(sampleIncident);
  assert("Anchors incident block to chain", blockReceipt.status === "confirmed", `Block #${blockReceipt.blockIndex}`);
  assert("Blockchain is valid", myBlockchain.isChainValid(), `Total blocks: ${myBlockchain.chain.length}`);

  const verifyPass = myBlockchain.verifyIncidentReport(sampleIncident, hash1, blockReceipt.blockIndex);
  assert("Verifies untampered incident report on-chain", verifyPass.valid === true, `Computed: ${verifyPass.computedHash.slice(0, 12)}...`);

  // Tamper test: modify risk level
  const tamperedIncident = { ...sampleIncident, riskLevel: "Low" };
  const verifyFail = myBlockchain.verifyIncidentReport(tamperedIncident, hash1, blockReceipt.blockIndex);
  assert("Detects tampered incident report content", verifyFail.valid === false && verifyFail.hashMatch === false, "Hash mismatch detected");

  console.log("\n==================================================");
  console.log(`RESULTS: ${passed} / ${total} tests passed (${Math.round((passed / total) * 100)}%)`);
  console.log("==================================================");

  if (passed === total) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
