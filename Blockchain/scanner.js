const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");
const { Blockchain } = require("./blockchain");

const dataDir = path.resolve(process.env.DATA_DIR || __dirname);
const myBlockchain = new Blockchain(path.join(dataDir, "blockchain.json"));
const MAX_PAGES = 10;
const REQUEST_TIMEOUT_MS = 10000;
const MAX_REDIRECTS = 5;

/**
 * Validates whether an IP address is in a private, loopback,
 * cloud metadata, or reserved non-routable range.
 */
function isPrivateAddress(address) {
  const version = net.isIP(address);
  if (version === 4) {
    const octets = address.split(".").map(Number);
    const [a, b, c] = octets;
    return (
      a === 0 || // Current network
      a === 10 || // Private RFC 1918
      a === 127 || // Loopback
      (a === 169 && b === 254) || // Link-local / Cloud metadata (AWS/Azure/GCP 169.254.169.254)
      (a === 172 && b >= 16 && b <= 31) || // Private RFC 1918
      (a === 192 && b === 168) || // Private RFC 1918
      (a === 100 && b >= 64 && b <= 127) || // Carrier-grade NAT RFC 6598
      (a === 198 && (b === 18 || b === 19)) || // Benchmark RFC 2544
      (a === 192 && b === 0 && (c === 0 || c === 2)) || // TEST-NET-1
      (a === 198 && b === 51 && c === 100) || // TEST-NET-2
      (a === 203 && b === 0 && c === 113) || // TEST-NET-3
      a >= 224 // Multicast & Reserved
    );
  }
  if (version === 6) {
    const lower = address.toLowerCase();
    if (lower.startsWith("::ffff:")) return isPrivateAddress(lower.slice(7));
    return (
      lower === "::" ||
      lower === "::1" ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") || // Unique Local Address (ULA)
      lower.startsWith("fe8") ||
      lower.startsWith("fe9") ||
      lower.startsWith("fea") ||
      lower.startsWith("feb") || // Link-local
      lower.startsWith("ff") // Multicast
    );
  }
  return true;
}

/**
 * Resolves a hostname via DNS and verifies that none of its resolved
 * addresses map to internal, loopback, or cloud metadata endpoints.
 */
async function assertPublicDestination(url) {
  const hostname = url.hostname;

  // Direct IP entered as hostname
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw new Error(`SSRF Protection: Direct access to private/internal IP address (${hostname}) is blocked.`);
    }
    return;
  }

  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw new Error(`DNS resolution failed for hostname "${hostname}": ${err.message}`);
  }

  if (!addresses || addresses.length === 0) {
    throw new Error(`No IP addresses found for hostname "${hostname}".`);
  }

  for (const { address } of addresses) {
    if (isPrivateAddress(address)) {
      throw new Error(`SSRF Protection: Hostname "${hostname}" resolves to private/internal IP (${address}), which is blocked.`);
    }
  }
}

/**
 * Fetches a URL with strict SSRF protection, timeout, and manual redirect re-validation.
 * Every redirect hop is verified against private IP and cloud metadata ranges.
 */
async function safeFetchWithSsrfProtection(targetUrl, maxRedirects = MAX_REDIRECTS) {
  let currentUrl = targetUrl;
  let redirectCount = 0;
  const redirectTrail = [];

  while (redirectCount <= maxRedirects) {
    let parsedUrl;
    try {
      parsedUrl = new URL(currentUrl);
    } catch {
      throw new Error(`Invalid URL encountered during fetch: ${currentUrl}`);
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password) {
      throw new Error(`URL must use HTTP or HTTPS without embedded credentials: ${currentUrl}`);
    }

    // SSRF Check: resolve hostname and ensure every address is strictly public
    await assertPublicDestination(parsedUrl);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let response;
    try {
      response = await fetch(currentUrl, {
        signal: controller.signal,
        redirect: "manual",
        headers: {
          "User-Agent": "CyberMesh-Security-Scanner/1.0 (+https://cybermesh.security)"
        }
      });
    } catch (err) {
      clearTimeout(timer);
      if (err.name === "AbortError") {
        throw new Error(`Connection timed out after ${REQUEST_TIMEOUT_MS / 1000}s while requesting ${currentUrl}.`);
      }
      throw new Error(`Network error requesting ${currentUrl}: ${err.message}`);
    } finally {
      clearTimeout(timer);
    }

    // Handle HTTP redirects (301, 302, 303, 307, 308)
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) {
        throw new Error(`Redirect response (${response.status}) missing Location header.`);
      }

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).href;
      } catch {
        throw new Error(`Invalid redirect Location: "${location}" from ${currentUrl}`);
      }

      redirectTrail.push({
        status: response.status,
        from: currentUrl,
        to: nextUrl
      });

      redirectCount++;
      if (redirectCount > maxRedirects) {
        throw new Error(`Redirect limit exceeded (${maxRedirects} hops).`);
      }

      currentUrl = nextUrl;
      continue;
    }

    return {
      response,
      finalUrl: currentUrl,
      redirectTrail
    };
  }
}

/**
 * Inspects a URL for suspicious patterns (raw IP, excessive subdomains,
 * deceptive phishing keywords, non-standard ports, punycode).
 */
function inspectUrlPatterns(url) {
  const indicators = [];
  const parsed = new URL(url);

  // Raw IP in URL
  if (net.isIP(parsed.hostname)) {
    indicators.push({
      id: "URL-RAW-IP",
      title: "Raw IP Address Hostname",
      severity: "High",
      type: "Suspicious URL Pattern",
      description: "Website accessed via numeric IP address rather than a domain name. Often seen in temporary phishing or C2 servers.",
      remediation: "Access services through authenticated, TLS-secured domain names with proper DNS management."
    });
  }

  // Deep subdomain hierarchy
  const hostParts = parsed.hostname.split(".");
  if (hostParts.length > 4 && !net.isIP(parsed.hostname)) {
    indicators.push({
      id: "URL-DEEP-SUBDOMAIN",
      title: "Excessive Subdomain Nesting",
      severity: "Medium",
      type: "Suspicious URL Pattern",
      description: `Domain has ${hostParts.length} levels (${parsed.hostname}). Deep nesting is sometimes used to obfuscate destinations or bypass filters.`,
      remediation: "Review domain structure and verify that subdomains belong to legitimate infrastructure."
    });
  }

  // Suspicious authentication / deception keywords
  const suspiciousKeywords = [
    "login", "verify", "secure", "account", "banking", "authenticate",
    "paypal", "wallet", "admin-panel", "recovery", "update-info"
  ];
  const lowerUrl = (parsed.hostname + parsed.pathname).toLowerCase();
  const matchedKeywords = suspiciousKeywords.filter((kw) => lowerUrl.includes(kw));
  if (matchedKeywords.length > 0) {
    indicators.push({
      id: "URL-SUSPICIOUS-KEYWORD",
      title: "Sensitive Authentication Keyword in URL",
      severity: "Low",
      type: "Suspicious URL Pattern",
      description: `URL contains sensitive keywords (${matchedKeywords.join(", ")}). Phishing sites frequently mimic authentication paths.`,
      remediation: "Ensure URL matches verified organization domains and official portal paths."
    });
  }

  // Non-standard port
  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    indicators.push({
      id: "URL-NON-STANDARD-PORT",
      title: "Non-Standard HTTP(S) Port",
      severity: "Medium",
      type: "Suspicious URL Pattern",
      description: `Service is hosted on non-standard port :${parsed.port}. Public production services typically use 80 or 443.`,
      remediation: "Ensure standard web ports are used and internal development ports are not exposed publicly."
    });
  }

  // Punycode / IDN homograph indicator
  if (parsed.hostname.toLowerCase().includes("xn--")) {
    indicators.push({
      id: "URL-PUNYCODE-HOMOGRAPH",
      title: "Internationalized Domain / Punycode Detected",
      severity: "Medium",
      type: "Suspicious URL Pattern",
      description: `Domain contains Punycode (${parsed.hostname}). Can be used in homograph phishing attacks that visually mimic known brands.`,
      remediation: "Verify Unicode character representation matches the intended organization name."
    });
  }

  return indicators;
}

/**
 * Inspects HTTP response headers for missing security configurations
 * and information disclosure headers.
 */
function inspectSecurityHeaders(response, url) {
  const indicators = [];
  const parsed = new URL(url);
  const headers = response.headers;

  const isHttps = parsed.protocol === "https:";

  // 1. Strict-Transport-Security (HSTS)
  const hsts = headers.get("strict-transport-security");
  if (isHttps && !hsts) {
    indicators.push({
      id: "SEC-HDR-HSTS",
      title: "Missing HSTS Header",
      severity: "Low",
      type: "Defensive Hardening Advisory",
      description: "Strict-Transport-Security header is not present. Browsers will not strictly enforce HTTPS, allowing potential SSL-stripping man-in-the-middle attacks.",
      remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to server responses."
    });
  }

  // 2. Content-Security-Policy (CSP)
  const csp = headers.get("content-security-policy");
  if (!csp) {
    indicators.push({
      id: "SEC-HDR-CSP",
      title: "Missing Content-Security-Policy (CSP)",
      severity: "Low",
      type: "Defensive Hardening Advisory",
      description: "Content-Security-Policy header is missing. CSP is a defense-in-depth header that mitigates Cross-Site Scripting (XSS) by whitelisting trusted script and style sources.",
      remediation: "Implement a robust Content-Security-Policy header defining trusted sources for scripts, styles, and frames."
    });
  }

  // 3. X-Frame-Options (Clickjacking defense)
  const xfo = headers.get("x-frame-options");
  const cspFrameAncestors = csp && csp.includes("frame-ancestors");
  if (!xfo && !cspFrameAncestors) {
    indicators.push({
      id: "SEC-HDR-XFO",
      title: "Missing Clickjacking Protection",
      severity: "Low",
      type: "Defensive Hardening Advisory",
      description: "Neither X-Frame-Options nor CSP frame-ancestors is configured. The page can theoretically be embedded in an iframe on third-party sites.",
      remediation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''.' to prevent unauthorized framing."
    });
  }

  // 4. X-Content-Type-Options (MIME Sniffing)
  const xcto = headers.get("x-content-type-options");
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    indicators.push({
      id: "SEC-HDR-XCTO",
      title: "Missing X-Content-Type-Options: nosniff",
      severity: "Low",
      type: "Informational Advisory",
      description: "X-Content-Type-Options is missing or not set to 'nosniff'. Browsers may attempt to MIME-sniff response content.",
      remediation: "Add 'X-Content-Type-Options: nosniff' header to all HTTP responses."
    });
  }

  // 5. Referrer-Policy
  const referrerPolicy = headers.get("referrer-policy");
  if (!referrerPolicy) {
    indicators.push({
      id: "SEC-HDR-REF",
      title: "Missing Referrer-Policy",
      severity: "Low",
      type: "Informational Advisory",
      description: "Referrer-Policy header is not set. Browsers may leak full URLs and sensitive path/query parameters in Referer headers when navigating to external origins.",
      remediation: "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
    });
  }

  // 6. Information Disclosure: Server header
  const server = headers.get("server");
  if (server && /\d/.test(server)) {
    indicators.push({
      id: "INFO-DISC-SERVER",
      title: "Server Version Disclosed",
      severity: "Low",
      type: "Informational Advisory",
      description: `Server header exposes version details: "${server}". Version disclosure simplifies targeted exploit research for attackers.`,
      remediation: "Suppress or generalize the Server header in web server configuration (e.g. 'Server: webserver')."
    });
  }

  // 7. Information Disclosure: X-Powered-By header
  const xPoweredBy = headers.get("x-powered-by");
  if (xPoweredBy) {
    indicators.push({
      id: "INFO-DISC-POWERED",
      title: "Backend Framework Disclosed (X-Powered-By)",
      severity: "Low",
      type: "Informational Advisory",
      description: `X-Powered-By banner discloses underlying technology stack: "${xPoweredBy}".`,
      remediation: "Disable X-Powered-By header in application framework settings (e.g. 'app.disable(\"x-powered-by\")')."
    });
  }

  // 8. Plaintext HTTP Protocol Check
  if (!isHttps) {
    indicators.push({
      id: "SEC-PROTO-HTTP",
      title: "Unencrypted Plaintext HTTP Protocol",
      severity: "High",
      type: "Security Vulnerability",
      description: "Website transmits data unencrypted over plaintext HTTP. All communication, including session tokens and input data, is vulnerable to eavesdropping and alteration.",
      remediation: "Obtain a TLS certificate (e.g. Let's Encrypt) and enforce HTTPS redirection for all endpoints."
    });
  }

  return {
    indicators,
    securityHeaders: {
      strictTransportSecurity: hsts || null,
      contentSecurityPolicy: csp ? `${csp.slice(0, 100)}...` : null,
      xFrameOptions: xfo || null,
      xContentTypeOptions: xcto || null,
      referrerPolicy: referrerPolicy || null,
      serverBanner: server || null,
      xPoweredByBanner: xPoweredBy || null
    }
  };
}

/**
 * Computes an overall numerical risk score (0-100) and risk category.
 * Distinguishes optional defensive hardening advisories (Low) from active critical flaws (High).
 */
function computeRiskAssessment(indicators, changeStatus) {
  let score = 0;

  for (const ind of indicators) {
    if (ind.severity === "High") score += 35;
    else if (ind.severity === "Medium") score += 15;
    else if (ind.severity === "Low") score += 5;
  }

  if (changeStatus === "Change detected") {
    score += 25;
  }

  // Bound score strictly between 0 and 100
  score = Math.min(100, score);

  let category = "None";
  if (score >= 70) category = "High";
  else if (score >= 40) category = "Medium";
  else if (score > 0) category = "Low";

  return {
    riskScore: score,
    riskCategory: category,
    totalIndicators: indicators.length,
    highRiskCount: indicators.filter((i) => i.severity === "High").length,
    mediumRiskCount: indicators.filter((i) => i.severity === "Medium").length,
    lowRiskCount: indicators.filter((i) => i.severity === "Low").length,
    taxonomy: {
      type: "Security Configuration & Hardening Indicators",
      disclaimer: "These findings represent observed defensive hardening recommendations and header configuration opportunities. They are security indicators rather than confirmed exploitable vulnerabilities."
    }
  };
}

// 1. Find internal links of the same website
function getInternalLinks(html, baseUrl) {
  const links = new Set();
  const hrefRegex = /href\s*=\s*["']([^"']+)["']/gi;
  let match;

  while ((match = hrefRegex.exec(html)) !== null) {
    try {
      const link = new URL(match[1], baseUrl);

      if (
        link.origin === new URL(baseUrl).origin &&
        ["http:", "https:"].includes(link.protocol)
      ) {
        link.hash = "";
        if (!/\.(pdf|jpg|jpeg|png|gif|svg|zip|css|js|ico)$/i.test(link.pathname)) {
          links.add(link.href);
        }
      }
    } catch {
      // Ignore invalid links
    }
  }

  return links;
}

// 2. Analyze links, scripts and iframes
function analyzePage(html, baseUrl) {
  const internalLinks = new Set();
  const externalLinks = new Set();
  const scripts = new Set();
  const iframes = new Set();
  const base = new URL(baseUrl);

  const linkRegex = /<a\b[^>]*href\s*=\s*["']([^"']+)["']/gi;
  const scriptRegex = /<script\b[^>]*src\s*=\s*["']([^"']+)["']/gi;
  const iframeRegex = /<iframe\b[^>]*src\s*=\s*["']([^"']+)["']/gi;

  function collectUrls(regex, callback) {
    let match;
    while ((match = regex.exec(html)) !== null) {
      try {
        const url = new URL(match[1], baseUrl);
        if (["http:", "https:"].includes(url.protocol)) {
          callback(url);
        }
      } catch {
        // Ignore invalid URLs
      }
    }
  }

  collectUrls(linkRegex, (url) => {
    if (url.origin === base.origin) internalLinks.add(url.href);
    else externalLinks.add(url.href);
  });

  collectUrls(scriptRegex, (url) => scripts.add(url.href));
  collectUrls(iframeRegex, (url) => iframes.add(url.href));

  return {
    internalLinks: [...internalLinks],
    externalLinks: [...externalLinks],
    scripts: [...scripts],
    iframes: [...iframes]
  };
}

// 3. Scan the website, inspect security indicators, and compare SHA-256 hashes
async function scanWebsite(url) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error("Please provide a valid website URL.");
  }

  if (
    !["http:", "https:"].includes(parsedUrl.protocol) ||
    parsedUrl.username ||
    parsedUrl.password
  ) {
    throw new Error("Please provide a valid public HTTP or HTTPS website URL.");
  }

  // Pre-validate initial destination against SSRF
  await assertPublicDestination(parsedUrl);

  const startUrl = parsedUrl.href;
  const queue = [startUrl];
  const visited = new Set();
  const pages = [];
  const errors = [];
  const allIndicators = [];

  // Analyze URL patterns for the root target
  const urlIndicators = inspectUrlPatterns(startUrl);
  allIndicators.push(...urlIndicators);

  const recordFile = path.join(dataDir, "scan-records.json");
  let records = {};

  if (fs.existsSync(recordFile)) {
    try {
      records = JSON.parse(fs.readFileSync(recordFile, "utf8"));
    } catch {
      throw new Error("Could not read scan-records.json. Check whether the JSON file is valid.");
    }
  }

  while (queue.length > 0 && visited.size < MAX_PAGES) {
    const currentUrl = queue.shift();

    if (visited.has(currentUrl)) {
      continue;
    }
    visited.add(currentUrl);

    try {
      console.log("Scanning:", currentUrl);

      // Fetch with SSRF protection, redirect verification, and timeout
      const { response, finalUrl, redirectTrail } = await safeFetchWithSsrfProtection(currentUrl);

      const contentType = response.headers.get("content-type") || "";

      if (!response.ok) {
        errors.push({
          website: currentUrl,
          message: `HTTP status ${response.status}`
        });
        continue;
      }

      if (!contentType.includes("text/html")) {
        continue;
      }

      const html = await response.text();

      // Check security headers on the page
      const { indicators: headerIndicators, securityHeaders } = inspectSecurityHeaders(response, finalUrl);
      allIndicators.push(...headerIndicators);

      // Generate SHA-256 hash
      const hash = crypto.createHash("sha256").update(html).digest("hex");

      // Compare with the previous scan baseline
      const previousHash = records[currentUrl];
      let changeStatus;

      if (!previousHash) {
        changeStatus = "First scan";
      } else if (previousHash === hash) {
        changeStatus = "No change";
      } else {
        changeStatus = "Change detected";
      }

      records[currentUrl] = hash;

      // Analyze page DOM elements (links, scripts, iframes)
      const analysis = analyzePage(html, currentUrl);

      const pageResult = {
        website: currentUrl,
        finalUrl,
        httpStatus: response.status,
        contentType,
        contentLength: Buffer.byteLength(html),
        sha256: hash,
        changeStatus,
        securityHeaders,
        indicators: [...headerIndicators],
        redirectTrail,
        analysis
      };

      pages.push(pageResult);

      // Save scan record in the local blockchain ledger
      myBlockchain.addBlock({
        website: currentUrl,
        httpStatus: response.status,
        sha256: hash,
        changeStatus
      });

      console.log("Status:", changeStatus);
      console.log("SHA-256:", hash);

      // Add newly discovered internal pages to crawl queue
      for (const link of getInternalLinks(html, currentUrl)) {
        if (!visited.has(link) && !queue.includes(link)) {
          queue.push(link);
        }
      }
    } catch (error) {
      errors.push({
        website: currentUrl,
        message: error.message
      });
    }
  }

  // Deduplicate indicators by ID
  const uniqueIndicatorsMap = new Map();
  for (const ind of allIndicators) {
    if (!uniqueIndicatorsMap.has(ind.id)) {
      uniqueIndicatorsMap.set(ind.id, ind);
    }
  }
  const uniqueIndicators = [...uniqueIndicatorsMap.values()];

  // Deduce aggregate change status
  const hasChanges = pages.some((p) => p.changeStatus === "Change detected");
  const overallChangeStatus = hasChanges ? "Change detected" : pages.length ? "No change" : "Failed";

  // Compute risk assessment and risk score
  const riskAssessment = computeRiskAssessment(uniqueIndicators, overallChangeStatus);

  // Save hashes for future comparisons
  fs.writeFileSync(recordFile, JSON.stringify(records, null, 2));

  return {
    startUrl,
    pagesScanned: pages.length,
    pages,
    errors,
    pageLimit: MAX_PAGES,
    indicators: uniqueIndicators,
    riskAssessment,
    blockchainValid: myBlockchain.isChainValid()
  };
}

module.exports = {
  scanWebsite,
  myBlockchain,
  assertPublicDestination,
  isPrivateAddress,
  inspectUrlPatterns,
  inspectSecurityHeaders,
  computeRiskAssessment
};
