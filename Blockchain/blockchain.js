const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

class Block {
  constructor(index, timestamp, data, previousHash = "") {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.hash = this.calculateHash();
  }

  calculateHash() {
    return crypto
      .createHash("sha256")
      .update(
        this.index +
        this.timestamp +
        JSON.stringify(this.data) +
        this.previousHash
      )
      .digest("hex");
  }
}

/**
 * Deterministically serialize any object with sorted keys
 * to ensure reproducible SHA-256 hashes across platforms.
 */
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
}

/**
 * Creates a deterministic SHA-256 hash for a security incident report.
 * Volatile display-only fields (e.g. status) are excluded so the core evidence is immutable.
 */
function hashIncidentReport(report) {
  const coreEvidence = {
    id: report.id,
    timestamp: report.timestamp,
    sourceIp: report.sourceIp,
    activityType: report.activityType,
    riskLevel: report.riskLevel,
    indicators: report.indicators || [],
    evidence: report.evidence || {}
  };
  return crypto.createHash("sha256").update(canonicalStringify(coreEvidence)).digest("hex");
}

class Blockchain {
  constructor(filePath = path.join(__dirname, "blockchain.json")) {
    this.filePath = filePath;
    if (fs.existsSync(this.filePath)) {
      const savedData = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      if (!Array.isArray(savedData.chain) || savedData.chain.length === 0) {
        throw new Error("blockchain.json does not contain a valid chain.");
      }
      this.chain = savedData.chain.map((item) => {
        const block = new Block(item.index, item.timestamp, item.data, item.previousHash);
        block.hash = item.hash;
        return block;
      });
      if (!this.isChainValid()) {
        throw new Error("The saved blockchain is invalid. Restore a valid blockchain.json before starting the scanner.");
      }
    } else {
      this.chain = [this.createGenesisBlock()];
      this.saveChain();
    }
  }

  saveChain() {
    fs.writeFileSync(this.filePath, JSON.stringify({ chain: this.chain }, null, 2));
  }

  createGenesisBlock() {
    return new Block(
      0,
      new Date().toISOString(),
      { message: "Genesis Block" },
      "0"
    );
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  addBlock(data) {
    const previousBlock = this.getLatestBlock();
    const newBlock = new Block(
      this.chain.length,
      new Date().toISOString(),
      data,
      previousBlock.hash
    );

    this.chain.push(newBlock);
    this.saveChain();
    return newBlock;
  }

  /**
   * Anchors an incident report hash on the blockchain.
   * Deliberately omits personal details, sensitive credentials, or raw body data.
   */
  addIncidentBlock(report) {
    const reportHash = hashIncidentReport(report);
    const previousBlock = this.getLatestBlock();

    // Store only non-sensitive summary metadata and the cryptographic digest
    const blockData = {
      recordType: "security_incident",
      incidentId: report.id,
      reportHash: reportHash,
      activityType: report.activityType,
      riskLevel: report.riskLevel,
      timestamp: report.timestamp
    };

    const newBlock = new Block(
      this.chain.length,
      new Date().toISOString(),
      blockData,
      previousBlock.hash
    );

    this.chain.push(newBlock);
    this.saveChain();

    return {
      blockIndex: newBlock.index,
      blockHash: newBlock.hash,
      timestamp: newBlock.timestamp,
      reportHash: reportHash,
      status: "confirmed"
    };
  }

  /**
   * Verifies whether an incident report matches its recorded SHA-256 hash
   * and whether the block on the blockchain remains valid.
   */
  verifyIncidentReport(report, recordedHash, blockIndex) {
    const computedHash = hashIncidentReport(report);
    const hashMatch = computedHash === recordedHash;
    const chainValid = this.isChainValid();

    let onChainBlock = null;
    if (typeof blockIndex === "number" && this.chain[blockIndex]) {
      onChainBlock = this.chain[blockIndex];
    } else {
      onChainBlock = this.chain.find(
        (b) => b.data && b.data.reportHash === recordedHash
      );
    }

    const onChainMatch = onChainBlock ? onChainBlock.data.reportHash === recordedHash : false;

    return {
      valid: hashMatch && chainValid && Boolean(onChainMatch),
      computedHash,
      expectedHash: recordedHash,
      hashMatch,
      chainValid,
      onChainMatch,
      blockIndex: onChainBlock ? onChainBlock.index : null,
      blockHash: onChainBlock ? onChainBlock.hash : null
    };
  }

  isChainValid() {
    if (!this.chain.length || this.chain[0].previousHash !== "0" || this.chain[0].hash !== this.chain[0].calculateHash()) {
      return false;
    }
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      if (currentBlock.hash !== currentBlock.calculateHash()) {
        return false;
      }

      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }
    }

    return true;
  }
}

module.exports = { Block, Blockchain, hashIncidentReport, canonicalStringify };
