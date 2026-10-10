const express = require("express");
const cors = require("cors");
const { crawlWebsite } = require("./crawler");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        message: "CyberMesh backend is running!",
        status: "success"
    });
});

app.post("/api/scan", async (req, res) => {
    const { website } = req.body || {};

    if (typeof website !== "string" || !website.trim()) {
        return res.status(400).json({
            status: "error",
            message: "Please provide a website URL."
        });
    }

    let target;

    try {
        target = new URL(website.trim());

        if (
            !["http:", "https:"].includes(target.protocol) ||
            target.username ||
            target.password
        ) {
            throw new Error("Invalid URL");
        }
    } catch {
        return res.status(400).json({
            status: "error",
            message: "Enter a valid HTTP or HTTPS URL."
        });
    }

    try {
        const result = await crawlWebsite(target.href);

        if (!result) {
            return res.status(502).json({
                status: "error",
                message: "Website scan failed."
            });
        }

        return res.json({
            status: "success",
            data: result
        });
    } catch (error) {
        console.error("Scan failed:", error.message);

        return res.status(502).json({
            status: "error",
            message: "Unable to scan this website."
        });
    }
});

app.listen(PORT, () => {
    console.log(`CyberMesh backend running at http://localhost:${PORT}`);
});