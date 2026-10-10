const { crawlWebsite } = require("./crawler");

async function compareWebsites() {
    const original = await crawlWebsite(
        "http://localhost:8000/original.html"
    );

    const modified = await crawlWebsite(
        "http://localhost:8000/tampered.html"
    );

    if (!original || !modified) {
        console.log("Scan failed. Check both local servers.");
        return;
    }

    console.log("\n=== CYBERMESH COMPARISON REPORT ===");

    if (original.title !== modified.title) {
        console.log("Title changed:", original.title, "->", modified.title);
    }

    if (original.pageContent !== modified.pageContent) {
        console.log("Page content changed!");
    }

    if (JSON.stringify(original.links) !== JSON.stringify(modified.links)) {
        console.log("Website links changed!");
    }
}

compareWebsites().catch(console.error);