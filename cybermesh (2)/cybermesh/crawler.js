const axios = require("axios");
const cheerio = require("cheerio");

async function crawlWebsite(website) {
    try {
        const target = new URL(website);

        if (target.protocol !== "http:" && target.protocol !== "https:") {
            throw new Error("Invalid website URL");
        }

        const response = await axios.get(target.href, {
            timeout: 10000
        });

        const $ = cheerio.load(response.data);

        const title = $("title").text().trim();
        const pageContent = $("body").text().replace(/\s+/g, " ").trim();

        const links = [];
        const scripts = [];

        $("a[href]").each((index, element) => {
            const href = $(element).attr("href");

            try {
                const url = new URL(href, target.href);

                if (url.protocol === "http:" || url.protocol === "https:") {
                    links.push(url.href);
                }
            } catch (error) {
                // Ignore invalid links
            }
        });

        $("script[src]").each((index, element) => {
            const src = $(element).attr("src");

            try {
                const url = new URL(src, target.href);

                if (url.protocol === "http:" || url.protocol === "https:") {
                    scripts.push(url.href);
                }
            } catch (error) {
                // Ignore invalid script URLs
            }
        });

        const result = {
            website: target.href,
            title: title,
            pageContent: pageContent.slice(0, 10000),
            links: [...new Set(links)],
            scripts: [...new Set(scripts)],
            statusCode: response.status,
            scannedAt: new Date().toISOString()
        };

        console.log(JSON.stringify(result, null, 2));

        return result;

    } catch (error) {
        console.error("Crawler error:", error.message);
        return null;
    }
}

if (require.main === module){
    crawlWebsite("https://example.com");
}
module.exports = { crawlWebsite };