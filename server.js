const express = require("express");
const puppeteer = require("puppeteer");

const app = express();
const PORT = 3000;

app.use(express.static("public"));

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

app.get("/scan", async (req, res) => {
    const url = req.query.url;
    if (!url) return res.json({ error: "URL parameter is required." });

    let browser;
    try {
        browser = await puppeteer.launch({ 
            headless: "new",
            args: ['--no-sandbox']
        });
        
        const page = await browser.newPage();
        await page.setDefaultNavigationTimeout(30000);
        
        await page.goto(url, { 
            waitUntil: "networkidle0",
            timeout: 30000 
        });

        const detectionResults = await page.evaluate(() => {
            const providers = {
                "OneTrust": () => !!window.OneTrust || document.querySelector("script[src*='onetrust.com']"),
                "InMobi": () => document.querySelector("script[src*='inmobi.com']"),
                "Sourcepoint": () => document.querySelector("script[src*='sourcepoint.com']"),
                "TrustArc": () => document.querySelector("script[src*='trustarc.com']"),
                "Admiral": () => document.querySelector("script[src*='admiral.com']"),
                "Transcend": () => document.querySelector("script[src*='transcend.io']"),
                "Osano": () => document.querySelector("script[src*='cmp.osano.com']"),
                "Cookiebot": () => !!window.CookieConsent || document.querySelector("script[src*='cookiebot.com']"),
                "CookieYes": () => document.querySelector("script[src*='cookieyes.com']"),
                "TrustCassie": () => document.querySelector("script[src*='trustcassie.com']"),
                "Termly": () => document.querySelector("script[src*='termly.io']"),
                "Ketch": () => document.querySelector("script[src*='ketch.com']"),
                "CookieScript": () => document.querySelector("script[src*='cookie-script.com']"),
                "Nextroll": () => document.querySelector("script[src*='nextroll.com']")
            };

            let detectedCMPs = [];
            let detectionDetails = {};

            // Check for CMPs and collect evidence
            for (const [name, check] of Object.entries(providers)) {
                try {
                    if (check()) {
                        detectedCMPs.push(name);
                        
                        // Collect evidence
                        const evidence = {
                            globalObject: name === "OneTrust" ? !!window.OneTrust : 
                                        name === "Cookiebot" ? !!window.CookieConsent : false,
                            scripts: Array.from(document.querySelectorAll(`script[src*='${name.toLowerCase()}']`))
                                        .map(script => script.src),
                        };
                        detectionDetails[name] = evidence;
                    }
                } catch (e) {
                    console.error(`Error checking ${name}:`, e);
                }
            }

            // Check for cookies
            const knownCookies = {
                "euconsent-v2": "IAB TCF 2.0",
                "didomi_*": "Didomi",
                "consentUUID": "OneTrust",
                "sp_*": "Sourcepoint",
                "iab_consent": "IAB Framework",
                "cookie_consent": "Generic Consent Storage",
                "cookieyes-consent": "CookieYes",
                "cc_cookie": "Civic Cookie Control",
                "piwik_optin": "Piwik PRO",
                "quantcast_choice": "Quantcast Choice",
                "admiral_consent": "Admiral",
                "transcend_consent": "Transcend",
                "ketch_consent": "Ketch",
                "cookie_script": "CookieScript",
                "nextroll_consent": "Nextroll"
            };

            let foundCookies = [];
            let cookieDetails = {};

            document.cookie.split("; ").forEach(cookie => {
                const [key, value] = cookie.split("=");
                for (const [pattern, name] of Object.entries(knownCookies)) {
                    if (key.match(new RegExp(pattern.replace("*", ".*")))) {
                        foundCookies.push(`${name} (${key})`);
                        cookieDetails[key] = {
                            provider: name,
                            value: value
                        };
                    }
                }
            });

            // Collect all scripts for analysis
            const allScripts = Array.from(document.querySelectorAll('script[src]')).map(script => script.src);

            return {
                detectedCMPs,
                foundCookies,
                evidence: {
                    detectionDetails,
                    cookieDetails,
                    allScripts: allScripts.filter(src => 
                        src.includes('consent') || 
                        src.includes('cookie') || 
                        src.includes('privacy') ||
                        src.includes('cmp')
                    )
                }
            };
        });

        await browser.close();
        res.json(detectionResults);
    } catch (error) {
        if (browser) await browser.close();
        res.status(500).json({ 
            error: "Failed to scan the website", 
            details: error.message 
        });
    }
});

app.listen(PORT, () => console.log(`✅ Server running at http://localhost:3000`));
