const express = require("express");
const puppeteer = require("puppeteer-core");
const { cmpProviders, cookiePatterns } = require('./cmp-rules');
const fs = require('fs');
const { execSync } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// Find Chrome executable path
const findChromeExecutable = () => {
    const paths = [
        '/usr/bin/google-chrome-stable',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser'
    ];
    
    for (const path of paths) {
        try {
            fs.accessSync(path);
            console.log('Found Chrome at:', path);
            return path;
        } catch (err) {
            console.log('Chrome not found at:', path);
        }
    }
    
    throw new Error('Chrome executable not found');
};

// Configure Puppeteer options based on environment
const getPuppeteerOptions = () => {
    const isProduction = process.env.NODE_ENV === 'production';
    const options = {
        headless: "new",
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--single-process'
        ]
    };

    try {
        const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || findChromeExecutable();
        console.log('Using Chrome executable path:', executablePath);
        options.executablePath = executablePath;
    } catch (err) {
        console.error('Error finding Chrome:', err);
        throw err;
    }

    return options;
};

// Ensure URL has protocol
const ensureValidUrl = (url) => {
    if (!url) return null;
    try {
        // If URL is valid as-is, return it
        new URL(url);
        return url;
    } catch (e) {
        // If URL is invalid, try adding https://
        try {
            const urlWithProtocol = url.startsWith('http') ? url : `https://${url}`;
            new URL(urlWithProtocol);
            return urlWithProtocol;
        } catch (e) {
            return null;
        }
    }
};

app.use(express.static("public"));

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

app.get("/scan", async (req, res) => {
    const url = ensureValidUrl(req.query.url);
    if (!url) {
        return res.status(400).json({ 
            error: "Invalid URL provided. Please include protocol (http:// or https://) or provide a valid domain." 
        });
    }

    let browser;
    try {
        const options = getPuppeteerOptions();
        console.log('Launching browser with options:', JSON.stringify(options, null, 2));
        
        browser = await puppeteer.launch(options);
        console.log('Browser launched successfully');
        
        const page = await browser.newPage();
        console.log('New page created');
        
        await page.setDefaultNavigationTimeout(30000);
        console.log('Navigation timeout set');
        
        console.log('Navigating to URL:', url);
        await page.goto(url, { 
            waitUntil: "networkidle0",
            timeout: 30000 
        });
        console.log('Navigation complete');

        // Convert functions to strings before injecting
        const serializedProviders = {};
        for (const [key, fn] of Object.entries(cmpProviders)) {
            serializedProviders[key] = fn.toString();
        }

        // Inject the detection rules
        await page.evaluate((providers, patterns) => {
            window.cmpProviders = providers;
            window.cookiePatterns = patterns;
        }, serializedProviders, cookiePatterns);
        console.log('Detection rules injected');

        // Convert the stringified functions back to functions and check for CMPs
        const detectionResults = await page.evaluate(async () => {
            let detectedCMPs = [];
            let detectionDetails = {};
            let storageEvidence = {
                localStorage: {},
                sessionStorage: {},
                indexedDB: []
            };

            // Helper function to safely check storage
            const checkStorage = (storage, type) => {
                const items = {};
                try {
                    for (let i = 0; i < storage.length; i++) {
                        const key = storage.key(i);
                        if (key.toLowerCase().match(/(consent|privacy|gdpr|ccpa|cookie|cmp)/)) {
                            try {
                                items[key] = storage.getItem(key);
                            } catch (e) {
                                items[key] = "Unable to read value";
                            }
                        }
                    }
                } catch (e) {
                    console.error(`Error checking ${type}:`, e);
                }
                return items;
            };

            // Check localStorage
            storageEvidence.localStorage = checkStorage(localStorage, 'localStorage');

            // Check sessionStorage
            storageEvidence.sessionStorage = checkStorage(sessionStorage, 'sessionStorage');

            // Check IndexedDB
            try {
                const databases = await window.indexedDB.databases();
                storageEvidence.indexedDB = databases
                    .filter(db => db.name.toLowerCase().match(/(consent|privacy|gdpr|ccpa|cookie|cmp)/))
                    .map(db => db.name);
            } catch (e) {
                console.error('Error checking IndexedDB:', e);
            }

            // Convert the stringified functions back to functions and check for CMPs
            for (const [name, fnStr] of Object.entries(window.cmpProviders)) {
                try {
                    const check = new Function('return ' + fnStr)();
                    if (check()) {
                        detectedCMPs.push(name);
                        
                        // Collect evidence
                        const evidence = {
                            globalObject: name === "OneTrust" ? !!window.OneTrust : 
                                        name === "Cookiebot" ? !!window.CookieConsent : false,
                            scripts: Array.from(document.querySelectorAll(`script[src*='${name.toLowerCase()}']`))
                                        .map(script => script.src),
                            storage: {
                                localStorage: Object.entries(storageEvidence.localStorage)
                                    .filter(([key]) => key.toLowerCase().includes(name.toLowerCase()))
                                    .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {}),
                                sessionStorage: Object.entries(storageEvidence.sessionStorage)
                                    .filter(([key]) => key.toLowerCase().includes(name.toLowerCase()))
                                    .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {}),
                                indexedDB: storageEvidence.indexedDB
                                    .filter(dbName => dbName.toLowerCase().includes(name.toLowerCase()))
                            }
                        };
                        detectionDetails[name] = evidence;
                    }
                } catch (e) {
                    console.error(`Error checking ${name}:`, e);
                }
            }

            let foundCookies = [];
            let cookieDetails = {};

            document.cookie.split("; ").forEach(cookie => {
                const [key, value] = cookie.split("=");
                for (const [pattern, name] of Object.entries(window.cookiePatterns)) {
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
                    storageEvidence,
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
        console.log('Browser closed');
        res.json(detectionResults);
    } catch (error) {
        console.error('Scan error:', error);
        if (browser) await browser.close();
        console.log('Browser closed after error');
        res.status(500).json({ 
            error: "Failed to scan the website", 
            details: error.message 
        });
    }
});

app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
