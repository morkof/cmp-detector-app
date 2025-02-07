const express = require("express");
const puppeteer = require("puppeteer-core");
const { cmpProviders, cookiePatterns } = require('./cmp-rules');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure Puppeteer options based on environment
const getPuppeteerOptions = () => {
    if (process.env.NODE_ENV === 'production') {
        const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome';
        console.log('Checking Chrome executable path:', executablePath);
        try {
            if (fs.existsSync(executablePath)) {
                console.log('Chrome executable found at:', executablePath);
            } else {
                console.log('Chrome executable NOT found at:', executablePath);
                // List contents of /usr/bin to help debug
                if (fs.existsSync('/usr/bin')) {
                    console.log('Contents of /usr/bin:');
                    fs.readdirSync('/usr/bin').forEach(file => {
                        if (file.includes('chrome') || file.includes('chromium')) {
                            console.log('- ' + file);
                        }
                    });
                }
            }
        } catch (error) {
            console.error('Error checking Chrome executable:', error);
        }

        return {
            headless: "new",
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--single-process',
                '--disable-gpu'
            ],
            executablePath
        };
    }
    
    // Local development - try to find Chrome in standard locations
    const possiblePaths = [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', // macOS
        '/usr/bin/google-chrome',                                      // Linux
        '/usr/bin/chromium',                                          // Linux
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',  // Windows
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
    ];

    for (const path of possiblePaths) {
        try {
            if (fs.existsSync(path)) {
                console.log('Found Chrome at:', path);
                return {
                    headless: "new",
                    args: ['--no-sandbox'],
                    executablePath: path
                };
            }
        } catch (e) {
            console.error(`Error checking path ${path}:`, e);
        }
    }

    throw new Error('Could not find Chrome/Chromium installation. Please install Chrome or set PUPPETEER_EXECUTABLE_PATH.');
};

app.use(express.static("public"));

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

app.get("/scan", async (req, res) => {
    const url = req.query.url;
    if (!url) return res.json({ error: "URL parameter is required." });

    let browser;
    try {
        const options = getPuppeteerOptions();
        console.log('Launching browser with options:', options);
        browser = await puppeteer.launch(options);
        
        const page = await browser.newPage();
        await page.setDefaultNavigationTimeout(30000);
        
        console.log('Navigating to URL:', url);
        await page.goto(url, { 
            waitUntil: "networkidle0",
            timeout: 30000 
        });

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
        res.json(detectionResults);
    } catch (error) {
        console.error('Scan error:', error);
        if (browser) await browser.close();
        res.status(500).json({ 
            error: "Failed to scan the website", 
            details: error.message 
        });
    }
});

app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
