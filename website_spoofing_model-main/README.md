# 🛡️ PhishGuard v3 – AI Phishing & URL Threat Analyzer

PhishGuard is a comprehensive, deep-scan security intelligence tool designed to detect phishing domains, obfuscated URLs, and high-risk server configurations. It uses an **XGBoost ML Pipeline** operating in tandem with **6 realtime heuristic modules**.

It features both a **Web Dashboard** and a **Chrome Extension** for proactive threat mitigation.

---

## 🚀 1. How It Works (The Two Flows)

PhishGuard operates in two different modes to analyze security risks.

### Flow A: Manual URL Scan (Web Dashboard)
When a user manually types a URL into the Dashboard:
1. The **Dashboard** passes the URL to the Flask Backend via `POST /analyze`.
2. The Backend runs URL checks (ML Model, SSL handshake, WHOIS lookup, and server HTML scraping).
3. The server checks for *server-set cookies* returned during the request.
4. The Risk Engine calculates an overall score.

### Flow B: Deep Session Scan (Chrome Extension)
When a user actually visits a webpage in Google Chrome:
1. The **Extension** (`background.js`) instantly grabs the visited URL.
2. It uses `chrome.cookies.getAll()` to scrape the **LIVE, real browser session cookies** belonging to that domain.
3. It sends both the URL and the live cookie array to the Flask Backend.
4. The Backend runs the standard checks, but performs **Deep Cookie Security Analysis** (checking `HttpOnly`, `Secure` flags, session hijacking risks, exposed tokens) using the *real* browser data.
5. A popup instantly warns the user if the combined ML + Cookie Security + Domain risk is dangerously high.

---

## 🧠 2. Deep Analysis Modules

The system breaks down a URL into **6 parallel security checks**:

1. **🤖 XGBoost ML Model**
   - We trained an offline XGBoost model on the PhiUSIIL dataset, extracting 27 structural features from the raw URL string alone (e.g., character diversity, digits-to-length ratio, special symbol counts, subdomain counts).

2. **🔒 SSL Certificate Validator** (`app/ssl_checker.py`)
   - The backend performs a live port-443 handshake to fetch the SSL certificate.
   - It checks Expiry Dates (flagging certs expiring within 30 days), Trusted Issuers, and SNI domain mismatches.

3. **🌍 WHOIS & DNS Validator** (`app/whois_checker.py`)
   - Ensures the domain actually exists via DNS pre-checks.
   - **Crucial Metric:** Flags dead or unresolvable domains (+30% risk penalty). Phishing domains are frequently burned/taken down.
   - Extracts registration age. Domains under 30 days old trigger immediate warnings.

4. **🍪 Cookie Security Inspector** (`app/cookie_detector.py`)
   - Checks if persistent session cookies are missing crucial protection flags (`HttpOnly` to stop XSS stealing, `Secure` to stop MiTM).
   - Looks for exposed JWTs or session tokens directly returned in insecure cookies.

5. **🔤 URL Encoding Detector** 
   - Unwraps the URL to identify obfuscation techniques (like `%2520` double-encoding) commonly used to sneak payloads past firewalls.

6. **📄 HTML Content Scraper** (`app/html_analyzer.py`)
   - Fetches the webpage's DOM to detect hidden login fields (`<input type="password">`).
   - Looks for iFrames or external `<form action="...">` paths submitting credentials to third-party phishing drops.

---

## 📊 3. System Architecture & Flow

```text
+---------------------+           +--------------------------+
|  Chrome Extension   |   ====>   |  PhishGuard Flask API    |
|  (Scrapes URL +     |   JSON    |   Endpoint: /analyze     |
|   Live Cookies)     |           |                          |
+---------------------+           +--+--------------------+--+
          |                          |                    |
          |                          v                    |
          |                 +-----------------------+     |
          |                 | 1) XGBoost ML Predict |     |
          |                 +-----------------------+     |
+---------------------+              |                    |
|  Web Dashboard UI   |     +-----------------------+     |
|  (Manual URLs)      |     | 2) WHOIS / Age / DNS  |     |
+---------------------+     +-----------------------+     |
          |                          |                    |
          ----------------------->   |                    |
                                     v                    v
                            +-----------------------+     |
                            | 3) SSL Cert Trust     |     |
                            +-----------------------+     |
                                     |                    |
                            +-----------------------+     |
                            | 4-6) HTML / Encoding  |     |
                            |      & Cookie Flags   |     |
                            +-----------------------+     |
                                     |                    |
                                     v                    v
                            +--------------------------------+
                            | RISK ENGINE (Scoring 0 - 100%) |
                            +--------------------------------+
                                     |
                                     v
                           (Returns JSON Verdict)
```

---

## 📦 4. Project Structure (For Sharing/Integration)

```text
PhishGuard/
├── app/                      
│   ├── cookie_detector.py    # Analyzes HttpOnly/Secure flags
│   ├── html_analyzer.py      # Scrapes DOM for phishing forms
│   ├── logger.py             # Internal loguru config
│   ├── predictor.py          # Wrapper for loading XGBoost model
│   ├── ssl_checker.py        # Handshakes and cert validation
│   └── whois_checker.py      # Domain age and DNS pre-checks
├── dashboard/                
│   └── index.html            # The white/blue manual URL dashboard
├── extension/                
│   ├── background.js         # Extension core (intercepts cookies + URL)
│   ├── popup.html            # Extension UI structure
│   ├── popup.js              # Extension UI logic
│   ├── style.css             # Extension styling
│   └── manifest.json         # Chrome V3 Configuration
├── models/                   
│   └── url_phishing_xgboost_v3.pkl # Trarined model artefacts
├── data/                     # CSV datasets for testing
├── .env                      # Environment config (model paths)
├── flask_api.py              # Main Python Backend Server
└── requirements.txt          # Python dependencies
```

---

## ⚡ 5. How To Run & Test (Integration Guide)

### Step 1: Start the Backend API
You needPython 3.10+ installed.

1. Install requirements: `pip install -r requirements.txt`
2. Run the server: `python flask_api.py`
*(The server will start on `http://127.0.0.1:5000`)*

### Step 2: Use the Dashboard
1. Open the file `dashboard/index.html` in any web browser.
2. Paste any generic URL (like `https://google.com`) or a known fake/dead domain. 

### Step 3: Install the Chrome Deep Scan Extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** toggle in the top right.
3. Click **Load unpacked** and select the `/extension/` folder from this project.
4. Pin the `PhishGuard` shield icon to your toolbar.
5. Open any website and click the shield! It will read the actual real browser cookies and instantly check them against the running Flask API.
