# 🛡️ AegisAI — Intelligent Threat Detection Platform

> AI-powered fraud detection dashboard built with React 18, Framer Motion, Recharts, and Tailwind CSS.

---

## 📁 Complete Project Structure

```
aegisai/
├── index.html                          ← Root HTML (Google Fonts: DM Sans + JetBrains Mono)
├── vite.config.js                      ← Vite bundler config
├── tailwind.config.js                  ← Custom sky-blue theme + animation keyframes
├── postcss.config.js                   ← PostCSS
├── package.json                        ← All dependencies
│
└── src/
    ├── main.jsx                        ← React entry point
    ├── App.jsx                         ← Root layout + page router (useState)
    ├── index.css                       ← Global styles, wave bars, terminal colors, table utils
    │
    ├── constants/
    │   └── navigation.jsx              ← NAV_ITEMS + PAGE_META (react-icons, no emojis)
    │
    ├── hooks/
    │   └── useCountUp.js               ← Animated number counter (ease-out cubic, RAF-based)
    │
    ├── components/
    │   ├── layout/
    │   │   ├── Sidebar.jsx             ← Fixed sidebar, spring nav indicator (layoutId)
    │   │   └── Topbar.jsx              ← Sticky topbar, backdrop blur
    │   └── ui/
    │       └── index.jsx               ← ALL shared components:
    │                                       Card, Btn, RiskBadge, StatCard, ScoreMeter,
    │                                       ProgressBar, ConfidenceRow, ResultPanel,
    │                                       AlertStrip, DropZone, Tag, HorizBar,
    │                                       Pagination, SubTabs, FormInput, FormTextarea,
    │                                       FormLabel, FormSelect, PageWrapper, PageHeader,
    │                                       SectionHeader, SidebarStat
    │
    └── pages/
        ├── Dashboard.jsx               ← Live feed, module status, risk tier grid, stat cards
        ├── EmailPhishing.jsx           ← Header form, BERT scores, history panel
        ├── CredentialScanner.jsx       ← Secrets table, entropy values, type breakdown
        ├── AttachmentAnalyzer.jsx      ← Drag-drop, YARA/magic-byte checks grid
        ├── WebsiteSpoofing.jsx         ← URL analysis, cookie monitor, visual clone compare
        ├── DeepfakeVoice.jsx           ← Animated waveform bars, MFCC/Wav2Vec2 scores
        ├── PromptInjection.jsx         ← Pattern detection, decoded payload terminal
        ├── AgentSandbox.jsx            ← Docker config, animated terminal output
        ├── FeedbackRetraining.jsx      ← Filter table, 94.2% accuracy, retraining queue
        └── AdminAnalytics.jsx          ← 6 Recharts charts (Line, Bar, Pie, horizontal bar)
```

---

## ⚙️ Setup — Step by Step

### Prerequisites
- **Node.js** v18 or higher → [nodejs.org](https://nodejs.org)
- **npm** v9+ (comes with Node)

Check versions:
```bash
node --version   # should print v18.x.x or higher
npm --version    # should print 9.x.x or higher
```

---

### Step 1 — Create the project folder

```bash
mkdir aegisai
cd aegisai
```

---

### Step 2 — Copy all files into place

Create the exact directory structure shown above and paste each file's content.

```bash
# Create all directories at once
mkdir -p src/components/layout
mkdir -p src/components/ui
mkdir -p src/constants
mkdir -p src/hooks
mkdir -p src/pages
```

Then copy each file from this project into the matching path.

---

### Step 3 — Install dependencies

```bash
npm install
```

This installs:
| Package | Version | Purpose |
|---|---|---|
| `react` + `react-dom` | 18.3 | Core framework |
| `framer-motion` | 11.x | Page transitions, card hovers, score meter, waveform, count-up spring |
| `recharts` | 2.x | Line, Bar, Pie charts in Admin Analytics |
| `react-icons` | 5.x | All icons — Remix Icon set (`ri` prefix), zero emojis |
| `tailwindcss` | 3.x | Utility CSS with custom sky-blue theme |
| `vite` | 5.x | Dev server + build tool |
| `autoprefixer` + `postcss` | latest | CSS processing |

---

### Step 4 — Start the development server

```bash
npm run dev
```

Open in browser: **http://localhost:5173**

The app hot-reloads automatically when you edit any file.

---

### Step 5 — Build for production

```bash
npm run build
```

Output goes to `dist/` folder — ready to deploy to Vercel, Netlify, or any static host.

Preview the production build locally:
```bash
npm run preview
# → http://localhost:4173
```

---

## 🎨 Design System

### Colors (sky-blue only)
```
sky-50   #f0f9ff  — card backgrounds, hover states
sky-100  #e0f2fe  — borders, dividers
sky-200  #bae6fd  — progress track, scrollbars
sky-300  #7dd3fc  — wave bars, subtle accents
sky-400  #38bdf8  — icons, status dots, primary elements
sky-500  #0ea5e9  — primary buttons, active nav, links
sky-600  #0284c7  — hover states, chart bars
sky-700  #0369a1  — high risk badge, chart fills
sky-900  #0c4a6e  — critical badge, dark terminal, headings
```

### Risk Level Mapping (all sky shades — no red/orange/green)
| Level | Background | Meaning |
|---|---|---|
| `critical` | `sky-900` | Score 76–100 — Block immediately |
| `high` | `sky-700` | Score 51–75 — Quarantine |
| `suspicious` | `sky-200` | Score 21–50 — Alert |
| `safe` | `sky-50` | Score 0–20 — Monitor |

### Animations
| Effect | Implementation |
|---|---|
| Page transition | `AnimatePresence` + `mode="wait"` + fade/slide |
| Nav active indicator | `motion.div` with `layoutId="activeNav"` spring |
| Stat count-up | `useCountUp` hook — RAF-based, ease-out cubic |
| Score meter | SVG `strokeDashoffset` animated via Framer Motion |
| Card hover lift | `whileHover={{ y: -2 }}` on every Card |
| Logo pulse | `animate={{ boxShadow: [...] }}` loop |
| Waveform bars | CSS `animation: wave` staggered with `nth-child` delays |
| Terminal output | Interval-driven line reveal with slide-in animation |
| Staggered lists | `transition={{ delay: i * 0.06 }}` on list items |
| Progress bars | `initial={{ width:0 }} animate={{ width: X% }}` |

---

## 🔌 Connecting Your Python Models

Each page's **"Analyze"** button currently shows mock results. To connect your real FastAPI backend:

```jsx
// Example: EmailPhishing.jsx
const handleAnalyze = async () => {
  const res = await fetch('http://localhost:8000/analyze/email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ headers: headerData, body: emailBody }),
  })
  const data = await res.json()
  setResult(data)   // { score, level, confidence: { bert, header, url, dkim } }
  setAnalyzed(true)
}
```

Replace the `onClick={() => setAnalyzed(true)}` call on each Analyze/Scan button with the async fetch above.

---

## 📦 Deploying

### Vercel (recommended)
```bash
npm install -g vercel
vercel
```

### Netlify
```bash
npm run build
# Drag & drop the dist/ folder to netlify.com/drop
```

### Docker
```dockerfile
FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
```
