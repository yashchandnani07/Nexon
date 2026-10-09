// outlook-plugin/server.js
// FraudShield AI
// HTTPS server for Outlook add-in + API proxy to docker-compose services.
//
// Service routing (env-configurable; defaults work when plugin runs on the host):
//   /api/analyze/email  → email-monitor:8009  /analyze/phishing  (payload adapted)
//   /api/feedback       → local ack (feedback acknowledged without persisting)
//   /api/*              → email-monitor:8009  /*
//   /voice/*            → voice-scanner:8006  /*   (host port 8006 → container port 8000)
//   /credential/*       → credential-scanner:8002  /*
//   /guard/*            → prompt-guard:8005   /*   (path kept: API lives at /guard/check)
//   /attachment/*       → attachment-scanner:8007  /*
//   /smtp-gateway/*     → smtp-fraud-gateway:8010  /*
//   /website-check/*    → website-spoofing:8008    /*  (host port 8008 → container port 5000)

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const https = require('https');
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

// ── SSL certificates ───────────────────────────────────────────────────────────
const certDir  = process.env.CERT_DIR || path.join(os.homedir(), '.office-addin-dev-certs');
const keyPath  = path.join(certDir, 'localhost.key');
const certPath = path.join(certDir, 'localhost.crt');

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    console.error('[FraudShield] SSL certificates not found at:', certDir);
    console.error('[FraudShield] Run: npx office-addin-dev-certs install');
    process.exit(1);
}

const sslOptions = {
    key:  fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
};

// ── Backend service config (env-override for Docker; defaults for host-run) ────
//  When running as a container on aegisai-net, set the env vars (see docker-compose.yml).
//  When running directly on the host, the defaults target the exposed host ports.
const SVC = {
    email:      { host: process.env.EMAIL_HOST      || 'localhost', port: +(process.env.EMAIL_PORT      || 8009) },
    smtp:       { host: process.env.SMTP_HOST       || 'localhost', port: +(process.env.SMTP_PORT       || 8010) },
    voice:      { host: process.env.VOICE_HOST      || 'localhost', port: +(process.env.VOICE_PORT      || 8006) },
    credential: { host: process.env.CRED_HOST       || 'localhost', port: +(process.env.CRED_PORT       || 8002) },
    guard:      { host: process.env.GUARD_HOST      || 'localhost', port: +(process.env.GUARD_PORT      || 8005) },
    attachment: { host: process.env.ATTACH_HOST     || 'localhost', port: +(process.env.ATTACH_PORT     || 8007) },
    website:    { host: process.env.WEBSITE_HOST    || 'localhost', port: +(process.env.WEBSITE_PORT    || 8008) },
};

// ── MIME types ─────────────────────────────────────────────────────────────────
const MIME = {
    '.js':   'text/javascript',
    '.css':  'text/css',
    '.json': 'application/json',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.html': 'text/html',
    '.xml':  'application/xml',
};

// ── Payload adapter: plugin format → email-monitor /analyze/phishing ──────────
// Plugin sends: { text, subject, sender, receiver, reply_to, cc, use_llm }
// email-monitor expects: { from_name, from_email, reply_to, subject, raw_headers, body }
function adaptEmailRequest(raw) {
    let body;
    try { body = JSON.parse(raw); } catch (e) { body = {}; }
    return JSON.stringify({
        from_name:   '',
        from_email:  body.sender   || '',
        reply_to:    body.reply_to || '',
        subject:     body.subject  || '',
        raw_headers: '',
        body:        body.text     || body.body || '',
    });
}

// ── Response adapter: email-monitor /analyze/phishing → plugin format ─────────
// Plugin's buildDisplayResult() expects:
//   { tier, risk_score, verdict, roberta_phishing_prob, rule_based_score,
//     ai_generated_probability, top_indicators, header_flags, outlook_action,
//     processing_ms, prediction_id }
function adaptEmailResponse(raw) {
    let r;
    try { r = JSON.parse(raw); } catch (e) { return raw; }

    const score   = +(r.overall_score || 0);
    const level   = (r.risk_level || 'LOW').toUpperCase();
    const tier    = score >= 85 ? 'CRITICAL' : level;
    const verdict = r.recommendation === 'BLOCK' ? 'PHISHING' : 'LEGITIMATE';
    const action  = r.recommendation === 'BLOCK'   ? 'BLOCK'
                  : r.recommendation === 'REVIEW'  ? 'QUARANTINE'
                  : 'ALLOW';

    const roberta = r.roberta_ml      || {};
    const rule    = r.rule_based      || {};
    const ai      = r.ai_text         || {};
    const header  = r.header_analysis || {};

    const topIndicators = [
        ...(rule.indicators    || rule.top_indicators  || []),
        ...(rule.matched_rules || []),
    ].filter(Boolean).slice(0, 8);

    const headerFlags = [
        ...(header.flags        || []),
        ...(header.header_flags || []),
        ...(header.issues       || []),
    ].filter(Boolean);

    return JSON.stringify({
        tier,
        risk_score:               score,
        verdict,
        roberta_phishing_prob:    (roberta.score || 0) / 100,
        rule_based_score:         rule.score  || 0,
        ai_generated_probability: (ai.score   || 0) / 100,
        top_indicators:           topIndicators,
        header_flags:             headerFlags,
        outlook_action:           action,
        processing_ms:            r.processing_ms || 0,
        prediction_id:            null,
    });
}

// ── Error response helper ──────────────────────────────────────────────────────
function serviceError(res, host, port, err) {
    console.error(`[PROXY ERROR → ${host}:${port}]`, err.message);
    if (res.headersSent) return;
    res.writeHead(503);
    res.end(JSON.stringify({
        error:  `Service ${host}:${port} not reachable`,
        detail: err.message,
        hint:   'Run: docker compose up  (from the repo root)',
    }));
}

// ── Proxy: pipe raw bytes (multipart / binary) ─────────────────────────────────
function proxyPipe(req, res, host, port, targetPath) {
    const opts = {
        hostname: host,
        port,
        path:    targetPath,
        method:  req.method,
        headers: Object.assign({}, req.headers, { host: `${host}:${port}` }),
    };
    const proxyReq = http.request(opts, proxyRes => {
        res.writeHead(proxyRes.statusCode, {
            'Content-Type':                proxyRes.headers['content-type'] || 'application/json',
            'Access-Control-Allow-Origin': '*',
        });
        proxyRes.pipe(res);
    });
    proxyReq.on('error', err => serviceError(res, host, port, err));
    req.pipe(proxyReq);
}

// ── Proxy: buffer + optional transform request/response bodies ────────────────
function proxyJSON(req, res, host, port, targetPath, transformReq, transformRes) {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
        const outBody = transformReq ? transformReq(body) : (body || '');
        const opts = {
            hostname: host,
            port,
            path:    targetPath,
            method:  req.method,
            headers: {
                'Content-Type':   'application/json',
                'Content-Length': Buffer.byteLength(outBody),
            },
        };
        const proxyReq = http.request(opts, proxyRes => {
            let respBody = '';
            proxyRes.on('data', chunk => { respBody += chunk; });
            proxyRes.on('end', () => {
                const finalBody = transformRes ? transformRes(respBody) : respBody;
                res.writeHead(proxyRes.statusCode, {
                    'Content-Type':                'application/json',
                    'Access-Control-Allow-Origin': '*',
                });
                res.end(finalBody);
            });
        });
        proxyReq.on('error', err => serviceError(res, host, port, err));
        if (outBody) proxyReq.write(outBody);
        proxyReq.end();
    });
}

// ── Proxy: auto-detect multipart vs JSON ──────────────────────────────────────
function proxyAuto(req, res, host, port, targetPath) {
    const ct = req.headers['content-type'] || '';
    if (ct.includes('multipart/form-data') || ct.includes('application/octet-stream')) {
        proxyPipe(req, res, host, port, targetPath);
    } else {
        proxyJSON(req, res, host, port, targetPath, null, null);
    }
}

// ── HTTPS server ───────────────────────────────────────────────────────────────
https.createServer(sslOptions, (req, res) => {
    console.log(`[${req.method}] ${req.url}`);

    res.setHeader('Access-Control-Allow-Origin',  '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

    const cleanUrl = req.url.split('?')[0];

    // ── /api/analyze/email — adapted payload + response ───────────────────────
    if (cleanUrl === '/api/analyze/email') {
        const { host, port } = SVC.email;
        console.log(`  → Email Phishing (http:${host}:${port}/analyze/phishing)`);
        proxyJSON(req, res, host, port, '/analyze/phishing',
                  adaptEmailRequest, adaptEmailResponse);
        return;
    }

    // ── /api/feedback — acknowledge locally (no storage, returns ack to plugin) ─
    if (cleanUrl === '/api/feedback') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            let payload;
            try { payload = JSON.parse(body); } catch (e) { payload = {}; }
            const wasCorrect = (payload.model_verdict || '').toUpperCase() ===
                               (payload.user_verdict  || '').toUpperCase();
            res.writeHead(200, {
                'Content-Type':                'application/json',
                'Access-Control-Allow-Origin': '*',
            });
            res.end(JSON.stringify({
                was_correct: wasCorrect,
                model_said:  payload.model_verdict || '',
                user_said:   payload.user_verdict  || '',
                saved:       true,
                note:        'Feedback acknowledged by FraudShield plugin proxy',
            }));
        });
        return;
    }

    // ── /api/* → email-monitor (general fallthrough) ──────────────────────────
    if (cleanUrl.startsWith('/api/')) {
        const targetPath = cleanUrl.replace('/api', '') || '/';
        const { host, port } = SVC.email;
        console.log(`  → Email Monitor (http:${host}:${port}) ${targetPath}`);
        proxyAuto(req, res, host, port, targetPath);
        return;
    }

    // ── /voice/* → Voice Scanner ──────────────────────────────────────────────
    if (cleanUrl.startsWith('/voice/')) {
        const targetPath = cleanUrl.replace('/voice', '') || '/';
        const { host, port } = SVC.voice;
        console.log(`  → Voice Scanner (http:${host}:${port}) ${targetPath}`);
        proxyPipe(req, res, host, port, targetPath);
        return;
    }

    // ── /credential/* → Credential Scanner ───────────────────────────────────
    if (cleanUrl.startsWith('/credential/')) {
        const targetPath = cleanUrl.replace('/credential', '') || '/';
        const { host, port } = SVC.credential;
        console.log(`  → Credential Scanner (http:${host}:${port}) ${targetPath}`);
        proxyAuto(req, res, host, port, targetPath);
        return;
    }

    // ── /guard/* → Prompt Guard (path kept as-is — API routes live at /guard/*) ─
    if (cleanUrl.startsWith('/guard/')) {
        const { host, port } = SVC.guard;
        console.log(`  → Prompt Guard (http:${host}:${port}) ${cleanUrl}`);
        proxyJSON(req, res, host, port, cleanUrl, null, null);
        return;
    }

    // ── /attachment/* → Attachment Scanner ───────────────────────────────────
    if (cleanUrl.startsWith('/attachment/')) {
        const targetPath = cleanUrl.replace('/attachment', '') || '/';
        const { host, port } = SVC.attachment;
        console.log(`  → Attachment Scanner (http:${host}:${port}) ${targetPath}`);
        proxyPipe(req, res, host, port, targetPath);
        return;
    }

    // ── /smtp-gateway/* → SMTP Fraud Gateway ─────────────────────────────────
    if (cleanUrl.startsWith('/smtp-gateway/')) {
        const targetPath = cleanUrl.replace('/smtp-gateway', '') || '/';
        const { host, port } = SVC.smtp;
        console.log(`  → SMTP Fraud Gateway (http:${host}:${port}) ${targetPath}`);
        proxyAuto(req, res, host, port, targetPath);
        return;
    }

    // ── /website-check/* → Website Spoofing ──────────────────────────────────
    if (cleanUrl.startsWith('/website-check/')) {
        const targetPath = cleanUrl.replace('/website-check', '') || '/';
        const { host, port } = SVC.website;
        console.log(`  → Website Spoofing (http:${host}:${port}) ${targetPath}`);
        proxyAuto(req, res, host, port, targetPath);
        return;
    }

    // ── Static files ──────────────────────────────────────────────────────────
    let filePath = '.' + cleanUrl;
    if (filePath === './') filePath = './taskpane.html';

    const ext      = path.extname(filePath);
    const mimeType = MIME[ext] || 'text/html';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            console.error('[404]', filePath);
            res.writeHead(404);
            res.end('File not found: ' + filePath);
        } else {
            res.writeHead(200, {
                'Content-Type':                mimeType,
                'Access-Control-Allow-Origin': '*',
            });
            res.end(content, 'utf-8');
        }
    });

}).listen(3000, () => {
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log(' FraudShield Outlook Plugin  →  https://localhost:3000');
    console.log('═══════════════════════════════════════════════════════════');
    console.log('\nProxy routes (override via env vars):');
    const rows = [
        ['/api/analyze/email', `http://${SVC.email.host}:${SVC.email.port}/analyze/phishing`, '(adapted)'],
        ['/api/*',             `http://${SVC.email.host}:${SVC.email.port}/`,                 'email-monitor'],
        ['/voice/*',           `http://${SVC.voice.host}:${SVC.voice.port}/`,                 'voice-scanner'],
        ['/credential/*',      `http://${SVC.credential.host}:${SVC.credential.port}/`,       'credential-scanner'],
        ['/guard/*',           `http://${SVC.guard.host}:${SVC.guard.port}/`,                 'prompt-guard'],
        ['/attachment/*',      `http://${SVC.attachment.host}:${SVC.attachment.port}/`,       'attachment-scanner'],
        ['/smtp-gateway/*',    `http://${SVC.smtp.host}:${SVC.smtp.port}/`,                   'smtp-fraud-gateway'],
        ['/website-check/*',   `http://${SVC.website.host}:${SVC.website.port}/`,             'website-spoofing'],
    ];
    rows.forEach(([prefix, target, label]) =>
        console.log(`  ${prefix.padEnd(24)} → ${target.padEnd(36)} ${label}`));
    console.log('\nStart all services:  docker compose up  (from repo root)');
    console.log('═══════════════════════════════════════════════════════════\n');
});
