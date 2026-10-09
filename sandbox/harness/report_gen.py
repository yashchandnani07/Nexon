"""
harness/report_gen.py
Generates a professional, fully self-contained HTML security report.
No external dependencies — pure Python string generation.
"""

import os, datetime

RESULTS_DIR = os.getenv("RESULTS_DIR", "./results")
REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")

COLOR = {
    "CRITICAL": {"hex": "#DC2626", "bg": "#FEF2F2", "border": "#FECACA", "badge": "#DC2626"},
    "HIGH":     {"hex": "#D97706", "bg": "#FFFBEB", "border": "#FDE68A", "badge": "#D97706"},
    "MEDIUM":   {"hex": "#2563EB", "bg": "#EFF6FF", "border": "#BFDBFE", "badge": "#2563EB"},
    "LOW":      {"hex": "#059669", "bg": "#ECFDF5", "border": "#A7F3D0", "badge": "#059669"},
}
SEV_COLOR = {
    "critical": {"bg": "#FEF2F2", "text": "#DC2626", "border": "#FECACA", "dot": "#DC2626"},
    "high":     {"bg": "#FFFBEB", "text": "#D97706", "border": "#FDE68A", "dot": "#D97706"},
    "medium":   {"bg": "#EFF6FF", "text": "#2563EB", "border": "#BFDBFE", "dot": "#2563EB"},
    "low":      {"bg": "#ECFDF5", "text": "#059669", "border": "#A7F3D0", "dot": "#059669"},
}


def _fmt_bytes(b: int) -> str:
    if b >= 1e9: return f"{b/1e9:.1f} GB"
    if b >= 1e6: return f"{b/1e6:.1f} MB"
    return f"{b/1e3:.0f} KB"


def _bar(pct: float, color: str) -> str:
    safe = max(0, min(100, pct))
    return (
        f'<div style="width:100%;height:8px;background:#F1F5F9;border-radius:4px;overflow:hidden">'
        f'<div style="width:{safe}%;height:100%;background:{color};border-radius:4px;transition:width .6s ease"></div>'
        f'</div>'
    )


def _sev_badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, SEV_COLOR["medium"])
    return (
        f'<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;'
        f'border-radius:999px;font-size:11px;font-weight:700;'
        f'background:{c["bg"]};color:{c["text"]};border:1px solid {c["border"]}">'
        f'<span style="width:6px;height:6px;border-radius:50%;background:{c["dot"]}"></span>'
        f'{sev.upper()}</span>'
    )


def generate_report(payload: dict) -> str:
    """Render scan results to a professional self-contained HTML report."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    scan_id   = payload.get("scan_id", "unknown")
    html_path = os.path.join(RESULTS_DIR, f"{scan_id}_report.html")

    model     = payload.get("model", "unknown")
    ts        = payload.get("timestamp", "")
    risk      = payload.get("risk_score", {})
    dims      = payload.get("dimensions", {})
    generated = datetime.datetime.now().strftime("%d %B %Y, %H:%M")

    score   = risk.get("score", 0)
    rating  = risk.get("rating", "MEDIUM")
    rc      = COLOR.get(rating, COLOR["MEDIUM"])

    # ── Collect all findings ──────────────────────────────────────────────────
    all_findings = []
    for dim_key, dim_data in dims.items():
        if not isinstance(dim_data, dict) or "error" in dim_data:
            continue
        items = (dim_data.get("tests", []) +
                 dim_data.get("scenarios", []) +
                 dim_data.get("groups", []))
        for item in items:
            if not item.get("passed", True):
                all_findings.append({
                    "dimension": dim_data.get("dimension", dim_key).replace("_", " ").title(),
                    "id":        str(item.get("id", "—")),
                    "name":      str(item.get("name", item.get("category", item.get("intent", "—")))),
                    "severity":  item.get("severity", "medium"),
                    "response":  str(item.get("response", ""))[:300],
                    "reason":    str(item.get("reason", item.get("judge_reason", "—")))[:200],
                })

    all_findings.sort(key=lambda f: ["critical","high","medium","low"].index(f["severity"])
                      if f["severity"] in ["critical","high","medium","low"] else 3)

    # ── Dimension rows ────────────────────────────────────────────────────────
    dim_rows_html = ""
    for dim_key, dim_data in dims.items():
        if not isinstance(dim_data, dict): continue
        if "error" in dim_data:
            dim_rows_html += f"""
            <tr>
              <td style="padding:14px 16px;font-weight:600;color:#374151">{dim_key.replace('_',' ').title()}</td>
              <td colspan="4" style="padding:14px 16px;color:#EF4444;font-size:12px">Error: {dim_data['error'][:80]}</td>
            </tr>"""
            continue
        name     = dim_data.get("dimension", dim_key).replace("_", " ").title()
        passed   = dim_data.get("passed", 0)
        failed   = dim_data.get("failed", 0)
        total    = dim_data.get("total", 0)
        pr       = dim_data.get("pass_rate", 0)
        pct      = round(pr * 100) if pr <= 1 else round(pr)
        bar_col  = "#059669" if pct >= 90 else "#D97706" if pct >= 60 else "#DC2626"
        pct_text = f'<span style="font-weight:800;color:{bar_col};font-family:monospace">{pct}%</span>'
        dim_rows_html += f"""
        <tr style="border-bottom:1px solid #F1F5F9">
          <td style="padding:14px 16px;font-weight:600;color:#1E293B">{name}</td>
          <td style="padding:14px 16px;color:#64748B;font-family:monospace">{passed} / {total}</td>
          <td style="padding:14px 16px;color:#EF4444;font-weight:700">{failed}</td>
          <td style="padding:14px 16px;min-width:140px">{_bar(pct, bar_col)}</td>
          <td style="padding:14px 16px">{pct_text}</td>
        </tr>"""

    # ── Findings cards ────────────────────────────────────────────────────────
    findings_html = ""
    if all_findings:
        for f in all_findings:
            c  = SEV_COLOR.get(f["severity"], SEV_COLOR["medium"])
            findings_html += f"""
            <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-left:4px solid {c["dot"]};
                        border-radius:8px;padding:16px 20px;margin-bottom:12px">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
                <span style="font-family:monospace;font-size:11px;color:#94A3B8">{f["id"]}</span>
                <span style="flex:1;font-weight:600;font-size:14px;color:#0F172A">{f["name"]}</span>
                {_sev_badge(f["severity"])}
              </div>
              <p style="font-size:12px;color:#64748B;margin:0 0 6px 0">
                <strong>Dimension:</strong> {f["dimension"]}
              </p>
              {f'<p style="font-size:12px;color:#94A3B8;margin:0 0 6px 0"><strong>Judge reason:</strong> {f["reason"]}</p>' if f["reason"] not in ("—","") else ""}
              {f'<pre style="font-size:11px;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:6px;padding:10px 14px;margin:8px 0 0 0;white-space:pre-wrap;word-break:break-word;color:#475569;overflow:hidden">{f["response"]}</pre>' if f["response"] else ""}
            </div>"""
    else:
        findings_html = '<p style="color:#059669;font-weight:600;text-align:center;padding:32px">✓ No failed tests — all probes passed!</p>'

    # ── Stat pills ────────────────────────────────────────────────────────────
    total_tests  = risk.get("total_tests", 0)
    total_passed = risk.get("total_passed", 0)
    total_failed = risk.get("total_failed", 0)
    pass_rate    = risk.get("overall_pass_rate", 0)
    crit_fails   = risk.get("critical_fails", 0)
    high_fails   = risk.get("high_fails", 0)

    def _stat_pill(value, label, color):
        return f"""
        <div style="text-align:center;padding:20px 24px;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:12px">
          <div style="font-size:28px;font-weight:900;color:{color};font-family:monospace">{value}</div>
          <div style="font-size:11px;color:#94A3B8;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">{label}</div>
        </div>"""

    # ── Assemble full HTML ────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Report — {model}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#F1F5F9;color:#0F172A;line-height:1.5}}
    @media print{{body{{background:white}} .no-print{{display:none}}}}
    table{{width:100%;border-collapse:collapse}}
    thead tr{{background:#F8FAFC;border-bottom:2px solid #E2E8F0}}
    th{{padding:12px 16px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#64748B}}
    a{{color:#2563EB;text-decoration:none}}
  </style>
</head>
<body>

<!-- ── HEADER BANNER ──────────────────────────────────────────────────────── -->
<div style="background:linear-gradient(135deg,#0F172A 0%,#1E293B 100%);padding:32px 48px;color:white">
  <div style="max-width:1100px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px">
    <div>
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px">
        <div style="width:36px;height:36px;background:{rc["hex"]};border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px">🛡️</div>
        <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#94A3B8">AegisAI · AI Security Sandbox</span>
      </div>
      <h1 style="font-size:26px;font-weight:900;margin-bottom:4px">Vulnerability Assessment Report</h1>
      <p style="font-size:13px;color:#94A3B8">Model: <span style="font-family:monospace;color:#E2E8F0;font-weight:600">{model}</span></p>
    </div>
    <div style="text-align:right">
      <div style="font-size:11px;color:#64748B;margin-bottom:4px">Scan ID</div>
      <div style="font-family:monospace;font-size:12px;color:#CBD5E1">{scan_id[:36]}</div>
      <div style="font-size:11px;color:#64748B;margin-top:8px">Generated</div>
      <div style="font-size:12px;color:#CBD5E1">{generated}</div>
    </div>
  </div>
</div>

<!-- ── RISK BANNER ────────────────────────────────────────────────────────── -->
<div style="background:{rc["bg"]};border-bottom:3px solid {rc["hex"]};padding:28px 48px">
  <div style="max-width:1100px;margin:0 auto;display:flex;align-items:center;gap:32px;flex-wrap:wrap">
    <!-- Score ring -->
    <div style="width:100px;height:100px;border-radius:50%;border:6px solid {rc["hex"]};
                display:flex;flex-direction:column;align-items:center;justify-content:center;
                background:white;flex-shrink:0">
      <span style="font-size:30px;font-weight:900;color:{rc["hex"]};font-family:monospace;line-height:1">{score}</span>
      <span style="font-size:10px;color:#94A3B8;font-weight:600">/100</span>
    </div>
    <div style="flex:1">
      <div style="font-size:22px;font-weight:900;color:{rc["hex"]};margin-bottom:4px">Risk Rating: {rating}</div>
      <p style="font-size:13px;color:#374151;margin-bottom:12px">
        {"⛔ Critical vulnerabilities detected. Do NOT deploy to production." if rating=="CRITICAL" else
         "⚠️ High-risk findings present. Remediate before deployment." if rating=="HIGH" else
         "ℹ️ Moderate findings. Review before production deployment." if rating=="MEDIUM" else
         "✅ Passed most security probes. Low risk for deployment."}
      </p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px">
        {_stat_pill(total_tests, "Total Tests", "#475569")}
        {_stat_pill(total_passed, "Passed", "#059669")}
        {_stat_pill(total_failed, "Failed", "#DC2626")}
        {_stat_pill(f"{pass_rate}%", "Pass Rate", "#059669" if pass_rate >= 80 else "#D97706" if pass_rate >= 60 else "#DC2626")}
        {_stat_pill(crit_fails, "Critical Fails", "#DC2626")}
        {_stat_pill(high_fails, "High Fails", "#D97706")}
      </div>
    </div>
  </div>
</div>

<!-- ── BODY ───────────────────────────────────────────────────────────────── -->
<div style="max-width:1100px;margin:0 auto;padding:36px 24px;display:grid;grid-template-columns:1fr;gap:28px">

  <!-- Dimension Summary Table -->
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:16px;overflow:hidden">
    <div style="padding:20px 24px;border-bottom:1px solid #F1F5F9;display:flex;align-items:center;gap:10px">
      <span style="font-size:16px">📊</span>
      <h2 style="font-size:16px;font-weight:700;color:#0F172A">Dimension Results</h2>
    </div>
    <table>
      <thead>
        <tr>
          <th>Dimension</th>
          <th>Passed / Total</th>
          <th>Failed</th>
          <th style="min-width:160px">Pass Rate</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {dim_rows_html}
      </tbody>
    </table>
  </div>

  <!-- Findings -->
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:16px;overflow:hidden">
    <div style="padding:20px 24px;border-bottom:1px solid #F1F5F9;display:flex;align-items:center;justify-content:space-between">
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:16px">🔍</span>
        <h2 style="font-size:16px;font-weight:700;color:#0F172A">Security Findings</h2>
        <span style="padding:2px 10px;border-radius:999px;background:#F1F5F9;font-size:12px;font-weight:700;color:#64748B">{len(all_findings)}</span>
      </div>
    </div>
    <div style="padding:20px 24px">
      {findings_html}
    </div>
  </div>

  <!-- Recommendations -->
  <div style="background:#FFFFFF;border:1px solid #E2E8F0;border-radius:16px;overflow:hidden">
    <div style="padding:20px 24px;border-bottom:1px solid #F1F5F9;display:flex;align-items:center;gap:10px">
      <span style="font-size:16px">💡</span>
      <h2 style="font-size:16px;font-weight:700;color:#0F172A">Recommendations</h2>
    </div>
    <div style="padding:20px 24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px">
      {"".join([
        f'''<div style="padding:16px;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:10px">
              <div style="font-weight:700;font-size:13px;color:#0F172A;margin-bottom:6px">{title}</div>
              <p style="font-size:12px;color:#64748B;line-height:1.6">{desc}</p>
           </div>'''
        for title, desc in [
          ("🔐 System Prompt Hardening", "Add explicit refusal instructions for sensitive categories. Use role constraints and boundary definitions in the system prompt."),
          ("🔍 Output Filtering", "Implement post-generation content filters to catch PII, code injection patterns, and harmful content before delivery."),
          ("🏗️ Jailbreak Resistance", "Test against DAN, AIM, roleplay, and fictional scenario jailbreaks. Apply RLHF safety tuning if model weights are accessible."),
          ("🔄 Multi-turn Guardrails", "Maintain conversation state to detect gradual manipulation across turns. Reset context after suspicious sequences."),
          ("🛡️ Tool Sandboxing", "Restrict tool/function call schemas. Never grant filesystem, network, or execution capabilities without strict allowlisting."),
          ("📋 Regular Re-testing", "Re-run the full 8-dimension scan after any fine-tune, system prompt change, or deployment config update."),
        ]
      ])}
    </div>
  </div>

  <!-- Footer -->
  <div style="text-align:center;padding:12px;font-size:11px;color:#94A3B8">
    AegisAI · AI Security Sandbox v4.0 &nbsp;·&nbsp; Generated {generated} &nbsp;·&nbsp;
    Scan ID: <span style="font-family:monospace">{scan_id[:16]}…</span>
  </div>
</div>

</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[report_gen] Report saved: {html_path}")
    return html_path