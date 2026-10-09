# attachment_scanner/pattern_engine.py
# Layer 2e — YARA Rule Engine
#
# Two-layer scanning:
#   Layer A — Real YARA engine (1973 community rules)
#   Layer B — Fallback pattern scan (if YARA unavailable)
#
# YARA rules are compiled ONCE at startup for fast scanning.

import os
import re

RULES_DIR = os.path.join(os.path.dirname(__file__), "yara_rules")

# ── Fallback patterns (used if YARA unavailable) ──────────────────────────────
FALLBACK_PATTERNS = [
    # ── Ransomware ───────────────────────────────────────────────────────────
    (b"your files have been encrypted", "Critical", "ransomware",
     "Ransomware note detected in file"),
    (b"pay the ransom",                 "Critical", "ransomware",
     "Ransom payment demand found"),
    (b"decrypt your files",             "Critical", "ransomware",
     "File decryption offer — ransomware indicator"),
    (b"vssadmin delete shadows",        "Critical", "evasion",
     "Deletes volume shadow copies — ransomware technique"),

    # ── ActiveX / COM scripting (JS, VBScript, WSH) ──────────────────────────
    (b"activexobject",                  "Critical", "activex",
     "ActiveXObject instantiation — COM/shell access from script"),
    (b"wscript.shell",                  "Critical", "activex",
     "WScript.Shell — executes arbitrary OS commands"),
    (b"wscript.createobject",           "Critical", "activex",
     "WScript.CreateObject — creates arbitrary COM objects"),
    (b"shell.application",              "Critical", "activex",
     "Shell.Application COM object — file system and process access"),
    (b"scripting.filesystemobject",     "High",     "activex",
     "FileSystemObject — reads/writes/deletes files"),
    (b"createobject(",                  "High",     "activex",
     "CreateObject call — instantiates COM/ActiveX object"),

    # ── Dangerous script execution ─────────────────────────────────────────
    (b"shell.run(",                     "Critical", "shell_exec",
     "Shell.Run() — executes OS process from script"),
    (b"shell.exec(",                    "Critical", "shell_exec",
     "Shell.Exec() — executes OS command with output capture"),
    (b"cmd.exe",                        "Critical", "shell_exec",
     "CMD execution detected"),
    (b"powershell.exe",                 "Critical", "shell_exec",
     "PowerShell executable referenced in file"),
    (b"mshta",                          "Critical", "lolbin",
     "MSHTA execution — bypasses application controls"),
    (b"regsvr32",                       "Critical", "lolbin",
     "Regsvr32 abuse — LOLBin COM registration bypass"),

    # ── PowerShell ────────────────────────────────────────────────────────
    (b"invoke-expression",              "Critical", "powershell",
     "PowerShell Invoke-Expression — executes dynamic code"),
    (b"iex(",                           "Critical", "powershell",
     "IEX shorthand — obfuscated PowerShell execution"),
    (b"-executionpolicy bypass",        "Critical", "powershell",
     "Bypasses PowerShell execution policy"),
    (b"powershell -enc",                "Critical", "powershell",
     "Encoded PowerShell — obfuscated command"),
    (b"invoke-webrequest",              "High",     "downloader",
     "Invoke-WebRequest — downloads content from internet"),
    (b"downloadstring(",                "High",     "downloader",
     "DownloadString — downloads and executes remote code"),

    # ── Obfuscation ───────────────────────────────────────────────────────
    (b"frombase64string",               "High",     "obfuscation",
     "Base64 decoding — common payload obfuscation"),
    (b"eval(unescape",                  "Critical", "obfuscation",
     "eval(unescape()) — classic JS malware obfuscation pattern"),
    (b"eval(atob(",                     "Critical", "obfuscation",
     "eval(atob()) — base64-decoded JS execution"),
    (b"string.fromcharcode(",           "High",     "obfuscation",
     "String.fromCharCode() — character-code obfuscation"),
    (b"document.write(unescape",        "High",     "obfuscation",
     "document.write(unescape()) — injecting decoded content"),

    # ── Network / Downloader ──────────────────────────────────────────────
    (b"urldownloadtofile",              "Critical", "downloader",
     "URLDownloadToFile — downloads and saves remote payload"),
    (b"xmlhttp",                        "High",     "downloader",
     "XMLHTTP object — HTTP request from script (C2 / dropper)"),
    (b"winhttp",                        "High",     "downloader",
     "WinHTTP object — HTTP request from script"),
    (b"bitsadmin",                      "High",     "lolbin",
     "BITSAdmin — background download utility abuse"),
    (b"certutil",                       "High",     "lolbin",
     "CertUtil — can decode and download files"),

    # ── Persistence ───────────────────────────────────────────────────────
    (b"net user /add",                  "Critical", "persistence",
     "Creates hidden user account"),
    (b"net localgroup administrators",  "Critical", "persistence",
     "Adds user to admin group"),
    (b"schtasks /create",               "High",     "persistence",
     "Creates scheduled task — persistence mechanism"),
    (b"reg add",                        "High",     "persistence",
     "Registry key creation — possible persistence or config change"),

    # ── DDE / Macro ───────────────────────────────────────────────────────
    (b"ddeauto",                        "Critical", "dde",
     "DDE auto-execute command in document"),
]

# ── YARA compiler — runs once at startup ──────────────────────────────────────

def _compile_yara_rules():
    """
    Walks yara_rules/ directory, compiles all .yar/.yara files.
    Skips files with syntax errors and continues.
    Returns compiled rules object or None if YARA unavailable.
    """
    try:
        import yara
    except ImportError:
        print("WARNING: yara-python not installed — using fallback patterns")
        return None

    if not os.path.exists(RULES_DIR):
        print(f"WARNING: YARA rules directory not found at {RULES_DIR}")
        print("Run: python download_yara_rules.py")
        return None

    # Collect all rule files
    rule_files   = {}
    skipped      = 0
    loaded       = 0

    for root, _, files in os.walk(RULES_DIR):
        for fname in files:
            if not fname.endswith((".yar", ".yara")):
                continue

            fpath     = os.path.join(root, fname)
            namespace = fname.replace(".yar", "").replace(".yara", "")

            # Try compiling each file individually first to skip bad ones
            try:
                yara.compile(filepath=fpath)
                rule_files[namespace] = fpath
                loaded += 1
            except yara.SyntaxError:
                skipped += 1
            except Exception:
                skipped += 1

    if not rule_files:
        print("WARNING: No valid YARA rules found")
        return None

    # Compile all valid rules together
    try:
        compiled = yara.compile(filepaths=rule_files)
        print(f"[YARA] Loaded {loaded} rule files ({skipped} skipped due to syntax errors)")
        return compiled
    except Exception as e:
        print(f"WARNING: YARA compilation failed: {e}")
        return None


# Compile once at server startup
YARA_RULES = _compile_yara_rules()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(rule, description, detail, risk, category, context=""):
    return {
        "stage":       "YARA-style Pattern Engine",
        "rule":        rule,
        "description": description,
        "detail":      detail,
        "risk_tier":   risk,
        "category":    category,
        "context":     context[:120],
    }


# ── Layer A — Real YARA scan ──────────────────────────────────────────────────

# Map YARA rule name keywords to risk tiers
RISK_KEYWORDS = {
    "Critical": [
        "ransomware", "shellcode", "exploit", "backdoor",
        "rootkit", "rat_", "trojan", "dropper", "injector",
        "keylogger", "stealer", "worm", "apt_",
    ],
    "High": [
        "malware", "miner", "cryptominer", "botnet",
        "downloader", "obfuscat", "packer", "powershell",
        "macro", "webshell", "lolbin",
    ],
    "Medium": [
        "suspicious", "generic", "heuristic",
        "potentially", "unwanted", "adware",
    ],
}

def _get_risk_from_rule_name(rule_name: str) -> str:
    name_lower = rule_name.lower()
    for risk, keywords in RISK_KEYWORDS.items():
        if any(kw in name_lower for kw in keywords):
            return risk
    return "Medium"

def _get_category_from_rule_name(rule_name: str) -> str:
    name_lower = rule_name.lower()
    category_map = {
        "ransomware":  "ransomware",
        "rat":         "rat",
        "trojan":      "trojan",
        "backdoor":    "backdoor",
        "rootkit":     "rootkit",
        "shellcode":   "shellcode",
        "exploit":     "exploit",
        "miner":       "cryptominer",
        "botnet":      "botnet",
        "downloader":  "downloader",
        "webshell":    "webshell",
        "packer":      "packer",
        "powershell":  "powershell",
        "macro":       "macro",
        "stealer":     "stealer",
        "keylogger":   "keylogger",
        "apt":         "apt",
        "worm":        "worm",
    }
    for keyword, category in category_map.items():
        if keyword in name_lower:
            return category
    return "malware_generic"


def _yara_scan(file_bytes: bytes) -> list:
    """
    Scan file bytes against all compiled YARA rules.
    Returns findings in standard format.
    """
    if YARA_RULES is None:
        return []

    findings = []

    try:
        matches = YARA_RULES.match(data=file_bytes, timeout=30)
    except Exception:
        return []

    seen = set()

    for match in matches:
        rule_name = match.rule
        if rule_name in seen:
            continue
        seen.add(rule_name)

        # Get context from first string match
        context = ""
        try:
            if match.strings:
                first = match.strings[0]
                # yara-python 4.x uses instances
                if hasattr(first, "instances") and first.instances:
                    instance = first.instances[0]
                    raw      = getattr(instance, "matched_data", b"")
                    context  = raw.decode("latin-1", errors="ignore")[:80]
                elif hasattr(first, "matched_data"):
                    context = first.matched_data.decode("latin-1", errors="ignore")[:80]
        except Exception:
            pass

        risk     = _get_risk_from_rule_name(rule_name)
        category = _get_category_from_rule_name(rule_name)

        # Use YARA rule metadata if available
        description = f"YARA rule matched: {rule_name}"
        detail      = f"Namespace: {match.namespace}"

        try:
            meta = match.meta
            if meta.get("description"):
                description = meta["description"]
            if meta.get("author"):
                detail = f"Author: {meta['author']} | {detail}"
        except Exception:
            pass

        findings.append(_make_finding(
            rule        = rule_name,
            description = description,
            detail      = detail,
            risk        = risk,
            category    = category,
            context     = context,
        ))

    return findings


# ── Layer B — Fallback pattern scan ───────────────────────────────────────────

def _fallback_scan(file_bytes: bytes) -> list:
    """
    Simple byte pattern scan used when YARA is unavailable.
    """
    findings   = []
    file_lower = file_bytes.lower()
    seen       = set()

    for (pattern, risk, category, desc) in FALLBACK_PATTERNS:
        pattern_lower = pattern.lower()
        if pattern_lower not in file_lower:
            continue
        if pattern_lower in seen:
            continue
        seen.add(pattern_lower)

        pos     = file_lower.find(pattern_lower)
        start   = max(0, pos - 30)
        end     = min(len(file_bytes), pos + 80)
        context = (
            file_bytes[start:end]
            .decode("latin-1", errors="ignore")
            .replace("\x00", " ")
            .strip()
        )

        findings.append(_make_finding(
            rule        = pattern.decode("utf-8", errors="ignore"),
            description = desc,
            detail      = "Matched via fallback pattern scan",
            risk        = risk,
            category    = category,
            context     = context,
        ))

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def scan(file_bytes: bytes) -> list:
    """
    Dual-layer scan:
      Layer A — YARA community rules (when available)
      Layer B — Critical fallback patterns always run alongside YARA
                to catch ActiveX, shell exec, PS obfuscation, etc.
    Results from both layers are merged and deduplicated.
    """
    findings = []

    if YARA_RULES is not None:
        findings += _yara_scan(file_bytes)

    # Always run fallback patterns — they catch specific critical indicators
    # that YARA community rules frequently miss (ActiveXObject, Shell.Run, etc.)
    findings += _fallback_scan(file_bytes)

    # Deduplicate: keep highest-severity entry per (category, pattern)
    TIER_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    seen: dict = {}
    for f in findings:
        key      = (f.get("category", ""), f.get("rule", "").split(" (")[0].lower())
        existing = seen.get(key)
        if not existing:
            seen[key] = f
        else:
            if TIER_ORDER.get(f.get("risk_tier", "Low"), 1) > \
               TIER_ORDER.get(existing.get("risk_tier", "Low"), 1):
                seen[key] = f

    return list(seen.values())