# attachment_scanner/pe_analyzer.py
# Layer 2c — PE (Windows Executable) Analyzer
#
# Four-layer analysis:
#   Layer A — Import table scan        (rules from pe_rules.json via pefile)
#   Layer B — Section analysis         (entropy, names, characteristics)
#   Layer C — PE header inspection     (timestamps, packer, TLS, overlay)
#   Layer D — String scan              (URLs, IPs, suspicious strings)
#
# Safe — file is never executed at any point.

import json
import math
import os
import re
import struct

# ── Rules loaded from pe_rules.json ──────────────────────────────────────────
_RULES_PATH = os.path.join(os.path.dirname(__file__), "pe_rules.json")

def _load_rules() -> list:
    try:
        with open(_RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"[pe_analyzer] pe_rules.json not found at {_RULES_PATH}."
        )
    except json.JSONDecodeError as e:
        raise ValueError(f"[pe_analyzer] pe_rules.json is invalid JSON: {e}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(rule, description, detail, risk, category, context=""):
    return {
        "stage":       "PE Header Analyzer",
        "rule":        rule,
        "description": description,
        "detail":      detail,
        "risk_tier":   risk,
        "category":    category,
        "context":     context[:120],
    }

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return round(
        -sum((c / length) * math.log2(c / length)
             for c in freq.values()), 3
    )


# ── Layer A — Import table scan (pefile) ─────────────────────────────────────

def _import_scan(pe, rules: list) -> list:
    """
    Parse actual PE import table using pefile and match
    against pe_rules.json suspicious API list.
    """
    findings = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return []

    # Build flat set of all imported API names
    imported_apis = set()
    import_map    = {}  # api -> dll name

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown"
        for imp in entry.imports:
            if imp.name:
                api = imp.name.decode("utf-8", errors="ignore")
                imported_apis.add(api)
                import_map[api] = dll_name

    # Match against rules
    for rule in rules:
        api = rule["api"]
        if api in imported_apis:
            dll = import_map.get(api, "unknown")
            findings.append(_make_finding(
                rule        = api,
                description = rule["description"],
                detail      = rule["detail"],
                risk        = rule["risk"],
                category    = rule["category"],
                context     = f"imported from {dll}",
            ))

    return findings


# ── Layer B — Section analysis ────────────────────────────────────────────────

SUSPICIOUS_SECTION_NAMES = {
    "UPX0":    ("UPX packer section detected",           "High",     "packer"),
    "UPX1":    ("UPX packer section detected",           "High",     "packer"),
    ".packed": ("Generic packed section name",           "High",     "packer"),
    ".themida":("Themida protector — strong anti-analysis","Critical","packer"),
    ".vmp0":   ("VMProtect section — VM-based obfuscation","Critical","packer"),
    ".vmp1":   ("VMProtect section — VM-based obfuscation","Critical","packer"),
    ".enigma1":("Enigma protector section",              "High",     "packer"),
    ".nsp0":   ("NsPack packer section",                 "High",     "packer"),
    ".MPRESS1":("MPRESS packer section",                 "High",     "packer"),
}

def _section_scan(pe) -> list:
    findings = []

    if not hasattr(pe, "sections"):
        return []

    high_entropy_reported = False

    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00").strip()
        data = section.get_data()
        ent  = _entropy(data)

        # Known packer section names
        if name in SUSPICIOUS_SECTION_NAMES:
            desc, risk, cat = SUSPICIOUS_SECTION_NAMES[name]
            findings.append(_make_finding(
                rule        = f"section_{name}",
                description = desc,
                detail      = f"Section name '{name}' matches known packer/protector",
                risk        = risk,
                category    = cat,
                context     = f"name={name} entropy={ent} size={len(data)}",
            ))

        # High entropy = packed or encrypted content
        if ent > 7.2 and not high_entropy_reported:
            high_entropy_reported = True
            findings.append(_make_finding(
                rule        = "high_entropy_section",
                description = f"Section '{name}' has entropy {ent} — packed or encrypted",
                detail      = "Entropy > 7.2 strongly indicates compressed/encrypted payload",
                risk        = "High",
                category    = "packer",
                context     = f"section={name} entropy={ent}",
            ))

        # Executable + writable section = shellcode staging area
        characteristics = section.Characteristics
        EXEC  = 0x20000000
        WRITE = 0x80000000
        if (characteristics & EXEC) and (characteristics & WRITE):
            findings.append(_make_finding(
                rule        = "rwx_section",
                description = f"Section '{name}' is both writable and executable",
                detail      = "RWX sections are used to stage and execute shellcode",
                risk        = "Critical",
                category    = "shellcode",
                context     = f"section={name} characteristics={hex(characteristics)}",
            ))

        # Empty raw size but large virtual size = unpacking stub
        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0x1000:
            findings.append(_make_finding(
                rule        = "empty_raw_section",
                description = f"Section '{name}' has no raw data but large virtual size",
                detail      = "Classic packer pattern — section filled at runtime during unpack",
                risk        = "High",
                category    = "packer",
                context     = f"section={name} virtual_size={hex(section.Misc_VirtualSize)}",
            ))

    return findings


# ── Layer C — PE header inspection ───────────────────────────────────────────

KNOWN_PACKERS = [
    (b"UPX!",     "UPX packer signature"),
    (b"ASPack",   "ASPack packer signature"),
    (b"Themida",  "Themida protector signature"),
    (b"PECompact","PECompact packer signature"),
    (b"MPRESS",   "MPRESS packer signature"),
    (b"nsp0",     "NsPack packer signature"),
    (b"PEC2",     "PECompact 2 signature"),
    (b"PEPACK",   "PEPACK packer signature"),
    (b"FSG!",     "FSG packer signature"),
    (b"WinUpack", "WinUpack packer signature"),
]

def _header_scan(pe, file_bytes: bytes) -> list:
    findings = []

    # ── Compile timestamp ────────────────────────────────────────────────────
    try:
        import datetime
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0:
            findings.append(_make_finding(
                rule        = "zero_timestamp",
                description = "PE compile timestamp is zero — wiped to hinder analysis",
                detail      = "Malware often zeros timestamps to remove forensic artifacts",
                risk        = "Medium",
                category    = "anti_analysis",
            ))
        else:
            dt = datetime.datetime.utcfromtimestamp(ts)
            # Future timestamp = fake/manipulated
            if dt.year > 2026:
                findings.append(_make_finding(
                    rule        = "future_timestamp",
                    description = f"PE timestamp is in the future: {dt.strftime('%Y-%m-%d')}",
                    detail      = "Manipulated timestamps are used to confuse forensic tools",
                    risk        = "Medium",
                    category    = "anti_analysis",
                    context     = str(dt),
                ))
            # Very old timestamp = fake (pre-PE era)
            elif dt.year < 1990:
                findings.append(_make_finding(
                    rule        = "ancient_timestamp",
                    description = f"PE timestamp predates Windows: {dt.strftime('%Y-%m-%d')}",
                    detail      = "Timestamp set before Windows existed — clearly manipulated",
                    risk        = "Medium",
                    category    = "anti_analysis",
                    context     = str(dt),
                ))
    except Exception:
        pass

    # ── TLS callbacks ────────────────────────────────────────────────────────
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            callbacks = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
            if callbacks:
                findings.append(_make_finding(
                    rule        = "tls_callbacks",
                    description = "TLS callbacks found — code executes before main entry point",
                    detail      = "Used for anti-debug tricks and to execute code before analysis",
                    risk        = "High",
                    category    = "anti_analysis",
                    context     = f"TLS callback VA: {hex(callbacks)}",
                ))
    except Exception:
        pass

    # ── Overlay detection ────────────────────────────────────────────────────
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset:
            overlay_size = len(file_bytes) - overlay_offset
            overlay_ent  = _entropy(file_bytes[overlay_offset:overlay_offset + 4096])
            findings.append(_make_finding(
                rule        = "pe_overlay",
                description = f"PE overlay detected — {overlay_size} bytes appended after PE",
                detail      = "Data appended after PE sections — hidden payload or config",
                risk        = "High" if overlay_ent > 7.0 else "Medium",
                category    = "hidden_payload",
                context     = f"offset={overlay_offset} size={overlay_size} entropy={overlay_ent}",
            ))
    except Exception:
        pass

    # ── Security features check ──────────────────────────────────────────────
    try:
        chars = pe.OPTIONAL_HEADER.DllCharacteristics
        ASLR  = 0x0040
        DEP   = 0x0100
        missing = []
        if not (chars & ASLR):
            missing.append("ASLR")
        if not (chars & DEP):
            missing.append("DEP/NX")
        if missing:
            findings.append(_make_finding(
                rule        = "missing_security_features",
                description = f"PE missing security features: {', '.join(missing)}",
                detail      = "Disabling ASLR/DEP makes exploitation significantly easier",
                risk        = "Medium",
                category    = "exploit",
                context     = f"DllCharacteristics={hex(chars)}",
            ))
    except Exception:
        pass

    # ── Known packer signatures ──────────────────────────────────────────────
    seen_packers = set()
    for sig, desc in KNOWN_PACKERS:
        if sig in file_bytes and sig not in seen_packers:
            seen_packers.add(sig)
            findings.append(_make_finding(
                rule        = sig.decode("utf-8", errors="ignore"),
                description = desc,
                detail      = "Known packer/protector signature found in binary",
                risk        = "High",
                category    = "packer",
            ))

    # ── Suspicious section count ─────────────────────────────────────────────
    try:
        if len(pe.sections) > 10:
            findings.append(_make_finding(
                rule        = "many_sections",
                description = f"Unusually high section count: {len(pe.sections)}",
                detail      = "High section counts can indicate protectors or injected code",
                risk        = "Medium",
                category    = "packer",
                context     = f"section_count={len(pe.sections)}",
            ))
    except Exception:
        pass

    return findings


# ── Layer D — String scan ─────────────────────────────────────────────────────

SUSPICIOUS_STRINGS = [
    (rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
     "IP-based URL — likely C2 server",                  "High",   "network"),
    (rb"\\cmd\.exe",
     "CMD path hardcoded in binary",                      "High",   "shell_exec"),
    (rb"\\powershell\.exe",
     "PowerShell path hardcoded in binary",               "High",   "powershell"),
    (rb"net user .{1,40} /add",
     "User creation command — backdoor account",          "Critical","persistence"),
    (rb"net localgroup administrators .{1,40} /add",
     "Privilege escalation — adding user to admins",      "Critical","persistence"),
    (rb"schtasks /create",
     "Scheduled task creation — persistence",             "High",   "persistence"),
    (rb"reg add .{1,60}\\run",
     "Registry run key modification — persistence",       "High",   "persistence"),
    (rb"[a-zA-Z0-9+/]{100,}={0,2}",
     "Large base64 blob — encoded payload",               "Medium", "obfuscation"),
    (rb"TEMP\\[a-zA-Z0-9]{4,20}\.(exe|dll|bat|vbs)",
     "Temp directory payload drop",                       "High",   "dropper"),
    (rb"\\AppData\\Roaming\\[a-zA-Z0-9]{4,30}\.exe",
     "AppData persistence location",                      "High",   "persistence"),
]

def _string_scan(file_bytes: bytes) -> list:
    findings = []
    seen     = set()

    for pattern, desc, risk, category in SUSPICIOUS_STRINGS:
        match = re.search(pattern, file_bytes, re.IGNORECASE)
        if match and pattern not in seen:
            seen.add(pattern)
            context = file_bytes[
                max(0, match.start()-20): match.end()+40
            ].decode("latin-1", errors="ignore").replace("\x00", "")
            findings.append(_make_finding(
                rule        = desc,
                description = desc,
                detail      = "Suspicious string found in PE binary content",
                risk        = risk,
                category    = category,
                context     = context,
            ))

    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedupe(findings: list) -> list:
    TIER_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    seen = {}
    for f in findings:
        key      = (f["rule"].split(" (")[0].lower(), f["category"])
        existing = seen.get(key)
        if not existing:
            seen[key] = f
        else:
            if TIER_ORDER.get(f["risk_tier"], 0) > TIER_ORDER.get(existing["risk_tier"], 0):
                seen[key] = f
    return list(seen.values())


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze(file_bytes: bytes) -> list:
    """
    Full 4-layer PE analysis.
    Called by attachment_main.py — returns list of findings.
    """
    if file_bytes[:2] != b"\x4d\x5a":
        return []

    try:
        import pefile
    except ImportError:
        return [_make_finding(
            rule        = "pefile_missing",
            description = "pefile not installed — PE header scan skipped",
            detail      = "Run: pip install pefile",
            risk        = "Low",
            category    = "scanner_warning",
        )]

    import pefile

    rules    = _load_rules()
    findings = []

    try:
        pe = pefile.PE(data=file_bytes, fast_load=False)
    except Exception as e:
        return [_make_finding(
            rule        = "pe_parse_error",
            description = f"PE structure could not be parsed: {e}",
            detail      = "Malformed PE — may be corrupted, truncated or obfuscated",
            risk        = "Medium",
            category    = "malformed",
        )]

    findings += _import_scan(pe, rules)     # Layer A
    findings += _section_scan(pe)           # Layer B
    findings += _header_scan(pe, file_bytes)# Layer C
    findings += _string_scan(file_bytes)    # Layer D

    pe.close()

    findings = _dedupe(findings)
    return findings