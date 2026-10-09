# attachment_scanner/hash_checker.py
# Stage 3 — Hash Reputation Checker
#
# Computes MD5, SHA1, SHA256 of file
# Checks SHA256 against MalwareBazaar offline CSV
# Falls back to local known-bad hash list
#
# CSV is loaded ONCE at server startup into memory
# for fast O(1) lookups on every scan.

import hashlib
import os

# ── Paths ─────────────────────────────────────────────────────────────────────
CSV_PATH = os.path.join(os.path.dirname(__file__), "malwarebazaar_full.csv")

# ── Local fallback — always checked even without CSV ─────────────────────────
KNOWN_BAD_HASHES = {
    # MD5
    "44d88612fea8a8f36de82e1278abb02f": "EICAR antivirus test file",
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file — possible evasion",
    "cf8bd9dfddff007f75adf4c2be48005c": "Mirai botnet sample",
    # SHA256
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
        "EICAR antivirus test file",
}

# ── CSV column indices (MalwareBazaar format) ─────────────────────────────────
COL_FIRSTSEEN = 0
COL_SHA256    = 1
COL_MD5       = 2
COL_SHA1      = 3
COL_FILENAME  = 5
COL_FILETYPE  = 6
COL_SIGNATURE = 8


def _load_csv() -> dict:
    db = {}

    if not os.path.exists(CSV_PATH):
        print(f"WARNING: {CSV_PATH} not found")
        return db

    try:
        count = 0
        with open(CSV_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                try:
                    # Strip outer quotes and split on '", "'
                    line   = line.strip('"')
                    values = line.split('", "')

                    sha256 = values[COL_SHA256].strip().lower()

                    if not sha256 or len(sha256) != 64:
                        continue

                    db[sha256] = {
                        "malware_family": values[COL_SIGNATURE].strip()
                            if len(values) > COL_SIGNATURE else "Unknown",
                        "file_type":      values[COL_FILETYPE].strip()
                            if len(values) > COL_FILETYPE  else "Unknown",
                        "first_seen":     values[COL_FIRSTSEEN].strip()
                            if len(values) > COL_FIRSTSEEN else "Unknown",
                        "file_name":      values[COL_FILENAME].strip()
                            if len(values) > COL_FILENAME  else "Unknown",
                        "md5":            values[COL_MD5].strip().lower()
                            if len(values) > COL_MD5       else "",
                        "sha1":           values[COL_SHA1].strip().lower()
                            if len(values) > COL_SHA1      else "",
                    }
                    count += 1

                except Exception:
                    continue

        print(f"Loaded {count:,} hashes from MalwareBazaar CSV")

    except Exception as e:
        print(f"Error loading MalwareBazaar CSV: {e}")

    return db


# ── Load once at server startup ───────────────────────────────────────────────
MALWAREBAZAAR_DB = _load_csv()


# ── Main entry point ──────────────────────────────────────────────────────────

def check(file_bytes: bytes) -> dict:
    """
    Calculate file hashes and check against:
    1. MalwareBazaar offline CSV (SHA256)
    2. Local fallback database   (MD5 + SHA256)

    Returns result dict used by attachment_main.py
    """
    md5    = hashlib.md5(file_bytes).hexdigest()
    sha1   = hashlib.sha1(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    known_malware = None
    source        = None
    details       = None

    # Step 1 — MalwareBazaar CSV (SHA256 lookup)
    match = MALWAREBAZAAR_DB.get(sha256.lower())
    if match:
        known_malware = match["malware_family"] or "Unknown malware family"
        source        = "MalwareBazaar CSV"
        details       = match

    # Step 2 — local fallback (MD5 + SHA256)
    if not known_malware:
        local = (
            KNOWN_BAD_HASHES.get(md5.lower()) or
            KNOWN_BAD_HASHES.get(sha256.lower())
        )
        if local:
            known_malware = local
            source        = "Local database"
            details       = {"malware_family": local}

    return {
        "md5":           md5,
        "sha1":          sha1,
        "sha256":        sha256,
        "known_malware": known_malware,
        "verdict":       "MALWARE DETECTED" if known_malware else "Not in database",
        "source":        source or "Not found",
        "details":       details,
        "database_size": f"{len(MALWAREBAZAAR_DB):,} hashes loaded",
        "malwarebazaar": "Offline CSV mode — fully private",
    }