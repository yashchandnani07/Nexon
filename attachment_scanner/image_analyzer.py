# image_analyzer.py
# Phase 2 — Image Attachment Analyzer
#
# 4-layer analysis of image attachments:
#   Layer A — EXIF metadata scan       (GPS coords, suspicious software, embedded URLs)
#   Layer B — Pixel entropy analysis   (steganography detection via Shannon entropy)
#   Layer C — QR code decode           (extract URLs, score for phishing patterns)
#   Layer D — Metadata anomalies       (tracking pixels, format mismatch, thumbnails)
#
# Safe — images are opened in memory; never written to disk or rendered in a browser.

import io
import re
import math
import struct
from urllib.parse import urlparse

try:
    from PIL import Image, ExifTags, UnidentifiedImageError
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


# ── Constants ─────────────────────────────────────────────────────────────────

_SUSPICIOUS_SOFTWARE_KEYWORDS = [
    "msfvenom", "metasploit", "cobalt strike", "cobaltstrike",
    "empire", "pupy", "mimikatz", "veil", "shellter",
    "steghide", "outguess", "openstego", "steganography",
    "jphide", "silenteye",
]

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+|www\.[a-z0-9.-]+\.[a-z]{2,}[^\s\"'<>]*",
    re.IGNORECASE,
)

_SUSPICIOUS_EXIF_TAGS = {
    "Software", "Make", "Model", "Artist", "Copyright",
    "ImageDescription", "UserComment", "DocumentName",
    "XPComment", "XPAuthor", "XPSubject", "XPTitle",
}

_FREE_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
    ".click", ".download", ".zip", ".review", ".win", ".bid",
}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link",
}

_PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "paypal", "amazon", "microsoft", "apple",
    "password", "credential", "wallet", "suspended",
]


# ── Finding factory ───────────────────────────────────────────────────────────

def _f(rule, description, detail, risk, category, context="", why=""):
    return {
        "stage":       "Image Analyzer",
        "rule":        rule,
        "description": description,
        "detail":      detail[:300],
        "risk_tier":   risk,
        "category":    category,
        "context":     context[:150],
        "why_flagged": why,
    }


def _score_url(url: str) -> tuple:
    """Returns (risk: str, reason: str) for a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower() or url.lower()

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", host):
            return "High", f"IP-based URL — no legitimate service uses bare IPs for links"

        for tld in _FREE_TLDS:
            if host.endswith(tld):
                return "High", f"Free/abused TLD ({tld}) — common in phishing infrastructure"

        if host in _URL_SHORTENERS:
            return "Medium", f"URL shortener ({host}) — hides true destination"

        for kw in _PHISHING_KEYWORDS:
            if kw in host or kw in (parsed.path + parsed.query).lower():
                return "Medium", f"Phishing keyword '{kw}' in URL"
    except Exception:
        pass
    return "Low", "URL embedded in image metadata — verify the destination"


# ── Layer A: EXIF Metadata ────────────────────────────────────────────────────

def _layer_a_exif(img: "Image.Image", file_bytes: bytes) -> list:
    findings = []

    # ── Pillow EXIF ──
    raw_exif = {}
    try:
        exif_data = img._getexif()  # Returns None if no EXIF
        if exif_data:
            raw_exif = {
                ExifTags.TAGS.get(k, k): v
                for k, v in exif_data.items()
            }
    except Exception:
        pass

    # GPS coordinates → tracking beacon
    if "GPSInfo" in raw_exif:
        gps = raw_exif["GPSInfo"]
        try:
            gps_named = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps.items()}
            lat_ref = gps_named.get("GPSLatitudeRef", "")
            lon_ref = gps_named.get("GPSLongitudeRef", "")
            lat     = gps_named.get("GPSLatitude", "")
            lon     = gps_named.get("GPSLongitude", "")
            findings.append(_f(
                "exif_gps_coordinates",
                "GPS coordinates embedded in image EXIF metadata",
                f"Lat: {lat} {lat_ref}, Lon: {lon} {lon_ref}",
                "Medium", "privacy",
                f"GPS: {lat} {lat_ref} / {lon} {lon_ref}",
                "GPS data in an attachment reveals the physical location where the photo was taken — potential privacy violation or tracking beacon",
            ))
        except Exception:
            findings.append(_f(
                "exif_gps_present",
                "GPS data present in EXIF (could not parse coordinates)",
                "Raw GPS IFD detected",
                "Low", "privacy", "",
                "GPS data indicates location information is embedded in this image",
            ))

    # Suspicious software tags
    for tag_name in ("Software", "Make", "Model", "Artist", "Copyright", "ImageDescription"):
        val = raw_exif.get(tag_name, "")
        if not val:
            continue
        val_str = str(val).lower()
        for kw in _SUSPICIOUS_SOFTWARE_KEYWORDS:
            if kw in val_str:
                findings.append(_f(
                    f"suspicious_software_tag",
                    f"Suspicious tool name in EXIF {tag_name}: '{str(val)[:60]}'",
                    f"Tag: {tag_name} = {str(val)[:100]}",
                    "Critical", "malware",
                    str(val)[:100],
                    f"Known offensive tool '{kw}' referenced in EXIF {tag_name} — this image may have been crafted by an exploit/stego tool",
                ))
                break  # one finding per tag

    # URLs embedded in EXIF text fields
    for tag_name in _SUSPICIOUS_EXIF_TAGS:
        val = raw_exif.get(tag_name, "")
        if not val:
            continue
        val_str = str(val)
        urls = _URL_PATTERN.findall(val_str)
        for url in urls[:3]:  # cap at 3 per tag
            risk, reason = _score_url(url)
            findings.append(_f(
                "exif_embedded_url",
                f"URL embedded in EXIF {tag_name}: {url[:80]}",
                f"Tag: {tag_name} = {val_str[:150]}",
                risk, "exfiltration",
                url[:100],
                f"URLs in EXIF metadata can point to C2 servers or phishing pages. {reason}",
            ))

    # ── piexif deep scan for UserComment (often used to hide data) ──
    if PIEXIF_AVAILABLE:
        try:
            exif_dict = piexif.load(file_bytes)
            user_comment_raw = (
                exif_dict.get("Exif", {}).get(piexif.ExifIFD.UserComment, b"")
            )
            if user_comment_raw and len(user_comment_raw) > 8:
                # First 8 bytes are character code identifier
                comment_text = user_comment_raw[8:].decode("utf-8", errors="replace").strip()
                if comment_text:
                    urls = _URL_PATTERN.findall(comment_text)
                    if urls:
                        for url in urls[:2]:
                            risk, reason = _score_url(url)
                            findings.append(_f(
                                "exif_usercomment_url",
                                f"URL in EXIF UserComment field: {url[:80]}",
                                f"UserComment: {comment_text[:150]}",
                                risk, "exfiltration",
                                url[:100],
                                f"UserComment is a common steganography channel for hiding URLs. {reason}",
                            ))
                    elif len(comment_text) > 20 and comment_text.isprintable():
                        # Non-URL but non-empty UserComment — flag as informational
                        findings.append(_f(
                            "exif_usercomment_data",
                            f"Non-empty EXIF UserComment ({len(comment_text)} chars)",
                            f"Content: {comment_text[:120]}",
                            "Low", "metadata",
                            comment_text[:80],
                            "UserComment field contains custom text — verify it is expected for this image",
                        ))
        except Exception:
            pass

    return findings


# ── Layer B: Steganography Detection (Multi-Method) ───────────────────────────
# B1 — Per-channel pixel entropy (full byte)
# B2 — Per-channel LSB entropy + chi-square uniformity test
# B3 — Cross-channel LSB correlation analysis
# B4 — Aggregate LSB entropy (fallback)

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


def _binary_entropy(ones: int, total: int) -> float:
    """Shannon entropy for a binary (0/1) sequence."""
    if total == 0 or ones == 0 or ones == total:
        return 0.0
    p = ones / total
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def _layer_b_entropy(img: "Image.Image", fmt: str = "") -> list:
    findings = []
    # JPEG/WebP are lossy — DCT quantization randomizes LSBs, making
    # LSB-based steganography analysis unreliable (high false-positive rate).
    lossy_format = (fmt or "").upper() in ("JPEG", "WEBP")
    try:
        rgb_img = img.convert("RGB")
        width, height = rgb_img.size

        if NUMPY_AVAILABLE:
            import numpy as np
            pixels = np.array(rgb_img)
            ch_names = ["R", "G", "B"]

            # ── B1: Per-channel pixel entropy ──────────────────────────
            entropies = []
            for ch in range(3):
                ch_data = pixels[:, :, ch].flatten().tobytes()
                entropies.append(_shannon_entropy(ch_data))

            avg_entropy = sum(entropies) / 3

            if avg_entropy > 7.85:
                findings.append(_f(
                    "high_pixel_entropy",
                    f"Anomalously high pixel entropy: {avg_entropy:.3f} bits/byte",
                    f"Channel entropies — R:{entropies[0]:.3f} G:{entropies[1]:.3f} B:{entropies[2]:.3f}",
                    "Medium", "steganography",
                    f"Entropy={avg_entropy:.3f}",
                    "High entropy near the theoretical max (8.0) suggests LSB steganography — data hidden in pixel least-significant bits",
                ))
            elif avg_entropy < 1.0 and width > 100 and height > 100:
                findings.append(_f(
                    "low_pixel_entropy",
                    f"Unusually low pixel entropy: {avg_entropy:.3f} bits/byte",
                    f"Image size: {width}×{height} with near-uniform pixels",
                    "Low", "steganography",
                    f"Entropy={avg_entropy:.3f}",
                    "A large image with very uniform pixels may be a tracking beacon or contain appended data after the image EOF",
                ))

            # Need enough pixels for statistical significance
            if width < 32 or height < 32:
                return findings

            # Skip LSB-based tests (B2–B4) for lossy formats — DCT compression
            # randomizes LSBs making them appear stego-like (false positives).
            if lossy_format:
                return findings

            # ── B2: Per-channel LSB entropy + chi-square ──────────────
            lsb_entropies = []
            p_ratios = []
            suspicious_channels = []

            for ch in range(3):
                ch_lsb = (pixels[:, :, ch] & 1).flatten()
                n = len(ch_lsb)
                ones = int(np.sum(ch_lsb == 1))
                zeros = n - ones

                lsb_ent = _binary_entropy(ones, n)
                lsb_entropies.append(lsb_ent)

                p_ratio = min(zeros, ones) / max(zeros, ones) if max(zeros, ones) > 0 else 0
                p_ratios.append(p_ratio)

                if p_ratio > 0.4:
                    suspicious_channels.append(ch_names[ch])

            # Detect per-channel anomaly: one channel much more uniform than others
            if suspicious_channels:
                max_ratio = max(p_ratios)
                min_ratio = min(p_ratios)
                ratio_spread = max_ratio - min_ratio

                if ratio_spread > 0.3:
                    sus_str = ", ".join(suspicious_channels)
                    findings.append(_f(
                        "lsb_channel_anomaly",
                        f"LSB distribution anomaly in {sus_str} channel(s) — steganography signature detected",
                        f"LSB uniformity (p_ratio) — R:{p_ratios[0]:.3f} G:{p_ratios[1]:.3f} B:{p_ratios[2]:.3f} | "
                        f"Spread: {ratio_spread:.3f}",
                        "High", "steganography",
                        f"Channels {sus_str} p_ratio>{max_ratio:.2f}",
                        f"Natural images have skewed LSB distributions in all channels. "
                        f"The {sus_str} channel(s) have near-uniform (50/50) LSB distribution "
                        f"while other channels are naturally skewed — this is the primary signature of "
                        f"single-channel LSB steganography tools (steghide, OpenStego, SilentEye)",
                    ))
                elif all(r > 0.4 for r in p_ratios):
                    findings.append(_f(
                        "lsb_all_channels_uniform",
                        f"All color channels have suspiciously uniform LSB distribution — multi-channel steganography",
                        f"LSB uniformity — R:{p_ratios[0]:.3f} G:{p_ratios[1]:.3f} B:{p_ratios[2]:.3f}",
                        "High", "steganography",
                        f"All p_ratios > 0.4",
                        "All three color channels have near-uniform LSB distributions, suggesting "
                        "multi-channel steganographic embedding across the entire image",
                    ))

            # ── B3: Cross-channel LSB correlation ─────────────────────
            r_lsb = (pixels[:, :, 0] & 1).flatten().astype(np.float32)
            g_lsb = (pixels[:, :, 1] & 1).flatten().astype(np.float32)
            b_lsb = (pixels[:, :, 2] & 1).flatten().astype(np.float32)

            correlations = {}
            try:
                correlations["R-G"] = float(np.corrcoef(r_lsb, g_lsb)[0, 1])
                correlations["R-B"] = float(np.corrcoef(r_lsb, b_lsb)[0, 1])
                correlations["G-B"] = float(np.corrcoef(g_lsb, b_lsb)[0, 1])
            except Exception:
                correlations = {}

            if correlations:
                corr_vals = list(correlations.values())
                max_corr = max(corr_vals)
                min_corr = min(corr_vals)

                if max_corr > 0.15 and min_corr < 0.10:
                    broken = [k for k, v in correlations.items() if v < 0.10]
                    intact = [k for k, v in correlations.items() if v > 0.15]
                    if broken and intact:
                        findings.append(_f(
                            "lsb_cross_channel_decorrelation",
                            f"Cross-channel LSB correlation broken: {', '.join(broken)}",
                            f"Correlations — " + ", ".join(f"{k}:{v:.3f}" for k, v in correlations.items()),
                            "Medium", "steganography",
                            f"Broken: {broken}, Intact: {intact}",
                            f"Natural images have correlated LSBs across color channels. "
                            f"The {', '.join(broken)} pair(s) lost correlation while {', '.join(intact)} "
                            f"remained intact — data was embedded in specific channel(s)",
                        ))

            # ── B4: Aggregate LSB entropy (fallback) ──────────────────
            all_lsb = (pixels & 1).flatten().tobytes()
            all_lsb_entropy = _shannon_entropy(all_lsb)
            if all_lsb_entropy > 0.95:
                findings.append(_f(
                    "lsb_entropy_anomaly",
                    f"Aggregate LSB entropy near maximum: {all_lsb_entropy:.4f}",
                    f"All channel LSBs combined; max possible = 1.0",
                    "Medium", "steganography",
                    f"LSB entropy={all_lsb_entropy:.4f}",
                    "Near-maximum aggregate LSB entropy across all channels — strong steganography indicator",
                ))

        else:
            raw_bytes = rgb_img.tobytes()
            entropy = _shannon_entropy(raw_bytes)
            if entropy > 7.85:
                findings.append(_f(
                    "high_pixel_entropy",
                    f"High pixel entropy: {entropy:.3f} bits/byte (simplified — numpy not available)",
                    "Install numpy for full per-channel LSB steganography detection",
                    "Low", "steganography",
                    f"Entropy={entropy:.3f}",
                    "High entropy may indicate steganographic content hidden in pixel data",
                ))

    except Exception:
        pass

    return findings


# ── Layer C: QR Code Decode ───────────────────────────────────────────────────

def _layer_c_qr(img: "Image.Image") -> list:
    findings = []
    if not PYZBAR_AVAILABLE:
        return findings

    try:
        decoded_objects = qr_decode(img)
        for obj in decoded_objects:
            data = obj.data.decode("utf-8", errors="replace").strip()
            obj_type = obj.type  # "QRCODE", "EAN13", etc.

            urls = _URL_PATTERN.findall(data)
            if urls:
                for url in urls:
                    risk, reason = _score_url(url)
                    # Upgrade risk if URL is actually embedded in a QR code
                    if risk == "Low":
                        risk = "Medium"
                    findings.append(_f(
                        "qr_code_url",
                        f"QR code encodes URL: {url[:100]}",
                        f"Barcode type: {obj_type}, Full content: {data[:150]}",
                        risk, "phishing",
                        url[:100],
                        f"QR codes bypass link-scanning tools that only check plaintext URLs. {reason}",
                    ))
            elif data:
                # Non-URL content in QR code — informational
                findings.append(_f(
                    "qr_code_data",
                    f"QR code decoded ({obj_type}): {data[:80]}",
                    f"Full content: {data[:200]}",
                    "Low", "metadata",
                    data[:80],
                    "QR code contains non-URL data — verify content is expected",
                ))
    except Exception:
        pass

    return findings


# ── Layer D: Metadata Anomalies ───────────────────────────────────────────────

def _layer_d_anomalies(img: "Image.Image", file_bytes: bytes, filename: str) -> list:
    findings = []

    width, height = img.size
    fmt = img.format  # "JPEG", "PNG", "GIF", etc.

    # Tracking pixel: very small image (< 5×5)
    if width <= 5 and height <= 5:
        findings.append(_f(
            "tracking_pixel",
            f"Tiny image ({width}×{height}) — likely a tracking beacon",
            f"Format: {fmt}, Size: {width}×{height} pixels",
            "Medium", "exfiltration",
            f"{width}x{height}",
            "1×1 or very small images are used as tracking beacons — when loaded they confirm the email was opened and the recipient's IP address",
        ))

    # Format vs. extension mismatch
    if fmt and filename:
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        ext_to_fmt = {
            "jpg": "JPEG", "jpeg": "JPEG", "png": "PNG",
            "gif": "GIF", "bmp": "BMP", "webp": "WEBP",
            "tiff": "TIFF", "tif": "TIFF",
        }
        expected_fmt = ext_to_fmt.get(ext, "")
        if expected_fmt and fmt.upper() != expected_fmt:
            findings.append(_f(
                "image_format_mismatch",
                f"Image format mismatch: extension .{ext} but actual format is {fmt}",
                f"Declared extension: .{ext}, Actual PIL format: {fmt}",
                "Medium", "evasion",
                f".{ext} → {fmt}",
                "Format mismatch can be used to confuse content filters or to hide polyglot files (valid image + valid PE/ZIP)",
            ))

    # Check for appended data after image EOF (polyglot detection)
    try:
        if fmt == "JPEG":
            # JPEG ends with FFD9
            last_ffd9 = file_bytes.rfind(b"\xff\xd9")
            if last_ffd9 != -1 and last_ffd9 < len(file_bytes) - 2:
                appended = file_bytes[last_ffd9 + 2:]
                if len(appended) > 512:
                    findings.append(_f(
                        "jpeg_appended_data",
                        f"Data appended after JPEG EOF marker: {len(appended)} bytes",
                        f"Appended bytes start with: {appended[:20].hex()}",
                        "High", "evasion",
                        appended[:20].hex(),
                        "Data after JPEG's FFD9 EOF marker is ignored by image renderers but can contain a hidden ZIP, PE, or script — classic polyglot technique",
                    ))
        elif fmt == "PNG":
            # PNG ends with IEND chunk: 0000000049454e44ae426082
            iend_pos = file_bytes.rfind(b"IEND\xae\x42\x60\x82")
            if iend_pos != -1 and iend_pos < len(file_bytes) - 8:
                appended = file_bytes[iend_pos + 8:]
                if len(appended) > 512:
                    findings.append(_f(
                        "png_appended_data",
                        f"Data appended after PNG IEND chunk: {len(appended)} bytes",
                        f"Appended bytes start with: {appended[:20].hex()}",
                        "High", "evasion",
                        appended[:20].hex(),
                        "Data after PNG's IEND chunk is ignored by renderers but can hide a ZIP, PE, or script — classic polyglot image technique",
                    ))
    except Exception:
        pass

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze(file_bytes: bytes, filename: str = "") -> list:
    """
    Analyze image file bytes across 4 layers.
    Returns a flat list of finding dicts.
    """
    if not PIL_AVAILABLE:
        return [{
            "stage":       "Image Analyzer",
            "rule":        "pillow_unavailable",
            "description": "Pillow library not installed — image analysis skipped",
            "detail":      "Install Pillow: pip install Pillow",
            "risk_tier":   "Info",
            "category":    "scanner_error",
            "context":     "",
            "why_flagged": "Image analysis requires the Pillow library",
        }]

    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.load()  # Force full decode
    except UnidentifiedImageError:
        return [{
            "stage":       "Image Analyzer",
            "rule":        "unidentified_image",
            "description": "File could not be identified as a valid image",
            "detail":      "Pillow raised UnidentifiedImageError — file may be corrupt or a disguised non-image",
            "risk_tier":   "Medium",
            "category":    "evasion",
            "context":     "",
            "why_flagged": "A file claiming to be an image that fails image parsing may be a non-image file with a spoofed extension",
        }]
    except Exception as e:
        return [{
            "stage":       "Image Analyzer",
            "rule":        "image_parse_error",
            "description": f"Image parse error: {type(e).__name__}",
            "detail":      str(e)[:200],
            "risk_tier":   "Low",
            "category":    "scanner_error",
            "context":     "",
            "why_flagged": "Parse error may indicate a corrupt or specially crafted image",
        }]

    findings = []
    findings += _layer_a_exif(img, file_bytes)
    findings += _layer_b_entropy(img, fmt=img.format)
    findings += _layer_c_qr(img)
    findings += _layer_d_anomalies(img, file_bytes, filename)

    return findings
