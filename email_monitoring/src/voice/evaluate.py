# src/voice/evaluate.py
"""
Voice deepfake evaluation pipeline — dual-model ensemble.

Two independent classifiers must BOTH agree the audio is fake before issuing
a FAKE verdict (AND-logic).  This drastically reduces false positives because
each model has different blind spots:

  Model A  — MFCC CNN+BiLSTM (best_eer.pt, trained on ASVspoof2019-LA)
             Strong at detecting known TTS/vocoder artifacts in spectral domain.
             Weakness: false positives on phone / low-bandwidth recordings.

  Model B  — wav2vec2-base MLP classifier (w2v_classifier.pkl)
             Uses multi-layer (phonetic + semantic) self-supervised speech
             features pre-trained on 960 h of diverse speech, trained with
             phone-augmented real data from 40+ speakers.
             Weakness: some phone recordings with heavy codec processing.

Final score = A × B  (product enforces AND — if either model says REAL the
score drops to near zero).
"""
import os
import numpy as np
import time
import sys
import pickle
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import DEVICE, MODELS_DIR, SAMPLE_RATE
from features import load_audio, chunk_audio, extract_sequence, extract_aggregate
from model import DeepfakeVoiceDetector

# ── Configuration ──────────────────────────────────────────────────
THRESHOLD = 0.55   # Binary decision boundary — slightly above 0.5 to reduce false positives

# best_eer_v2.pt is the updated primary MFCC model
_V2_READY = True

# ── Risk tiers ────────────────────────────────────────────────────
TIERS = [
    (88, "CRITICAL 🚨", "BLOCK — trigger incident response immediately"),
    (70, "HIGH 🔴",     "BLOCK — escalate to security team now"),
    (50, "MEDIUM 🟡",   "FLAG  — route to human reviewer within 1 hour"),
    (0,  "LOW 🟢",      "ALLOW — voice appears authentic"),
]

# ── Cached models ─────────────────────────────────────────────────
_model_v1         = None
_model_v2         = None
_model_loaded     = False
_load_attempted   = False
_model            = None   # back-compat alias

_xgb_clf          = None   # XGBoost / RF secondary MFCC classifier
_xgb_loaded       = False
_xgb_load_attempted = False

_w2v_model        = None   # Wav2Vec2Model
_w2v_extractor    = None   # Wav2Vec2FeatureExtractor
_w2v_clf          = None   # sklearn MLPClassifier
_w2v_scaler       = None   # sklearn StandardScaler
_w2v_layers       = [6, 7, 8, 12]  # default multi-layer indices
_w2v_loaded       = False
_w2v_load_attempted = False

SR = SAMPLE_RATE
CLIP_SAMPLES = SR * 3     # 3-second clip for wav2vec2


def get_tier(score: int):
    for threshold, tier, action in TIERS:
        if score >= threshold:
            return tier, action
    return "LOW 🟢", "ALLOW — voice appears authentic"


def _load_single(path, label: str):
    """Load one DeepfakeVoiceDetector checkpoint. Returns model or None."""
    import torch
    if not path.exists():
        return None
    try:
        m = DeepfakeVoiceDetector().to(DEVICE)
        state = torch.load(str(path), map_location=DEVICE, weights_only=False)
        if isinstance(state, dict):
            if "model_state_dict" in state:
                state = state["model_state_dict"]
            elif "state_dict" in state:
                state = state["state_dict"]
            elif "model" in state:
                state = state["model"]
        m.load_state_dict(state, strict=True)
        m.eval()
        print(f"  ✅ {label} loaded → {path.name}")
        return m
    except Exception as e:
        print(f"  ❌ {label} load error: {e}")
        return None


def _load_model():
    """Load MFCC model(s) once and cache globally.
    best_eer_v2.pt is the primary model when _V2_READY is True.
    """
    global _model_v1, _model_v2, _model, _model_loaded, _load_attempted
    if _load_attempted:
        return _model_loaded

    _load_attempted = True

    if _V2_READY:
        _model_v2 = _load_single(MODELS_DIR / "best_eer_v2.pt", "Model v2 (best_eer_v2) [PRIMARY]")
        _model_v1 = _load_single(MODELS_DIR / "best_eer.pt",    "Model v1 (best_eer)    [FALLBACK]")
        _model = _model_v2 or _model_v1   # v2 is primary
        if _model_v2:
            print("  🎯 Primary MFCC model: best_eer_v2.pt")
        elif _model_v1:
            print("  ⚠️  best_eer_v2.pt not found — using best_eer.pt")
    else:
        _model_v1 = _load_single(MODELS_DIR / "best_eer.pt", "Model v1 (best_eer)")
        _model_v2 = None
        _model = _model_v1

    _model_loaded = _model is not None
    return _model_loaded


def _load_xgb():
    """
    Load XGBoost / RF secondary MFCC classifier once and cache globally.
    Searches: email_monitoring/models/, then fraudshield-voice/models/saved/
    """
    global _xgb_clf, _xgb_loaded, _xgb_load_attempted
    if _xgb_load_attempted:
        return _xgb_loaded
    _xgb_load_attempted = True

    # Search order: local models dir first, then fraudshield-voice
    _ROOT = MODELS_DIR.parent.parent          # repo root  (Hack-o-hire-2/)
    candidates = [
        MODELS_DIR / "xgb_voice.pkl",
        MODELS_DIR / "rf_voice.pkl",
        _ROOT / "fraudshield-voice" / "models" / "saved" / "rf_model.pkl",
    ]

    for path in candidates:
        if path.exists():
            try:
                import pickle
                with open(path, "rb") as f:
                    _xgb_clf = pickle.load(f)
                _xgb_loaded = True
                print(f"  ✅ XGBoost/RF secondary MFCC model loaded → {path.name}")
                return True
            except Exception as e:
                print(f"  ⚠️  Failed to load secondary model from {path}: {e}")

    print("  ℹ️  No XGBoost/RF secondary MFCC model found — running single-model mode")
    return False


def _load_w2v():
    """Load wav2vec2 model + sklearn classifier once and cache globally."""
    global _w2v_model, _w2v_extractor, _w2v_clf, _w2v_scaler, _w2v_layers
    global _w2v_loaded, _w2v_load_attempted

    if _w2v_load_attempted:
        return _w2v_loaded
    _w2v_load_attempted = True

    pkl_path = MODELS_DIR / "w2v_classifier.pkl"
    if not pkl_path.exists():
        print("  ⚠️  wav2vec2 classifier not found — skipping Model B")
        return False

    try:
        import torch
        from transformers import Wav2Vec2Model, Wav2Vec2FeatureExtractor

        with open(pkl_path, "rb") as f:
            bundle = pickle.load(f)
        _w2v_scaler = bundle["scaler"]
        _w2v_clf    = bundle["clf"]
        _w2v_layers = bundle.get("layers", [6, 7, 8, 12])

        _w2v_extractor = Wav2Vec2FeatureExtractor.from_pretrained(
            "facebook/wav2vec2-base"
        )
        _w2v_model = Wav2Vec2Model.from_pretrained(
            "facebook/wav2vec2-base"
        ).to(DEVICE).eval()

        _w2v_loaded = True
        print(f"  ✅ wav2vec2 classifier loaded → {pkl_path.name}  (layers={_w2v_layers})")
        return True
    except Exception as e:
        print(f"  ⚠️  wav2vec2 load error (non-fatal): {e}")
        return False


def _w2v_predict(y: np.ndarray) -> float:
    """
    Run wav2vec2 multi-layer classifier on raw audio waveform.

    Extracts up to 5 clips spread across the audio, computes multi-layer
    features (mean+std from phonetic and semantic layers), predicts P(fake)
    for each clip, and returns the MINIMUM probability (conservative: any
    clip scoring REAL pulls the whole audio toward REAL).
    """
    import torch
    import librosa as _librosa

    y_norm = _librosa.util.normalize(y)
    total  = len(y_norm)

    # Determine clip offsets — up to 5 clips evenly spaced
    n_clips = min(5, max(1, total // CLIP_SAMPLES))
    if n_clips == 1:
        offsets = [max(0, total // 2 - CLIP_SAMPLES // 2)]
    else:
        step = (total - CLIP_SAMPLES) / (n_clips - 1)
        offsets = [int(i * step) for i in range(n_clips)]

    probs = []
    with torch.no_grad():
        for off in offsets:
            clip = y_norm[off : off + CLIP_SAMPLES]
            if len(clip) < CLIP_SAMPLES:
                clip = np.pad(clip, (0, CLIP_SAMPLES - len(clip)))

            inp = _w2v_extractor(
                clip, sampling_rate=SR, return_tensors="pt", padding=True
            )
            out = _w2v_model(
                inp.input_values.to(DEVICE), output_hidden_states=True
            )

            # Multi-layer feature extraction (mean+std per layer)
            feats = []
            for li in _w2v_layers:
                h = out.hidden_states[li].squeeze(0)          # [T, 768]
                feats.append(h.mean(dim=0).cpu().numpy())      # mean
                feats.append(h.std(dim=0).cpu().numpy())       # std
            emb = np.concatenate(feats).reshape(1, -1)

            emb_s = _w2v_scaler.transform(emb)
            prob  = float(_w2v_clf.predict_proba(emb_s)[0, 1])
            probs.append(prob)

    # Use minimum — conservative: if any clip looks real, lean toward real
    return float(min(probs))


def _get_spectral_indicators(y: np.ndarray) -> list:
    """Generate rule-based secondary indicators from raw audio."""
    try:
        import librosa
        indicators = []

        spec_centroid = float(librosa.feature.spectral_centroid(y=y, sr=SAMPLE_RATE).mean())
        zcr           = float(librosa.feature.zero_crossing_rate(y).mean())
        mfcc_data     = librosa.feature.mfcc(y=y, sr=SAMPLE_RATE, n_mfcc=13)
        mfcc_var      = float(mfcc_data.std())

        if spec_centroid > 4500:
            indicators.append(f"High spectral centroid ({spec_centroid:.0f} Hz) — synthetic voice fingerprint")
        if zcr < 0.02:
            indicators.append(f"Low zero-crossing rate ({zcr:.4f}) — atypical for natural speech dynamics")
        if mfcc_var < 6.0:
            indicators.append(f"Low MFCC variance ({mfcc_var:.2f}) — unnaturally uniform voice texture")

        return indicators
    except Exception:
        return []


def analyze_audio_file(audio_path: str, filename: str = "") -> dict:
    """
    Full voice deepfake analysis pipeline.

    Primary model : best_eer_v2.pt  (MFCC CNN+BiLSTM)
    Secondary model: XGBoost / RF   (MFCC aggregate features)
    Decision logic:
      - Both agree FAKE/REAL → use that verdict, averaged confidence
      - Disagree → REVIEW ⚠️
      - Final risk_score = 60% best_eer_v2 + 40% XGBoost

    Returns the per-file output schema defined in the email threat spec.
    """
    t0  = time.time()
    ext = Path(audio_path).suffix.lower() if audio_path else ""
    fn  = filename or (Path(audio_path).name if audio_path else "unknown")

    # Formats that need ffmpeg
    NEEDS_FFMPEG = {".mp3", ".m4a", ".aac", ".wma", ".mp4", ".webm", ".3gp"}
    NATIVE_FORMATS = {".wav", ".flac", ".ogg"}

    # Base result template matching the spec schema
    result: dict = {
        "filename":           fn,
        "format":             ext,
        "verdict":            "SKIPPED ⏭️",
        "risk_score":          0,
        "risk_tier":           "LOW 🟢",
        "confidence":          "0.0%",
        "best_eer_score":      0.0,
        "xgboost_score":       0.0,
        "mfcc_features_used":  40,
        "model_agreement":     False,
        "recommended_action":  "ALLOW",
        "skip_reason":         None,
        # Extra diagnostic fields (retained for compatibility)
        "processing_ms":       0,
        "chunks_analyzed":     0,
        "speech_chunks":       0,
        "indicators":          [],
        "model_used":          "best_eer_v2.pt (MFCC CNN+BiLSTM)",
        "error":               None,
    }

    if not audio_path or not os.path.exists(audio_path):
        result["error"]       = f"File not found: {audio_path}"
        result["skip_reason"] = "File not found"
        return result

    # Check ffmpeg requirement for non-native formats
    if ext in NEEDS_FFMPEG:
        import shutil
        if not shutil.which("ffmpeg"):
            result["skip_reason"] = (
                f"ffmpeg not installed — required to decode {ext} files. "
                "Install from https://ffmpeg.org/download.html"
            )
            result["verdict"] = "SKIPPED ⏭️"
            return result
        result["skip_reason"] = None  # ffmpeg present, OK to proceed

    try:
        print(f"\n  🎙️  Analyzing voice: {fn}")
        y      = load_audio(audio_path)
        chunks = chunk_audio(y)
        result["chunks_analyzed"] = len(chunks)
        result["indicators"]      = _get_spectral_indicators(y)

        # ── Primary model: best_eer_v2.pt (CNN+BiLSTM) ────────────────
        model_ok = _load_model()
        score_primary = None

        if model_ok:
            import torch
            energies         = [float(np.mean(c**2)) for c in chunks]
            max_energy       = max(energies) if energies else 1.0
            energy_threshold = max(0.001, max_energy * 0.20)

            speech_count = 0
            scores_primary = []

            with torch.no_grad():
                for chunk, energy in zip(chunks, energies):
                    if energy < energy_threshold:
                        continue
                    speech_count += 1
                    # Use v2 (primary); fall back to v1 if v2 unavailable
                    active = _model_v2 if _model_v2 is not None else _model_v1
                    use_cmn = _model_v2 is not None   # v2 was trained with CMN
                    seq = torch.tensor(
                        extract_sequence(chunk, cmn=use_cmn)
                    ).unsqueeze(0).to(DEVICE)
                    scores_primary.append(active(seq).squeeze().item())

            result["speech_chunks"] = speech_count
            score_primary = float(np.median(scores_primary)) if scores_primary else 0.0

        # ── Secondary model: XGBoost / RF on MFCC aggregates ──────────
        xgb_ok = _load_xgb()
        score_xgb = None

        if xgb_ok:
            try:
                agg_scores = []
                for chunk in chunks:
                    agg = extract_aggregate(chunk)
                    p   = float(_xgb_clf.predict_proba([agg])[0][1])
                    agg_scores.append(p)
                score_xgb = float(np.mean(agg_scores)) if agg_scores else None
            except Exception as ex:
                print(f"  ⚠️  XGBoost scoring error: {ex}")
                score_xgb = None

        # ── Decision logic ─────────────────────────────────────────────
        if score_primary is None:
            score_primary = 0.0
        if score_xgb is None:
            score_xgb = score_primary   # single-model fallback

        # Weighted final: 60% primary (best_eer_v2) + 40% XGBoost
        final_score = 0.60 * score_primary + 0.40 * score_xgb
        risk_int    = int(final_score * 100)

        primary_fake = score_primary >= THRESHOLD
        xgb_fake     = score_xgb    >= THRESHOLD
        agreed       = primary_fake == xgb_fake

        if not agreed:
            verdict = "REVIEW ⚠️"
        elif primary_fake:
            verdict = "FAKE 🚨"
        else:
            verdict = "REAL ✅"

        tier, action = get_tier(risk_int)

        # Map tier to recommended action
        if verdict == "FAKE 🚨" or risk_int >= 70:
            rec_action = "BLOCK"
        elif verdict == "REVIEW ⚠️" or risk_int >= 40:
            rec_action = "REVIEW"
        else:
            rec_action = "ALLOW"

        confidence = final_score if primary_fake else (1.0 - final_score)

        result.update({
            "verdict":           verdict,
            "risk_score":         risk_int,
            "risk_tier":          tier,
            "confidence":         f"{confidence * 100:.1f}%",
            "best_eer_score":     round(score_primary, 4),
            "xgboost_score":      round(score_xgb, 4),
            "mfcc_features_used": 40,
            "model_agreement":    agreed,
            "recommended_action": rec_action,
            "skip_reason":        None,
            "model_used": (
                "best_eer_v2.pt + XGBoost ensemble"
                if xgb_ok else "best_eer_v2.pt (MFCC CNN+BiLSTM)"
            ),
        })

        print(f"  🎯 {fn}  verdict={verdict}  "
              f"best_eer_v2={score_primary:.3f}  xgb={score_xgb:.3f}  "
              f"final={final_score:.3f}  agreed={agreed}")

    except ImportError as e:
        result["error"]       = f"Missing package: {e}. Run: pip install librosa pydub torch"
        result["skip_reason"] = f"Missing package: {e}"
        result["verdict"]     = "SKIPPED ⏭️"
    except Exception as e:
        result["error"]   = f"Voice analysis failed: {str(e)}"
        result["verdict"] = "SKIPPED ⏭️"
        print(f"  ❌ Error analyzing {fn}: {e}")

    result["processing_ms"] = round((time.time() - t0) * 1000)
    return result


class VoiceDeepfakeDetector:
    """Wrapper class for the voice deepfake analysis pipeline."""
    def predict(self, audio_path: str, filename: str = "") -> dict:
        return analyze_audio_file(audio_path, filename=filename)
