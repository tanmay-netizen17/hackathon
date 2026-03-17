"""
SpectraGuard Deepfake Detector v2
Multi-signal: HuggingFace face deepfake model + GAN artifact analysis + temporal consistency
"""

import os, io, sys
import numpy as np
from PIL import Image

# ── Model configuration ────────────────────────────────────────────────────────
HF_MODEL_NAME = "dima806/deepfake_vs_real_image_detection"
MODELS_DIR    = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
)

_hf_pipeline= None
_fake_index = None   # which logit index = Fake
_load_error = None

def _load_hf_model():
    global _hf_pipeline, _fake_index, _load_error
    if _hf_pipeline is not None:
        return True
    if _load_error:
        return False
    try:
        from transformers import pipeline
        import torch
        print(f"[DeepfakeDetector] Loading {HF_MODEL_NAME}...")
        _hf_pipeline = pipeline("image-classification", model=HF_MODEL_NAME, trust_remote_code=True)

        # Determine which index corresponds to Fake/Deepfake
        labels = _hf_pipeline.model.config.id2label
        print(f"[DeepfakeDetector] Model labels: {labels}")
        _fake_index = None
        for idx, label in labels.items():
            if any(kw in label.upper() for kw in ['FAKE','DEEPFAKE','ARTIFICIAL','GENERATED','0']):
                _fake_index = label
                break
        if _fake_index is None:
            _fake_index = labels.get(0, "Fake")
            
        print(f"[DeepfakeDetector] ✅ Model loaded. Fake label: {_fake_index}")
        return True
    except Exception as e:
        _load_error = str(e)
        import traceback
        traceback.print_exc()
        print(f"[DeepfakeDetector] ⚠ HF model failed to load: {e}")
        return False

# Load at import time
_load_hf_model()


def _hf_score(pil_img: Image.Image) -> "float | None":
    """Run HuggingFace deepfake classifier. Returns 0.0–1.0 probability of being fake, or None if unavailable."""
    if not _load_hf_model():
        return None
    try:
        results = _hf_pipeline(pil_img.resize((224, 224)))  # type: ignore[misc]
        
        fake_prob = 0.0
        for res in results:
            if res['label'] == _fake_index:
                fake_prob = res['score']
                break
                
        return float(fake_prob)
    except Exception as e:
        print(f"[DeepfakeDetector] HF inference error: {e}")
        return None


# ── GAN artifact detection ────────────────────────────────────────────────────

def _gan_artifact_score(arr: np.ndarray) -> float:
    """
    Detect GAN-specific artifacts:
    1. Checkerboard artifacts in frequency domain (common in upsampling layers)
    2. Unnatural color correlation patterns
    3. Eye/face region over-smoothness
    """
    try:
        gray = np.mean(arr, axis=2).astype(np.float32) / 255.0

        # FFT analysis — GANs show periodic patterns
        fft  = np.fft.fft2(gray)
        fft_shift = np.fft.fftshift(fft)
        mag  = np.abs(fft_shift)
        h, w = mag.shape

        # Checkerboard pattern: energy at Nyquist frequency corners
        corner_size = max(h // 16, 4)
        corners = (
            mag[:corner_size, :corner_size].mean() +
            mag[:corner_size, -corner_size:].mean() +
            mag[-corner_size:, :corner_size].mean() +
            mag[-corner_size:, -corner_size:].mean()
        ) / 4

        center_region = mag[h//4:3*h//4, w//4:3*w//4].mean()
        if center_region < 1e-8:
            return 0.3

        # High corner-to-center ratio = checkerboard artifact
        ratio = corners / center_region
        checkerboard_score = float(min(max((ratio - 0.5) / 2.0, 0.0), 1.0))

        # Color channel correlation (GANs produce unnatural correlations)
        r, g, b = arr[:,:,0].astype(float), arr[:,:,1].astype(float), arr[:,:,2].astype(float)
        corr_rg = float(np.corrcoef(r.flatten(), g.flatten())[0,1])
        corr_rb = float(np.corrcoef(r.flatten(), b.flatten())[0,1])
        corr_gb = float(np.corrcoef(g.flatten(), b.flatten())[0,1])
        avg_corr = (abs(corr_rg) + abs(corr_rb) + abs(corr_gb)) / 3

        # Real photos: natural correlation ~0.7-0.9
        # GANs: often either too perfect (>0.97) or too random (<0.4)
        if avg_corr > 0.97:
            color_score = 0.85   # suspiciously perfect
        elif avg_corr < 0.4:
            color_score = 0.75   # suspiciously uncorrelated
        else:
            color_score = 0.2   # natural

        # Local variance uniformity — deepfakes are too smooth
        block = 16
        variances = []
        for i in range(0, h - block, block):
            for j in range(0, w - block, block):
                patch = gray[i:i+block, j:j+block]
                variances.append(float(np.var(patch)))
        if variances:
            var_cv = np.std(variances) / (np.mean(variances) + 1e-8)
            # Real images: high variance variation (some smooth, some detailed)
            # Deepfakes: more uniform variance
            smoothness_score = float(max(0.0, 1.0 - var_cv / 2.0))
        else:
            smoothness_score = 0.3

        final = checkerboard_score * 0.4 + color_score * 0.3 + smoothness_score * 0.3
        return float(min(max(final, 0.0), 1.0))

    except Exception as e:
        print(f"[GAN] Error: {e}")
        return 0.3


def _ela_score(arr: np.ndarray) -> float:
    """Error Level Analysis — detects inconsistent compression regions."""
    try:
        pil  = Image.fromarray(arr.astype(np.uint8))
        buf  = io.BytesIO()
        pil.save(buf, format='JPEG', quality=75)
        buf.seek(0)
        comp = np.array(Image.open(buf)).astype(np.float32)
        orig = arr.astype(np.float32)
        if comp.shape != orig.shape:
            return 0.3
        ela  = np.abs(orig - comp)
        h, w = ela.shape[:2]
        r    = 4
        rh, rw = max(1, h // r), max(1, w // r)
        means = [
            float(ela[i*rh:(i+1)*rh, j*rw:(j+1)*rw].mean())
            for i in range(r) for j in range(r)
        ]
        cv = np.std(means) / (np.mean(means) + 1e-8)
        return float(min(cv / 3.0, 1.0))
    except Exception:
        return 0.3


def _dct_score(arr: np.ndarray) -> float:
    """DCT frequency analysis — synthetic content has abnormal high-freq components."""
    try:
        from scipy.fft import dct as sp_dct
        gray = np.mean(arr, axis=2).astype(np.float32) / 255.0
        d    = sp_dct(sp_dct(gray.T, norm='ortho').T, norm='ortho')
        h, w = d.shape
        lo   = np.abs(d[:h//8, :w//8]).mean()
        hi   = np.abs(d[h//4:, w//4:]).mean()
        if lo < 1e-8:
            return 0.4
        ratio = hi / lo
        return float(min(max((ratio - 0.10) / 0.30, 0.0), 1.0))
    except Exception:
        return 0.3


def _has_face(arr: np.ndarray) -> bool:
    """Detect if image contains a human face."""
    try:
        import cv2
        gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
        fc   = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        faces = fc.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4,
                                    minSize=(30, 30))
        return len(faces) > 0
    except Exception:
        return True   # assume face if detection unavailable


def _temporal_consistency_score(frame_scores: list) -> float:
    """
    Analyse temporal patterns across video frames.
    Real videos: consistent scores with natural variance.
    Deepfake videos: show flickering artifacts (high variance) OR synthetic smoothness (zero variance).
    """
    if len(frame_scores) < 3:
        return float(np.mean(frame_scores)) if frame_scores else 0.3
    arr  = np.array(frame_scores)
    mean = float(np.mean(arr))
    std  = float(np.std(arr))
    
    # High std = temporal inconsistency = GAN flickering artifact
    inconsistency_boost = min(std * 2.5, 0.4)
    
    # Low std + somewhat elevated mean = completely synthetic generation (like Deepseek video)
    # Natural videos always have some micro-jitter in statistical features.
    synthetic_smoothness_boost = 0.0
    if std < 0.02 and mean > 0.15:
        synthetic_smoothness_boost = 0.35 
        
    return float(min(mean + inconsistency_boost + synthetic_smoothness_boost, 1.0))


# ── Single frame analysis ─────────────────────────────────────────────────────

def _analyse_frame(pil_img: Image.Image) -> dict:
    arr      = np.array(pil_img.convert("RGB"))
    has_face = _has_face(arr)

    # Run all signals
    hf_raw   = _hf_score(pil_img)
    gan_raw  = _gan_artifact_score(arr)
    ela_raw  = _ela_score(arr)
    dct_raw  = _dct_score(arr)

    signals = {
        "hf_model":       round(hf_raw,  3) if hf_raw  is not None else None,
        "gan_artifacts":  round(gan_raw,  3),
        "ela_tampering":  round(ela_raw,  3),
        "dct_frequency":  round(dct_raw,  3),
        "face_detected":  has_face,
    }

    if hf_raw is not None and has_face:
        # HF model is primary (70%) + secondary signals (30%)
        secondary = gan_raw * 0.5 + ela_raw * 0.3 + dct_raw * 0.2
        # If HF model predicts 0 fake, but secondary signals are very high, don't let HF drag it to 0.
        raw_score = max(hf_raw * 0.70 + secondary * 0.30, secondary * 0.85)
        method    = "hf_model+statistical"
    else:
        # No HF model OR no face detected — use statistical ensemble entirely
        # We boost GAN artifacts (65%) when face is missing to explicitly catch AI synthetic scenes
        raw_score = min(gan_raw * 0.65 + ela_raw * 0.20 + dct_raw * 0.15 + 0.15, 1.0)
        method    = "statistical_ensemble"

    # Adjust for non-face content
    if not has_face:
        signals["note"] = "No face detected — relying entirely on GAN artifact analysis"

    return {
        "score":    float(min(max(raw_score, 0.0), 1.0)),
        "method":   method,
        "signals":  signals,
        "has_face": has_face,
    }


# ── Evidence builder ──────────────────────────────────────────────────────────

def _build_evidence(score: float, signals: dict, input_type: str = "image") -> list:
    notes = []
    pct   = round(score * 100)

    if not signals.get("face_detected", True):
        notes.append(
            "No human face detected. Deepfake analysis is optimised for face content — "
            "GAN artifact analysis applied instead."
        )

    hf = signals.get("hf_model")
    if hf is not None:
        if hf >= 0.75:
            notes.append(
                f"Face deepfake classifier: {round(hf*100)}% fake confidence. "
                f"EfficientNet model trained on FaceForensics++ and real/fake face datasets "
                f"flagged strong synthetic face characteristics."
            )
        elif hf >= 0.50:
            notes.append(
                f"Face deepfake classifier: {round(hf*100)}% fake confidence. "
                f"Moderate synthetic indicators — could be heavy filtering, face editing, "
                f"or AI-generated content."
            )
        else:
            notes.append(
                f"Face deepfake classifier: {round(hf*100)}% fake confidence — "
                f"face characteristics consistent with authentic photography."
            )

    gan = signals.get("gan_artifacts", 0)
    if gan > 0.55:
        notes.append(
            f"GAN artifacts detected ({round(gan*100)}%): checkerboard patterns in frequency "
            f"domain and unnatural colour correlations — characteristic of neural network generation."
        )

    ela = signals.get("ela_tampering", 0)
    if ela > 0.50:
        notes.append(
            f"ELA analysis ({round(ela*100)}%): inconsistent JPEG compression across "
            f"image regions — indicates compositing or pixel manipulation."
        )

    dct = signals.get("dct_frequency", 0)
    if dct > 0.50:
        notes.append(
            f"Frequency spectrum ({round(dct*100)}%): abnormal high-frequency components — "
            f"diffusion models and GANs leave characteristic spectral fingerprints."
        )

    if not notes:
        notes.append(
            f"No significant synthetic artifacts detected across all {len(signals)} analysis signals. "
            f"Content appears authentic."
        )

    return notes


# ── Public interface ──────────────────────────────────────────────────────────

def analyse_image_bytes(image_data: bytes) -> dict:
    try:
        pil_img = Image.open(io.BytesIO(image_data)).convert("RGB")
        frame   = _analyse_frame(pil_img)
        score   = frame["score"]
        score_pct = round(score * 100)

        return {
            "score":          round(score, 4),
            "score_pct":      score_pct,
            "label":          "deepfake" if score >= 0.5 else "authentic",
            "method":         frame["method"],
            "has_face":       frame["has_face"],
            "signals":        frame["signals"],
            "evidence_notes": _build_evidence(score, frame["signals"], "image"),
        }
    except Exception as e:
        import traceback
        print(f"[DeepfakeDetector] Error: {traceback.format_exc()}")
        return {
            "score": 0.0, "score_pct": 0,
            "label": "error", "method": "error",
            "error": str(e), "signals": {}, "evidence_notes": [],
        }


class DeepfakeDetector:
    def analyse(self, image_data: bytes) -> dict:
        return analyse_image_bytes(image_data)

    def analyse_video(self, video_path: str, sample_frames: int = 12) -> dict:
        try:
            import cv2
            cap   = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return {"score": 0.0, "label": "error",
                        "error": f"Cannot open video: {video_path}"}

            total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps   = cap.get(cv2.CAP_PROP_FPS) or 30
            step  = max(1, total // sample_frames)

            print(f"[DeepfakeDetector] Video: {total} frames @ {fps}fps, sampling every {step} frames")

            frame_results = []
            frame_scores  = []

            for i in range(sample_frames):
                cap.set(cv2.CAP_PROP_POS_FRAMES, i * step)
                ret, frame = cap.read()
                if not ret:
                    break
                rgb    = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil    = Image.fromarray(rgb)
                result = _analyse_frame(pil)
                frame_results.append(result)
                frame_scores.append(result["score"])
                print(f"[DeepfakeDetector] Frame {i+1}: score={result['score']:.3f} face={result['has_face']}")

            cap.release()

            if not frame_scores:
                return {"score": 0.0, "label": "error", "error": "No frames extracted"}

            # Temporal consistency analysis
            temporal_score = _temporal_consistency_score(frame_scores)
            avg_score      = float(np.mean(frame_scores))
            max_score      = float(np.max(frame_scores))

            # Final: temporal (30%) + avg (30%) + max (40%)
            final = temporal_score * 0.30 + avg_score * 0.30 + max_score * 0.40
            final = round(float(min(max(final, 0.0), 1.0)), 4)

            # Aggregate signals
            all_signals = [r["signals"] for r in frame_results]
            avg_signals = {}
            for key in ["hf_model", "gan_artifacts", "ela_tampering", "dct_frequency"]:
                vals = [s[key] for s in all_signals if s.get(key) is not None]
                if vals:
                    avg_signals[key] = round(float(np.mean(vals)), 3)

            faces_detected = sum(1 for r in frame_results if r.get("has_face", False))
            avg_signals["face_detected"] = float(1 if faces_detected > 0 else 0)
            avg_signals["faces_ratio"] = round(float(faces_detected) / max(len(frame_results), 1), 3)

            method = frame_results[0]["method"] if frame_results else "unknown"

            notes = _build_evidence(final, avg_signals, "video")
            notes.insert(0,
                f"Analysed {len(frame_scores)} frames. "
                f"Temporal consistency score: {round(temporal_score*100)}%. "
                f"Frame score range: {round(min(frame_scores)*100)}–{round(max(frame_scores)*100)}%."
            )

            return {
                "score":           final,
                "score_pct":       round(final * 100),
                "label":           "deepfake" if final >= 0.5 else "authentic",
                "method":          f"video_{method}",
                "frames_analysed": len(frame_scores),
                "frame_scores":    [round(s, 3) for s in frame_scores],
                "temporal_score":  round(temporal_score, 3),
                "signals":         avg_signals,
                "evidence_notes":  notes,
            }

        except ImportError:
            return {"score": 0.0, "label": "error",
                    "error": "opencv-python not installed. Run: pip install opencv-python"}
        except Exception as e:
            import traceback
            print(f"[DeepfakeDetector] Video error: {traceback.format_exc()}")
            return {"score": 0.0, "label": "error", "error": str(e)}
