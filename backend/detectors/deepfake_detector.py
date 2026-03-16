"""
SentinelAI Deepfake Detector
Multi-signal approach: DCT frequency analysis + facial consistency + noise analysis.
Works without labelled training data by detecting statistical anomalies
that are characteristic of GAN/diffusion-generated content.
"""

import numpy as np
import os, io
from PIL import Image

# Try loading torch for EfficientNet
_torch_available = False
_model           = None
MODEL_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "models", "deepfake_efficientnet.pt")
)

try:
    import torch
    import torch.nn as nn
    import torchvision.models as models
    import torchvision.transforms as T
    _torch_available = True

    TRANSFORM = T.Compose([
        T.Resize((224, 224)),
        T.ToTensor(),
        T.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
    ])

    def _load_model():
        global _model
        if _model is not None:
            return _model
        if not os.path.exists(MODEL_PATH):
            return None
        try:
            ckpt = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
            net  = models.efficientnet_b0(weights=None)
            n    = net.classifier[1].in_features
            net.classifier = nn.Sequential(nn.Dropout(0.2), nn.Linear(n, 2))
            net.load_state_dict(ckpt["model_state_dict"])
            net.eval()
            _model = net
            print("[DeepfakeDetector] ✅ EfficientNet model loaded")
            return _model
        except Exception as e:
            print(f"[DeepfakeDetector] ⚠ Model load failed: {e}")
            return None

    _load_model()

except ImportError:
    print("[DeepfakeDetector] torch not available — using statistical analysis only")


# ── Statistical deepfake detection signals ─────────────────────────────────────

def dct_frequency_score(img_array: np.ndarray) -> float:
    """
    Deepfakes from GANs/diffusion models have abnormal high-frequency DCT components.
    Real images have natural frequency falloff; synthetic images often don't.
    Returns 0.0 (authentic) to 1.0 (synthetic).
    """
    try:
        from scipy.fft import dct
        gray = np.mean(img_array, axis=2) if img_array.ndim == 3 else img_array
        gray = gray.astype(np.float32) / 255.0
        
        # Apply 2D DCT
        dct_coeffs = dct(dct(gray.T, norm='ortho').T, norm='ortho')
        
        # Real images: energy concentrated in low frequencies
        h, w = dct_coeffs.shape
        low_freq  = np.abs(dct_coeffs[:h//8, :w//8]).mean()
        high_freq = np.abs(dct_coeffs[h//4:, w//4:]).mean()
        
        # High ratio of high-to-low frequency = suspicious
        if low_freq < 1e-8:
            return 0.5
        ratio = high_freq / low_freq
        # Typical real images: ratio < 0.15; deepfakes often > 0.25
        score = min(max((ratio - 0.10) / 0.30, 0.0), 1.0)
        return float(score)
    except Exception:
        return 0.3


def noise_pattern_score(img_array: np.ndarray) -> float:
    """
    GAN-generated images have characteristic noise patterns (GAN fingerprints).
    Specifically, they show unnatural periodicity in the noise residual.
    """
    try:
        from scipy import ndimage
        gray = np.mean(img_array, axis=2).astype(np.float32) if img_array.ndim == 3 else img_array.astype(np.float32)
        
        # Extract noise residual by subtracting smoothed version
        smoothed = ndimage.gaussian_filter(gray, sigma=2)
        noise    = gray - smoothed
        
        # Compute noise statistics
        noise_std  = float(np.std(noise))
        noise_mean = float(np.abs(np.mean(noise)))
        
        # Real images: noise is relatively uniform across the image
        # Deepfakes: noise has systematic patterns in certain regions
        blocks = 8
        h, w = gray.shape
        bh, bw = h // blocks, w // blocks
        block_stds = []
        for i in range(blocks):
            for j in range(blocks):
                block = noise[i*bh:(i+1)*bh, j*bw:(j+1)*bw]
                block_stds.append(float(np.std(block)))
        
        # Coefficient of variation of block noise stds
        # High variation = uneven noise = possible synthetic
        cv = np.std(block_stds) / (np.mean(block_stds) + 1e-8)
        score = min(float(cv) / 2.0, 1.0)
        return score
        
    except Exception:
        return 0.3


def ela_score(img_array: np.ndarray) -> float:
    """
    Error Level Analysis: detects regions that have been composited/edited.
    Deepfakes often have inconsistent JPEG compression artifacts at face boundaries.
    """
    try:
        # Convert to PIL, save as JPEG at low quality, compare difference
        pil_img = Image.fromarray(img_array.astype(np.uint8))
        buf     = io.BytesIO()
        pil_img.save(buf, format='JPEG', quality=75)
        buf.seek(0)
        compressed = np.array(Image.open(buf)).astype(np.float32)
        original   = img_array.astype(np.float32)
        
        # Minimum size check
        if compressed.shape != original.shape:
            return 0.3
        
        ela = np.abs(original - compressed)
        
        # Region-wise ELA analysis
        h, w = ela.shape[:2]
        regions = 4
        rh, rw  = h // regions, w // regions
        region_means = []
        for i in range(regions):
            for j in range(regions):
                region = ela[i*rh:(i+1)*rh, j*rw:(j+1)*rw]
                region_means.append(float(np.mean(region)))
        
        # High variance between regions = suspicious tampering
        ela_cv   = np.std(region_means) / (np.mean(region_means) + 1e-8)
        ela_mean = np.mean(ela)
        
        # Normalise to 0-1
        score = min(float(ela_cv) / 3.0, 1.0) * 0.5 + min(ela_mean / 30.0, 1.0) * 0.5
        return float(score)
        
    except Exception:
        return 0.3


def facial_symmetry_score(img_array: np.ndarray) -> float:
    """
    Deepfakes often have subtle facial asymmetries or over-smoothed skin.
    Check horizontal symmetry of the image as a proxy.
    """
    try:
        gray   = np.mean(img_array, axis=2) if img_array.ndim == 3 else img_array
        h, w   = gray.shape
        left   = gray[:, :w//2]
        right  = np.fliplr(gray[:, w//2:w//2*2])
        
        if left.shape != right.shape:
            return 0.3
        
        # Unusually high symmetry = potentially synthetic face
        diff   = np.abs(left.astype(float) - right.astype(float))
        sym    = 1.0 - (diff.mean() / 128.0)
        
        # Real faces: symmetry ~0.7-0.85; deepfakes can be > 0.92
        score  = max(0.0, (sym - 0.80) / 0.15)
        return float(min(score, 1.0))
        
    except Exception:
        return 0.2


def analyse_image_bytes(image_data: bytes) -> dict:
    """Main entry point for image/frame analysis."""
    try:
        pil_img   = Image.open(io.BytesIO(image_data)).convert("RGB")
        img_array = np.array(pil_img)

        # Run all statistical signals
        dct_s  = dct_frequency_score(img_array)
        noise_s = noise_pattern_score(img_array)
        ela_s  = ela_score(img_array)
        sym_s  = facial_symmetry_score(img_array)

        # Run EfficientNet if available
        efficientnet_score = None
        if _torch_available and _model is not None:
            try:
                tensor = TRANSFORM(pil_img).unsqueeze(0)
                with torch.no_grad():
                    logits = _model(tensor)
                    probs  = torch.softmax(logits, dim=1)
                    efficientnet_score = float(probs[0][1])
            except Exception:
                pass

        # Ensemble: weighted combination
        if efficientnet_score is not None:
            # EfficientNet gets 40% weight; statistical signals get 60%
            statistical = (dct_s * 0.35 + noise_s * 0.30 + ela_s * 0.25 + sym_s * 0.10)
            final_score = efficientnet_score * 0.40 + statistical * 0.60
            method      = "efficientnet+statistical"
        else:
            # Pure statistical
            final_score = (dct_s * 0.35 + noise_s * 0.30 + ela_s * 0.25 + sym_s * 0.10)
            method      = "statistical"

        final_score = round(float(final_score), 4)
        label       = "deepfake" if final_score >= 0.5 else "authentic"

        return {
            "score":          final_score,
            "score_pct":      round(final_score * 100),
            "label":          label,
            "method":         method,
            "signals": {
                "dct_frequency":    round(dct_s, 3),
                "noise_pattern":    round(noise_s, 3),
                "ela_tampering":    round(ela_s, 3),
                "facial_symmetry":  round(sym_s, 3),
                "efficientnet":     round(efficientnet_score, 3) if efficientnet_score else None,
            },
            "evidence_notes": _build_evidence(dct_s, noise_s, ela_s, sym_s, final_score)
        }

    except Exception as e:
        return {
            "score": 0.0, "score_pct": 0,
            "label": "error", "method": "error",
            "error": str(e), "signals": {}, "evidence_notes": []
        }


def _build_evidence(dct_s, noise_s, ela_s, sym_s, final) -> list:
    notes = []
    if dct_s > 0.4:
        notes.append(
            f"Abnormal frequency spectrum: DCT analysis shows {dct_s*100:.0f}% "
            f"synthetic signature (GAN/diffusion models leave high-frequency artifacts)"
        )
    if noise_s > 0.5:
        notes.append(
            f"Uneven noise distribution: {noise_s*100:.0f}% anomaly — "
            f"indicates compositing or pixel manipulation"
        )
    if ela_s > 0.4:
        notes.append(
            f"ELA tampering score: {ela_s*100:.0f}% — "
            f"compression artifacts suggest regional editing"
        )
    if sym_s > 0.5:
        notes.append(
            f"Unusual facial symmetry: {sym_s*100:.0f}% — "
            f"synthetic faces are often unnaturally symmetric"
        )
    if not notes:
        notes.append("No significant synthetic artifacts detected in frequency, noise, or ELA analysis")
    return notes


class DeepfakeDetector:
    async def analyse(self, image_data: bytes) -> dict:
        # We can just call the synchronous helper inside, but we define it as async so Orchestrator can await it.
        return analyse_image_bytes(image_data)

    async def analyse_video(self, video_path: str, sample_frames: int = 8) -> dict:
        """
        Extract frames from video and average scores across them.
        Higher score consistency = higher confidence.
        """
        try:
            import cv2
            cap    = cv2.VideoCapture(video_path)
            total  = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps    = cap.get(cv2.CAP_PROP_FPS)
            step   = max(1, total // sample_frames)
            
            frame_scores  = []
            all_signals   = []
            
            for i in range(sample_frames):
                cap.set(cv2.CAP_PROP_POS_FRAMES, i * step)
                ret, frame = cap.read()
                if not ret:
                    break
                # Convert BGR to RGB
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                buf       = io.BytesIO()
                Image.fromarray(frame_rgb).save(buf, format='PNG')
                result = analyse_image_bytes(buf.getvalue())
                frame_scores.append(result["score"])
                all_signals.append(result.get("signals", {}))
            
            cap.release()
            
            if not frame_scores:
                return {"score": 0.0, "label": "error", "error": "No frames extracted"}
            
            avg_score  = float(np.mean(frame_scores))
            max_score  = float(np.max(frame_scores))
            # Consistency: high std = some frames look fake, others don't
            consistency = float(np.std(frame_scores))
            
            # Weighted final: average + boost if max is very high
            final = avg_score * 0.7 + max_score * 0.3
            
            # Average signals across frames
            avg_signals = {}
            for key in ["dct_frequency", "noise_pattern", "ela_tampering", "facial_symmetry"]:
                vals = [s.get(key, 0) for s in all_signals if s.get(key) is not None]
                avg_signals[key] = round(float(np.mean(vals)), 3) if vals else 0.0
            
            return {
                "score":        round(final, 4),
                "score_pct":    round(final * 100),
                "label":        "deepfake" if final >= 0.5 else "authentic",
                "method":       "video_frame_analysis",
                "frames_analysed": len(frame_scores),
                "frame_scores": [round(s, 3) for s in frame_scores],
                "consistency":  round(consistency, 3),
                "signals":      avg_signals,
                "evidence_notes": _build_evidence(
                    avg_signals.get("dct_frequency", 0),
                    avg_signals.get("noise_pattern", 0),
                    avg_signals.get("ela_tampering", 0),
                    avg_signals.get("facial_symmetry", 0),
                    final
                )
            }
            
        except ImportError:
            return {"score": 0.0, "label": "error",
                    "error": "opencv-python not installed. Run: pip install opencv-python"}
        except Exception as e:
            return {"score": 0.0, "label": "error", "error": str(e)}
