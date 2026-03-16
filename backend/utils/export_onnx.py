# pyre-ignore-all-errors
"""
SentinelAI — ONNX Export Utilities
Exports trained models to ONNX format for fully local (offline) inference.
"""

import os
import numpy as np


def export_nlp_model(model, tokenizer, output_path="models/nlp_detector.onnx"):
    """
    Export a HuggingFace transformer model to ONNX.
    Requires: torch, onnx, transformers
    """
    try:
        import torch
        dummy_input = tokenizer("test input", return_tensors="pt")
        torch.onnx.export(
            model,
            (dummy_input["input_ids"], dummy_input["attention_mask"]),
            output_path,
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids":      {0: "batch", 1: "seq"},
                "attention_mask": {0: "batch", 1: "seq"},
            },
            opset_version=14,
        )
        print(f"[ONNX] NLP model exported → {output_path}")
    except Exception as e:
        print(f"[ONNX] NLP export failed: {e}")
        raise


def export_url_model(lgbm_model, output_path="models/url_detector.onnx"):
    """
    Export a LightGBM / sklearn model to ONNX using skl2onnx.
    Requires: skl2onnx
    """
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        initial_type = [("float_input", FloatTensorType([None, 50]))]
        onx = convert_sklearn(lgbm_model, initial_types=initial_type)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(onx.SerializeToString())
        print(f"[ONNX] URL model exported → {output_path}")
    except Exception as e:
        print(f"[ONNX] URL export failed: {e}")
        raise


def export_all_models(nlp_model=None, tokenizer=None, url_model=None):
    """
    Convenience wrapper — export all models in one call.
    Pass None for any model you don't want to export.
    """
    os.makedirs("models", exist_ok=True)
    if nlp_model is not None and tokenizer is not None:
        export_nlp_model(nlp_model, tokenizer, "models/nlp_detector.onnx")
    if url_model is not None:
        export_url_model(url_model, "models/url_detector.onnx")
    print("[ONNX] All exports complete.")
