"""Encode the empty prompt once with the pipeline's T5 and save it where SparkVSR looks for it.

Why: the inference script runs T5 per call unless an empty-prompt embedding file exists, and T5
(about 9.5 GB in bf16) plus the transformer (about 11 GB) do not fit in the 16 GB of an RTX 5080.
With this file the worker never needs the text encoder, which is also what ComfyUI-Spark's cached
T5 does. Mirrors the encode code in sparkvsr_inference_script.py (padding, max length, special tokens).

usage (inside the bench image, GPU visible):
    python make_empty_prompt_embedding.py MODEL_DIR OUT_DIR
The file name is the sha256 of the empty string, the name the script expects.
"""
import hashlib
import sys
from pathlib import Path

import torch
from safetensors.torch import save_file
from transformers import AutoTokenizer, T5EncoderModel


def main(model_dir: str, out_dir: str) -> None:
    model = Path(model_dir)
    tokenizer = AutoTokenizer.from_pretrained(model / "tokenizer")
    encoder = T5EncoderModel.from_pretrained(model / "text_encoder", torch_dtype=torch.bfloat16).to("cuda").eval()

    max_len = 226  # transformer.config.max_text_seq_length for CogVideoX1.5
    ids = tokenizer("", padding="max_length", max_length=max_len, truncation=True,
                    add_special_tokens=True, return_tensors="pt").input_ids
    with torch.no_grad():
        embedding = encoder(ids.to("cuda"))[0].to("cpu")

    name = hashlib.sha256(b"").hexdigest() + ".safetensors"
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    save_file({"prompt_embedding": embedding.contiguous()}, str(out / name))
    print(f"saved {out / name} shape={tuple(embedding.shape)} dtype={embedding.dtype}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
