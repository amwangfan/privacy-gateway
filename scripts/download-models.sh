#!/usr/bin/env bash
# Download LoRA / GGUF weights from Hugging Face into the current directory.
set -euo pipefail

HF_LORA="${HF_LORA:-amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-LoRA}"
HF_GGUF="${HF_GGUF:-amwangfan/Qwen2.5-0.5B-Privacy-Gateway-v3-GGUF}"
OUT="${1:-.}"

if command -v huggingface-cli >/dev/null 2>&1; then
  huggingface-cli download "$HF_LORA" --local-dir "$OUT/privacy-gateway-v3-lora"
  huggingface-cli download "$HF_GGUF" --local-dir "$OUT/gguf"
elif command -v hf >/dev/null 2>&1; then
  hf download "$HF_LORA" --local-dir "$OUT/privacy-gateway-v3-lora"
  hf download "$HF_GGUF" --local-dir "$OUT/gguf"
else
  echo "Install huggingface_hub first: pip install huggingface_hub" >&2
  echo "Then: huggingface-cli download $HF_LORA --local-dir $OUT/privacy-gateway-v3-lora" >&2
  echo "      huggingface-cli download $HF_GGUF --local-dir $OUT/gguf" >&2
  exit 1
fi

echo "LoRA -> $OUT/privacy-gateway-v3-lora"
echo "GGUF -> $OUT/gguf"
echo "Production on Intel N100 currently uses the F16 GGUF if present;"
echo "Q4_K_M is published but generation-path SECRET/SAFE is unreliable."
