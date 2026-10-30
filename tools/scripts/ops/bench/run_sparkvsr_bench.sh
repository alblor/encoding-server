#!/bin/sh
# SparkVSR throughput benchmark for the M3 gate. Runs on the GPU host (the LXC), not on the Mac.
#
# usage: run_sparkvsr_bench.sh LABEL WIDTH HEIGHT UPSCALE TILE_H TILE_W CHUNK GPU [extra script args...]
#   LABEL     name of the run, results go to /dev/shm/bench/LABEL (RAM, nothing touches disk)
#   WIDTH/HEIGHT  size of the synthetic 49-frame input clip, built from the repo's own sample footage
#   UPSCALE   integer passed to --upscale (1 = same-size restoration)
#   TILE_H/TILE_W  pixel tile size at target resolution (0 0 = untiled)
#   CHUNK     --chunk_len (0 = the whole clip in one pass)
#   GPU       host GPU index to expose to the container
#
# Two identical clips are processed back to back: the first output time includes model loading, the
# gap between the two outputs is the warm per-clip time, which is the number that scales to a film.
# Peak VRAM comes from sampling nvidia-smi once a second on that GPU while the container runs.
set -eu

LABEL=$1; W=$2; H=$3; UP=$4; TH=$5; TW=$6; CHUNK=$7; GPU=$8; shift 8
FRAMES=49
WORK=/dev/shm/bench/$LABEL
CODE=/srv/src/SparkVSR
MODELS=/srv/models/sparkvsr
EMBEDDINGS=/srv/models/prompt_embeddings
IMG=sparkvsr-bench

rm -rf "$WORK" && mkdir -p "$WORK/in" "$WORK/out"

for n in a b; do
  docker run --rm -v "$CODE/test_input:/src:ro" -v "$WORK/in:/dst" "$IMG" \
    ffmpeg -v error -y -i /src/01.mp4 -vf "scale=${W}:${H}:flags=lanczos,format=yuv420p" \
    -frames:v "$FRAMES" -c:v libx264 -crf 10 "/dst/$n.mp4"
done

( while :; do nvidia-smi -i "$GPU" --query-gpu=memory.used --format=csv,noheader,nounits >> "$WORK/vram.log"; sleep 1; done ) &
SAMPLER=$!
trap 'kill $SAMPLER 2>/dev/null || true' EXIT

# A patched copy of the upstream script loads the pipeline without T5: the 9.5 GB text encoder plus the
# 11 GB transformer do not fit in 16 GB, and the empty-prompt embedding (make_empty_prompt_embedding.py)
# makes T5 unnecessary. Upstream files are never modified.
# VAE_ST=0 turns off the VAE's own tiling and slicing (upstream's --is_vae_st); default is on.
VAE_FLAG="--is_vae_st"; [ "${VAE_ST:-1}" = 0 ] && VAE_FLAG=""
# SWAP_TRANSFORMER=0 disables the temporary transformer-to-CPU swap around the VAE decode.
PATCH_FLAGS=""; [ "${SWAP_TRANSFORMER:-1}" = 1 ] && PATCH_FLAGS="--swap-transformer"
python3 "$(dirname "$0")/patch_sparkvsr.py" "$CODE/sparkvsr_inference_script.py" "$WORK/sparkvsr_noT5.py" $PATCH_FLAGS

# Upstream's ref_utils.py imports fal_client at the top, the client that uploads frames to fal.ai (the
# "api" reference mode). That mode is never allowed here, so the real package is not installed: this
# stub only satisfies the import and raises on any use. The container also runs with no network.
mkdir -p "$WORK/stubs"
cat > "$WORK/stubs/fal_client.py" <<'EOF'
def __getattr__(name):
    raise RuntimeError("fal_client is disabled: frames must never leave this host")
EOF

START=$(date +%s.%N)
docker run --rm --runtime=nvidia --network none -e NVIDIA_VISIBLE_DEVICES="$GPU" \
  -e NVIDIA_DRIVER_CAPABILITIES=compute,utility -e PYTHONPATH=/work/stubs:/code \
  -v "$MODELS:/models:ro" -v "$EMBEDDINGS:/work/pretrained_models/prompt_embeddings:ro" \
  -v "$CODE:/code:ro" -v "$WORK:/work" "$IMG" \
  python /work/sparkvsr_noT5.py \
    --input_dir /work/in --model_path /models --output_path /work/out \
    $VAE_FLAG --ref_mode no_ref --upscale "$UP" \
    --tile_size_hw "$TH" "$TW" --overlap_hw 32 32 --chunk_len "$CHUNK" --overlap_t 8 \
    --dtype bfloat16 "$@" > "$WORK/run.log" 2>&1 && STATUS=ok || STATUS=failed
END=$(date +%s.%N)

echo "label=$LABEL status=$STATUS in=${W}x${H} upscale=$UP tile=${TH}x${TW} chunk=$CHUNK frames=$FRAMES gpu=$GPU"
echo "wall_seconds=$(awk -v s="$START" -v e="$END" 'BEGIN {printf "%.1f", e - s}')"
echo "peak_vram_mib=$(sort -n "$WORK/vram.log" | tail -1)"
for phase in transformer vae_decode swap_overhead; do
  tr '\r' '\n' < "$WORK/run.log" | awk -v p="$phase" '
    /^\[bench\]/ { for (i = 2; i < NF; i++) if ($i == p) { v = $(i+1); sub(/s$/, "", v); n++; t += v } }
    END { if (n) printf "phase %-14s calls=%d total=%.1fs mean=%.2fs\n", p, n, t, t / n }'
done
echo "peak_alloc_gib=$(tr '\r' '\n' < "$WORK/run.log" | grep -oE 'peak_alloc [0-9.]+' | awk '{print $2}' | sort -n | tail -1)"
echo "output mtimes (epoch, relative to start):"
find "$WORK/out" -type f -name '*.mp4' -exec stat -c '%.Y %n' {} + | sort -n | \
  awk -v s="$START" '{printf "  +%.1fs  %s\n", $1 - s, $2}'
[ "$STATUS" = ok ] || { echo "--- last log lines ---"; tail -15 "$WORK/run.log"; exit 1; }
