#!/bin/sh
# ReCaVSR evaluation run on the GPU host (the LXC), not on the Mac. Peak VRAM and temperature are
# sampled once a second; output stays in RAM (/dev/shm). The container has no network and the
# weights are mounted read-only. Build the image from Dockerfile.recavsr-bench first.
#
# usage: [INPUT=/cmp/clip.mp4] run_recavsr_bench.sh LABEL SCALE FRAMES GPU [extra inference.py args...]
#   INPUT   clip path inside the container; clips live in /srv/src/cmp on the host, mounted at /cmp.
#           Defaults to the demo clip shipped in the repo.
#   SCALE   --scale passed to inference.py. On a 16 GB card 2 (about 1.6 Mpx) is the largest that fits;
#           3 and 4 ran out of memory in testing.
set -eu
LABEL=$1; SCALE=$2; FRAMES=$3; GPU=$4; shift 4
W=/dev/shm/recavsr/$LABEL; rm -rf "$W"; mkdir -p "$W"
( while :; do nvidia-smi -i "$GPU" --query-gpu=memory.used,temperature.gpu --format=csv,noheader,nounits >> "$W/vram.log"; sleep 1; done ) &
SAMP=$!; trap 'kill $SAMP 2>/dev/null || true' EXIT
START=$(date +%s.%N)
docker run --rm --runtime=nvidia --network none -e NVIDIA_VISIBLE_DEVICES="$GPU" -e NVIDIA_DRIVER_CAPABILITIES=compute,utility \
  -v /srv/models/recavsr:/m:ro -v /srv/src/cmp:/cmp:ro -v "$W:/out" recavsr-bench \
  /opt/recavsr/.venv/bin/python inference.py --input "${INPUT:-assets/demo/input.mp4}" --output /out/o.mp4 \
  --scale "$SCALE" --frames "$FRAMES" --model-dir /m --device cuda:0 "$@" > "$W/run.log" 2>&1 && ST=ok || ST=failed
END=$(date +%s.%N)
echo "label=$LABEL status=$ST scale=$SCALE frames=$FRAMES gpu=$GPU"
echo "wall_seconds=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.1f", e-s}')"
echo "peak_vram_mib=$(cut -d, -f1 "$W/vram.log" | sort -n | tail -1) max_temp_c=$(cut -d, -f2 "$W/vram.log" | sort -n | tail -1 | tr -d ' ')"
tr '\r' '\n' < "$W/run.log" | grep -v '^$' | tail -12 | cut -c1-200
