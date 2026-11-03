#!/bin/sh
# Stage the ReCaVSR weights for the restore workers. Run once, on the machine that runs the stack, with network access.
#
# The workers have no network at all, so the weights are fetched here, in a throwaway container, checked against
# pinned SHA-256 values, and left in a directory that the workers mount read-only. Weights are public artifacts, not
# media: they may live on disk. The three small config files come from the pinned ReCaVSR commit inside the worker image.
#
# usage: scripts/stage_restore_weights.sh [DEST]        DEST defaults to $RESTORE_MODELS_DIR or /srv/models/recavsr
# Needs: docker, and the worker image already built (make gpu-build).
set -eu

DEST=${1:-${RESTORE_MODELS_DIR:-/srv/models/recavsr}}
REPO=kopper/ReCaVSR
REVISION=b9bc1851e81188848de783203f8cdb0596520828
IMAGE=${RESTORE_WORKER_IMAGE:-encoding-restore-worker}

# file  sha256 (from the Hugging Face listing of the pinned revision)
CHECKSUMS="f4feb3e7b0b65f98e15bb709a1ba28dfaada7c06bf7fc0ce4cdbcb58803034e8  flashdecoder.safetensors
325ee3b5ec7d8bd43bc7ab186be5272dec0877c04e7c01a46fd0893260c9c6a5  prompt.safetensors
a43bc91689de37d286bfb1068e90049b2e121bbabb1cf4e6f5e9a801107e23ae  transformer.safetensors"

mkdir -p "$DEST"

if printf '%s\n' "$CHECKSUMS" | (cd "$DEST" && sha256sum -c --quiet - >/dev/null 2>&1); then
    echo "weights already staged and verified in $DEST"
else
    echo "downloading $REPO at $REVISION into $DEST (about 10.8 GB)"
    docker run --rm -v "$DEST":/m python:3.12-slim sh -c "
        pip install -q huggingface_hub &&
        python -c \"
from huggingface_hub import snapshot_download
snapshot_download(repo_id='$REPO', revision='$REVISION', local_dir='/m',
                  allow_patterns=['transformer.safetensors', 'prompt.safetensors', 'flashdecoder.safetensors'])
\""
    echo "verifying SHA-256"
    printf '%s\n' "$CHECKSUMS" | (cd "$DEST" && sha256sum -c -)
fi

# Face detector for fidelity.face_guard (YuNet, MIT licence, 232 KB, from OpenCV's model zoo), checked by SHA-256 like the rest.
YUNET_SHA256=8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4
YUNET_URL=https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx
if ! echo "$YUNET_SHA256  yunet.onnx" | (cd "$DEST" && sha256sum -c --quiet - >/dev/null 2>&1); then
    echo "downloading the YuNet face detector"
    curl -fsSL -o "$DEST/yunet.onnx" "$YUNET_URL"
    echo "$YUNET_SHA256  yunet.onnx" | (cd "$DEST" && sha256sum -c -)
fi

# Person detector for the heads the face detector cannot see (fidelity.face_guard zoom): YOLOX, Apache-2.0, 36 MB, OpenCV's zoo.
YOLOX_SHA256=c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063
YOLOX_URL=https://github.com/opencv/opencv_zoo/raw/main/models/object_detection_yolox/object_detection_yolox_2022nov.onnx
if ! echo "$YOLOX_SHA256  yolox.onnx" | (cd "$DEST" && sha256sum -c --quiet - >/dev/null 2>&1); then
    echo "downloading the YOLOX person detector"
    curl -fsSL -o "$DEST/yolox.onnx" "$YOLOX_URL"
    echo "$YOLOX_SHA256  yolox.onnx" | (cd "$DEST" && sha256sum -c -)
fi

# Config files of the pinned ReCaVSR commit: the loader wants them next to the weights.
docker run --rm -v "$DEST":/m --entrypoint sh "$IMAGE" -c 'cp -n /opt/recavsr/checkpoints/*.json /m/ && ls /m'
# Weights are public and read-only for the workers: readable by everyone, writable by nobody but the owner.
chmod -R a+rX,go-w "$DEST"
echo "done: mount $DEST at /m (read-only) in the worker, which docker-compose.secure.yml does through RESTORE_MODELS_DIR"
