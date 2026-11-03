"""ReCaVSR as a resident, tiled, bounded-memory restoration engine.

Why this exists: the reference script loads a whole clip, runs the full frame through the model in
one go (27.5 GB at 4K, against 16 GB on an RTX 5080) and pays about 100 s of torch.compile on every
process start. This engine keeps the model, the decoder and the compiled sessions alive between
segments, cuts each frame into equally sized tiles that fit the card, and composites the restored
tiles straight into the output buffer.

Streaming rule (from the model): a TransformerSession is the state of ONE video region. Its KV
cache, LQ history and recycled latents must be consumed block after block, in order. So each tile is
streamed through the whole segment on its own, and the session is reset (not rebuilt, which would
recompile) before the next tile. The segment is therefore held in RAM at source resolution as input
and at target resolution as output; the caller bounds the segment length.

Nothing here touches the network or the disk: weights are read from a read-only directory, frames
come in and go out as NumPy arrays.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable

import cv2
import numpy as np
import torch
from safetensors.torch import load_file

from recavsr_infer.runtime.cache import FixedKVCache
from recavsr_infer.runtime.constants import DEFAULT_SPATIAL_WINDOW
from recavsr_infer.runtime.decoder import create_decoder_session, load_decoder
from recavsr_infer.runtime.flashdecoder import decode_block
from recavsr_infer.runtime.transformer import TransformerSession
from recavsr_infer.video import block_schedule, rgb_uint8, scaled_size, validate_scale
from recavsr_infer.weights import load_model

from restore_core.tiling import Tile, TileLayout, alpha_mask, composite, plan_tiles
from restore_worker.quantize import quantize_transformer

log = logging.getLogger("restore_worker.recavsr")

# (tile index, tile count, frames written for this tile)
Progress = Callable[[int, int, int], None]


class RecavsrTiledEngine:
    def __init__(
        self,
        model_dir: str | Path,
        device: str = "cuda:0",
        *,
        decoder: str = "flashdecoder",
        compile_blocks: bool = True,
        compile_decoder: bool = True,
        seed: int = 42,
        window: tuple[int, int] = DEFAULT_SPATIAL_WINDOW,
        precision: str = "bf16",
    ) -> None:
        self.model_dir = Path(model_dir)
        self.device = torch.device(device)
        if self.device.type != "cuda" or not torch.cuda.is_available():
            raise RuntimeError("ReCaVSR needs a CUDA device")
        self.seed, self.window = seed, tuple(window)
        self.compile_blocks, self.compile_decoder = compile_blocks, compile_decoder
        self.decoder_kind = decoder
        self.precision = precision
        if precision == "fp8" and not compile_blocks:
            log.warning("precision fp8 without torch.compile is SLOWER than bf16: the casts run as separate passes")
        with torch.inference_mode(), torch.cuda.device(self.device):
            self.model = load_model(self.model_dir, device=self.device)
            # The reference CLI defaults the FlashDecoder checkpoint to MODEL_DIR/flashdecoder.safetensors;
            # the Wan decoder reads its weights from the model package and must not be given one.
            checkpoint = self.model_dir / "flashdecoder.safetensors" if decoder == "flashdecoder" else None
            self.vae = load_decoder(self.model_dir, device=self.device, decoder=decoder, checkpoint_path=checkpoint)
            self.prompt = load_file(self.model_dir / "prompt.safetensors")["positive"]
            # Quantize before any session exists: sessions precompute the cross-attention K/V from these weights.
            self.quantization = quantize_transformer(self.model, precision)
        # One (transformer session, decoder session) pair per tile shape: the compiled graphs live there.
        self._sessions: dict[tuple[int, int], tuple[TransformerSession, object]] = {}

    # --- sessions -------------------------------------------------------------------------------

    def _session(self, tile_h: int, tile_w: int):
        key = (tile_h, tile_w)
        if key not in self._sessions:
            log.info("creating session for %dx%d tiles (first use compiles, about 100 s)", tile_w, tile_h)
            with torch.inference_mode(), torch.cuda.device(self.device):
                transformer = TransformerSession(
                    self.model, self.prompt, tile_h, tile_w,
                    seed=self.seed, window=self.window, compile_blocks=self.compile_blocks,
                )
                decoder = create_decoder_session(self.vae, compile_decoder=self.compile_decoder)
            self._sessions[key] = (transformer, decoder)
        return self._sessions[key]

    def _reset(self, transformer: TransformerSession, decoder) -> None:
        """Start a new stream on an existing session without touching the compiled graphs."""
        router = transformer.model._static_kv_router
        transformer.caches = [
            FixedKVCache(
                action,
                initial=router.anchor_initial_index,
                stride=router.anchor_stride_latents,
                anchors=router.anchor_capacity_latents,
            )
            for action in router.layer_actions
        ]
        transformer.lq_state = transformer.model.lq_proj.create_streaming_state()
        transformer.generator = torch.Generator(device=transformer.device).manual_seed(self.seed)
        transformer.latent_offset, transformer.previous_latents = 0, None
        if hasattr(decoder, "state"):                     # FlashDecoder
            decoder.state = decoder.model.init_state()
        else:                                             # Wan decoder
            decoder.history = (None,) * decoder.model._cached_conv_counts["decoder"]
            decoder.first = True

    # --- one block of one tile -------------------------------------------------------------------

    def _tile_block(self, frames: np.ndarray, start: int, valid: int, block: int,
                    target: tuple[int, int], tile: Tile) -> torch.Tensor:
        """Normalised [1,3,block,tile_h,tile_w] LQ input for one tile, at target resolution."""
        target_h, target_w = target
        chunk = frames[start:start + valid]
        if chunk.shape[1:3] != (target_h, target_w):
            chunk = np.stack([cv2.resize(f, (target_w, target_h), interpolation=cv2.INTER_LINEAR) for f in chunk])
        crop = chunk[:, tile.y0:min(tile.y1, target_h), tile.x0:min(tile.x1, target_w)]
        pad_h, pad_w = tile.height - crop.shape[1], tile.width - crop.shape[2]
        if pad_h or pad_w:
            # Same as reflect-padding the whole frame: the pad (under 32 px) is far smaller than a tile.
            crop = np.pad(crop, ((0, 0), (0, pad_h), (0, pad_w), (0, 0)),
                          mode="reflect" if max(pad_h, pad_w) < min(crop.shape[1:3]) else "edge")
        x = torch.from_numpy(np.ascontiguousarray(crop)).to(self.device)
        x = x.permute(3, 0, 1, 2).unsqueeze(0).to(torch.float32) / 127.5 - 1.0
        if valid < block:                                  # the model needs full blocks; extra frames are dropped
            x = torch.cat((x, x[:, :, -1:].expand(-1, -1, block - valid, -1, -1)), 2)
        return x

    # --- a whole segment -------------------------------------------------------------------------

    @torch.inference_mode()
    def restore(
        self,
        frames: np.ndarray,
        *,
        scale: float = 1.0,
        tile_height: int = 1152,
        tile_width: int = 1344,
        min_overlap: int = 96,
        progress: Progress | None = None,
    ) -> tuple[np.ndarray, dict]:
        """Restore a segment: (T, H, W, 3) uint8 RGB in, (T, H*scale, W*scale, 3) uint8 RGB out.

        `scale` 1 is same-size cleanup (for 2160p sources), 2 or 1.5 and so on upscale first with
        bilinear resampling, as the reference script does, and let the model restore at target size.
        """
        if frames.ndim != 4 or frames.shape[3] != 3 or frames.dtype != np.uint8:
            raise ValueError("frames must be a (T, H, W, 3) uint8 array")
        total = len(frames)
        target = scaled_size(frames.shape[1], frames.shape[2], validate_scale(scale))
        layout = plan_tiles(*target, tile_height=tile_height, tile_width=tile_width, min_overlap=min_overlap)
        transformer, decoder = self._session(layout.tile_height, layout.tile_width)
        output = np.empty((total, *target, 3), dtype=np.uint8)
        tiles = layout.tiles
        torch.cuda.reset_peak_memory_stats(self.device)
        torch.cuda.synchronize(self.device)
        started = time.perf_counter()
        dit_events: list[tuple] = []     # (start, after DiT, after decode) per block, summed at the end
        io_seconds = 0.0                 # CPU side: resize, crop, upload, composite
        for index, tile in enumerate(tiles):
            self._reset(transformer, decoder)
            mask = alpha_mask(layout, tile)
            written = 0
            for start, valid, block in block_schedule(total):
                t_io = time.perf_counter()
                lq = self._tile_block(frames, start, valid, block, target, tile)
                io_seconds += time.perf_counter() - t_io
                e0, e1, e2 = (torch.cuda.Event(enable_timing=True) for _ in range(3))
                e0.record()
                latent = transformer.step(lq)
                e1.record()
                remaining, offset = valid, start
                for decoded in decode_block(decoder, latent, lq):
                    take = min(remaining, decoded.shape[2])
                    if take:
                        rgb = rgb_uint8(decoded[:, :, :take, :tile.height, :tile.width], tile.height, tile.width)
                        t_io = time.perf_counter()
                        composite(output[offset:offset + take], rgb, layout, tile, mask)
                        io_seconds += time.perf_counter() - t_io
                        offset += take
                        remaining -= take
                e2.record()
                dit_events.append((e0, e1, e2))
                if remaining:
                    raise RuntimeError("decoder returned too few frames")
                written += valid
                if progress:
                    progress(index, len(tiles), written)
        torch.cuda.synchronize(self.device)
        elapsed = time.perf_counter() - started
        # Drop the per-stream state (KV caches, LQ history) so the finishing stage has the VRAM to itself.
        transformer.caches, transformer.lq_state, transformer.previous_latents = [], None, None
        torch.cuda.empty_cache()
        return output, {
            "frames": total,
            "target": target,
            "tiles": len(tiles),
            "tile": (layout.tile_height, layout.tile_width),
            "overlap": (layout.overlap_h, layout.overlap_w),
            "seconds": elapsed,
            "seconds_per_frame": elapsed / total,
            # decode includes the device-to-host copy and CPU compositing that happen inside its loop
            "dit_seconds": sum(a.elapsed_time(b) for a, b, _ in dit_events) / 1000,
            "decode_and_composite_seconds": sum(b.elapsed_time(c) for _, b, c in dit_events) / 1000,
            "cpu_prepare_and_composite_seconds": io_seconds,
            "peak_allocated_gib": torch.cuda.max_memory_allocated(self.device) / 2**30,
        }
