"""Where does the restored picture differ from the source, by scale, in linear light? Diagnostic for the glow match.

usage (inside the CPU worker image): python glow_diagnose.py SOURCE.png RESTORED.png OUT_PREFIX
Prints, for several blur widths, the mean signed linear-light difference (source minus restored) near highlights and
elsewhere, and writes a map per width (grey = no difference, brighter = the source holds more light there)."""
import sys

import cv2
import numpy as np
import torch

from restore_worker.finish import blur, _luma


def load(path):
    return torch.from_numpy(cv2.cvtColor(cv2.imread(path), cv2.COLOR_BGR2RGB)).permute(2, 0, 1)[None].float() / 255.0


def main(src_path, rest_path, prefix):
    s, r = load(src_path), load(rest_path)
    ls, lr = s ** 2.2, r ** 2.2
    near_light = blur(_luma(ls), 24) > 0.04
    print(f"pixels near highlights: {near_light.float().mean():.3f}")
    for sigma in (2, 4, 8, 16, 32):
        d = _luma(blur(ls, sigma) - blur(lr, sigma))
        a = d[near_light].mean().item(); b = d[~near_light].mean().item()
        print(f"sigma {sigma:3d}: near highlights mean {a:+.5f} rms {d[near_light].pow(2).mean().sqrt():.5f} | elsewhere mean {b:+.6f} rms {d[~near_light].pow(2).mean().sqrt():.6f}")
        m = (0.5 + 4 * d)[0, 0].clamp(0, 1).numpy()
        cv2.imwrite(f"{prefix}_diff_s{sigma}.png", cv2.resize((m * 255).astype(np.uint8), (960, 540), interpolation=cv2.INTER_AREA))


if __name__ == "__main__":
    main(*sys.argv[1:4])
