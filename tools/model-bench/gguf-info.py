#!/usr/bin/env python3
"""Read GGUF metadata useful for GPU offload.

Prints: layers, KV heads, K/V dimension, estimated KV cache for a given context,
and weights per layer (approx). Usage: python3 gguf-info.py model1.gguf ...
"""

import os
import struct
import sys

TYPES = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}


def rs(f):
    (n,) = struct.unpack("<Q", f.read(8))
    return f.read(n).decode("utf-8", "replace")


def skip(f, t):
    if t == 8:
        rs(f)
    elif t == 9:
        et, = struct.unpack("<I", f.read(4))
        n, = struct.unpack("<Q", f.read(8))
        for _ in range(n):
            skip(f, et)
    else:
        f.read(struct.calcsize("<" + TYPES[t]))


def val(f, t):
    if t == 8:
        return rs(f)
    if t == 9:
        et, = struct.unpack("<I", f.read(4))
        n, = struct.unpack("<Q", f.read(8))
        return [val(f, et) for _ in range(n)]
    return struct.unpack("<" + TYPES[t], f.read(struct.calcsize("<" + TYPES[t])))[0]


def main():
    ctx = 8192
    for path in sys.argv[1:]:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            assert f.read(4) == b"GGUF"
            ver, = struct.unpack("<I", f.read(4))
            n_t, n_kv = struct.unpack("<QQ", f.read(16))
            meta = {}
            for _ in range(n_kv):
                key = rs(f)
                t, = struct.unpack("<I", f.read(4))
                # large arrays (tokenizer vocab, tags, base_model) are skipped without being read
                if key.startswith("tokenizer.") or key == "general.tags" or "base_model" in key:
                    skip(f, t)
                else:
                    meta[key] = val(f, t)
        arch = meta.get("general.architecture", "?")
        g = lambda s: meta.get(f"{arch}.{s}", meta.get(f"llama.{s}"))
        layers = g("block_count")
        heads = g("attention.head_count")
        heads_kv = g("attention.head_count_kv")
        embed = g("embedding_length")
        keylen = g("attention.key_length") or (embed // heads if embed and heads else None)
        vallen = g("attention.value_length") or keylen
        rec = g("attention.recurrent_layers")
        n_att = sum(1 for x in rec if not x) if isinstance(rec, list) else layers
        n_rec = sum(1 for x in rec if x) if isinstance(rec, list) else 0
        params = meta.get("general.parameter_count")
        print(f"\n{os.path.basename(path)}  ({size / 1e9:.2f} GB)  gguf v{ver}  arch {arch}  {layers} layers")
        if params:
            print(f"  params {params / 1e9:.2f}B  label {meta.get('general.size_label')}")
        print(f"  heads {heads} / KV {heads_kv} | K/V dim {keylen}/{vallen} | embed {embed}")
        if n_rec:
            print(f"  hybrid: {n_att} full-attention layers, {n_rec} recurrent layers (SSM)")
        if layers:
            print(f"  weights/layer ≈ {size / layers / 1e6:.0f} MB")
        if n_att and heads_kv and keylen and vallen:
            kv = n_att * heads_kv * (keylen + vallen) * ctx * 2
            print(f"  KV cache ctx={ctx} ≈ {kv / 1e6:.0f} MB (f16)")


if __name__ == "__main__":
    main()
