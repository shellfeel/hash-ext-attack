# -*- coding: utf-8 -*-
"""
md5_manual 与 hashlib 对拍自检。

覆盖 0..=300 全长度 + 键一些边界（56/57/63/64/121/127/128/129/191/192/255/256/511/512），
手写 MD5 必须与标准 hashlib 完全一致。

退出码：0 全通过，1 有失败。
"""
import hashlib
import os
import random
import sys

# 保证直接从 tests/ 目录运行时能导入项目包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hash_ext_attack import md5_manual


def main() -> int:
    rng = random.Random(20260921)
    boundary = [0, 1, 7, 14, 55, 56, 57, 62, 63, 64, 65, 71,
                110, 119, 120, 121, 127, 128, 129, 191, 192,
                255, 256, 511, 512]
    lens = boundary + list(range(0, 301)) + [rng.randrange(0, 600) for _ in range(30)]
    # 去重保序
    seen = set()
    lens = [l for l in lens if not (l in seen or seen.add(l))]

    bad = []
    for ml in lens:
        msg = bytes(rng.randrange(256) for _ in range(ml)) if ml else b""
        want = hashlib.md5(msg).hexdigest()
        got = md5_manual.run(msg)
        if want != got:
            bad.append((ml, got, want))
    if bad:
        print(f"FAIL：{len(bad)} 个长度不匹配")
        for ml, got, want in bad[:20]:
            print(f"  len={ml}: got={got} want={want}")
        return 1
    print(f"PASS：md5_manual 与 hashlib 在 {len(lens)} 个不同长度上完全一致 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())