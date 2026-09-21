# -*- coding: utf-8 -*-
"""
攻击链路回归测试。

用 hashlib 作为“服务器端”基准：
  1. 随机生成 密钥长度 / 已知明文 / 扩展字符
  2. 服务器签名 = md5(密钥模拟 + 已知明文)
  3. 攻击 run() 产出 (新明文, 新 hash)
  4. 断言 md5(密钥模拟 + 新明文) == 新 hash —— 服务器用同一密钥能验出的伪造签名

注意：攻击依赖模块级单例 md5_manual 的状态续算，为避免与 md5_manual.run()
等“全量调用”模式互相污染，本脚本独立进程运行，仅调用攻击的 run()。

退出码：0 全通过，1 有失败。
"""
import hashlib
import os
import random
import string
import sys

# 保证直接从 tests/ 目录运行时能导入项目包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hash_ext_attack import HashExtAttack


def gen_text(rng, n):
    return "".join(rng.choices(string.ascii_letters + string.digits + "&=", k=n))


def main() -> int:
    rng = random.Random(20260921)
    key_lens = [1, 2, 7, 15, 50, 55, 56, 57, 63, 64, 65, 127, 128, 129, 200]
    known_lens = [0, 1, 6, 55, 56, 57, 63, 64, 65, 100, 190, 191]
    rand_lens = [1, 7, 12, 13, 55, 56, 57, 63, 64, 65, 100]

    attack = HashExtAttack()
    n_bad = 0
    n_total = 0
    for kl in key_lens:
        for knl in known_lens:
            for rl in rand_lens:
                known_text = gen_text(rng, knl)
                rand_str = gen_text(rng, rl)
                secret = b"*" * kl  # 服务器密钥（攻击不知道内容，只用长度）
                server_hash = hashlib.md5(secret + known_text.encode()).hexdigest()

                new_text, new_hash = attack.run(known_text, server_hash, rand_str, kl)
                # 服务器侧复核
                verify = hashlib.md5(secret + new_text).hexdigest()
                n_total += 1
                if verify != new_hash:
                    n_bad += 1
                    print(f"FAIL kl={kl} knl={knl} rl={rl}: attack={new_hash} server={verify}")

    if n_bad:
        print(f"FAIL：{n_bad}/{n_total} 组合验证失败")
        return 1
    print(f"PASS：{n_total} 组 密钥长度×已知明文×扩展字符 组合全部可被服务器验证 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())