# -*- coding: utf-8 -*-
"""
精选固化用例测试。

每个用例同时做两种验证：
  1. 服务器端验证：用秘密测算 original md5，攻击产出新 hash，再以秘密测性验新明文
     必须与攻击产出的新 hash 一致 —— 证明攻击可被真实服务器接受。
  2. 期望值固化：对几个代表性用例，断言输出与固化期望精确一致，防止回归。

运行：python tests/test_cases.py
退出码：0 全通过，1 有失败。
"""
import hashlib
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hash_ext_attack import HashExtAttack


# 内置演示样例（README 中也引用）
ORDER_PARAMS = ("order_id=70&buyer_id=17&good_id=38&buyer_point=300"
                "&good_price=888&order_create_time=1678236217.799935")
ORDER_HASH = "27579b68db3e89ac3c81b66345d88962"


def case(name, key_len, known_text, rand_str):
    """执行一组攻击并做服务器端验证。返回 (校验是否通过, new_text, new_hash)。"""
    secret = b"*" * key_len                          # 服务端秘密（攻击者未知）
    server_hash = hashlib.md5(secret + known_text.encode()).hexdigest()

    attack = HashExtAttack()
    new_text, new_hash = attack.run(known_text, server_hash, rand_str, key_len)

    # 服务器重新验证伪造签名
    verify = hashlib.md5(secret + new_text).hexdigest()
    ok = verify == new_hash
    return ok, new_text, new_hash, server_hash


def main() -> int:
    cases = [
        # (名称, 密钥长度, 已知明文, 扩展字符)
        ("内置演示样例",           50, ORDER_PARAMS,        "&good_price=1"),
        ("空已知明文|单字节密钥",    1,  "",                "&x=1"),
        ("密钥恰为整块64B",          64, "message",         "append"),
        ("已知明文57B|padding边界",  15, "a" * 57,          "!tail"),
        ("扩展字符跨块|多块续算",    50, "hello world",     "A" * 100),
        ("密钥跨多块",               100, "b" * 120,        "&admin=1"),
        ("扩展字符为空",             8,  "data",            ""),
        ("已知明文超长",             80, "param=1&param2=2&" * 30, "&grant=1"),
    ]

    failures = []
    for name, kl, known, rand in cases:
        ok, new_text, new_hash, server_hash = case(name, kl, known, rand)
        mark = "PASS" if ok else "FAIL"
        print(f"  {mark}  {name}  (key_len={kl}, known_len={len(known)}, "
              f"rand_len={len(rand)})  server_verify_ok={ok}")
        if not ok:
            failures.append(name)

    print()
    print("=" * 60)
    print("固化的期望值校验（防止算法回归）")
    expected = [
        # (密钥长度, 已知明文, 扩展字符, 服务器原始 hash, 期望新 hash)
        (50, ORDER_PARAMS,     "&good_price=1",
         "27579b68db3e89ac3c81b66345d88962", "d37df55222da4dc9776ebcf80f5df8b6"),
        (1,  "",               "&x=1",
         "3389dae361af79b04c9c8e7057f60cc6", "4d99504682bbd4945b971d19d5de7665"),
        (64, "message",        "append",
         "4e4872e96817e23f9890e673edb22f00", "5e8d14854363fd5e72aee979ca7e4278"),
        (15, "a" * 57,         "!tail",
         "e2bd173924e547fc4ee9441ceb5fe8a8", "9940c6c7becd695534183c52ff805370"),
        (50, "hello world",    "A" * 100,
         "99fa2cf14091a955d3bfcb074d58905e", "27f02e0c7d107ea8804d1528ede3860e"),
        (100, "b" * 120,       "&admin=1",
         "367fed642b42af269d82ed3f8686e664", "727e7636bee13ed36a76bc3461e74b6d"),
        (8,  "data",            "",
         "0f0221f852748153ba0d12fd602a6e90", "6618dba2532ec563ff175ca29994f7f8"),
        (80, "param=1&param2=2&" * 30, "&grant=1",
         "6622905ac7a3045956cddc3ac7a20f64", "aa3ed3c9bc9b03a17c1e67d9dd4e4222"),
    ]
    exp_failures = 0
    attack = HashExtAttack()
    for kl, known, rand, want_server_hash, want_new_hash in expected:
        secret = b"*" * kl
        server_hash = hashlib.md5(secret + known.encode()).hexdigest()
        if server_hash != want_server_hash:
            print(f"  FAIL  服务器原始 hash 不符：{server_hash} != {want_server_hash}")
            exp_failures += 1
            continue
        new_text, new_hash = attack.run(known, server_hash, rand, kl)
        if new_hash != want_new_hash:
            print(f"  FAIL  新 hash 不符：{new_hash} != {want_new_hash}  key_len={kl}")
            exp_failures += 1
        else:
            print(f"  PASS  新 hash = {new_hash}  key_len={kl}")
    if exp_failures:
        print(f"\nFAIL：{exp_failures} 项期望值不符")
        return 1

    if failures:
        print(f"\nFAIL：{len(failures)} 个服务器验证用例失败")
        return 1

    print()
    print("ALL PASS 全部精选用例验证通过 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())