# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

MD5 哈希长度扩展攻击工具：在不知道密钥的情况下伪造 `md5(key || message)` 签名的纯 Python CTF 实现，用于替代需要编译的 hashpump。仅支持 MD5。仓库内注释、日志、README 均为中文，新增内容保持该约定。

## 常用命令

```bash
pip install -r requirements.txt   # 唯一依赖 loguru（macOS 系统 Python 受 PEP 668 限制时需用 venv）

# 交互式运行：依次提示输入 已知明文、已知hash、扩展字符、密钥长度
python hash_ext_attack.py

# 一键演示（内置样例，验证攻击链路是否仍通的最快方式）
python hash_ext_attack.py --demo

# 手写 MD5 与 hashlib 对拍自检（boundary + 随机长度）
python tests/test_md5.py

# 攻击链路回归（随机密钥长度 × 已知明文 × 扩展字符组合）
python tests/test_attack.py
```

本仓库没有测试框架、linter 或构建系统，验证手段即上述两个自检。

## 架构

调用链：`hash_ext_attack.py`（入口，负责把 loguru 重新挂载为 INFO 级别——默认 sink 输出 DEBUG）→ `hash_ext_attack.cli.main()` / `HashExtAttack.run()`。

- `hash_ext_attack/cli.py` — 交互式 CLI（输入校验、ANSI 结果面板、`--demo`）。
- `hash_ext_attack/attack.py` — 攻击编排。`run(know_text, know_hash, rand_str, key_len)` 是程序化调用接口（用于爆破未知密钥长度/批量生成），返回去掉密钥前缀的新明文与新 hash。
- `hash_ext_attack/md5_manual.py` — 纯手写 MD5。关键设计：内部寄存器 A/B/C/D 暴露且可写，`solve(chunk)` 每次只压缩一个 64B 块——这正是长度扩展攻击得以续算的基础。
- `hash_ext_attack/crypto_utils.py` — 唯一工具函数：hash 十六进制串转 bytes。
- `hash_ext_attack/ui.py` — ANSI 面板输出（零新依赖）。
- `common/` — 兼容转发层，旧 `common.HashExtAttack` 等 import 路径仍可用。

攻击核心在 `HashExtAttack._guess_new_hash()`（需与 md5_manual 一起阅读）：

1. 对 `key + 已知明文` 做 MD5 块对齐填充。密钥用 `'*' * key_len` 模拟——攻击只依赖密钥**长度**参与 padding 运算，返回值与日志中均会剥掉该前缀。
2. 新明文 = 填充后的已知明文 + 攻击者追加数据（`_gen_new_plain_text`）。
3. 把已知 hash 拆成 4 个小端 32 位字，直接写入 `md5_manual.A/B/C/D`，即从「密钥+明文已算完」的状态续算。
4. 将重新填充后的新明文从已知部分之后的追加数据**逐块**喂给 `solve()`（之前的块已包含在注入的初始状态里），`hex_digest()` 产出伪造 hash。

### 注意事项

- `md5_manual` 是**模块级单例**，HashExtAttack 直接改写其状态。每次攻击开始会把 A/B/C/D 重置为 know_hash，但 `muilt_block`/`msg_len` 不会重置：若同一进程内先调用过 `md5_manual.run()`/`init_mess()`（会置位 `muilt_block`），残留的 `msg_len` 会污染 `padding_str` 的长度计算，导致结果错误。两种用法不要在同一进程混用。
- 输出的新明文以"密钥已剥离"的形态返回（`new_text[key_len:]`），同时提供 URL 编码形式（`safe='&='`）；攻击真正依赖的是完整的含 padding 字节流。
- 若要支持其他哈希或不同的认证拼接方式，需改动 `run()` 中的密钥拼接逻辑与 md5_manual 对应的压缩函数。
