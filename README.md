# hash-ext-attack

MD5 哈希长度扩展攻击工具：在不知道密钥的情况下伪造 `md5(key || message)` 签名。
纯 Python 实现，免去 hashpump 需要编译的烦恼，仅支持 MD5。

## 依赖

唯一第三方依赖是 `loguru`：

```bash
pip install -r requirements.txt   # macOS 系统 Python 受 PEP 668 限制时需用 venv
```

## 用法

### 交互式

```bash
python hash_ext_attack.py
```

依次输入四组参数（运行后会给出使用说明）：
1. 已知明文（不含密钥，如订单参数串）
2. 已知 hash（即 `md5(密钥 || 明文)` 的 32 位 hex 签名）
3. 扩展字符（攻击者在签名后追加的数据）
4. 密钥长度（未知密钥的字节数）

输出为一个结果面板：输入回显、新明文（URL 编码形态）、以及伪造的新 hash。

### 一键演示

```bash
python hash_ext_attack.py --demo
```

使用内置样例直接运行并展示结果面板，用于验证攻击链路是否正常。

### 关闭颜色

```bash
HASH_EXT_NO_COLOR=1 python hash_ext_attack.py --demo
```

### 程序化调用

在不知道密钥长度、需要爆破或批量生成时，可程序化调用攻击引擎：

```python
from hash_ext_attack import HashExtAttack

attack = HashExtAttack()
new_text, new_hash = attack.run(
    "order_id=70&buyer_id=17&good_id=38&buyer_point=300"
    "&good_price=888&order_create_time=1678236217.799935",
    "27579b68db3e89ac3c81b66345d88962",
    "&good_price=1",
    50,
)
# new_text 是去除密钥前缀的新明文（bytes，含标准 padding）
# new_hash 是伪造的新签名
```

### 自检

```bash
# 手写 MD5 与 hashlib 对拍（全长度 + 边界）
python tests/test_md5.py

# 攻击链路回归（随机密钥长度 × 已知明文 × 扩展字符组合）
python tests/test_attack.py

# 精选固化用例（服务器端自验 + 期望值回归锁定）
python tests/test_cases.py
```

## 代码结构

```
hash_ext_attack.py           入口：配置 loguru 级别，调用 CLI
hash_ext_attack/             核心包
  ├── cli.py                 交互式 CLI（输入校验、结果面板、--demo）
  ├── attack.py              攻击引擎（纯逻辑，无 IO）
  ├── md5_manual.py          手写 MD5（A/B/C/D 可写，支持续算）
  ├── crypto_utils.py        hex 转 bytes 工具
  └── ui.py                  ANSI 面板输出（零新依赖）
common/                      兼容转发层（旧 import 路径仍可用）
tests/                       回归测试（无框架，直接可跑）
```

### 攻击原理（见 `attack.py` 与 `md5_manual.py`）

1. 用 `'*' * key_len` 模拟未知密钥，对「密钥 + 已知明文」做 MD5 块对齐填充。
   攻击只依赖密钥**长度**参与 padding，返回结果中会剥掉该前缀。
2. 新明文 = 填充后的已知明文 + 攻击者追加数据。
3. 把已知 hash 拆成 4 个小端 32 位字，直接写入 `md5_manual.A/B/C/D`，
   即从「密钥 + 明文已算完」的状态续算。
4. 重新填充新明文后，从已知部分之后的追加数据逐块喂给 `solve()`，
   `hex_digest()` 产出伪造 hash。

### 注意事项

- `md5_manual` 是**模块级单例**，攻击直接改写其状态。每次攻击开始会把
  A/B/C/D 重置为 known_hash，但 `multi_block` / `msg_len` 不会重置：
  若同一进程内先调用过 `md5_manual.run()` / `init_mess()`（会置位
  `multi_block`），残留的 `msg_len` 会污染 `padding_str` 的长度计算。
  两种用法不要在同一进程混用（tests/ 已用独立进程规避）。
- 输出的新明文以「密钥已剥离」形态返回，同时提供 URL 编码形态
  （保留 `&` `=`）；攻击真正依赖的是完整的含 padding 字节流。
- 若要支持其他哈希或不同的认证拼接方式，需改动 `run()` 中的密钥拼接逻辑，
  以及 `md5_manual` 对应的压缩函数。