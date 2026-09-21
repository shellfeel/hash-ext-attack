# -*- coding: utf-8 -*-
"""
攻击引擎：在不泄露密钥的情况下伪造 md5(key || message) 签名。

纯逻辑模块，不涉及任何 IO / 输出。交互交互由 cli.py 承担，自检由 tests/ 承担。

链路说明（建议与 md5_manual.py 一起阅读）：
1. 用 “*” * key_len 模拟未知密钥，对 “密钥 + 已知明文” 做 MD5 块对齐填充。
   攻击只依赖密钥【长度】参与 padding，返回结果中会剥掉该前缀。
2. 新明文 = 填充后的已知明文 + 追加数据（攻击者控制）。
3. 把已知 hash 拆成 4 个小端 32 位字，写入 md5_manual 的 A/B/C/D，
   即从「密钥 + 明文已算完」的状态开始续算。
4. 将新明文重新填充后，从 know_text_padding 之后的追加数据逐块喂给 solve()，
   产出伪造 hash。
"""
import struct
import urllib.parse

from .crypto_utils import hex_to_bytes
from .md5_manual import md5_manual


class HashExtAttack:
    """
    哈希长度扩展攻击（仅支持 MD5）。
    run() 为程序化接口，返回 (去除密钥前缀的新明文, 伪造 hash)。
    """

    def __init__(self):
        # 当前攻击输入（bytes）
        self.know_text = b""
        self.know_hash = b""
        self.rand_str = b""
        # 中间状态
        self.know_text_padding = b""
        self.new_text = b""
        self.new_hash = ""

    # ------------------------------------------------------------------ #
    #  内部步骤                                                            #
    # ------------------------------------------------------------------ #

    def _padding_msg(self):
        """步骤 1：对已知明文（含模拟密钥前缀）做 MD5 padding。"""
        self.know_text_padding = md5_manual.padding_str(self.know_text)

    def _gen_new_plain_text(self):
        """步骤 2：新明文 = 填充后的已知部分 + 攻击者追加数据。"""
        self.new_text = self.know_text_padding + self.rand_str

    def split_hash(self, hash_str: bytes):
        """把 32 位 hex digest 拆成 4 个小端 32 位寄存器值。"""
        by_new = hex_to_bytes(hash_str.decode())
        return struct.unpack("<IIII", by_new)

    def _guess_new_hash(self):
        """步骤 3-4：基于已知 hash 续算,产出新 hash。"""
        # 步骤 1-2：填充已知明文、拼接新明文（保证 run() 能从零状态调用）
        self._padding_msg()
        self._gen_new_plain_text()

        # 3.1 已知 hash 拆成 4 个寄存器
        hash_block = self.split_hash(hash_str=self.know_hash)
        md5_manual.A, md5_manual.B, md5_manual.C, md5_manual.D = hash_block

        # 3.2 新明文重新 padding（逐块续算）
        tmp_str = md5_manual.padding_str(self.new_text)

        # 已知 hash 的状态已压缩了 know_text_padding 里的所有块，
        # 续算应继续压缩 know_text_padding 之后的追加数据（可能跨多块）。
        offset = len(self.know_text_padding)
        appended = tmp_str[offset:]
        for i in range(0, len(appended), 64):
            md5_manual.solve(appended[i:i + 64])

        self.new_hash = md5_manual.hex_digest()

    # ------------------------------------------------------------------ #
    #  主入口                                                             #
    # ------------------------------------------------------------------ #

    def run(self, know_text, know_hash, rand_str, key_len) -> tuple:
        """
        执行攻击。

        :param know_text: 已知明文（不含密钥）
        :param know_hash: 已知 md5 签名（hex 字符串）
        :param rand_str:  追加数据（攻击者在签名后拼接的部分）
        :param key_len:   未知密钥长度（攻击仅依赖该长度参与 padding）
        :return: (去除密钥前缀的新明文 bytes, 伪造 hash str)
        """
        # 密钥仅由长度参与计算，用 '*' 占位模拟
        self.know_text = ("*" * key_len + know_text).encode()
        self.know_hash = know_hash.encode()
        self.rand_str = rand_str.encode()

        self._guess_new_hash()

        # 剥离模拟密钥前缀，返回攻击者真正可控的字节流
        self.new_text_stripped = self.new_text[key_len:]
        return self.new_text_stripped, self.new_hash

    # ------------------------------------------------------------------ #
    #  便捷方法                                                           #
    # ------------------------------------------------------------------ #

    def new_text_urlencoded(self) -> str:
        """新明文（已剥离密钥前缀）的 URL 编码形态（保留 & = 原文）。"""
        return urllib.parse.quote(self.new_text_stripped, safe="&=")

    def demo(self):
        """内置演示（与 CLI --demo 一致），返回 (新明文, 新 hash, 输入的已知字段)。"""
        known = ("order_id=70&buyer_id=17&good_id=38&buyer_point=300"
                 "&good_price=888&order_create_time=1678236217.799935")
        known_hash = "27579b68db3e89ac3c81b66345d88962"
        new_text, new_hash = self.run(known, known_hash, "&good_price=1", 50)
        return known, known_hash, "&good_price=1", 50, new_text, new_hash