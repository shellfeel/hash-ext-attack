# -*- coding: utf-8 -*-
"""
手写 MD5 算法，与 hashlib.md5 完全等价（可对拍验证）。

关键设计：
- 内部寄存器 A/B/C/D 暴露且可写，支持「续算」——这是哈希长度扩展攻击的核心。
- solve(chunk) 每次只压缩一个 64B 块，不关心边界。
- 模块级单例 md5_manual，attack.py 直接改写其状态。

注意：
- 不要在同一个进程中混用 md5_manual.run()（全量调用）和攻击续算模式（直接写 A/B/C/D）。
  run() 会置位 self.multi_block / self.msg_len，残留状态会污染 padding_str 的长度计算。
"""
import binascii
import math
import struct

from loguru import logger


class Md5Manual:
    """手动实现 MD5（RFC 1321）"""

    def __init__(self):
        self.multi_block = False
        self.msg_len = None
        logger.debug("Md5Manual init")
        # 初始向量
        self.A, self.B, self.C, self.D = (
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
        )
        # 循环左移位移表（64 轮）
        self.r = (
            # 第 1 轮
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            # 第 2 轮
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            # 第 3 轮
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            # 第 4 轮
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        )
        # T[i] = floor(abs(sin(i+1)) * 2^32)
        self.k = [int(math.floor(abs(math.sin(i + 1)) * (2 ** 32))) for i in range(64)]

    # ------------------------------------------------------------------ #
    #  标准 MD5 填充                                                       #
    # ------------------------------------------------------------------ #

    def padding_str(self, message: bytes) -> bytes:
        """
        MD5 padding：追加 0x80，填充零使长度 ≡ 56 (mod 64)，末尾写原消息比特长。
        返回值为 64B 对齐的完整消息。
        """
        logger.debug("padding_str")
        m_l = len(message)
        if self.multi_block:
            logger.debug("multi_block 启用，使用缓存长度")
            m_l = self.msg_len

        # 长度字段：消息原始比特数（64 位小端）
        length = struct.pack("<Q", m_l * 8)
        logger.debug(f"长度({m_l}B): {length.hex()}")

        # 追加 0x80
        message = message + b"\x80"
        # 零填充至 ≡ 56 (mod 64)
        blank = b"\x00" * ((56 - len(message)) % 64)
        message = message + blank
        logger.debug(f"零填充({len(blank)}B)")

        # 追加长度字段
        message = message + length
        logger.debug(f"填充后完整消息({len(message)}B)")
        return message

    # ------------------------------------------------------------------ #
    #  全量压缩（多块 + 尾部填充）                                          #
    # ------------------------------------------------------------------ #

    def init_mess(self, message: bytes):
        """预处理：逐块压缩直到剩余不足 64B，再 padding 后压缩最后一块。"""
        self.msg_len = len(message)
        if self.msg_len > 64:
            self.multi_block = True
        logger.debug(f"init_mess: {len(message)}B, multi_block={self.multi_block}")

        while len(message) > 64:
            self.solve(message[:64])
            message = message[64:]

        message = self.padding_str(message)
        while len(message) > 64:
            self.solve(message[:64])
            message = message[64:]
        self.solve(message[:64])

    # ------------------------------------------------------------------ #
    #  单块压缩                                                           #
    # ------------------------------------------------------------------ #

    def solve(self, chunk: bytes):
        """压缩一个 64 字节块。"""
        logger.debug(f"solve: {len(chunk)}B block")
        # 分成 16 组 32 位字
        w = list(struct.unpack("<" + "I" * 16, chunk))

        a, b, c, d = self.A, self.B, self.C, self.D

        for i in range(64):  # 64 轮运算
            # 轮函数 F 与取字下标 g
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (b & d) | (c & (~d))
                g = (5 * i + 1) % 16
            elif i < 48:
                f = (b ^ c ^ d)
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            tmp = b + self._lrot((a + f + self.k[i] + w[g]) & 0xFFFFFFFF, self.r[i])
            a, b, c, d = d, tmp & 0xFFFFFFFF, b, c

        # 块压缩结果累加到寄存器
        self.A = (self.A + a) & 0xFFFFFFFF
        self.B = (self.B + b) & 0xFFFFFFFF
        self.C = (self.C + c) & 0xFFFFFFFF
        self.D = (self.D + d) & 0xFFFFFFFF
        logger.debug(f"块后 A={self.A:08x}")

    # ------------------------------------------------------------------ #
    #  辅助                                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _lrot(x: int, n: int) -> int:
        """32 位循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def digest(self) -> bytes:
        return struct.pack("<IIII", self.A, self.B, self.C, self.D)

    def hex_digest(self) -> str:
        return binascii.hexlify(self.digest()).decode()

    # ------------------------------------------------------------------ #
    #  全量摘要（仅用于基准/自检，攻击不走这里）                               #
    # ------------------------------------------------------------------ #

    def run(self, mess) -> str:
        """全量调用：重置状态 → 预处理 → 返回 hex digest。"""
        self.__init__()
        if isinstance(mess, str):
            mess = mess.encode()
        self.init_mess(mess)
        return self.hex_digest()

    def self_check(self, output=print) -> bool:
        """与 hashlib 对拍自检（无 loguru），boundary + 随机长度全通过才返回 True。"""
        import hashlib as _hashlib
        import random as _random

        boundary = [0, 1, 7, 14, 55, 56, 57, 62, 63, 64, 65, 71,
                    110, 119, 120, 121, 127, 128, 129, 191, 192,
                    255, 256, 511, 512]
        rng = _random.Random(20260921)
        ok_all = True
        for ml in boundary + [rng.randrange(0, 500) for _ in range(20)]:
            msg = bytes(rng.randrange(256) for _ in range(ml)) if ml else b""
            want = _hashlib.md5(msg).hexdigest()
            got = self.run(msg)
            ok = want == got
            ok_all = ok_all and ok and not output(f"  {'OK ' if ok else 'FAIL'}  len={ml:>3}  got={got}  want={want}")
        output("  " + ("ALL PASS ✓" if ok_all else "SOME FAILED ✗"))
        return ok_all


# ------------------------------------------------------------------ #
#  模块级单例（attack.py 直接改写其 A/B/C/D 做续算）                      #
# ------------------------------------------------------------------ #

md5_manual = Md5Manual()

if __name__ == "__main__":
    import hashlib

    logger.remove()
    test_str = "1" * 56
    print(test_str)
    print("hashlib   :", hashlib.md5(test_str.encode()).hexdigest())
    print("md5_manual:", md5_manual.run(test_str.encode()))
    print("--- self_check ---")
    md5_manual.self_check()