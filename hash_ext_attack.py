import base64
import hashlib
import hmac
import struct
import sys
import time
import urllib.parse

from common.md5_manual import md5_manual
from loguru import logger
from common.crypto_utils import CryptoUtils


class HashExtAttack:
    """
    哈希长度扩展攻击,解决 hashpump 在win下使用困难的问题
    目前仅支持md5，如果你对认证算法有了解可以手动改写str_add中的字符串拼接方式
    """

    def __init__(self):
        self.know_text = b""
        self.know_text_padding = b""
        self.new_text = b""
        self.rand_str = b''
        self.know_hash = b"3c5a36dd888251601d36bbc184648717"
        self.key_length = 15

    def _padding_msg(self):
        """填充明文"""
        logger.debug("填充明文")
        self.know_text_padding = md5_manual.padding_str(self.know_text)
        logger.debug(f"已知明文填充：{self.know_text_padding}")

    def _gen_new_plain_text(self):
        """生成新明文"""
        self.new_text = self.know_text_padding + self.rand_str  # b'80' + 55 * b'\x00' + struct.pack("<Q", 512 + len(self.rand_str) *8)
        logger.debug(f"new_text: {self.new_text}")

    def split_hash(self, hash_str: bytes):
        by_new = CryptoUtils.trans_str_origin2_bytes(hash_str.decode())
        return struct.unpack("<IIII", by_new)

    def _guess_new_hash(self) -> tuple:
        """生成新hash"""
        # 第一步先生成新的字符串
        # 对已知明文进行填充
        self._padding_msg()
        # 第二步 生成新明文
        self._gen_new_plain_text()
        # 第三步 生成新hash(基于已知hash进行计算)
        # 3.1 hash拆分成4个分组
        hash_block = self.split_hash(hash_str=self.know_hash)
        md5_manual.A, md5_manual.B, md5_manual.C, md5_manual.D = hash_block
        tmp_str = md5_manual.padding_str(self.new_text)
        logger.debug(f"新明文填充tmp_str({len(tmp_str)}): {tmp_str}")
        logger.debug(f"参与手工分块计算的byte：{tmp_str[-64:]}")
        md5_manual.solve(tmp_str[-64:])
        self.new_hash = md5_manual.hex_digest()

        return self.new_text, self.new_hash

    def run(self, know_text, know_hash, rand_str, key_len) -> tuple:
        # self.know_text = input("请输入已知明文：")
        self.know_text = ("*" * key_len + know_text).encode()  # 密钥拼接
        self.know_hash = know_hash.encode()
        self.rand_str = rand_str.encode()

        self._guess_new_hash()
        logger.info(f"已知明文：{self.know_text[key_len:]}")
        logger.info(f"已知hash：{self.know_hash}")
        logger.debug(f"任意填充：{self.rand_str}")
        logger.info(f"新明文：{self.new_text[key_len:]}")
        logger.info(f"新明文(url编码)：{urllib.parse.quote(self.new_text[key_len:], safe='&=')}")
        # logger.debug(f"新明文：{base64.b64encode(self.new_text[key_len:])}")
        logger.info(f"新hash:{self.new_hash}")
        return self.new_text[key_len:], self.new_hash

    def input_run(self):
        time.sleep(0.2)
        self.run(input("请输入已知明文："), input("请输入已知hash： "), input("请输入扩展字符: "),
                 int(input("请输入密钥长度：")))

    def test(self):
        self.run(
            "order_id=70&buyer_id=17&good_id=38&buyer_point=300&good_price=888&order_create_time=1678236217.799935",
            "178944d4a39e4e4af6522c6de6cb24c5", "&good_price=1", 50)


hash_ext_attack = HashExtAttack()

if __name__ == '__main__':

    logger.remove()
    logger.add(sys.stderr, level="INFO")
    hash_ext_attack.input_run()
