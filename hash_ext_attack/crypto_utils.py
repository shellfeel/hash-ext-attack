# -*- coding: utf-8 -*-
"""
工具函数：hex 字符串转 bytes。
"""
import struct


class CryptoUtils:

    @staticmethod
    def trans_str_origin2_bytes(strings: str) -> bytes:
        """
        hex 字符串 -> bytes（类似 ctypes 写入）

        旧名保留作为别名：hex_to_bytes = trans_str_origin2_bytes
        """
        plain_text = strings
        tmp_b_array = bytearray()
        for index, i in enumerate(plain_text):
            index += 1
            if index % 2 == 0:
                tmp_str = plain_text[index - 2:index]
                tmp_b_array.append(int(tmp_str, 16))
        return bytes(tmp_b_array)


hex_to_bytes = CryptoUtils.trans_str_origin2_bytes