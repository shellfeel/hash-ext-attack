# -*- coding: utf-8 -*-
"""
兼容转发层：老代码 `from common.crypto_utils import CryptoUtils` 仍可用。
新代码请改用 `from hash_ext_attack.crypto_utils import CryptoUtils`。
"""
from hash_ext_attack.crypto_utils import CryptoUtils, hex_to_bytes  # noqa: F401

__all__ = ["CryptoUtils", "hex_to_bytes"]