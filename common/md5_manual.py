# -*- coding: utf-8 -*-
"""
兼容转发层：老代码 `from common.md5_manual import md5_manual (Md5Manual)` 仍可用。
新代码请改用 `from hash_ext_attack import md5_manual, Md5Manual`。
"""
from hash_ext_attack import Md5Manual, md5_manual  # noqa: F401

__all__ = ["Md5Manual", "md5_manual"]