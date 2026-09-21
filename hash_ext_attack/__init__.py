# -*- coding: utf-8 -*-
"""
hash_ext_attack 包：MD5 哈希长度扩展攻击工具。

对外导出核心类与便捷入口：
    HashExtAttack   —— 攻击引擎（纯逻辑，无 IO）
    Md5Manual       —— 手写 MD5 类
    md5_manual      —— 模块级单例（用于续算）
    main            —— 交互式 CLI 入口（含 --demo）
"""
from .attack import HashExtAttack
from .md5_manual import Md5Manual, md5_manual
from .cli import main

__all__ = ["HashExtAttack", "Md5Manual", "md5_manual", "main"]