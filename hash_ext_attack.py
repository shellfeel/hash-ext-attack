# -*- coding: utf-8 -*-
"""
入口：配置 loguru 为 INFO 级别后启动 CLI。

默认 loguru sink 会输出 DEBUG 刷屏，这里关掉默认 handler 并挂 INFO，
攻击流程本身的进度由 cli.py 的 ANSI 面板承担，loguru 仅保留必要信息。
"""
import sys

from loguru import logger

from hash_ext_attack.cli import main

if __name__ == "__main__":
    # 默认 sink 是 DEBUG，这里收敛到 INFO，避免刷屏
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    raise SystemExit(main())