# -*- coding: utf-8 -*-
"""
轻量终端美化：ANSI 颜色 + Box Drawing 面板，无第三方依赖。

要点：
- CJK 字符按 2 列宽计算，保证含中文的 box 对齐。
- 所有返回字符串均已带 ANSI 码（无 TTY 时终端通常也会按原样显示，
  如需纯文本可用 display_width / 环境变量关闭）。
"""
import os


# ------------------------------------------------------------------ #
#  ANSI 颜色                                                          #
# ------------------------------------------------------------------ #

class Colors:
    """ANSI 16 色 + 样式。"""

    # 样式
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    ITALIC = "\x1b[3m"
    UNDERLINE = "\x1b[4m"
    REVERSE = "\x1b[7m"

    # 前景色
    BLACK = "\x1b[30m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"
    BRIGHT_BLACK = "\x1b[90m"
    BRIGHT_RED = "\x1b[91m"
    BRIGHT_GREEN = "\x1b[92m"
    BRIGHT_YELLOW = "\x1b[93m"
    BRIGHT_BLUE = "\x1b[94m"
    BRIGHT_MAGENTA = "\x1b[95m"
    BRIGHT_CYAN = "\x1b[96m"
    BRIGHT_WHITE = "\x1b[97m"

    # 背景色（精选）
    BG_BLACK = "\x1b[40m"
    BG_RED = "\x1b[41m"
    BG_GREEN = "\x1b[42m"
    BG_YELLOW = "\x1b[43m"
    BG_BLUE = "\x1b[44m"
    BG_MAGENTA = "\x1b[45m"
    BG_CYAN = "\x1b[46m"
    BG_WHITE = "\x1b[47m"


# 环境变量可关闭颜色（CI / 纯日志）
USE_COLOR = os.environ.get("HASH_EXT_NO_COLOR", "") == ""


def _c(code: str, text: str, reset: str = Colors.RESET) -> str:
    """给 text 包裹 ANSI 码。USE_COLOR=False 时原样返回。"""
    if not USE_COLOR or not code:
        return text
    return f"{code}{text}{reset}"


def color(text: str, code: str, bold: bool = False) -> str:
    return _c((Colors.BOLD if bold else "") + code, text)


# ------------------------------------------------------------------ #
#  字符宽度（CJK 按 2 列）                                              #
# ------------------------------------------------------------------ #

def display_width(s: str) -> int:
    """可见终端宽度：中文/全角按 2 列，其余按 1 列。"""
    w = 0
    for ch in s:
        # 简单判断：CJK 范围（含常见扩展）
        cp = ord(ch)
        if cp >= 0x1100 and (
                (cp <= 0x115F) or
                (cp >= 0x2E80 and cp <= 0xA4CF) or
                (cp >= 0xAC00 and cp <= 0xD7A3) or
                (cp >= 0xF900 and cp <= 0xFAFF) or
                (cp >= 0xFE30 and cp <= 0xFE4F) or
                (cp >= 0xFF00 and cp <= 0xFF60) or
                (cp >= 0xFFE0 and cp <= 0xFFE6)) or \
           (cp >= 0x1F600 and cp <= 0x1F64F) or \
           (cp >= 0x1F300 and cp <= 0x1F5FF):
            w += 2
        else:
            w += 1
    return w


def _pad(text: str, width: int) -> str:
    """用空格把 text 填充到 width 列宽。"""
    return text + " " * max(0, width - display_width(text))


# ------------------------------------------------------------------ #
#  Box Drawing 面板                                                   #
# ------------------------------------------------------------------ #

class Box:
    """box-drawing 字符集合。"""
    TL = "╭"  # 左上
    TR = "╮"  # 右上
    BL = "╰"
    BR = "╯"
    H = "─"
    V = "│"


def box(title: str, lines: list, title_color: str = Colors.BRIGHT_CYAN,
        border_color: str = Colors.BRIGHT_BLACK, width: int = 56) -> str:
    """
    画一个带标题的面板。lines 为已处理好的文本行（可含 ANSI 码）。

    布局：
        ╭─ 标题 ──────────────╮
        │ 第 1 行              │
        ╰─────────────────────╯

    边框宽度按【可见宽度】对齐，行内 ANSI 不影响计数。
    """
    if not USE_COLOR:
        border_color = ""
        title_color = ""

    inner_w = width - 2  # V | 内容 | V
    out = []

    # 顶部：左上标题（╭─ 标题 ─ ... ─╮）
    if title:
        title_w = display_width(title)
        left_h = 1            # ╭─ 后 1 个 H
        right_h = inner_w - left_h - title_w - 2  # 标题前后各 1 空格，右段补齐
        top = (border_color + Box.TL + Box.H * left_h
               + " " + title_color + title + Colors.RESET + " "
               + border_color + Box.H * max(0, right_h) + Box.TR + Colors.RESET)
    else:
        top = (border_color + Box.TL + Box.H * inner_w + Box.TR + Colors.RESET)
    out.append(top)

    # 内容行（左对齐，右空格补齐）
    for ln in lines:
        plain = _strip_ansi(ln)
        gap = inner_w - display_width(plain)
        out.append(border_color + Box.V + Colors.RESET
                   + ln
                   + " " * max(0, gap)
                   + border_color + Box.V + Colors.RESET)

    # 底部
    out.append(border_color + Box.BL + Box.H * inner_w + Box.BR + Colors.RESET)
    return "\n".join(out)


def _strip_ansi(s: str) -> str:
    """去掉 ANSI 转义序列，用于计算可见宽度。"""
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


# ------------------------------------------------------------------ #
#  行与区块辅助                                                        #
# ------------------------------------------------------------------ #

def kv_line(key: str, value: str, key_color: str = Colors.BRIGHT_YELLOW,
            value_color: str = Colors.WHITE, align: int = 12) -> str:
    """key: value 对齐输出的单行（key 固定宽，CJK 感知）。"""
    return (color(_pad(key + ":", align), key_color)
            + " " + color(value, value_color))


def section(title: str, color_code: str = Colors.BRIGHT_CYAN) -> str:
    """区块小标题：『 title 』"""
    return color("▶ ", Colors.BRIGHT_BLACK) + color(title, color_code)


def success(text: str) -> str:
    """绿色成功态。"""
    return color("✔ ", Colors.GREEN) + color(text, Colors.BRIGHT_GREEN, bold=True)


def failure(text: str) -> str:
    """红色失败态。"""
    return color("✘ ", Colors.RED) + color(text, Colors.BRIGHT_RED, bold=True)


def hint(text: str) -> str:
    """灰字提示。"""
    return color(text, Colors.BRIGHT_BLACK)


# ------------------------------------------------------------------ #
#  帮助 / 横幅文字                                                     #
# ------------------------------------------------------------------ #

BANNER_TITLE = "MD5 哈希长度扩展攻击"
BANNER_SUB = "在未知密钥下伪造 md5(key || message) 签名"


def banner() -> str:
    """程序开场的横幅（两行文字 + 面板）。"""
    lines = [
        color("  " + BANNER_TITLE, Colors.BRIGHT_GREEN, bold=True),
        color("  " + BANNER_SUB, Colors.BRIGHT_BLACK),
    ]
    return box("", [color(BANNER_TITLE, Colors.BRIGHT_GREEN, bold=True),
                    color(BANNER_SUB, Colors.BRIGHT_BLACK)], width=50)


def help_text() -> str:
    """交互式输入前的提示文字。"""
    return box(
        "使用说明",
        [
            section("输入参数"),
            "  1) 已知明文    —— 不含密钥的部分（如订单参数串）",
            "  2) 已知 hash   —— md5(密钥 || 明文) 的 hex 签名",
            "  3) 扩展字符    —— 攻击者在签名后追加的数据",
            "  4) 密钥长度    —— 未知密钥的字节数",
            "",
            section("其他信息"),
            color("  运行示例   ", Colors.BRIGHT_BLACK)
            + color("python hash_ext_attack.py --demo", Colors.CYAN),
            "  关闭颜色   HASH_EXT_NO_COLOR=1 python hash_ext_attack.py ...",
        ],
        width=58,
    )