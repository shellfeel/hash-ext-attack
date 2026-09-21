# -*- coding: utf-8 -*-
"""
交互式 CLI：引导输入 已知明文 / 已知 hash / 扩展字符 / 密钥长度，
执行攻击后以面板形式输出结果。支持 --demo 一键演示。

所有校验不通过时给出红色提示并退出（不会继续读入）。
"""
import sys

from .attack import HashExtAttack
from .ui import banner, box, color, Colors, failure, help_text, hint, kv_line, success, section


class InputError(ValueError):
    """输入校验失败的异常。"""


def _read_input(prompt: str) -> str:
    """读取一行输入（自动去首尾空白）。"""
    try:
        raw = input(color(prompt, Colors.BRIGHT_CYAN, bold=True) + " ")
        return raw.strip()
    except (EOFError, KeyboardInterrupt):
        raise InputError("用户取消输入")


def _validate_hash(raw: str) -> str:
    """校验 hash：必须是 32 位 hex。"""
    if len(raw) != 32 or any(c not in "0123456789abcdef" for c in raw.lower()):
        raise InputError(f"已知 hash 必须是 32 位十六进制串，收到：{raw!r}")
    return raw


def _validate_key_len(raw: str) -> int:
    """校验密钥长度：必须是非负整数。"""
    try:
        n = int(raw)
    except ValueError:
        raise InputError(f"密钥长度必须是整数，收到：{raw!r}")
    if n < 0:
        raise InputError(f"密钥长度不能为负数，收到：{raw}")
    return n


def _gather_input() -> tuple:
    """交互式收集四元输入并校验。"""
    known_text = _read_input("请输入已知明文")
    known_hash = _validate_hash(_read_input("请输入已知 hash"))
    rand_str = _read_input("请输入扩展字符")
    key_len = _validate_key_len(_read_input("请输入密钥长度"))
    return known_text, known_hash, rand_str, key_len


def _format_result(known_text, known_hash, rand_str, key_len, new_text, new_hash) -> str:
    """把攻击结果渲染成面板。new_text 为 bytes。"""
    import urllib.parse

    new_text_url = urllib.parse.quote(new_text, safe="&=")

    lines = [
        success("攻击成功"),
        "",
        section("输入"),
        kv_line("已知明文", known_text),
        kv_line("已知hash", known_hash),
        kv_line("扩展字符", rand_str),
        kv_line("密钥长度", str(key_len) + " 字节"),
        "",
        section("伪造结果"),
        hint(f"新明文共 {len(new_text)} 字节（含标准 padding）"),
    ]
    # URL 编码很长，按面板内宽折叠成多行
    lines += _fold_kv("URL 编码", new_text_url, value_color=Colors.BRIGHT_CYAN)
    lines += [
        "",
        section("伪造签名"),
        kv_line("新 hash", new_hash, value_color=Colors.BRIGHT_MAGENTA, align=10),
        "",
        hint("将「URL 编码」内容替换请求中的 message，并用「新 hash」作为签名即可。"),
    ]
    return box(
        "攻击结果",
        lines,
        title_color=Colors.BRIGHT_YELLOW,
        border_color=Colors.BRIGHT_CYAN,
        width=62,
    )


def _fold_kv(key: str, value: str, value_color: str = Colors.WHITE,
             key_align: int = 10, content_width: int = 58) -> list:
    """
    把「key: value」按内容宽度折叠成多行。首行 key 对齐，续行用空格对齐 value 起点。
    返回可直接放入 box() 的文本行列表。
    """
    from .ui import display_width

    prefix_w = key_align + 1  # "key:" 占宽 + 一个空格
    avail = content_width - prefix_w
    first = kv_line(key, value[:avail], value_color=value_color, align=key_align)
    lines = [first]
    rest = value[avail:]
    # 续行：前缀用空格对齐到 value 起点
    indent = " " * prefix_w
    while rest:
        lines.append(indent + color(rest[:avail], value_color))
        rest = rest[avail:]
    return lines


def _wrap_display(text: str, limit: int = 52) -> list:
    """长字节流按宽度拆行显示。"""
    out = []
    while len(text) > limit:
        out.append(text[:limit])
        text = text[limit:]
    out.append(text or "")
    return out


def main(argv=None):
    """CLI 入口。argv=None 则读 sys.argv。"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="hash-ext-attack",
        description="MD5 哈希长度扩展攻击：在未知密钥下伪造 md5(key || message) 签名。",
    )
    parser.add_argument("--demo", action="store_true",
                        help="使用内置演示样例直接运行并输出结果（不等待输入）")
    args = parser.parse_args(argv)

    # 横幅
    print(banner())
    print()

    attack = HashExtAttack()

    if args.demo:
        known_text, known_hash, rand_str, key_len, new_text, new_hash = attack.demo()
        print(help_text() + "\n")
        print(_format_result(known_text, known_hash, rand_str, key_len, new_text, new_hash))
        return 0

    # 交互式
    try:
        print(help_text() + "\n")
        known_text, known_hash, rand_str, key_len = _gather_input()
    except InputError as e:
        print(failure(f"输入取消或无效：{e}"))
        return 1

    try:
        new_text, new_hash = attack.run(known_text, known_hash, rand_str, key_len)
    except Exception as e:
        print(failure(f"攻击执行失败：{type(e).__name__}: {e}"))
        return 1

    print()
    print(_format_result(known_text, known_hash, rand_str, key_len, new_text, new_hash))
    return 0


if __name__ == "__main__":
    sys.exit(main())