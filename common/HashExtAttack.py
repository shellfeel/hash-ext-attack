# -*- coding: utf-8 -*-
"""
兼容转发层：老代码 `from common.HashExtAttack import HashExtAttack` 仍可用。

新代码请改用 `from hash_ext_attack import HashExtAttack`。
此处仅封装旧接口（test / input_run），不修改新包核心类。
"""
from hash_ext_attack.attack import HashExtAttack as _Base

__all__ = ["HashExtAttack"]


class HashExtAttack(_Base):
    """兼容旧接口的包装类（test / input_run 已迁移）。"""

    def test(self):
        """老式内置演示：返回 (新明文 bytes, 新 hash str)（保持旧语义）。"""
        known, known_hash, rand, key_len = self._demo_params()
        return self.run(known, known_hash, rand, key_len)

    def input_run(self):
        """老式交互入口（已迁移到 CLI，直接调用新入口）。"""
        from hash_ext_attack.cli import main
        return main()

    @staticmethod
    def _demo_params():
        """内置演示的输入参数（与 hash_ext_attack.cli 的 --demo 一致）。"""
        known = ("order_id=70&buyer_id=17&good_id=38&buyer_point=300"
                 "&good_price=888&order_create_time=1678236217.799935")
        known_hash = "27579b68db3e89ac3c81b66345d88962"
        return known, known_hash, "&good_price=1", 50