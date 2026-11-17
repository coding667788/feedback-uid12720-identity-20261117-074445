"""可注入时钟。

生产代码使用 :class:`SystemClock`（真实时间）；测试与 cases.json 使用
:class:`FakeClock`，时间只能通过 :meth:`FakeClock.advance` 显式推进，
不同进程持有的 FakeClock 从同一固定起点出发，保证可重放。
"""

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int:
        """当前 Unix 秒（整数）。"""
        raise NotImplementedError


class SystemClock:
    """真实系统时钟。"""

    def now(self) -> int:
        return int(time.time())


class FakeClock:
    """固定起点、手动推进的假时钟。"""

    def __init__(self, start: int = 1_700_000_000):
        self._now = int(start)

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> int:
        """推进 ``seconds`` 秒（必须为非负整数），返回推进后的时间。"""
        if seconds < 0:
            raise ValueError("FakeClock 不允许回拨时间")
        self._now += int(seconds)
        return self._now

    def set(self, value: int) -> int:
        """直接设置时间（仅用于构造特殊起点）。"""
        self._now = int(value)
        return self._now


def make_clock(spec: dict | None) -> Clock:
    """根据 cases.json 的 clock 配置构造时钟。

    - None / {"type": "system"} -> SystemClock
    - {"type": "fake", "start": <unix秒>} -> FakeClock
    """
    if not spec or spec.get("type", "fake") == "system":
        return SystemClock()
    return FakeClock(int(spec.get("start", 1_700_000_000)))
