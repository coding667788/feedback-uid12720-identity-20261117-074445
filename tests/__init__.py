"""tests 包初始化：把项目根目录加入 sys.path，保证 `python -m unittest
discover -s tests -v` 从任意 cwd 启动都能 import solution。
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
