import os
from typing import Any
import pytest

from yls.debugger import Debugger
from yls.hookspecs import ErrorMessage


@pytest.mark.parametrize(
    "expr, expected",
    [
        (
            "pe.number_of_sections",
            """- context(SAMPLE) -> Integer (4, 0x4) -> True
- context(CUCKOO) -> Integer (4, 0x4) -> True
""",
        ),
        (
            "cuckoo.filesystem.file_access(/.*/)",
            """- context(SAMPLE) -> Integer (0, 0x0) -> False
- context(CUCKOO) -> Integer (1, 0x1) -> True
""",
        ),
        (
            "$s00",
            """- context(SAMPLE) -> Integer (1, 0x1) -> True
- context(CUCKOO) -> Integer (1, 0x1) -> True
""",
        ),
        (
            "$s00 and pe.number_of_sections > 3",
            """- context(SAMPLE) -> Integer (1, 0x1) -> True
- context(CUCKOO) -> Integer (1, 0x1) -> True
""",
        ),
    ],
)
async def test_debugger(expr: str, expected: Any) -> None:
    debugger = Debugger()
    debugger.set_samples_dir(os.path.join(os.path.dirname(__file__), "assets"))
    ctx_res = await debugger.set_context(
        "7eb8f8828fa773fbea73b4d481b9ac007255f63c83e7a61b632e9ec4637ab828",
        """import "pe"

rule test_rule {
    strings:
        $s00 = "Hello"
    condition:
        $s00 and pe.number_of_sections > 3
}
""",
    )
    assert isinstance(ctx_res, ErrorMessage) is False

    eval_res = debugger.eval(expr)
    assert eval_res == expected
