# type: ignore

from typing import Any

import pytest

from yls.debugger import Debugger
from yls.hookspecs import ErrorMessage


@pytest.mark.parametrize(
    "expr, expected",
    [
        (
            "pe.number_of_sections",
            """- context(SAMPLE) -> Integer (18, 0x12) -> True
- context(CUCKOO) -> Integer (18, 0x12) -> True
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
async def test_debugger(expr: str, expected: Any, samples_dir_with_pe) -> None:
    debugger = Debugger()
    debugger.set_samples_dir(str(samples_dir_with_pe))
    ctx_res = await debugger.set_context(
        "fa6b73d710b5c96df05632ad6b979e787befd257284f986c3264dbbbb0481609",
        """import "pe"

rule test_rule {
    strings:
        $s00 = "Hello"
    condition:
        $s00 and pe.number_of_sections > 3
}
""",
    )
    assert not isinstance(ctx_res, ErrorMessage)

    eval_res = debugger.eval(expr)
    assert eval_res == expected
