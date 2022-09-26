from __future__ import annotations

import pytest

from yls.strings import StringType
from yls.strings import estimate_string_type


@pytest.mark.parametrize(
    "line, string_type",
    (
        ("", None),
        ("$", None),
        ("$s00", None),
        ("$s00 = ", None),
        ('$s00 = ""', StringType.PLAIN),
        ("$s00 = /test/", StringType.REGEX),
        ("$s00 = { 11", StringType.HEX),
        ("$s00 = {", StringType.HEX),
    ),
)
def test_estimate_string_type(line: str, string_type: StringType | None) -> None:
    assert estimate_string_type(line) == string_type
