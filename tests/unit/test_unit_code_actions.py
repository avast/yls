# type: ignore

import pytest

from yls.code_actions import estimate_first_new_string_index
from yls.code_actions import lines_for_string_extraction


@pytest.mark.parametrize(
    "source, cursor_line, strings",
    [
        (
            """rule test {
    strings:
"test"
    condition:
        true
}

rule test1 {
    strings:
"ignore"
    condition:
        false
}""",
            2,
            ['"test"'],
        ),
        (
            """rule test {
    strings:
test
    condition:
        true
}

rule test1 {
    strings:
ignore
    condition:
        false
}""",
            2,
            ["test"],
        ),
        (
            """rule test {
    strings:
"test00"
"test01"
    condition:
        true
}

rule test1 {
    strings:
"ignore"
    condition:
        false
}""",
            3,
            ['"test00"', '"test01"'],
        ),
        (
            """rule test {
    strings:
"test01"
test02
"test03"
test04
    condition:
        true
}""",
            3,
            ['"test01"', "test02", '"test03"', "test04"],
        ),
        (
            """rule test {
    strings:
"test01"
test02
"test03"
test04
    condition:
        true
}""",
            4,
            ['"test01"', "test02", '"test03"', "test04"],
        ),
    ],
)
def test_lines_for_string_extraction(source, cursor_line, strings, mocker):
    doc = mocker.MagicMock()
    doc.lines = list(source.splitlines())
    assert lines_for_string_extraction(doc, cursor_line).strings == strings


@pytest.mark.parametrize(
    "source, cursor_line, last_string_index",
    [
        (
            """rule test {
    strings:
"test"
    condition:
        true
}""",
            2,
            0,
        ),
        (
            """rule test {
    strings:
test
    condition:
        true
}""",
            2,
            0,
        ),
        (
            """rule decoy {
    strings:
        $s00 = "aaa"
    condition:
        false
}

rule test {
    strings:
"test"
    condition:
        true
}""",
            9,
            0,
        ),
        (
            """rule decoy {
    strings:
        $s00 = "aaa"
    condition:
        false
}

rule test {
    strings:
test
    condition:
        true
}""",
            9,
            0,
        ),
        (
            """rule decoy {
    strings:
        $s00 = "aaa"
    condition:
        false
}

rule test {
    strings:
        $s00 = "test00"
        $s01 = "test01"
        $s02 = "test02"
        $s03 = "test03"
        $s04 = "test04"
        $s05 = "test05"
"test"
    condition:
        true
}""",
            15,
            6,
        ),
        (
            """rule decoy {
    strings:
        $s00 = "aaa"
    condition:
        false
}

rule test {
    strings:
        $s00 = "test00"
        $s01 = "test01"
        $s02 = "test02"
        $s03 = "test03"
        $s04 = "test04"
        $s05 = "test05"
test
    condition:
        true
}""",
            15,
            6,
        ),
    ],
)
def test_estimate_last_string_index(source, cursor_line, last_string_index, mocker):
    doc = mocker.MagicMock()
    doc.lines = list(source.splitlines())
    assert estimate_first_new_string_index(doc, cursor_line) == last_string_index
