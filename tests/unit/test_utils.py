# type: ignore

import pytest
import pytest_yls.utils as _utils
import yaramod
from pytest_mock import MockerFixture

from yls import utils


@pytest.mark.parametrize(
    "string, prefix, expected",
    [
        ("test", "test", ""),
        ("test", "tes", "t"),
        ("test", "te", "st"),
        ("test", "t", "est"),
        ("test", "", "test"),
        ("hint in /home/user", "hint in ", "/home/user"),
        ("/home/user", "hint in ", "/home/user"),
        ("test", "est", "test"),
        ("test", "es", "test"),
        ("test", "e", "test"),
        (b"test", b"test", b""),
        (b"test", b"tes", b"t"),
        (b"test", b"te", b"st"),
        (b"test", b"t", b"est"),
        (b"test", b"", b"test"),
        (b"hint in /home/user", b"hint in ", b"/home/user"),
        (b"/home/user", b"hint in ", b"/home/user"),
        (b"test", b"est", b"test"),
        (b"test", b"es", b"test"),
        (b"test", b"e", b"test"),
    ],
)
def test_remove_prefix(string, prefix, expected):
    assert utils.remove_prefix(string, prefix) == expected


@pytest.mark.parametrize(
    "string, suffix, expected",
    [
        ("test", "test", ""),
        ("test", "est", "t"),
        ("test", "st", "te"),
        ("test", "t", "tes"),
        ("test", "", "test"),
        ("test", "tes", "test"),
        ("test", "te", "test"),
        (b"test", b"test", b""),
        (b"test", b"est", b"t"),
        (b"test", b"st", b"te"),
        (b"test", b"t", b"tes"),
        (b"test", b"", b"test"),
        (b"test", b"tes", b"test"),
        (b"test", b"te", b"test"),
    ],
)
def test_remove_suffix(string, suffix, expected):
    assert utils.remove_suffix(string, suffix) == expected


def test_first_non_space():
    assert utils.first_non_space_pos("test") == 0
    assert utils.first_non_space_pos("    test") == 4
    assert utils.first_non_space_pos("    ") == 0


def test_is_sha():
    assert utils.is_hash("f3b7edffa346c23f24beba4d93880f358532085b3598319fed0cfa3010bbe675")
    assert utils.is_hash("93880f358532085b3598319fed0cfa3010bbe675")
    assert utils.is_hash("8532085b3598319fed0cfa3010bbe675")
    assert utils.is_hash("8532085B3598319FED0CFA3010BBE675")
    assert not utils.is_hash("")
    assert not utils.is_hash(" " + "A" * 64)
    assert not utils.is_hash("A" * 64 + " ")


def test_range_from_line(mocker: MockerFixture):
    file = """import "cuckoo"
rule asd {
	condition:
		false
}
"""
    document = mocker.MagicMock()
    document.lines = file.splitlines()
    assert utils.range_from_line(0, document) == utils.range_from_coords((0, 0), (0, 15))
    assert utils.range_from_line(0, document, strip_whitespace=False) == utils.range_from_coords(
        (0, 0), (0, 15)
    )

    assert utils.range_from_line(1, document) == utils.range_from_coords((1, 0), (1, 10))

    assert utils.range_from_line(2, document) == utils.range_from_coords((2, 1), (2, 11))
    assert utils.range_from_line(2, document, strip_whitespace=False) == utils.range_from_coords(
        (2, 0), (2, 11)
    )


def test_yarafile_path(yls_prepare_with_settings, ymod):
    files = {
        "main.yar": """include "./other.yar"
rule main {
    condition:
        true
}""",
        "other.yar": """rule other {
    meta:
        other = true
    condition:
        false
}""",
    }
    context = yls_prepare_with_settings(files=files)

    path_main = str(context.get_file_path("main.yar"))
    yfile_main = utils.yaramod_parse_file(path_main)
    assert path_main == utils.yarafile_path(yfile_main)

    path_other = str(context.get_file_path("other.yar"))
    yfile_other = utils.yaramod_parse_file(path_other)
    assert path_other == utils.yarafile_path(yfile_other)

    yfile_string = ymod.parse_string("rule string_rule { condition: true }")
    assert utils.yarafile_path(yfile_string) is None


def test_yaramod_rules_in_file(yls_prepare_with_settings, ymod):
    files = {
        "main.yar": """include "./other.yar"
rule main {
    condition:
        true
}

rule main1 {
    condition:
        true and true
}""",
        "other.yar": """rule other {
    meta:
        other = true
    condition:
        false
}""",
    }
    context = yls_prepare_with_settings(files=files)

    path_main = str(context.get_file_path("main.yar"))
    yfile_main = utils.yaramod_parse_file(path_main)
    assert len(list(utils.yaramod_rules_in_file(yfile_main))) == 2

    path_other = str(context.get_file_path("other.yar"))
    yfile_other = utils.yaramod_parse_file(path_other)
    assert len(list(utils.yaramod_rules_in_file(yfile_other))) == 1

    yfile_string = ymod.parse_string("rule string_rule { condition: true }")
    assert len(list(utils.yaramod_rules_in_file(yfile_string))) == 1


def test_yarafile_get_rule(yls_prepare_with_settings, ymod):
    files = {
        "main.yar": """include "./other.yar"
rule main {
    condition:
        true
}

rule main1 {
    condition:
        true and true
}""",
        "other.yar": """rule other {
    meta:
        other = true
    condition:
        false
}""",
    }
    context = yls_prepare_with_settings(files=files)

    path_main = str(context.get_file_path("main.yar"))
    yfile_main = utils.yaramod_parse_file(path_main)
    assert utils.yarafile_get_rule(yfile_main, "main") is not None
    assert utils.yarafile_get_rule(yfile_main, "main", ignore_includes=False) is not None
    assert utils.yarafile_get_rule(yfile_main, "main1") is not None
    assert utils.yarafile_get_rule(yfile_main, "not_existing") is None
    assert utils.yarafile_get_rule(yfile_main, "other") is None
    assert utils.yarafile_get_rule(yfile_main, "other", ignore_includes=False) is not None

    path_other = str(context.get_file_path("other.yar"))
    yfile_other = utils.yaramod_parse_file(path_other)
    assert utils.yarafile_get_rule(yfile_other, "main") is None
    assert utils.yarafile_get_rule(yfile_other, "main1") is None
    assert utils.yarafile_get_rule(yfile_other, "not_existing") is None
    assert utils.yarafile_get_rule(yfile_other, "other") is not None
    assert utils.yarafile_get_rule(yfile_other, "other", ignore_includes=False) is not None

    yfile_string = ymod.parse_string("rule string_rule { condition: true }")
    assert utils.yarafile_get_rule(yfile_string, "string_rule") is not None
    assert utils.yarafile_get_rule(yfile_string, "main") is None


@pytest.mark.parametrize(
    "expr_str, expected",
    [
        ("cuckoo.sync.mutex(/test/)", "cuckoo.sync.mutex"),
        ("pe.entry_point", "pe.entry_point"),
        ("pe.imphash()", "pe.imphash"),
        ('pe.version_info["test"]', "pe.version_info[]"),
        ("pe.export_details[28].name", "pe.export_details[].name"),
        ("filesize", "filesize"),
    ],
)
def test_yaramod_expression_to_symbol(expr_str, expected):
    expr = _utils.expr_from_str(expr_str)
    assert utils.yaramod_expression_to_symbol(expr) == expected


@pytest.mark.parametrize(
    "rule_source, expr, _range",
    [
        (
            'import "cuckoo" rule asd { condition: cu<$>ckoo.sync.mutex(/test/) }',
            yaramod.FunctionCallExpression,
            utils.range_from_coords((0, 38), (0, 63)),
        ),
        (
            """import "cuckoo"
rule asd {
    condition:
        cu<$>ckoo.sync.mutex(/test/) or
        false
}""",
            yaramod.FunctionCallExpression,
            utils.range_from_coords((3, 8), (3, 33)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        pe.imphash() =<$>= "123" and
        cuckoo.sync.mutex(/test/)
}""",
            yaramod.EqExpression,
            utils.range_from_coords((4, 8), (4, 29)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        pe.entry<$>_point == 123 and
        cuckoo.sync.mutex(/test/)
}""",
            yaramod.StructAccessExpression,
            utils.range_from_coords((4, 8), (4, 22)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        pe.entry_point <$>!= 123 and
        cuckoo.sync.mutex(/test/)
}""",
            yaramod.NeqExpression,
            utils.range_from_coords((4, 8), (4, 29)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        pe.entry_point <$>>= 123 and
        cuckoo.sync.mutex(/test/)
}""",
            yaramod.GeExpression,
            utils.range_from_coords((4, 8), (4, 29)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        pe.entry_point <$>> 123 and
        cuckoo.sync.mutex(/test/)
}""",
            yaramod.GtExpression,
            utils.range_from_coords((4, 8), (4, 28)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        pe.entry_point <$><= 123 and
        cuckoo.sync.mutex(/test/)
}""",
            yaramod.LeExpression,
            utils.range_from_coords((4, 8), (4, 29)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        pe.entry_point<$> < 123 and
        cuckoo.sync.mutex(/test/)
}""",
            yaramod.StructAccessExpression,
            utils.range_from_coords((4, 8), (4, 22)),
        ),
        (
            """import "cuckoo"
import "pe"
rule asd {
    condition:
        fa<$>lse
}""",
            None,
            utils.range_from_coords((4, 8), (4, 22)),
        ),
    ],
)
def test_cursor_expression(rule_source, expr, _range, ymod):
    rule_source, cursor_pos = _utils.find_cursor(rule_source)
    yfile = ymod.parse_string(rule_source)
    cursor_expr = utils.cursor_expression(yfile, cursor_pos)

    if expr is not None:
        assert isinstance(cursor_expr, expr)
        assert utils.range_from_yaramod_expression(cursor_expr) == _range
    else:
        assert cursor_expr is None


@pytest.mark.parametrize(
    "input_list, expected",
    [
        ([], []),
        ([["a"]], ["a"]),
        ([[1, 2, 3]], [1, 2, 3]),
        ([[1, 2, 3], [4, 5, 6]], [1, 2, 3, 4, 5, 6]),
    ],
)
def test_flatten_list(input_list, expected):
    assert utils.flatten_list(input_list) == expected


@pytest.mark.parametrize(
    "source, cursor_line, result",
    [
        (
            """test
rule test {
    strings:
        $s00 = "abc"
    condition:
        true
}""",
            0,
            False,
        ),
        (
            """rule test {
    strings:
        $s00 = "abc"
    condition:
        true
}
test""",
            6,
            False,
        ),
        (
            """rule test {
test
    strings:
        $s00 = "abc"
    condition:
        true
}""",
            1,
            False,
        ),
        (
            """rule test {
    strings:
        $s00 = "abc"
test
    condition:
        true
}""",
            3,
            True,
        ),
        (
            """rule test {
    strings:
        $s00 = "abc"
    condition:
        test
}""",
            4,
            False,
        ),
        (
            """rule test {
    strings:
        $s00 = "abc"
    test:
        true
}""",
            3,
            False,
        ),
        (
            """rule test {
    meta:
        key = "value"
test
    strings:
        $s00 = "abc"
    condition:
        true
}""",
            3,
            False,
        ),
        (
            """rule test1 {
    strings:
        $s00 = "abc"
    condition:
        true
}
test
rule test2 {
    strings:
        $s00 = "abc"
    condition:
        true
}""",
            7,
            False,
        ),
    ],
)
def test_is_in_yara_section(source, cursor_line, result, mocker):
    doc = mocker.MagicMock()
    doc.lines = list(source.splitlines())
    assert utils.is_in_yara_section(doc, cursor_line, "strings") == result


@pytest.mark.parametrize(
    "metas, expected",
    [
        ("\n", False),
        ('''hash = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"''', True),
        (
            """author = "Test"
hash = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
""",
            True,
        ),
        (
            """author = "Test"
hash = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
hash = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be01"
""",
            True,
        ),
        (
            """author = "Test"
hash = "not valid hash"
""",
            False,
        ),
    ],
)
def test_yaramod_rule_has_hashes(ymod, metas, expected):
    rule = f"""rule test {{
meta:
    {metas}
condition:
    false
}}"""
    yrule = ymod.parse_string(rule).rules[0]

    assert utils.yaramod_rule_has_hashes(yrule) == expected
