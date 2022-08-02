# type: ignore

from pygls.lsp import methods
from pygls.lsp import types

from yls import utils


def test_code_actions_extract_strings(yls_prepare):
    contents = """rule prev_decoy {
    strings:
        $s00 = "zero"
        $s01 = "one"
        $s02 = "two"
        $s03 = "three"
    condition:
        false
}

rule test {
    strings:
"te<$>st00"
"test01"
test02
    "test03"
    test04"
    "test05
	condition:
		true
}

rule decoy {
    strings:
"ignore_this"
    condition:
        false
}"""

    context = yls_prepare(contents)

    response = context.send_request(
        methods.CODE_ACTION,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            range=context.get_cursor_range(),
            context=types.CodeActionContext(diagnostics=[]),
        ),
    )

    assert len(response) == 1
    fix = response[0]
    assert fix["kind"] == "refactor.rewrite"
    assert fix["title"] == "Extract as strings"

    fix_file = next(iter(fix["edit"]["changes"]))
    assert (
        fix["edit"]["changes"][fix_file][0]["newText"]
        == '\t\t$s00 = "test00"\n\t\t$s01 = "test01"\n\t\t$s02 = "test02"\n\t\t$s03 = "test03"\n\t\t$s04 = "test04"\n\t\t$s05 = "test05"'
    )
    assert (
        fix["edit"]["changes"][fix_file][0]["range"]
        == utils.range_from_coords((12, 0), (17, 12)).dict()
    )


def test_code_actions_extract_strings_with_strings_in_rule(yls_prepare):
    contents = """rule prev_decoy {
    strings:
        $s00 = "zero"
        $s01 = "one"
        $s02 = "two"
        $s03 = "three"
    condition:
        false
}

rule test {
    strings:
        $s00 = "zero"
        $s01 = "one"
"te<$>st00"
"test01"
test02
    "test03"
    test04"
    "test05
	condition:
		true
}

rule decoy {
    strings:
"ignore_this"
    condition:
        false
}"""

    context = yls_prepare(contents)

    response = context.send_request(
        methods.CODE_ACTION,
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            range=context.get_cursor_range(),
            context=types.CodeActionContext(diagnostics=[]),
        ),
    )

    assert len(response) == 1
    fix = response[0]
    assert fix["kind"] == "refactor.rewrite"
    assert fix["title"] == "Extract as strings"

    fix_file = next(iter(fix["edit"]["changes"]))
    assert (
        fix["edit"]["changes"][fix_file][0]["newText"]
        == '\t\t$s02 = "test00"\n\t\t$s03 = "test01"\n\t\t$s04 = "test02"\n\t\t$s05 = "test03"\n\t\t$s06 = "test04"\n\t\t$s07 = "test05"'
    )
    assert (
        fix["edit"]["changes"][fix_file][0]["range"]
        == utils.range_from_coords((14, 0), (19, 12)).dict()
    )
