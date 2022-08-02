# type: ignore

from pygls.lsp import methods
from pygls.lsp import types


def test_hover_basic(yls_prepare):
    contents = """import "cuckoo"
rule test {
    condition:
        cuckoo.filesystem.file_ac<$>cess(/test/)
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.HOVER,
        types.TextDocumentPositionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    response_text = response["contents"]["value"].lower()
    assert "file_access(regex) -> int" in response_text
    assert "evaluation result" not in response_text
    assert (
        "function returning true if the program accessed a file matching the provided regular expression"
        in response_text
    )


def test_hover_string_plain(yls_prepare):
    contents = """rule test {
    strings:
        $s = "string"
    condition:
        $<$>s
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.HOVER,
        types.TextDocumentPositionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert "$s" in response["contents"]["value"]
    assert "string" in response["contents"]["value"]


def test_hover_string_hex(yls_prepare):
    contents = """rule test {
    strings:
        $h = { 12 34 56 78 }
    condition:
        $<$>h
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.HOVER,
        types.TextDocumentPositionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert "$h" in response["contents"]["value"]
    assert "12 34 56 78" in response["contents"]["value"]


def test_hover_string_regex(yls_prepare):
    contents = """rule test {
    strings:
        $r = /my.*custom.*regex/
    condition:
        $<$>r
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.HOVER,
        types.TextDocumentPositionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert "$r" in response["contents"]["value"]
    assert "/my.*custom.*regex/" in response["contents"]["value"]


def test_hover_private_rule_same_file(yls_prepare):
    contents = """private rule PRIV_TEST {
    condition:
        false
}

rule test {
    condition:
        PRIV_T<$>EST
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.HOVER,
        types.TextDocumentPositionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert "Rule name" in response["contents"]["value"]
    assert "PRIV_TEST" in response["contents"]["value"]
    assert "Condition" in response["contents"]["value"]


def test_hover_constant_symbol_value(yls_prepare):
    contents = """import "pe"
rule test {
    condition:
        pe.MACH<$>INE_ARM
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.HOVER,
        types.TextDocumentPositionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert "MACHINE_ARM" in response["contents"]["value"]
    assert "int" in response["contents"]["value"]
