# type: ignore

from pygls.lsp import methods
from pygls.lsp import types
from pytest_yls.utils import assert_completable


def test_completion_basic(yls_prepare):
    contents = """rule test {
    condition:
        <$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            textDocument=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    for module in ["cuckoo", "elf", "pe", "time"]:
        assert any(
            module in item["label"] for item in response["items"]
        ), f"{module=} is not in response"


def test_completion_basic_with_word(yls_prepare):
    contents = """rule test {
    condition:
        cu<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert any("cuckoo" in item["label"] for item in response["items"]), "cuckoo is not in response"


def test_completion_basic_nested(yls_prepare):
    contents = """rule test {
    condition:
        cuckoo.<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    for struct in ["filesystem", "network", "sync"]:
        assert any(
            struct in item["label"] for item in response["items"]
        ), f"{struct=} is not in response"


def test_completion_in_condition(yls_prepare):
    contents = """rule test {
    strings:
        $s1 = "test"
    condition:
        any of them and cuckoo.<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    for struct in ["filesystem", "network", "sync"]:
        assert any(
            struct in item["label"] for item in response["items"]
        ), f"{struct=} is not in response"


def test_completion_no_suggestions(yls_prepare):
    contents = """rule test {
    strings:
        $s1 = "test"
    condition:
        any of<$> them
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert not response["items"]


def test_completion_import(yls_prepare):
    contents = """import "<$>
rule test {
    condition:
        false
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    for module in ["cuckoo", "pe", "elf", "math", "time"]:
        assert any(
            module == item["label"] for item in response["items"]
        ), f"{module=} is not in response"


def test_completion_constant(yls_prepare):
    contents = """import "pe"
rule test {
    condition:
        pe.MACHINE_AR<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    expect = (
        ("MACHINE_ARM", types.CompletionItemKind.Constant),
        ("MACHINE_ARM64", types.CompletionItemKind.Constant),
        ("MACHINE_ARMNT", types.CompletionItemKind.Constant),
    )
    assert_completable(expect, response)


def test_completion_array(yls_prepare):
    contents = """import "elf"
rule test {
    condition:
        elf.sectio<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    expect = (("sections", types.CompletionItemKind.Struct),)
    assert_completable(expect, response)

    items = response["items"]
    for completion in items:
        if completion["label"] in expect:
            # Assert that we are completing array indices
            assert completion["insertTextFormat"] == types.InsertTextFormat.Snippet
            assert "[" in completion["insertText"]
            assert "]" in completion["insertText"]


def test_completion_dictionary(yls_prepare):
    contents = """import "pe"
rule test {
    condition:
        pe.version_in<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    items = response["items"]
    expect = ("version_info",)
    assert any(completion["label"] in expect for completion in items)
    for completion in items:
        if completion["label"] in expect:
            assert completion["kind"] == types.CompletionItemKind.Variable

            # Assert that we are completing dictionary indexing
            assert completion["insertTextFormat"] == types.InsertTextFormat.Snippet
            assert "[" in completion["insertText"]
            assert '"' in completion["insertText"]
            assert "]" in completion["insertText"]


def test_completion_fully_typed_symbol(yls_prepare):
    contents = """import "pe"
rule test {
    condition:
        pe.MACHINE_ARM64<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    expect = (("MACHINE_ARM64", types.CompletionItemKind.Constant),)
    assert_completable(expect, response)


def test_completion_fully_typed_symbol_with_dot(yls_prepare):
    contents = """import "pe"
rule test {
    condition:
        pe.MACHINE_ARM64.<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert len(response["items"]) == 0


def test_completion_fully_typed_symbol_with_more_completions(yls_prepare):
    contents = """import "pe"
rule test {
    condition:
        pe.MACHINE_ARM<$>
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    expect = (
        ("MACHINE_ARM", types.CompletionItemKind.Constant),
        ("MACHINE_ARMNT", types.CompletionItemKind.Constant),
        ("MACHINE_ARM64", types.CompletionItemKind.Constant),
    )
    assert_completable(expect, response)
