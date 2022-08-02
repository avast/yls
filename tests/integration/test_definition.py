# type: ignore

from pygls.lsp import methods
from pygls.lsp import types


def test_definition_string_normal(yls_prepare):
    contents = """rule test {
    strings:
        $s = "test"
    condition:
        $<$>s
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.DEFINITION,
        types.DefinitionParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )

    assert response
    assert len(response) == 1
    definition = response[0]
    assert definition["uri"] == context.opened_file.as_uri()
    assert definition["range"]["start"]["line"] == 2
    assert definition["range"]["start"]["character"] == 9
    assert definition["range"]["end"]["line"] == 2
    assert definition["range"]["end"]["character"] == 9
