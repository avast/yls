# type: ignore

import lsprotocol.types as lsp_types


def test_definition_string_normal(yls_prepare):
    contents = """rule test {
    strings:
        $s = "test"
    condition:
        $<$>s
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        lsp_types.TEXT_DOCUMENT_DEFINITION,
        lsp_types.DefinitionParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )

    assert response
    assert len(response) == 1
    definition = response[0]
    assert definition.uri == context.opened_file.as_uri()
    assert definition.range == lsp_types.Range(lsp_types.Position(2, 9), lsp_types.Position(2, 9))
