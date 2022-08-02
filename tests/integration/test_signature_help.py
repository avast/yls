# type: ignore

from pygls.lsp import methods
from pygls.lsp import types


def test_signature_help_basic(yls_prepare):
    contents = """rule test {
    condition:
        cuckoo.network.http_get(<$>)
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.SIGNATURE_HELP,
        types.SignatureHelpParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    assert len(response["signatures"]) == 1
    http_get_signature = response["signatures"][0]
    assert "cuckoo.network.http_get" in http_get_signature["label"]
    assert "-> int" in http_get_signature["label"]


def test_signature_help_two_functions_on_single_line(yls_prepare):
    contents = r"""rule test {
    condition:
        cuckoo.network.http_get(/evil\.com/) and cuckoo.sync.mutex(<$>)
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.SIGNATURE_HELP,
        types.SignatureHelpParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response
    assert len(response["signatures"]) == 1
    sync_mutex = response["signatures"][0]
    assert "cuckoo.sync.mutex" in sync_mutex["label"]
    assert "-> int" in sync_mutex["label"]


def test_signature_help_nested_parens(yls_prepare):
    contents = r"""rule test {
    condition:
        cuckoo.network.http_get(/evil(<$>).com and some other/)
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.SIGNATURE_HELP,
        types.SignatureHelpParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    assert len(response["signatures"]) == 1
    http_get_signature = response["signatures"][0]
    assert "cuckoo.network.http_get" in http_get_signature["label"]


def test_signature_help_nested_parens_single_left(yls_prepare):
    contents = r"""rule test {
    condition:
        cuckoo.network.http_get(/evil(<$>.com and some other/)
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.SIGNATURE_HELP,
        types.SignatureHelpParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    assert len(response["signatures"]) == 1
    http_get_signature = response["signatures"][0]
    assert "cuckoo.network.http_get" in http_get_signature["label"]


def test_signature_help_nested_parens_single_right(yls_prepare):
    contents = r"""rule test {
    condition:
        cuckoo.network.http_get(/evil<$>).com and some other/)
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.SIGNATURE_HELP,
        types.SignatureHelpParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    assert len(response["signatures"]) == 1
    http_get_signature = response["signatures"][0]
    assert "cuckoo.network.http_get" in http_get_signature["label"]


def test_signature_help_overloads(yls_prepare):
    contents = r"""rule test {
    condition:
        pe.exports(<$>)
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.SIGNATURE_HELP,
        types.SignatureHelpParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )
    assert response

    assert len(response["signatures"]) == 3
    for overload in response["signatures"]:
        assert "pe.exports" in overload["label"]


def test_signature_help_invalid_place(yls_prepare):
    contents = """rule test {
    condition<$>:
        cuckoo.network.http_request()
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        methods.SIGNATURE_HELP,
        types.SignatureHelpParams(
            text_document=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )

    # One or more signatures. If no signatures are available the signature help
    # request should return `null`.
    assert response is None
