# type: ignore

import typing

import lsprotocol.types as lsp_types
import pytest

pytestmark = pytest.mark.slow


def torture_document(context: typing.Any) -> None:
    """Torture operations on the whole file."""

    # DOCUMENT_SYMBOL
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_DOCUMENT_SYMBOL,
        lsp_types.DocumentSymbolParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri())
        ),
    )

    # FORMATTING
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_FORMATTING,
        lsp_types.DocumentFormattingParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            options=lsp_types.FormattingOptions(tab_size=4, insert_spaces=False),
        ),
    )

    # WORKSPACE_DID_CHANGE_CONFIGURATION
    # This should work after https://github.com/openlawlibrary/pygls/pull/201 is resolved
    # _ = context.send_request(
    #     lsp_types.WORKSPACE_DID_CHANGE_CONFIGURATION,
    #     lsp_types.DidChangeConfigurationParams(settings=[]),
    # )


def torture_position(context: typing.Any, position: lsp_types.Position) -> None:
    """Torture operations on a single position within a file."""
    _range = lsp_types.Range(
        start=position, end=lsp_types.Position(line=position.line, character=position.character + 1)
    )

    # Test the we won't throw an exception

    # CODE_ACTION
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_CODE_ACTION,
        lsp_types.CodeActionParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            range=_range,
            context=lsp_types.CodeActionContext(diagnostics=[]),
        ),
    )

    # COMPLETION
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_COMPLETION,
        lsp_types.CompletionParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=position,
        ),
    )

    # DEFINITION
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_DEFINITION,
        lsp_types.DefinitionParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=position,
        ),
    )

    # DOCUMENT_HIGHLIGHT
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_DOCUMENT_HIGHLIGHT,
        lsp_types.DocumentHighlightParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=position,
        ),
    )

    # HOVER
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_HOVER,
        lsp_types.HoverParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=position,
        ),
    )

    # REFERENCES
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_REFERENCES,
        lsp_types.ReferenceParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=position,
            context=lsp_types.ReferenceContext(include_declaration=True),
        ),
    )

    # SIGNATURE_HELP
    _ = context.send_request(
        lsp_types.TEXT_DOCUMENT_SIGNATURE_HELP,
        lsp_types.SignatureHelpParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=position,
        ),
    )


def torture_file(context: typing.Any, file_contents: str) -> None:
    """Iterate over file contents and torture every position."""
    for y, line in enumerate(file_contents.splitlines()):
        for x in range(len(line)):
            position = lsp_types.Position(line=y, character=x)
            torture_position(context, position)


@pytest.mark.parametrize("remove_file", [False, True])
def test_torture(yls_prepare_with_settings, remove_file):
    contents = {
        "main.yar": r"""include "./includes.yar"
import "cuckoo"
import "pe"

rule SECOND {
    condition:
        false
}

rule test {
    meta:
        author = "Me, Avast"
        description = "description"
        type = "bot"
    strings:
        $s = "test"
        $h00 = { 00 00 00 00 00 00 80 82 }
        $h01 = { 11 11 ?? 11 1? 11 }
        $h02 = { 22 22 [2-3] 22 22 }
        $h03 = { 33 33 ( 33 33 | 33 ) 33 }
    condition:
        for any of ($s*) : ( $ in (@h00 .. (@h00 + uint32(@h00 - 4))) and true) or
        cuckoo.network.http_request(/web\.com/) or
        pe.version_info["CompanyName"] == "MyCompany" or
        pe.export_details[0].name == "DllGetClassObjectMain" or
        OTHER and
        SECOND
}""",
        "includes.yar": r"""import "cuckoo"
rule OTHER {
    condition:
        cuckoo.filesystem.file_access(/test/)
}""",
    }

    context = yls_prepare_with_settings(contents)

    if remove_file:
        context.get_file_path("main.yar").unlink()

    torture_document(context)
    torture_file(context, contents["main.yar"])


@pytest.mark.parametrize("remove_file", [False, True])
def test_torture_empty_file(yls_prepare_with_settings, remove_file):
    main_file = ""
    contents = {"main.yar": main_file}

    context = yls_prepare_with_settings(contents)

    if remove_file:
        context.get_file_path("main.yar").unlink()

    torture_document(context)

    position = lsp_types.Position(0, 0)
    torture_position(context, position)
