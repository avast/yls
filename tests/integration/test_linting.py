# type: ignore

import lsprotocol.types as lsp_types
import pytest

pytestmark = pytest.mark.sleep


def test_linting_valid_rule(yls_prepare_with_settings):
    contents = {
        "file.yar": """rule test {
    strings:
        $s1 = "test"
    condition:
        $s1
}"""
    }
    context = yls_prepare_with_settings(files=contents)

    params = context.wait_for_notification(lsp_types.TEXT_DOCUMENT_PUBLISH_DIAGNOSTICS)
    assert hasattr(params, "diagnostics")
    assert not bool(params.diagnostics)


def test_linting_empty_file(yls_prepare_with_settings):
    contents = {"file.yar": ""}
    context = yls_prepare_with_settings(files=contents)

    params = context.wait_for_notification(lsp_types.TEXT_DOCUMENT_PUBLISH_DIAGNOSTICS)
    assert hasattr(params, "diagnostics")
    assert not bool(params.diagnostics)


def test_linting_invalid_syntax(yls_prepare_with_settings):
    contents = {
        "file.yar": """rule {
  cond:
    any of us
}"""
    }
    context = yls_prepare_with_settings(files=contents)

    params = context.wait_for_notification(lsp_types.TEXT_DOCUMENT_PUBLISH_DIAGNOSTICS)

    assert hasattr(params, "diagnostics")
    assert bool(params.diagnostics)
    assert all(
        hasattr(d, "severity") and d.severity == lsp_types.DiagnosticSeverity.Error
        for d in params.diagnostics
    )


def test_linting_no_warnings_and_hints(yls_prepare_with_settings):
    contents = {
        "file.yar": """rule test {
  strings:
    $re0 = /this_should_be_good/
  condition:
    any of them
}"""
    }
    context = yls_prepare_with_settings(files=contents)

    params = context.wait_for_notification(lsp_types.TEXT_DOCUMENT_PUBLISH_DIAGNOSTICS)
    assert hasattr(params, "diagnostics")
    assert not bool(params.diagnostics)
