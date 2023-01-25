# pylint: disable=trailing-whitespace
# type: ignore

import lsprotocol.types as lsp_types


def make_formatting_test(contents: str, expected: str = None):
    """Function to prepare formatting tests."""

    def _test(yls_prepare, ymod):
        """This function will invoke formatting request on the server and
        test if the response matches yaramod formatted output.
        """

        context = yls_prepare(contents)

        response = context.send_request(
            lsp_types.TEXT_DOCUMENT_FORMATTING,
            lsp_types.DocumentFormattingParams(
                text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
                options=lsp_types.FormattingOptions(tab_size=4, insert_spaces=True),
            ),
        )

        if expected is None:
            yfile = ymod.parse_string(contents)
            assert response[0].new_text == yfile.text_formatted
        else:
            assert response[0].new_text == expected

        assert response[0].range.end.line == len(contents.splitlines()) + 1

    return _test


def test_formatting_with_syntax_error(yls_prepare):
    contents = """rule test {
    cond: // <-- should be 'condition'
}"""
    context = yls_prepare(contents)

    response = context.send_request(
        lsp_types.TEXT_DOCUMENT_FORMATTING,
        lsp_types.DocumentFormattingParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            options=lsp_types.FormattingOptions(tab_size=4, insert_spaces=True),
        ),
    )
    assert not response, "server should not send any edits"

    params = context.wait_for_notification(lsp_types.WINDOW_SHOW_MESSAGE)
    assert hasattr(params, "message")
    assert params.message


test_formatting_bare_rule = make_formatting_test(
    """rule test {
    condition:
        false
}"""
)


test_formatting_multiple_bare_rules = make_formatting_test(
    """rule test {
    condition:
        false
}


rule my_test {
    meta:
        author = "Who?"
    condition:
        true
}"""
)

test_formatting_empty_file = make_formatting_test("")


test_formatting_trim_whitespace_from_one_line_comments = make_formatting_test(
    """rule asd
{
	// Comment with a trailing space 
	// Comment with a trailing tab	
	// Comment with a trailing combination 	 
	condition:
		false
}
""",
    """rule asd
{
	// Comment with a trailing space
	// Comment with a trailing tab
	// Comment with a trailing combination
	condition:
		false
}
""",
)


test_formatting_formated_file_is_shorter_than_original_yara_1619 = make_formatting_test(
    """rule asd
{
	meta:
		author = "Matej Kastak, Avast"
 
		description = "description"

		type = "bot"

	condition:

		false

}
""",
    """rule asd
{
	meta:
		author = "Matej Kastak, Avast"
		description = "description"
		type = "bot"
	condition:
		false
}
""",
)


def test_formatting_split_includes_and_imports(yls_prepare_with_settings):

    context = yls_prepare_with_settings(
        {
            "test.yar": """include "file.yar" import "cuckoo"
rule asd
{
	condition:
		false
}
""",
            "file.yar": """rule from_include
{
	condition:
		false
}
""",
        }
    )

    response = context.send_request(
        lsp_types.TEXT_DOCUMENT_FORMATTING,
        lsp_types.DocumentFormattingParams(
            text_document=lsp_types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            options=lsp_types.FormattingOptions(tab_size=4, insert_spaces=True),
        ),
    )

    expected = """include "file.yar"

import "cuckoo"

rule asd
{
	condition:
		false
}
"""
    assert response[0].new_text == expected
