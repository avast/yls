from __future__ import annotations

import pygls.lsp.types as lsp_types

from yls import utils
from yls.snippet_string import SnippetString


def generate_snippets_from_configuration(
    config: dict | None = None,
) -> list[lsp_types.CompletionItem]:
    """Generate dynamic snippets from the user configuration.

    User can specify the configuration in the editor and this function will generate a custom snippet for it.
    """

    # Default is empty config
    config = config or {}

    res = []
    if config.get("meta", False):
        item = lsp_types.CompletionItem(
            label="meta",
            detail="Generate a meta section (YARA)",
            kind=lsp_types.CompletionItemKind.Snippet,
            insert_text=str(_generate_meta_snippet(SnippetString(), config)),
            insert_text_format=lsp_types.InsertTextFormat.Snippet,
            documentation=utils.markdown_content('meta:\n\tKEY = "VALUE"'),
            sort_text="a",
        )
        res.append(item)

    if config.get("condition", False):
        item = lsp_types.CompletionItem(
            label="condition",
            detail="Generate a condition section (YARA)",
            kind=lsp_types.CompletionItemKind.Snippet,
            insert_text=str(_generate_condition_snippet(SnippetString())),
            insert_text_format=lsp_types.InsertTextFormat.Snippet,
            documentation=utils.markdown_content("condition:\n\tCONDITIONS"),
            sort_text="a",
        )
        res.append(item)

    if config.get("strings", False):
        item = lsp_types.CompletionItem(
            label="strings",
            detail="Generate a strings skeleton (YARA)",
            kind=lsp_types.CompletionItemKind.Snippet,
            insert_text=str(_generate_string_snippet(SnippetString())),
            insert_text_format=lsp_types.InsertTextFormat.Snippet,
            documentation=utils.markdown_content('strings:\n\t$NAME = "STRING"'),
            sort_text="a",
        )
        res.append(item)

    if config.get("rule", False):
        item = lsp_types.CompletionItem(
            label="rule",
            detail="Generate a rule skeleton (YARA)",
            kind=lsp_types.CompletionItemKind.Snippet,
            insert_text=str(_generate_rule_snippet(SnippetString(), config)),
            insert_text_format=lsp_types.InsertTextFormat.Snippet,
            documentation=utils.markdown_content("rule NAME {"),
            sort_text="a",
        )
        res.append(item)

    return res


def _generate_rule_snippet(snippet: SnippetString, config: dict) -> SnippetString:
    snippet.append_text("rule ")
    snippet.append_placeholder("my_rule")
    snippet.append_text(" {\n")
    snippet = _generate_meta_snippet(snippet, config)
    snippet = _generate_string_snippet(snippet)
    snippet.append_text("\n")
    snippet = _generate_condition_snippet(snippet)
    snippet.append_text("\n}\n")
    return snippet


def _generate_condition_snippet(snippet: SnippetString) -> SnippetString:
    snippet.append_text("\tcondition:\n\t\t")
    snippet.append_placeholder("any of them")
    return snippet


def _generate_string_snippet(snippet: SnippetString) -> SnippetString:
    snippet.append_text("\tstrings:\n\t\t")
    snippet.append_placeholder(r"\$name")
    snippet.append_text(" = ")
    snippet.append_choice(('"string"', "/regex/", "{ HEX }"))
    return snippet


def _generate_meta_snippet(snippet: SnippetString, config: dict) -> SnippetString:
    meta_config_dict = config.get("metaEntries", {})
    should_sort_meta = config.get("sortMeta", False)
    meta_config: list[tuple[str, str]] = list(meta_config_dict.items())
    if should_sort_meta:
        meta_config = sorted(meta_config)

    snippet.append_text("\tmeta:\n")

    if len(meta_config) == 0:
        snippet.append_text("\t\t")
        snippet.append_placeholder("KEY")
        snippet.append_text(" = ")
        snippet.append_placeholder('"VALUE"')
        snippet.append_text("\n")
    else:
        for key, value in meta_config:
            if value == "":
                snippet.append_text(f'\t\t{key} = "')
                snippet.append_tabstop()
                snippet.append_text('"\n')
            else:
                snippet.append_text(f'\t\t{key} = "{value}"\n')

    return snippet
