from __future__ import annotations

from typing import Any

import pygls.lsp.types as lsp_types

from yls import utils
from yls.snippet_string import SnippetString


class SnippetGenerator:
    config: dict[str, Any]

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    def generate_snippets(self) -> list[lsp_types.CompletionItem]:
        res = []
        if self.config.get("meta", False):
            item = lsp_types.CompletionItem(
                label="meta",
                detail="Generate a meta section (YARA)",
                kind=lsp_types.CompletionItemKind.Snippet,
                insert_text='meta:\n\t$1 = "$2"',
                insert_text_format=lsp_types.InsertTextFormat.Snippet,
                documentation=utils.markdown_content('meta:\n\tKEY = "VALUE"'),
                sort_text="a",
            )
            res.append(item)

        if self.config.get("condition", False):
            item = lsp_types.CompletionItem(
                label="condition",
                detail="Generate a condition section (YARA)",
                kind=lsp_types.CompletionItemKind.Snippet,
                insert_text="condition:\n\t${1:conditions}",
                insert_text_format=lsp_types.InsertTextFormat.Snippet,
                documentation=utils.markdown_content("condition:\n\tCONDITIONS"),
                sort_text="a",
            )
            res.append(item)

        if self.config.get("strings", False):
            item = lsp_types.CompletionItem(
                label="strings",
                detail="Generate a strings skeleton (YARA)",
                kind=lsp_types.CompletionItemKind.Snippet,
                insert_text='strings:\n\t\\$${1:name} = "${2:string}"',
                insert_text_format=lsp_types.InsertTextFormat.Snippet,
                documentation=utils.markdown_content('strings:\n\t$NAME = "STRING"'),
                sort_text="a",
            )
            res.append(item)

        if self.config.get("rule", False):
            item = lsp_types.CompletionItem(
                label="rule",
                detail="Generate a rule skeleton (YARA)",
                kind=lsp_types.CompletionItemKind.Snippet,
                insert_text="rule ${1:$TM_FILENAME_BASE} {\n\t",
                insert_text_format=lsp_types.InsertTextFormat.Snippet,
                documentation=utils.markdown_content("rule NAME {"),
                sort_text="a",
            )
            res.append(item)

        return res

    def generate_rule_snippet(self, snippet: SnippetString) -> None:
        snippet.append_text("rule ")
        snippet.append_placeholder("my_rule")
        snippet.append_text(" {\n")
        self.generate_meta_snippet(snippet)
        self.generate_string_snippet(snippet)
        snippet.append_text("\n")
        self.generate_condition_snippet(snippet)
        snippet.append_text("\n}\n")

    @staticmethod
    def generate_condition_snippet(snippet: SnippetString) -> None:
        snippet.append_text("\tcondition:\n\t\t")
        snippet.append_placeholder("any of them")

    @staticmethod
    def generate_string_snippet(snippet: SnippetString) -> None:
        snippet.append_text("\tstrings:\n\t\t")
        snippet.append_placeholder(r"\$name")
        snippet.append_text(" = ")
        snippet.append_choice(('"string"', "/regex/", "{ HEX }"))

    def generate_meta_snippet(self, snippet: SnippetString) -> None:
        meta_config_dict = self.config.get("metaEntries", {})
        should_sort_meta = self.config.get("sortMeta", False)
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

    def generate(self) -> str:
        snippet = SnippetString()
        self.generate_rule_snippet(snippet)

        return str(snippet)
