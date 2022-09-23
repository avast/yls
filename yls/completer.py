from __future__ import annotations

import logging
import re
from typing import Any

import pygls.lsp.types as lsp_types
from pygls.workspace import Document

from yls import completion
from yls import utils
from yls.completion import CONDITION_KEYWORDS
from yls.plugin_manager_provider import PluginManagerProvider
from yls.strings import estimate_string_type
from yls.strings import string_modifiers_completion_items

log = logging.getLogger(__name__)


class Completer:

    REGEXP_META = re.compile(r'^\s*(\w+)\s+=\s+"(.*)$')
    REGEXP_IMPORT = re.compile(r'^import\s+"(.*)$')

    def __init__(self, ls: Any):
        self.ls = ls
        self.completion_cache = completion.CompletionCache.from_yaramod(self.ls.ymod)

    def complete(self, params: lsp_types.CompletionParams) -> lsp_types.CompletionList:
        return lsp_types.CompletionList(is_incomplete=False, items=self._complete(params))

    def signature_help(self, params: lsp_types.CompletionParams) -> lsp_types.SignatureHelp | None:
        signatures = self._signature_help(params)
        if signatures is None:
            return None

        return lsp_types.SignatureHelp(
            signatures=signatures, active_parameter=0, active_signature=0
        )

    def _signature_help(
        self, params: lsp_types.CompletionParams
    ) -> list[lsp_types.SignatureInformation] | None:
        text_doc = self.ls.workspace.get_document(params.text_document.uri)
        word = utils.cursor_word(text_doc, params.position)
        log.debug(f'[SIGNATURE_HELP] Cursor word is "{word}"')
        if word is None:
            log.debug("[SIGNATURE_HELP] Aborting signature help request")
            return None

        # Try to extract the function call from the word
        word = re.sub(r"\(.*", "", word)
        word = word.replace("(", "").replace(")", "")
        log.debug(f'[SIGNATURE_HELP] Normalized cursor word is "{word}"')

        if not word:
            log.debug(
                "[SIGNATURE_HELP] Aborting signature help request - invalid word after normalization"
            )
            return None

        symbol = self.completion_cache.get_function(word)
        if not symbol:
            log.debug("[SIGNATURE_HELP] Aborting signature help request - no symbol found")
            return None

        info: list[lsp_types.SignatureInformation] = []

        # NOTE: Handler other overloads
        info.extend(symbol.to_signature_information(word))

        return info

    def _complete(self, params: lsp_types.CompletionParams) -> list[lsp_types.CompletionItem]:
        document = self.ls.workspace.get_document(params.text_document.uri)

        res = []

        # If the cursor is not on a word, we still want to provide completions
        # for root module
        word = utils.cursor_word(document, params.position) or ""

        # Import completion
        log.debug("[COMPLETION] Adding import completion")
        res += self.complete_import(document, params.position)

        # String modifiers completion
        log.debug("[COMPLETION] Adding string modifiers completion")
        res += self.complete_string_modifiers(document, params.position, word)

        # Condition keywords completion
        log.debug("[COMPLETION] Adding condition keywords completion")
        res += self.complete_condition_keywords(document, params.position, word)

        # Function completion
        log.debug("[COMPLETION] Adding module completion")
        res += self.complete_word(document, params.position, word)

        # Symbols from last yara file completion
        log.debug("[COMPLETION] Adding last valid yara file")
        res += self.complete_last_valid_yara_file(document, params, word)

        # Plugin completion
        log.debug("COMPLETION] Adding completion items from plugings")
        res += utils.flatten_list(
            PluginManagerProvider.instance().hook.yls_completion(params=params, document=document)
        )

        return res

    def complete_last_valid_yara_file(
        self, document: Document, params: lsp_types.CompletionParams, word: str
    ) -> list[lsp_types.CompletionItem]:
        """Return list of completion items from last valid YaraFile."""
        if self.ls.last_valid_yara_file is None:
            return []

        if not utils.is_in_yara_section(document, params.position.line, "condition"):
            return []

        res = []

        # Add rules
        log.debug("[COMPLETION] Adding symbols from last valid YARA file")
        res += [
            lsp_types.CompletionItem(label=rule.name, insert_text=rule.name, sort_text="zb")
            for rule in self.ls.last_valid_yara_file.rules
            if rule.name.startswith(word)
        ]

        rule = self.ls.get_current_rule(
            params.text_document.uri, params.position, self.ls.last_valid_yara_file
        )
        if rule is None:
            return res

        # Add current rule strings
        res += [
            lsp_types.CompletionItem(
                label=string.identifier, insert_text=string.identifier, sort_text="za"
            )
            for string in rule.strings
            if string.identifier.startswith(word)
        ]

        return res

    def complete_word(
        self, document: Document, position: lsp_types.Position, word: str
    ) -> list[lsp_types.CompletionItem]:
        """Complete a function."""
        log.debug(f'[COMPLETION] Cursor word is "{word}"')

        if not utils.is_in_yara_section(document, position.line, "condition"):
            return []

        res = []

        symbols = self.completion_cache.get_symbols_matching(word)

        for symbol in symbols:
            res.extend(symbol.to_completion_items())
            # symbol_doc = symbol_doc.strip().replace("\t", "")
            # symbol_doc = re.sub(r" {2,}", "", symbol_doc)

        return res

    def complete_import(
        self, document: Document, position: lsp_types.Position
    ) -> list[lsp_types.CompletionItem]:
        """Complete an import statement."""
        res = []

        line = utils.cursor_line(document, position)
        match_res = self.REGEXP_IMPORT.search(line)

        if match_res:
            log.debug("[COMPLETION] Completing import values")
            for module in self.completion_cache.modules.attributes.keys():
                res.append(
                    lsp_types.CompletionItem(
                        label=module,
                        insert_text=module,
                        sort_text="aaa",
                        kind=lsp_types.CompletionItemKind.Module,
                    )
                )

        return res

    def complete_string_modifiers(
        self, document: Document, position: lsp_types.Position, word: str
    ) -> list[lsp_types.CompletionItem]:
        """Complete string modifiers."""

        # Check if the line is not empty
        line = utils.cursor_line(document, position)
        if not line.strip():
            return []

        # Complete only if end of the string is before the cursor
        characters_after_cursor = set(line[position.character :])
        if {'"', "/", "}"}.intersection(characters_after_cursor):
            return []

        # Complete only in `strings:` section
        if not utils.is_in_yara_section(document, position.line, "strings"):
            return []

        # Filter out the modifiers based on the string type
        estimated_string_type = estimate_string_type(line)
        final_list = iter(string_modifiers_completion_items(estimated_string_type))

        # Filter the modifiers based on the word under the cursor
        final_list = filter(lambda item: item.label.startswith(word), final_list)
        return list(final_list)

    def complete_condition_keywords(
        self, document: Document, position: lsp_types.Position, word: str
    ) -> list[lsp_types.CompletionItem]:

        # Complete only in `condition:` section
        if not utils.is_in_yara_section(document, position.line, "condition"):
            return []

        res = []
        for keyword in CONDITION_KEYWORDS:
            if not keyword.startswith(word):
                continue

            item = lsp_types.CompletionItem(
                label=keyword,
                kind=lsp_types.CompletionItemKind.Keyword,
                insert_text=keyword,
                insert_text_format=lsp_types.InsertTextFormat.PlainText,
                sort_text="a",
            )

            res.append(item)
        return res
