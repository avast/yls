from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import pygls.lsp.types as lsp_types
from pygls.workspace import Document

from yls import utils
from yls.plugin_manager_provider import PluginManagerProvider

log = logging.getLogger(__name__)


def from_params(
    ls: Any, params: lsp_types.CodeActionParams
) -> list[lsp_types.Command | lsp_types.CodeAction] | None:
    """Convert the request params to list of `CodeAction`s."""
    log.debug(f"[CODE_ACTION] {params=}")

    doc = ls.workspace.get_document(params.text_document.uri)
    res: list[lsp_types.Command | lsp_types.CodeAction] = []

    # Try to create string extraction code actions
    res.extend(string_extraction(doc, params))

    # Get the code actions from plugins
    plugin_code_actions = utils.flatten_list(
        PluginManagerProvider.instance().hook.yls_code_actions(ls=ls, params=params)
    )
    res.extend(plugin_code_actions)

    return res


def string_extraction(
    doc: Document, params: lsp_types.CodeActionParams
) -> list[lsp_types.CodeAction]:
    res = []
    cursor_line_index = params.range.start.line
    cursor_line = utils.document_line(doc, cursor_line_index)

    if is_line_for_string_extraction(cursor_line) and utils.is_in_yara_section(
        doc, cursor_line_index, "strings"
    ):
        string_extraction = lines_for_string_extraction(doc, cursor_line_index)

        if not string_extraction.strings:
            return []

        first_new_string_index = estimate_first_new_string_index(doc, cursor_line_index)

        # Construct the new code
        new_text = ""
        for idx, line in enumerate(string_extraction.strings):
            line = line.strip()
            if not line.startswith('"'):
                line = f'"{line}'
            if not line.endswith('"'):
                line = f'{line}"'
            new_text += f"\t\t$s{first_new_string_index + idx:02} = {line}\n"

        # Strip the last newline from the string, for some reason it is
        # inserted automatically
        new_text = new_text.rstrip()

        edit = lsp_types.TextEdit(
            range=utils.range_from_lines(
                string_extraction.first_string_line,
                string_extraction.last_string_line,
                doc,
                strip_whitespace=False,
            ),
            new_text=new_text,
        )
        res.append(
            lsp_types.CodeAction(
                title="Extract as strings",
                edit=lsp_types.WorkspaceEdit(changes={doc.uri: [edit]}),
                kind=lsp_types.CodeActionKind.RefactorRewrite,
            )
        )

    return res


def is_line_for_string_extraction(line: str) -> bool:
    """Check if the string can be extracted from line."""
    return bool(re.match(r'((\s*".*"\s*)|(^(?!\s+((//)|(\$\w+ =)|([a-z]+:)|($)))))', line))


@dataclass
class StringExtraction:
    strings: list[str]
    first_string_line: int

    @property
    def last_string_line(self) -> int:
        return self.first_string_line + len(self.strings) - 1


def lines_for_string_extraction(doc: Document, cursor_line: int) -> StringExtraction:
    """Return a list of lines around `cursor_line` that contains extractable strings."""
    res: list[str] = []
    first_string_line = 0

    # Walk back from cursor position (cursor_line included)
    for i in reversed(range(0, cursor_line + 1)):
        if is_line_for_string_extraction(doc.lines[i]):
            res.insert(0, doc.lines[i])
            first_string_line = i
        else:
            break

    # Walk forward from cursor position
    for i in range(cursor_line + 1, len(doc.lines)):
        if is_line_for_string_extraction(doc.lines[i]):
            res.append(doc.lines[i])
        else:
            break

    return StringExtraction(res, first_string_line)


def estimate_first_new_string_index(doc: Document, cursor_line: int) -> int:
    """Estimate the index of the upcoming string in current string section of
    YARA rule.

    If we are not able to find a proper value return 0 as a neutral element.
    """

    # Walk back from cursor position (cursor_line included)
    for i in reversed(range(0, cursor_line + 1)):

        # If we encounter end of string section, stop searching
        if re.match(r"\s*strings:\s*", doc.lines[i]):
            break

        # Check if the line looks like a string id
        match = re.match(r'\s*\$s(?P<idx>\d+) = ".*"\s*', doc.lines[i], re.ASCII)
        if match:
            last_string_index = int(match.group("idx"))
            return last_string_index + 1

    # If we did not find a suitable `id`, return neutral element
    return 0
