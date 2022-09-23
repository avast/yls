from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

import pygls.lsp.types as lsp_types

from yls import utils


class StringType(Enum):
    """Type of the YARA string."""

    PLAIN = "text"
    REGEX = "regexp"
    HEX = "hex"


@dataclass
class StringModifier:
    keyword: str
    string_types: list[StringType]
    summary: str
    restrictions: str

    def to_completion_item(self) -> lsp_types.CompletionItem:
        return lsp_types.CompletionItem(
            label=self.keyword,
            kind=lsp_types.CompletionItemKind.Keyword,
            insert_text=self.keyword,
            insert_text_format=lsp_types.InsertTextFormat.PlainText,
            documentation=utils.markdown_content(self.documentation),
            sort_text="a",  # High priority
        )

    @property
    def documentation(self) -> str:
        return f"""`{self.keyword}`

**Summary:** {self.summary}

**String types:** {", ".join(map(lambda s: s.value, self.string_types))}

**Restrictions:** {self.restrictions}
"""


STRING_MODIFIERS = {
    "nocase": StringModifier(
        "nocase",
        [StringType.PLAIN, StringType.REGEX],
        "Ignore case",
        "Cannot use with `xor`, `base64`, or `base64wide`",
    ),
    "wide": StringModifier(
        "wide",
        [StringType.PLAIN, StringType.REGEX],
        "Emulate UTF16 by interleaving null (0x00) characters",
        "None",
    ),
    "ascii": StringModifier(
        "ascii",
        [StringType.PLAIN, StringType.REGEX],
        "Also match ASCII characters, only required if `wide` is used",
        "None",
    ),
    "xor": StringModifier(
        "xor",
        [StringType.PLAIN],
        "XOR text string with single byte keys",
        "Cannot use with `nocase`, `base64`, or `base64wide`",
    ),
    "base64": StringModifier(
        "base64",
        [StringType.PLAIN],
        "Convert to 3 base64 encoded strings",
        "Cannot use with `nocase`, `xor`, or `fullword`",
    ),
    "base64wide": StringModifier(
        "base64wide",
        [StringType.PLAIN],
        "Convert to 3 base64 encoded strings, then interleaving null characters like wide",
        "Cannot use with `nocase`, `xor`, or `fullword`",
    ),
    "fullword": StringModifier(
        "fullword",
        [StringType.PLAIN, StringType.REGEX],
        "Match is not preceded or followed by an alphanumeric character",
        "Cannot use with `base64`, or `base64wide`",
    ),
    "private": StringModifier(
        "private",
        [StringType.PLAIN, StringType.REGEX, StringType.HEX],
        "Match never included in output",
        "None",
    ),
}


@lru_cache
def string_modifiers_completion_items(
    string_type: StringType | None,
) -> list[lsp_types.CompletionItem]:
    res = []
    for string_modifier in STRING_MODIFIERS.values():
        if string_type not in string_modifier.string_types:
            continue

        res.append(string_modifier.to_completion_item())

    return res


def estimate_string_type(line: str) -> StringType | None:
    """Estimate YARA string type based on the line from the source.

    This is only an estimation, since we have to also consider unfinished
    strings. We can pretty reliably estimate this based on the opening
    character after the equals sign. If the estimation cannot be done, we
    return `None`.
    """
    if re.search(r'=\s*"', line) is not None:
        return StringType.PLAIN
    elif re.search(r"=\s*/", line) is not None:
        return StringType.REGEX
    elif re.search(r"=\s*{", line) is not None:
        return StringType.HEX
    else:
        return None
