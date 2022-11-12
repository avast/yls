from __future__ import annotations
from typing import Iterable

SUPPORTED_VARIABLES = {
    "TM_SELECTED_TEXT",
    "TM_CURRENT_LINE",
    "TM_CURRENT_WORD",
    "TM_LINE_INDEX",
    "TM_LINE_NUMBER",
    "TM_FILENAME",
    "TM_FILENAME_BASE",
    "TM_DIRECTORY",
    "TM_FILEPATH",
    "RELATIVE_FILEPATH",
    "CLIPBOARD",
    "WORKSPACE_NAME",
    "WORKSPACE_FOLDER",
    "CURSOR_INDEX",
    "CURSOR_NUMBER",
    "CURRENT_YEAR",
    "CURRENT_YEAR_SHORT",
    "CURRENT_MONTH",
    "CURRENT_MONTH_NAME",
    "CURRENT_MONTH_NAME_SHORT",
    "CURRENT_DATE",
    "CURRENT_DAY_NAME",
    "CURRENT_DAY_NAME_SHORT",
    "CURRENT_HOUR",
    "CURRENT_MINUTE",
    "CURRENT_SECOND",
    "CURRENT_SECONDS_UNIX",
    "RANDOM",
    "RANDOM_HEX",
    "UUID",
    "BLOCK_COMMENT_START",
    "BLOCK_COMMENT_END",
    "LINE_COMMENT",
}


class SnippetString:
    cur_idx: int
    value: str

    def __init__(self, value: str = ""):
        self.value = value
        self.cur_idx = 1

    def append_choice(self, values: Iterable[str]) -> None:
        self.value += f"${{{self.get_and_inc()}|{','.join(values)}|}}"

    def append_placeholder(self, value: str) -> None:
        self.value += f"${{{self.get_and_inc()}:{value}}}"

    def append_tabstop(self) -> None:
        self.value += f"${self.get_and_inc()}"

    def append_text(self, value: str) -> None:
        """WARNING: For now you are expected to escape the string if necessary."""
        self.value += value

    def append_variable(self, name: str, default_value: str) -> None:
        if name in SUPPORTED_VARIABLES:
            self.value += f"${{{name}}}"
        else:
            self.value += f"${{{default_value}}}"

    def get_and_inc(self) -> int:
        i = self.cur_idx
        self.cur_idx += 1
        return i

    def __str__(self) -> str:
        return self.value
