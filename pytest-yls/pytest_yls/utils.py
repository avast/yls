from __future__ import annotations

from typing import Any

import pygls.lsp.types as lsp_types
import yaramod


def find_cursor(contents: str, cursor_symbol: str = "<$>") -> tuple[str, lsp_types.Position | None]:
    """Find the cursor in the source code and return position and new source code."""

    res = []
    cursor_pos = None
    for idx, line in enumerate(contents.splitlines()):
        cursor_index = line.find(cursor_symbol)
        if cursor_index != -1:
            if cursor_pos is None:
                # This is the first cursor in source
                cursor_pos = lsp_types.Position(line=idx, character=cursor_index)

                # Cleanup the line
                line = line.replace(cursor_symbol, "")
            else:
                # We already have a cursor, this should not happen
                raise ValueError("Cursor is already present in the workspace")
        res.append(line)
    return ("\n".join(res), cursor_pos)


def expr_from_str(expr: str) -> yaramod.Expression:
    ymod = yaramod.Yaramod()
    yfile_source = f"""
import "cuckoo"
import "elf"
import "hash"
import "magic"
import "math"
import "pe"
import "time"

rule asd {{
    condition:
        {expr}
}}"""
    return ymod.parse_string(yfile_source).rules[0].condition


def assert_completable(expected: tuple[str | tuple[str, str]], response: Any) -> None:
    """Assert that response contains the expected completion items."""
    assert response["items"]
    completions = response["items"]

    for item in expected:
        if isinstance(item, str):
            assert any(item == completion["label"] for completion in completions)
        elif isinstance(item, tuple):
            assert any(
                item[0] == completion["label"] and item[1] == completion["kind"]
                for completion in completions
            )
