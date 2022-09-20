# pylint: disable=unused-argument

"""
Declaration of the available hooks for YLS.

WARNING: Declared API is unstable and is likely to change.
If you want to write a plugin for YLS feel free to contact us using issues or
other means.
"""

from __future__ import annotations

from typing import Any
from typing import Awaitable
from typing import Callable
from typing import TypeVar
from typing import Union

import pluggy
import yaramod
from pygls.lsp.types import CodeAction
from pygls.lsp.types import CodeActionParams
from pygls.lsp.types import CodeLens
from pygls.lsp.types import CodeLensParams
from pygls.lsp.types import Command
from pygls.lsp.types import CompletionItem
from pygls.lsp.types import CompletionParams
from pygls.lsp.types import Diagnostic
from pygls.lsp.types import DocumentFormattingParams
from pygls.lsp.types import MessageType
from pygls.lsp.types import TextEdit
from pygls.workspace import Document

hookspec = pluggy.HookspecMarker("yls")

T = TypeVar("T")
PluggyRes = Union[Awaitable[T], Callable[[], T], T]


@hookspec(firstresult=True)
def create_yaramod_instance() -> yaramod.Yaramod | None:
    ...


@hookspec
def yls_lint(document: Document) -> list[Diagnostic]:
    ...


@hookspec
def yls_completion(params: CompletionParams, document: Document) -> list[CompletionItem]:
    ...


@hookspec(firstresult=True)
def yls_formatting(
    ls: Any, params: DocumentFormattingParams, document: Document
) -> list[TextEdit] | None:
    ...


@hookspec
def yls_code_actions(ls: Any, params: CodeActionParams) -> list[Command | CodeAction]:
    ...


@hookspec
def yls_supported_commands(ls: Any) -> list[str]:
    ...


@hookspec
def yls_execute_command(command: str, ls: Any, params: Any) -> PluggyRes[Any | None]:
    ...


@hookspec
def yls_code_lens(ls: Any, params: CodeLensParams) -> list[CodeLens]:
    ...


@hookspec
def yls_scan(ls: Any, document: Document, rule_name: str | None) -> PluggyRes[list[Diagnostic]]:
    ...


@hookspec
def yls_scan_enabled() -> bool:
    ...


@hookspec
def yls_eval_enabled() -> bool:
    ...


class EvalError:
    def __init__(self, message: str, message_type: MessageType = MessageType.Error):
        self.message = message
        self.message_type = message_type

    def __str__(self) -> str:
        return f"Evaluation error: {self.message}"

    def show(self, ls: Any) -> None:
        ls.show_message(str(self), self.message_type)


@hookspec
def yls_eval(ls: Any, expr: str) -> PluggyRes[str | EvalError]:
    ...


@hookspec
def yls_eval_set_context(ls: Any, _hash: str, ruleset: str) -> PluggyRes[str | EvalError]:
    ...
