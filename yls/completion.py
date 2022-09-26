from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import pygls.lsp.types as lsp_types
import yaramod

from yls import utils

log = logging.getLogger(__name__)

# Keywords which can occur in condition section
CONDITION_KEYWORDS = {
    "all",
    "and",
    "any",
    "at",
    "contains",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "icontains",
    "iendswith",
    "iequals",
    "in",
    "int16",
    "int16be",
    "int32",
    "int32be",
    "int8",
    "int8be",
    "istartswith",
    "matches",
    "none",
    "not",
    "of",
    "or",
    "startswith",
    "them",
    "true",
    "uint16",
    "uint16be",
    "uint32",
    "uint32be",
    "uint8",
    "uint8be",
    "defined",
}


@dataclass
class Symbol:
    name: str

    def to_completion_items(self) -> list[lsp_types.CompletionItem]:
        return []

    # pylint: disable-next=unused-argument
    def to_hover(self, path: str | None = None) -> lsp_types.Hover:
        return lsp_types.Hover(contents=utils.markdown_content(self.name))

    def kind(self) -> lsp_types.CompletionItemKind:
        return lsp_types.CompletionItemKind.Text


@dataclass
class Structure(Symbol):
    name: str
    attributes: dict[str, Any]

    def detail(self) -> str:
        return "struct"

    def kind(self) -> lsp_types.CompletionItemKind:
        return lsp_types.CompletionItemKind.Struct

    def to_completion_items(self) -> list[lsp_types.CompletionItem]:
        log.debug(f'[to_completion_items] Creating completion for structure "{self.name}"')
        return [
            lsp_types.CompletionItem(
                label=self.name,
                kind=self.kind(),
                insert_text=self.name,
                insert_text_format=lsp_types.InsertTextFormat.PlainText,
                sort_text="a",  # High priority
            )
        ]


@dataclass
class Reference(Symbol):
    name: str
    symbol: Symbol

    def detail(self) -> str:
        return f"ref to {self.symbol.name}"

    def kind(self) -> lsp_types.CompletionItemKind:
        return self.symbol.kind()

    def to_completion_items(self) -> list[lsp_types.CompletionItem]:
        log.debug(f'[to_completion_items] Creating completion for reference "{self.name}"')
        return [
            lsp_types.CompletionItem(
                label=self.name,
                kind=self.kind(),
                insert_text=self.name,
                insert_text_format=lsp_types.InsertTextFormat.PlainText,
                detail=self.detail(),
                sort_text="a",  # High priority
            )
        ]


@dataclass
class Value(Symbol):
    name: str
    type_: yaramod.ExpressionType
    documentation: str = ""

    def detail(self) -> str:
        return Function.TYPE_TO_STRING[self.type_]

    def is_constant(self) -> bool:
        return self.name.isupper()

    def kind(self) -> lsp_types.CompletionItemKind:
        return (
            lsp_types.CompletionItemKind.Constant
            if self.is_constant()
            else lsp_types.CompletionItemKind.Variable
        )

    def sort_text(self) -> str:
        return "ab" if self.is_constant() else "a"

    def to_completion_items(self) -> list[lsp_types.CompletionItem]:
        log.debug(f'[to_completion_items] Creating completion for variable "{self.name}"')
        return [
            lsp_types.CompletionItem(
                label=self.name,
                kind=self.kind(),
                insert_text_format=lsp_types.InsertTextFormat.PlainText,
                documentation=utils.markdown_content(self.documentation),
                detail=self.detail(),
                sort_text=self.sort_text(),
            )
        ]

    def signature(self) -> str:
        return f"{self.name}:{self.detail()}"

    def hover_string(self) -> str:
        res = f"**{self.signature()}**\n********\n\n{self.documentation}"
        return res

    def to_hover(self, path: str | None = None) -> lsp_types.Hover:
        return lsp_types.Hover(contents=utils.markdown_content(self.documentation))


@dataclass
class Overload:
    parameters: list[yaramod.ExpressionType]
    documentation: str

    def param_string(self) -> str:
        return ", ".join(map(lambda p: Function.TYPE_TO_STRING[p], self.parameters))


@dataclass
class Function(Symbol):
    name: str
    overloads: list[Overload]
    return_type: yaramod.ExpressionType
    documentation: str = ""

    TYPE_TO_STRING = {
        yaramod.ExpressionType.Undefined: "undefined",
        yaramod.ExpressionType.Bool: "bool",
        yaramod.ExpressionType.Int: "int",
        yaramod.ExpressionType.String: "string",
        yaramod.ExpressionType.Regexp: "regex",
        yaramod.ExpressionType.Object: "object",
        yaramod.ExpressionType.Float: "float",
    }

    TYPE_TO_SHORT_STRING = {
        yaramod.ExpressionType.Undefined: "u",
        yaramod.ExpressionType.Bool: "b",
        yaramod.ExpressionType.Int: "i",
        yaramod.ExpressionType.String: "s",
        yaramod.ExpressionType.Regexp: "r",
        yaramod.ExpressionType.Object: "o",
        yaramod.ExpressionType.Float: "f",
    }

    def snippet(self) -> str:
        # return "{}(${{0:params}})".format(name)
        return f"{self.name}($0)"

    def signature(self) -> str:
        return f"{self.name}({self.overloads[0].param_string()}) -> {self.TYPE_TO_STRING[self.return_type]}"

    def hover_documentation(self) -> str:
        res = ""
        # NOTE: Handle overloads
        overload = self.overloads[0]

        res += f"**{self.signature()}**\n********\n\n"

        documentation = overload.documentation
        for line in documentation.splitlines(keepends=True):
            if line.strip().casefold().startswith("example"):
                res += "```\n"
                res += line
                res += "\n```\n"
            else:
                res += line

        return res

    def to_completion_items(self) -> list[lsp_types.CompletionItem]:
        log.debug(f'[to_completion_items] Creating completion for function "{self.name}"')
        res = []
        for overload in self.overloads:
            res.append(
                lsp_types.CompletionItem(
                    label=self.name,
                    kind=lsp_types.CompletionItemKind.Function,
                    insert_text=self.snippet(),
                    insert_text_format=lsp_types.InsertTextFormat.Snippet,
                    command=lsp_types.Command(
                        title="editor.action.triggerParameterHints",
                        command="editor.action.triggerParameterHints",
                        arguments=[],
                    ),
                    documentation=utils.markdown_content(overload.documentation),
                    detail=overload.param_string(),
                    sort_text="a",  # High priority
                )
            )
        return res

    def to_signature_information(
        self, path: str | None = None
    ) -> list[lsp_types.SignatureInformation]:
        res = []
        for overload in self.overloads:
            path = path or self.name
            doc = utils.markdown_content(overload.documentation)

            signature_string = (
                f"{path}({overload.param_string()}) -> {self.TYPE_TO_STRING[self.return_type]}"
            )
            parameters = []
            for param in overload.parameters:
                parameters.append(lsp_types.ParameterInformation(label=self.TYPE_TO_STRING[param]))

            res.append(
                lsp_types.SignatureInformation(
                    label=signature_string, parameters=parameters, documentation=doc
                )
            )

        return res

    def to_hover(self, path: str | None = None) -> lsp_types.Hover:
        return lsp_types.Hover(contents=utils.markdown_content(self.documentation))


@dataclass
class Array(Symbol):
    name: str
    element: Structure | Reference | Value
    documentation: str = ""

    def detail(self) -> str:
        return self.element.detail()

    def snippet(self) -> str:
        return f"{self.name}[$0]"

    def to_completion_items(self) -> list[lsp_types.CompletionItem]:
        log.debug(f'[to_completion_items] Creating completion for array "{self.name}"')
        return [
            lsp_types.CompletionItem(
                label=self.name,
                kind=self.element.kind(),
                insert_text=self.snippet(),
                insert_text_format=lsp_types.InsertTextFormat.Snippet,
                documentation=utils.markdown_content(self.documentation),
                detail=self.detail(),
                sort_text="a",  # High priority
            )
        ]


@dataclass
class Dictionary(Symbol):
    name: str
    element: Structure | Reference | Value
    documentation: str = ""

    def detail(self) -> str:
        return self.element.detail()

    def snippet(self) -> str:
        return f'{self.name}["$0"]'

    def to_completion_items(self) -> list[lsp_types.CompletionItem]:
        log.debug(f'[to_completion_items] Creating completion for dictionary "{self.name}"')
        return [
            lsp_types.CompletionItem(
                label=self.name,
                kind=self.element.kind(),
                insert_text=self.snippet(),
                insert_text_format=lsp_types.InsertTextFormat.Snippet,
                documentation=utils.markdown_content(self.documentation),
                detail=self.detail(),
                sort_text="a",  # High priority
            )
        ]


class CompletionCache:
    modules: Structure

    def __init__(self) -> None:
        pass

    def get_symbols_matching(self, path: str) -> list[Symbol]:
        """Returns a list of symbols that match the given path.

        Examples:
        - `pe.MACHINE_ARM` returns 3 symbols that match the prefix
          (MACHINE_ARM, MACHINE_ARM64, MACHINE_ARMNT).
        - `p` returns 2 symbols that match the prefix (pe, phish).
        - `` (empty string) returns all module symbols.
        """
        symbols, path_remainder = self._get_symbols(path)

        # Construct a list of results that match the given prefix
        symbols = list(filter(lambda x: x.name.startswith(path_remainder), symbols))

        return symbols

    def _get_symbols(self, path: str) -> tuple[list[Symbol], str]:
        """Return list of symbols that match the longest prefix path and a path remainder.

        If the match is exact (e.g. `pe.MACHINE_ARM64`) the returned remained is
        empty string. Otherwise the remainder is the first part that did not match
        the path.
        """

        # Split the path
        parts = path.split(".")

        # Initialize the search
        finder = self.modules

        # Enumerate all parts except the last one. This is because we want to find
        # all symbols with given prefix and manually select only those that match
        # the remainder.
        for i, part in enumerate(parts[:-1]):
            try:
                finder = finder.attributes[part]
            except KeyError:
                # The path is invalid
                return list(finder.attributes.values()), ".".join(parts[i:])
            except AttributeError:
                # We hit the "end" (Value, Array, ...)
                return [], ".".join(parts[i:])
        try:
            return list(finder.attributes.values()), parts[-1]
        except AttributeError:
            # In case we finish on a non Structure symbol
            # Example: 'pe.MACHINE_ARM64.'
            return [], ""

    def get_symbol(self, path: str) -> Symbol | None:
        """Returns a symbols that exactly matches the specified path.

        If the symbol is not found returns None.
        """
        parts = path.split(".")
        finder = self.modules
        for part in parts:
            try:
                finder = finder.attributes[part]
            except (KeyError, AttributeError):
                # We either tried to advance with invalid path or we
                # tried to move after we reached the "end". For example
                # selecting a Value and trying to advance past it.
                return None
        return finder

    def get_function(self, path: str) -> Function | None:
        symbol = self.get_symbol(path)
        if symbol is None:
            return None

        if not isinstance(symbol, Function):
            return None

        return symbol

    @staticmethod
    def visit_symbol(symbol: Any) -> Symbol:
        # pylint: disable=no-else-return,too-many-branches,too-many-return-statements
        if symbol.is_structure:
            attributes = {}
            for name, nested_symbol in symbol.attributes.items():
                attributes[name] = CompletionCache.visit_symbol(nested_symbol)
            return Structure(symbol.name, attributes)
        elif symbol.is_reference:
            return Reference(symbol.name, symbol.symbol)
        elif symbol.is_function:
            overloads = []
            for parameters, doc in zip(symbol.overloads, symbol.documentations):
                overloads.append(Overload(parameters, doc))
            return Function(symbol.name, overloads, symbol.return_type, symbol.documentation)
        elif symbol.is_array:
            element: Structure | Reference | Value
            if symbol.element_type != yaramod.ExpressionType.Object:
                # This array has a simple type
                # All are from dotnet module
                element = Value(symbol.name, symbol.element_type)
            else:
                attributes = {}
                if symbol.structure.is_reference:
                    element = Reference(symbol.name, symbol.structure.symbol)
                else:
                    for name, nested_symbol in symbol.structure.attributes.items():
                        attributes[name] = CompletionCache.visit_symbol(nested_symbol)
                    element = Structure(symbol.name, attributes)
            return Array(symbol.name, element, symbol.documentation)
        elif symbol.is_dictionary:
            element = Value(symbol.name, symbol.element_type)
            return Dictionary(symbol.name, element, symbol.documentation)
        elif symbol.is_value:
            return Value(symbol.name, symbol.data_type, symbol.documentation)
        else:
            log.warning(
                f"[visit_symbol] Unimplemented type {symbol} '{symbol.name}' creating a default fallback."
            )
            return Value(symbol.name, symbol.data_type)

    @staticmethod
    def from_yaramod(ymod: yaramod.Yaramod) -> "CompletionCache":
        res = CompletionCache()

        attributes = {}
        for name, module in ymod.modules.items():
            attributes[name] = CompletionCache.visit_symbol(module.structure)

        res.modules = Structure("", attributes)

        return res
