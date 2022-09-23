from __future__ import annotations

import logging
from typing import Any

import pygls.lsp.types as lsp_types
import yaramod
from pygls.workspace import Document

from yls import completion
from yls import utils
from yls.hookspecs import ErrorMessage
from yls.hookspecs import PopupMessage
from yls.plugin_manager_provider import PluginManagerProvider

log = logging.getLogger(__name__)


class Hoverer:
    def __init__(self, ls: Any) -> None:
        self.ls = ls
        self.selected_range: lsp_types.Range | None = None

    async def hover(self, params: lsp_types.TextDocumentPositionParams) -> lsp_types.Hover | None:

        document = self.ls.workspace.get_document(params.text_document.uri)
        position = params.position

        if self.ls.debug_hover:
            return utils.debug_hover(document, position)

        # Evaluate entire block of selected expressions
        if (
            self.selected_range
            and self.selected_range.start != self.selected_range.end
            and utils.position_in_range(position, self.selected_range)
        ):
            expr_range = utils.range_to_expression(document, self.selected_range)
            if not expr_range:
                return None

            expr = utils.text_from_range(document, expr_range)
            log.debug(f'[HOVER] Hover request with selected text "{expr}"')
            eval_result = await self.eval_expression(expr)
            log.debug(f"[HOVER] Evaluation returned {eval_result}")
            return lsp_types.Hover(
                contents=utils.markdown_content(
                    f"""{self.result_to_markdown(eval_result)}
*Expression*:
```
{utils.remove_whitespace(expr)}
```

"""
                )
            )

        token = utils.cursor_token(document, position)

        # Yaramod failed to parse but we can do textual fallback
        if not token:
            return lsp_types.Hover(
                contents=utils.markdown_content(self.get_cursor_documentation(document, position))
            )

        log.debug(f'[HOVER] Hover request with token "{token}" and type "{token.type}"')
        if token.type == yaramod.TokenType.StringId:
            return await self.hover_string(token, document, position)
        elif token.type == yaramod.TokenType.Id:
            yara_file = utils.yaramod_parse_file(document.path)
            if yara_file is None:
                return None

            for rule in yara_file.rules:
                if rule.name == token.text:
                    rule_doc = f"""*Rule name* = "{rule.name}"

```
{rule.text}
```

*Condition*:
```
{rule.condition.text}
```
"""

                    eval_result = await self.eval_expression(rule.name)
                    if eval_result:
                        rule_doc = f"{self.result_to_markdown(eval_result)}\n{rule_doc}"

                    return lsp_types.Hover(contents=utils.markdown_content(rule_doc))
        elif token.type in [
            yaramod.TokenType.ValueSymbol,
            yaramod.TokenType.StructureSymbol,
            yaramod.TokenType.FunctionSymbol,
            yaramod.TokenType.DictionarySymbol,
            yaramod.TokenType.ArraySymbol,
            yaramod.TokenType.Lt,
            yaramod.TokenType.Gt,
            yaramod.TokenType.Le,
            yaramod.TokenType.Ge,
            yaramod.TokenType.Eq,
            yaramod.TokenType.Neq,
            yaramod.TokenType.And,
            yaramod.TokenType.Or,
            yaramod.TokenType.Not,
        ]:
            return await self.hover_cursor(document, position)

        return None

    async def hover_cursor(
        self, document: Document, position: lsp_types.Position
    ) -> lsp_types.Hover | None:
        log.debug(f'[HOVER] Hover cursor "{document}" @ "{position}"')
        # Get the documentation for word under the cursor
        cursor_documentation = self.get_cursor_documentation(document, position)

        hover_string = ""

        yara_file = utils.yaramod_parse_file(document.path)
        if yara_file:
            expr = utils.cursor_expression(yara_file, position)
            if expr:
                eval_result = await self.eval_expression(expr.text)
                if eval_result:
                    hover_string += self.result_to_markdown(eval_result)

        hover_string += cursor_documentation

        return lsp_types.Hover(contents=utils.markdown_content(hover_string))

    def result_to_markdown(self, result: str) -> str:
        return f"*Evaluation result*:\n\n{result}\n********\n\n"

    async def eval_expression(self, expr: str) -> str:
        log.debug(f'[HOVER] Evaluate expression "{expr}"')

        # Evaluate the expression
        eval_result_collected = []
        eval_results = await utils.pluggy_results(
            PluginManagerProvider.instance().hook.yls_eval(ls=self.ls, expr=expr)
        )

        res_success = next((res for res in eval_results if not isinstance(res, ErrorMessage)), None)
        for i, eval_result in enumerate(eval_results):
            # Display errors
            if isinstance(eval_result, PopupMessage):
                # Show errors only if no debugger returned a valid result
                if not res_success:
                    if len(eval_results) > 1:
                        eval_result.message = f"{utils.DEBUGGER_SOURCES[i]}: {eval_result.message}"
                    eval_result.show(self.ls)

                log.debug(eval_result.message)
                continue

            if not eval_result:
                continue

            if len(eval_results) > 1:
                eval_result_collected.append(f"**{utils.DEBUGGER_SOURCES[i]}**:\n{eval_result}")
            else:
                eval_result_collected.append(eval_result)

        return "\n".join(eval_result_collected)

    def get_cursor_documentation(self, document: Document, position: lsp_types.Position) -> str:
        word = utils.cursor_symbol(document, position)
        log.debug(f'[HOVER] Hover request for symbol or function "{word}"')
        if word is None:
            return ""

        symbol = self.ls.completer.completion_cache.get_symbol(word)
        if symbol is None:
            return ""

        if isinstance(symbol, completion.Function):
            doc = symbol.hover_documentation()
        elif isinstance(symbol, completion.Value):
            doc = symbol.hover_string()
        else:
            return ""

        return doc

    async def hover_string(
        self, token: yaramod.Token, document: Document, position: lsp_types.Position
    ) -> lsp_types.Hover | None:
        """Generate Hover for string"""
        cur_rule = self.ls.get_current_rule(document.uri, position)
        if not cur_rule:
            return None

        # NOTE: This can be prob abstracted
        for string in cur_rule.strings:
            # NOTE: Check the type of string
            if string.identifier == token.pure_text:
                string_doc = f"{string.identifier} = {string.text}"

                eval_result = await self.eval_expression(string.identifier)
                if eval_result:
                    string_doc = f"{self.result_to_markdown(eval_result)}\n{string_doc}"

                return lsp_types.Hover(contents=utils.markdown_content(string_doc))

        return None
