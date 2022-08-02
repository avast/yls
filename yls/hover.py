from __future__ import annotations

import logging
from typing import Any

import pygls.lsp.types as lsp_types
import yaramod
from pygls.workspace import Document

from yls import completion
from yls import utils
from yls.hookspecs import EvalError
from yls.plugin_manager_provider import PluginManagerProvider

log = logging.getLogger(__name__)


class Hoverer:
    def __init__(self, ls: Any) -> None:
        self.ls = ls

    async def hover(self, params: lsp_types.TextDocumentPositionParams) -> lsp_types.Hover | None:

        document = self.ls.workspace.get_document(params.text_document.uri)
        position = params.position

        if self.ls.debug_hover:
            return utils.debug_hover(document, position)

        token = utils.cursor_token(document, position)

        # Yaramod failed to parse but we can do textual fallback
        if not token:
            return lsp_types.Hover(
                contents=utils.markdown_content(self.get_cursor_documentation(document, position))
            )

        log.debug(f'[HOVER] Hover request with token "{token}" and type "{token.type}"')
        if token.type == yaramod.TokenType.StringId:
            return self.hover_string(token, document, position)
        elif token.type == yaramod.TokenType.Id:
            yara_file = utils.yaramod_parse_file(document.path)
            if yara_file is None:
                return None

            for rule in yara_file.rules:
                if rule.name == token.text:
                    return lsp_types.Hover(
                        contents=utils.markdown_content(
                            f"""*Rule name* = "{rule.name}"

```
{rule.text}
```

*Condition*:
```
{rule.condition.text}
```
"""
                        )
                    )
        elif token.type in [
            yaramod.TokenType.ValueSymbol,
            yaramod.TokenType.StructureSymbol,
            yaramod.TokenType.FunctionSymbol,
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

        eval_result = await self.hover_eval(document, position)
        if eval_result:
            eval_result_formatted = f"Evaluation result:\n{eval_result}\n********\n\n"
            hover_string += eval_result_formatted

        hover_string += cursor_documentation

        return lsp_types.Hover(contents=utils.markdown_content(hover_string))

    async def hover_eval(self, document: Document, position: lsp_types.Position) -> str:
        log.debug(f'[HOVER] Hover eval "{document}" @ "{position}"')

        # Evaluate the expression
        eval_result_collected = ""
        eval_results = await utils.pluggy_results(
            PluginManagerProvider.instance().hook.yls_eval(
                ls=self.ls, document=document, position=position
            )
        )
        for eval_result in eval_results:
            # Handle errors from the plugins
            if isinstance(eval_result, EvalError):
                eval_result.show(self.ls)
                continue

            eval_result_collected += eval_result

        return eval_result_collected

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

    def hover_string(
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
                return lsp_types.Hover(
                    contents=utils.markdown_content(f"{string.identifier} = {string.text}")
                )

        return None
