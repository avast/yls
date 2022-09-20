from __future__ import annotations

import logging
from typing import Any

import yaramod
from pluggy import PluginManager
from pygls.lsp.types import DocumentFormattingParams
from pygls.lsp.types import MessageType
from pygls.lsp.types import TextEdit
from pygls.workspace import Document

from yls import hookimpl
from yls import hookspecs
from yls import utils
from yls.debugger import DebuggerProvider
from yls.hookspecs import PopupMessage
from yls.hookspecs import PluggyRes

log = logging.getLogger(__name__)


def get_plugin_manager() -> PluginManager:
    """Construct new plugin manager instance."""
    log.info("Creating PluginManager")
    manager = PluginManager("yls")
    manager.add_hookspecs(hookspecs)
    manager.load_setuptools_entrypoints("yls")
    manager.register(YlsCorePlugin(), name="core")
    log.info(f"\t{manager.get_plugins()=}")
    log.info(f"\t{manager.list_name_plugin()=}")
    manager.trace.root.setwriter(print)
    return manager


class PluginManagerProvider:
    """Singleton class providing PluginManager parser object."""

    manager = None

    @classmethod
    def instance(cls) -> PluginManager:
        """Return singleton instance."""
        if cls.manager is None:
            cls.manager = get_plugin_manager()
        return cls.manager


class YlsCorePlugin:
    @hookimpl(trylast=True)
    def create_yaramod_instance(self) -> yaramod.Yaramod | None:
        return yaramod.Yaramod()

    @hookimpl(trylast=True)
    def yls_formatting(
        self,
        ls: Any,
        params: DocumentFormattingParams,  # pylint: disable=unused-argument
        document: Document,
    ) -> list[TextEdit]:
        # NOTE: Change after yaramod has support for "include" in parse_string
        yfile = utils.yaramod_parse_file(document.path)
        if yfile is None:
            ls.show_message(
                "Cannot parse the current document, please fix all errors before formatting.",
                MessageType.Error,
            )
            return []

        formatted_file = yfile.text_formatted

        total_lines = len(document.source.splitlines()) + 1
        res = [
            TextEdit(
                range=utils.range_from_coords((0, 0), (total_lines, 0)), new_text=formatted_file
            )
        ]
        return res

    @hookimpl
    def yls_scan_enabled(self) -> bool:
        return False

    @hookimpl
    def yls_eval_set_samples_dir(
        self,  # pylint: disable=unused-argument
        ls: Any,  # pylint: disable=unused-argument
        _dir: str,
    ) -> str:
        return DebuggerProvider().instance().set_samples_dir(_dir)

    @hookimpl(trylast=True)
    def yls_eval(
        self,  # pylint: disable=unused-argument
        ls: Any,  # pylint: disable=unused-argument
        expr: str,
    ) -> PluggyRes[str | PopupMessage]:
        return DebuggerProvider().instance().eval(expr)

    @hookimpl
    def yls_eval_set_context(
        self,  # pylint: disable=unused-argument
        ls: Any,  # pylint: disable=unused-argument
        _hash: str,
        ruleset: str,
    ) -> PluggyRes[PopupMessage]:
        return DebuggerProvider().instance().set_context(_hash, ruleset)

    @hookimpl
    def yls_eval_enabled(self) -> bool:
        return True
