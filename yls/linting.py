from __future__ import annotations

import logging
import re

import yaramod
from pygls.lsp.types import Diagnostic
from pygls.lsp.types import DiagnosticSeverity
from pygls.workspace import Document

from yls import utils
from yls.plugin_manager_provider import PluginManagerProvider
from yls.yaramod_provider import YaramodProvider

log = logging.getLogger(__name__)


def get_diagnostics(document: Document) -> list[Diagnostic]:
    """Return diagnostic information for the given `Document`.

    This will perform various linting procedures and return a list of
    `Diagnostic`."""
    return Linter(document).lint()


class Linter:

    SOURCE_YARA = "Yara Python"
    SOURCE_YARAMOD = "Yaramod"

    SCHEMA_JSON_FILENAME = "schema.json"

    def __init__(self, document: Document):
        self.document = document

        # Result of the linting
        self.diag: list[Diagnostic] = []

    def lint(self) -> list[Diagnostic]:
        """Invoke linting procedure for each linter."""
        diagnostic = []

        diagnostic += utils.flatten_list(
            PluginManagerProvider.instance().hook.yls_lint(document=self.document)
        )
        diagnostic += self.lint_with_yaramod()

        return diagnostic

    def lint_with_yaramod(self) -> list[Diagnostic]:
        """Perform linting with Yaramod."""
        try:
            _ = YaramodProvider.instance().parse_file(self.document.path)
            log.debug("[LINT] Yaramod - no problems")
        except yaramod.ParserError as e:
            etext = str(e)
            log.debug(f'[LINT] Yaramod parse exception: "{etext}"')

            m = re.search(r"^Error at ([^ ]*):(\d+)\.(\d+)-?(\d*):(.*)", etext)
            if m:
                line = int(m.group(2)) - 1
                start = int(m.group(3)) - 1
                end = int(m.group(4)) if m.group(4) else start
                error_msg = m.group(5).strip()
                diagnostic = Diagnostic(
                    range=utils.range_from_coords((line, start), (line, end)),
                    message=error_msg,
                    source=self.SOURCE_YARAMOD,
                    severity=DiagnosticSeverity.Error,
                )
                return [diagnostic]

        return []
