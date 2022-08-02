import logging
import os
import re
from typing import List

import yara

from yls import hookimpl
from yls import utils
from yls.lsp_types import Diagnostic
from yls.lsp_types import DiagnosticSeverity
from yls.lsp_types import Position

log = logging.getLogger(__name__)

SOURCE_YARA = "Yara Python"


@hookimpl()
def yls_lint(document) -> List[Diagnostic]:
    return lint_with_yara(document)


def lint_with_yara(document) -> List[Diagnostic]:
    try:
        _ = yara.compile(document.path, error_on_warning=True)
        log.debug("[LINT] Yara - no problems")
    except yara.SyntaxError as exc:
        etext = str(exc)
        log.debug(f'[LINT] Yara compile exception: "{etext}"')

        match_res = re.search(r"^.*\((.*)\):(.*)", etext)
        if match_res:
            line = int(match_res.group(1)) - 1
            error_msg = match_res.group(2).strip()
            diagnostic = Diagnostic(
                range=utils.range_from_line(line, document),
                message=error_msg,
                source=SOURCE_YARA,
                severity=DiagnosticSeverity.Error,
            )
            return [diagnostic]
    except yara.WarningError as exc:
        # This exception is thrown when yara encounters warnings. Warnings
        # in this case also include hints
        return parse_yara_warnings_and_hints(document, exc.warnings)
    except yara.Error as exc:
        # `yara.Error` is most likely thrown because the file does not exist
        # NOTE: We should at least parse the source of the file instead of ignoring it
        log.debug(f'[LINT] Yara compile exception: "{exc}"')

    return []


def parse_yara_warnings_and_hints(document, problems: List[str]) -> List[Diagnostic]:
    """Extract diagnostic information from yara output."""

    log.debug(f'[LINT] Yara warnings/hints: "{problems}"')

    res = []
    for problem_full in problems:
        # Strip the leading text if present
        problem = utils.remove_prefix(problem_full, "hint in ")

        match_res = re.search(r"^(.*)\((.*)\):(.*)", problem)

        if match_res:
            file_path = match_res.group(1)
            line = int(match_res.group(2)) - 1
            error_msg = match_res.group(3).strip()

            # Ignore warning/hints from included files
            if not os.path.samefile(file_path, document.path):
                continue

            source_line = utils.cursor_line(document, Position(line=line, character=0))
            start_char = utils.first_non_space_pos(source_line)
            end_char = len(source_line)

            diagnostic = Diagnostic(
                range=utils.range_from_coords((line, start_char), (line, end_char)),
                message=error_msg,
                source=SOURCE_YARA,
                severity=DiagnosticSeverity.Hint
                if problem_full.startswith("hint")
                else DiagnosticSeverity.Warning,
            )
            res.append(diagnostic)

    return res
