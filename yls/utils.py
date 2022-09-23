from __future__ import annotations

import argparse
import asyncio
import itertools
import logging
import os
import pathlib
import platform
import re
import sys
import uuid
from typing import Any
from typing import Iterator
from typing import TypeVar

import pygls.lsp.types as lsp_types
import yaramod
from pluggy import PluginManager
from pygls.workspace import Document

from yls.version import __version__
from yls.yaramod_provider import YaramodProvider

log = logging.getLogger(__name__)


DEBUGGER_SOURCES = ["avast", "core"]


def create_options_parser() -> argparse.ArgumentParser:
    """Create argparse parser object."""
    parser = argparse.ArgumentParser(description="Yara Language Server")
    parser.add_argument("-v", "--verbose", action="count", help="verbosity level", default=0)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def setup_logging() -> None:
    """Setup the default application logging."""
    # Configure the application logging
    root_logger = logging.getLogger()

    # Remove old handlers
    for handler in root_logger.handlers:
        root_logger.removeHandler(handler)
        handler.close()

    log_format = "[{asctime}] [{name:>15}:{lineno:<3}] [{levelname:.4}] -- {message}"

    # Default logging is to stderr
    steam_logging_handler = logging.StreamHandler(stream=sys.stderr)
    steam_logging_handler.setFormatter(logging.Formatter(log_format, style="{"))
    root_logger.addHandler(steam_logging_handler)

    yls_log_file = os.environ.get("YLS_LOG_FILE")
    if yls_log_file:
        file_logging_handler = logging.FileHandler(yls_log_file)
        file_logging_handler.setFormatter(logging.Formatter(log_format, style="{"))
        root_logger.addHandler(file_logging_handler)


def set_logging_level(verbose_count: int) -> None:
    """Set the logging level based on the number of -v options on command line."""
    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    log_level = log_levels[min(verbose_count, len(log_levels) - 1)]
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)


def log_command(command: str) -> None:
    """Log command in a standard format.

    NOTE: Be careful when changing this format, we estimate metrics from it.
    """
    if not command:
        return

    log.info(f"LSP_COMMAND = {command}")


def logging_prolog(plugin_manager: PluginManager) -> None:
    """Emit dependency version information."""
    log.info("Starting yls language server...")
    log.info(f"System platform: {platform.system()}")
    log.info(f"YLS version: {__version__}")
    log.info(f"Yaramod version: {yaramod.YARAMOD_VERSION}")

    plugins = ", ".join(plugin[0] for plugin in plugin_manager.list_name_plugin())
    log.info(f"Activated plugins: {plugins}")


def range_from_coords(x: tuple[int, int], y: tuple[int, int]) -> lsp_types.Range:
    """Helper function to create a range from coordinates.

    NOTE: If any of the coordinates is negative, truncate it to 0."""
    return lsp_types.Range(
        start=lsp_types.Position(line=max(0, x[0]), character=max(0, x[1])),
        end=lsp_types.Position(line=max(0, y[0]), character=max(0, y[1])),
    )


def range_from_yaramod_location(location: yaramod.Location) -> lsp_types.Range:
    """Helper function to create a range from yaramod location."""
    return range_from_coords(
        (location.begin.line - 1, location.begin.column - 1),
        (location.end.line - 1, location.end.column),
    )


def range_from_yaramod_token(token: yaramod.Token) -> lsp_types.Range:
    """Helper function to create a range from yaramod token."""
    return range_from_yaramod_location(token.location)


def range_from_yaramod_rule(rule: yaramod.Rule) -> lsp_types.Range:
    """Helper function to create a range from yaramod rule."""
    return range_from_coords(
        (rule.location.begin.line - 1, rule.location.begin.column - 1),
        (rule.location.end.line - 1, rule.location.end.column),
    )


def range_from_yaramod_expression(expr: yaramod.Expression) -> lsp_types.Range:
    """Convert Yaramod expression to LSP range."""
    end = lsp_types.Position(
        line=expr.token_last.location.end.line - 1, character=expr.token_last.location.end.column
    )
    start = lsp_types.Position(
        line=expr.token_first.location.begin.line - 1,
        character=expr.token_first.location.begin.column - 1,
    )
    return lsp_types.Range(start=start, end=end)


def range_from_line(
    line: int, document: Document, strip_whitespace: bool = True
) -> lsp_types.Range:
    """Helper function to create a range from line index.

    This function will ignore any leading/trailing whitespace."""
    line_content = document.lines[line]
    line_len = len(line_content)

    if strip_whitespace:
        start_char = line_len - len(line_content.lstrip())
        end_char = len(line_content.rstrip())
    else:
        start_char = 0
        end_char = line_len

    return range_from_coords((line, start_char), (line, end_char))


def range_from_lines(
    first_line: int, last_line: int, document: Document, strip_whitespace: bool = True
) -> lsp_types.Range:
    """Helper function to create a range for multiple lines.

    This function will ignore any leading/trailing whitespace."""
    first = range_from_line(first_line, document, strip_whitespace)
    last = range_from_line(last_line, document, strip_whitespace)
    return range_from_coords(
        (first.start.line, first.start.character), (last.end.line, last.end.character)
    )


def range_for_first_line() -> lsp_types.Range:
    """Create range for the first line.

    Editors should bound the range to an actual line length `min(len(line), 200)`."""
    return range_from_coords((0, 0), (0, 200))


T = TypeVar("T", str, bytes)


def remove_prefix(source: T, prefix: T) -> T:
    """Remove prefix from string or bytes if present."""
    if source.startswith(prefix):
        return source[len(prefix) :]
    return source


def remove_suffix(source: T, suffix: T) -> T:
    """Remove suffix from string or bytes if present."""
    if source.endswith(suffix):
        return source[: len(source) - len(suffix)]
    return source


def first_non_space_pos(line: str) -> int:
    """Return the index of first non space character in string.

    This is useful when calculating the `Range` and the leading spaces should
    not be included in this range."""
    counter = 0
    for c in line:
        if not c.isspace():
            return counter
        counter += 1
    return 0


def document_line(document: Document, line: int, keepends: bool = False) -> str:
    """Return the line of the document."""
    try:
        line_str = document.source.splitlines(keepends)[line]
    except IndexError:
        return ""
    return line_str


def cursor_line(document: Document, position: lsp_types.Position, keepends: bool = False) -> str:
    """Return the line the cursor is on."""
    return document_line(document, position.line, keepends=keepends)


def cursor_symbol(document: Document, position: lsp_types.Position) -> str | None:
    """Return the symbol under the cursor."""
    line = cursor_line(document, position)
    cursor = position.character
    for m in re.finditer(r"[\w$*.]+", line):
        if m.start() <= cursor <= m.end():
            return line[m.start() : m.end()]
    return None


def cursor_word(
    document: Document, position: lsp_types.Position, include_all: bool = True
) -> str | None:
    """Return the word under the cursor."""
    res = cursor_word_and_range(document, position, include_all=include_all)
    if res:
        return res[0]
    return None


def cursor_word_and_range(
    document: Document, position: lsp_types.Position, include_all: bool = True
) -> tuple[str, lsp_types.Range] | None:
    """Return the word and its range under the cursor."""
    line = cursor_line(document, position)
    cursor = position.character
    for m in re.finditer(r"[\w$*.()\/\\#:]+", line):
        end = m.end() if include_all else cursor
        if m.start() <= cursor <= m.end():
            word = (
                line[m.start() : end],
                range_from_coords((position.line, m.start()), (position.line, end)),
            )
            return word
    return None


def cursor_token(document: Document, position: lsp_types.Position) -> yaramod.Token | None:
    """Return the token under the cursor."""
    yara_file = yaramod_parse_file(document.path)
    if yara_file is None:
        return None

    # Iterate over tokens and find token with matching position
    for token in yara_file.tokenstream.tokens:
        if (
            token.location.file_path
            and os.path.samefile(token.location.file_path, document.path)
            and token.location.begin.line == position.line + 1
            and token.location.begin.column <= position.character + 1
            and token.location.end.column >= position.character + 1
        ):
            return token

    return None


def is_in_yara_section(document: Document, cursor_line: int, section_name: str) -> bool:
    found_beginning = False
    found_end = False

    if len(document.lines) <= cursor_line:
        return False

    # Walk back from cursor position (cursor_line included)
    for i in reversed(range(0, cursor_line + 1)):
        if re.match(r"^}\s*$", document.lines[i]):
            # Found the end of previous rule, which means cursor is not pointing into a rule
            return False

        if re.match(rf"^(({{)|(rule \w+)|((?!\s+{section_name}:)\s+[a-z]+:))", document.lines[i]):
            # Found the beginning of current rule or different section, stop searching for section_name
            break

        if re.match(rf"\s+{section_name}:", document.lines[i]):
            found_beginning = True
            break

    if found_beginning:
        # Walk forward from cursor position
        for i in range(cursor_line + 1, len(document.lines)):
            if re.match(r"^((\s+[a-z]+:)|(}))\s*$", document.lines[i]):
                # Found the next section or the end of current rule
                found_end = True
                break
    return found_beginning and found_end


def position_in_range(position: lsp_types.Position, _range: lsp_types.Range) -> bool:
    """Returns if a given position is contained within the specified range."""
    return (
        _range.start.line < position.line
        or (_range.start.line == position.line and _range.start.character <= position.character)
    ) and (
        _range.end.line > position.line
        or (_range.end.line == position.line and _range.end.character >= position.character)
    )


# pylint: disable-next=too-many-public-methods
class YaramodExpressionExtractor(yaramod.ObservingVisitor):  # type: ignore
    """Helper to extract interesting expressions."""

    def __init__(self, position: lsp_types.Position) -> None:
        super().__init__()
        self.position = position
        self.expr = None

    def run(self, condition: yaramod.Expression) -> yaramod.Expression | None:
        self.observe(condition)
        return self.expr

    def extract(self, expr: yaramod.Expression) -> None:
        expr_range = range_from_yaramod_expression(expr)
        if position_in_range(self.position, expr_range):
            self.expr = expr

    # pylint: disable-next=invalid-name
    def visit_FunctionCallExpression(self, expr: yaramod.FunctionCallExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_IdExpression(self, expr: yaramod.IdExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_StructAccessExpression(self, expr: yaramod.StructAccessExperssion) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_ArrayAccessExpression(self, expr: yaramod.ArrayAccessExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_StringExpression(self, expr: yaramod.StringExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_StringCountExpression(self, expr: yaramod.StringCountExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_StringOffsetExpression(self, expr: yaramod.StringOffsetExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_StringLengthExpression(self, expr: yaramod.StringLengthExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_OfExpression(self, expr: yaramod.OfExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_ForExpression(self, expr: yaramod.ForExpression) -> None:
        self.extract(expr)

    # pylint: disable-next=invalid-name
    def visit_IequalsExpression(self, expr: yaramod.IequalsExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_LtExpression(self, expr: yaramod.LtExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_GtExpression(self, expr: yaramod.GtExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_LeExpression(self, expr: yaramod.LeExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_GeExpression(self, expr: yaramod.GeExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_EqExpression(self, expr: yaramod.EqExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_NeqExpression(self, expr: yaramod.NeqExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_AndExpression(self, expr: yaramod.AndExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_OrExpression(self, expr: yaramod.OrExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_NotExpression(self, expr: yaramod.NotExpression) -> None:
        self.extract(expr)
        expr.operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_DefinedExpression(self, expr: yaramod.DefinedExpression) -> None:
        self.extract(expr)
        expr.operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_ContainsExpression(self, expr: yaramod.ContainsExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    # pylint: disable-next=invalid-name
    def visit_MatchesExpression(self, expr: yaramod.MatchesExpression) -> None:
        self.extract(expr)
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)


def cursor_expression(
    yfile: yaramod.YaraFile, position: lsp_types.Position
) -> yaramod.Expression | None:
    """Return the expression under the cursor."""

    extractor = YaramodExpressionExtractor(position)
    for rule in yaramod_rules_in_file(yfile):
        expr = extractor.run(rule.condition)
        if expr is not None:
            return expr

    return None


def debug_hover(document: Document, position: lsp_types.Position) -> lsp_types.Hover:
    token = cursor_token(document, position)
    if token:
        return lsp_types.Hover(
            contents=markdown_content(
                f"{token.text=}\n\n"  # Double newline to force line breaks
                f"{token.pure_text=}\n\n"
                f"{token.type=}\n\n"
                f"Begin = ({token.location.begin.line}, {token.location.begin.column})\n\n"
                f"End = ({token.location.end.line}, {token.location.end.column})\n\n"
                f"LSP Position = {position}\n\n"
                f"_cursor_word = {cursor_word(document, position)}"
            )
        )
    return lsp_types.Hover(contents=f"Token = {token}\nLSP Position = {position}")


def is_sha256_hash(i: str) -> bool:
    """Check if the `i` looks like a sha256 hash.

    We accept only lowercase hashes because it is the same behavior as YRTC."""
    return re.fullmatch("[0-9a-f]{64}", i) is not None


def markdown_content(value: str) -> lsp_types.MarkupContent:
    """Return the MarkupContent with Markdown kind."""
    return lsp_types.MarkupContent(kind=lsp_types.MarkupKind.Markdown, value=value)


def yaramod_parse_file(path: str) -> yaramod.YaraFile | None:
    """Wrapper around `Yaramod().parse_file()`."""
    try:
        return YaramodProvider.instance().parse_file(path)
    except yaramod.ParserError as e:
        log.debug(f'[YARAMOD_PARSE_FILE] Yaramod parse exception: "{e}"')
        return None


def yaramod_rules_in_file(yfile: yaramod.YaraFile) -> Iterator[yaramod.Rule]:
    """Yield only rules from the file specified by path.

    YaraFile contains all rules (even ones that come from includes). Most of the times we care
    only about the rules that are coming the source code file.
    """
    path = yarafile_path(yfile)
    for rule in yfile.rules:
        # Ignore rules coming from include statements
        if path is not None and not pathlib.Path(rule.location.file_path).samefile(
            pathlib.Path(path)
        ):
            continue

        yield rule


def yaramod_rule_has_hashes(rule: yaramod.Rule) -> bool:
    """Check if YARA rule contains sample hashes in hash meta."""
    for meta in rule.metas:
        # Consider only hash metas that have valid hash as value
        if meta.key != "hash" or not is_sha256_hash(meta.value.pure_text):
            continue

        return True

    return False


def yaramod_expression_to_symbol(expr: yaramod.StructAccessExpression) -> str | None:
    if isinstance(expr, yaramod.StructAccessExpression):
        base_expr = expr
    elif isinstance(expr, yaramod.FunctionCallExpression):
        base_expr = expr.function
    elif isinstance(expr, yaramod.ArrayAccessExpression):
        # For some reason array access has the full symbol path in expr.symbol.name
        # This is not the case for other kinds of expressions
        return f"{expr.symbol.name}[]"
    elif isinstance(expr, yaramod.FilesizeExpression):
        return "filesize"
    else:
        log.warning(f"Failed to convert {expr=} to symbol string.")
        return None

    cursor = base_expr
    func_name = ""
    while True:
        if isinstance(cursor, yaramod.StructAccessExpression):
            func_name = f"{cursor.symbol.name}.{func_name}"
            cursor = cursor.structure
        elif isinstance(cursor, yaramod.ArrayAccessExpression):
            func_name = f"{cursor.symbol.name}[].{func_name}"
            cursor = cursor.array.structure
        elif isinstance(cursor, yaramod.IdExpression):
            func_name = f"{cursor.symbol.name}.{func_name}"
            break
        else:
            log.warning(
                f"Error while converting expression to function name, unknown type {cursor=}"
            )
            return None

    return func_name[:-1]


def yarafile_to_string(yara_file: yaramod.YaraFile) -> str:
    """Explode YaraFile (and all includes) to a single string.

    This function will try import all modules.
    """

    ruleset = """import "cuckoo"
import "elf"
import "hash"
import "math"
import "pe"

"""
    for rule in yara_file.rules:
        ruleset += rule.text
        ruleset += "\n"

    return ruleset


def yarafile_path(yfile: yaramod.YaraFile) -> str | None:
    """Estimate the path of YaraFile.

    We are trying to ignore rules that come from `include`. Rules should be in order they
    appear in the source code. Getting the last rule should ensure, we get the rule that is
    from the source code even if there are included rules.

    If the file does not exist or YaraFile is created by parsing a string return None. This
    is also the case when there are no rules in the YaraFile.
    """
    rules = yfile.rules
    if len(rules) == 0:
        return None

    path: str = rules[-1].location.file_path
    if path == "[stream]":
        return None

    if not pathlib.Path(path).exists():
        return None

    return path


def yarafile_get_rule(
    yara_file: yaramod.YaraFile, rule_name: str, ignore_includes: bool = True
) -> yaramod.Rule | None:
    """Search for rule in YaraFile with a given name.

    If `ignore_includes` is True, consider only rules that are not from includes.
    """
    rules = yaramod_rules_in_file(yara_file) if ignore_includes else yara_file.rules
    for rule in rules:
        if rule.name == rule_name:
            return rule
    return None


def generate_progress_token() -> str:
    """Generate unique token that can be used to signalize progress."""
    return str(uuid.uuid4())


def flatten_list(list_of_lists: list[list[Any]]) -> list[Any]:
    return list(itertools.chain(*list_of_lists))


async def pluggy_results(objs: list[Any]) -> Any:
    res = []
    for obj in objs:
        resolved_object = await pluggy_result(obj)
        res.append(resolved_object)
    return res


async def pluggy_result(obj: Any) -> Any:
    """Get the result from YLS plugin. Try to extract the value from object.

    Taken from: https://simonwillison.net/2020/Sep/2/await-me-maybe/
    """
    log.debug(f"Resolving {obj=}")

    if callable(obj):
        return obj()
    if asyncio.iscoroutine(obj):
        return await obj
    return obj


async def start_progress(ls: Any, msg: str) -> str | None:
    """Helper to kick-start the progress indicator in editor."""
    token = generate_progress_token()
    log.debug(f"Generated a new {token=}")

    try:
        await ls.progress.create_async(token)
    except Exception:  # pylint: disable=broad-except
        # For some reason they raise plain exception when the token is already used
        ls.show_error_message("Progress token is already used")
        return None

    if msg:
        ls.progress.begin(
            token, lsp_types.WorkDoneProgressBegin(kind="begin", title=msg, percentage=0)
        )

    return token


class RuleDependencyIdentifier(yaramod.ObservingVisitor):  # type: ignore
    """A class for obtaining rules that are in the condition (recursively)."""

    def __init__(self) -> None:
        super().__init__()
        self.discovered_rules: set[str] = set()
        self.last_rule: yaramod.Rule = None

    def indirectly_affected(self, yara_file: yaramod.YaraFile, root_rule: str) -> set[str]:
        self.discovered_rules = {root_rule}

        last_discovered: set[str] = set()
        while last_discovered != self.discovered_rules:
            last_discovered = set(self.discovered_rules)
            for rule in yara_file.rules:
                self.last_rule = rule
                self.observe(rule.condition)

        return self.discovered_rules

    def visit_IdExpression(self, expr: yaramod.IdExpression) -> None:
        if self.last_rule and self.last_rule.name in self.discovered_rules:
            self.discovered_rules.add(expr.symbol.name)


def extract_rule_context_from_yarafile(yara_file: yaramod.YaraFile, rule: yaramod.Rule) -> str:
    """Extract specified rule, private rules and modules it is dependent on from YaraFile."""

    # Get rules ordered from deepest dependency to `rule` so they can be compiled.
    rule_names = RuleDependencyIdentifier().indirectly_affected(yara_file, rule.name)
    rule_context = "\n\n".join(rule.text for rule in yara_file.rules if rule.name in rule_names)

    # Import only modules that are needed by context
    imports = "\n".join(
        f'import "{module.name}"'
        for module in yara_file.imports
        if re.search(rf"\W{module.name}\.", rule_context)
    )
    if imports:
        rule_context = imports + "\n\n" + rule_context

    return rule_context


def text_from_range(document: Document, expr_range: lsp_types.Range) -> str:
    """Extract text from `document` which is located in provided `range`"""
    first_line = document_line(document, expr_range.start.line)

    if expr_range.start.line == expr_range.end.line:
        return first_line[expr_range.start.character : expr_range.end.character]
    else:
        expr = first_line[expr_range.start.character :]

        for line_idx in range(expr_range.start.line + 1, expr_range.end.line):
            expr += document_line(document, line_idx) + "\n"

        end_line = document_line(document, expr_range.end.line)
        expr += end_line[0 : expr_range.end.character + 1]
        return expr


def range_to_expression(document: Document, _range: lsp_types.Range) -> lsp_types.Range | None:
    """Converts selected range in expression to the smallest possible Yaramod expression that covers the entire range."""
    yara_file = yaramod_parse_file(document.path)
    if yara_file is None:
        return None

    start = cursor_expression(yara_file, _range.start)
    end = cursor_expression(yara_file, _range.end)

    if start and end:
        return lsp_types.Range(
            start=range_from_yaramod_expression(start).start,
            end=range_from_yaramod_expression(end).end,
        )
    else:
        return None


def remove_whitespace(text: str) -> str:
    """Remove redundant whitespaces to display text in a single line."""
    return re.sub(r"\s+", " ", text)


def truncate_message(text: str, limit: int = 150) -> str:
    return (text[:limit] + "..") if len(text) > limit else text


async def get_config_from_editor(ls: Any, section: str) -> Any:
    """Get the configuration from the editor."""
    config = await ls.get_configuration_async(
        lsp_types.ConfigurationParams(
            items=[lsp_types.ConfigurationItem(scope_uri="", section=section)]
        )
    )

    # We should get list of configuration items here with exactly one element
    assert isinstance(config, list)
    assert len(config) == 1

    return config[0]
