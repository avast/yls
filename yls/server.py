from __future__ import annotations

import functools
import logging
import pathlib
import re
from typing import Any

import pygls.lsp.types as lsp_types
import yaramod
from pygls.lsp.methods import CODE_ACTION
from pygls.lsp.methods import CODE_LENS
from pygls.lsp.methods import COMPLETION
from pygls.lsp.methods import DEFINITION
from pygls.lsp.methods import DOCUMENT_HIGHLIGHT
from pygls.lsp.methods import DOCUMENT_SYMBOL
from pygls.lsp.methods import FORMATTING
from pygls.lsp.methods import HOVER
from pygls.lsp.methods import INITIALIZED
from pygls.lsp.methods import REFERENCES
from pygls.lsp.methods import SIGNATURE_HELP
from pygls.lsp.methods import TEXT_DOCUMENT_DID_CHANGE
from pygls.lsp.methods import TEXT_DOCUMENT_DID_OPEN
from pygls.lsp.methods import TEXT_DOCUMENT_DID_SAVE
from pygls.lsp.methods import WORKSPACE_DID_CHANGE_CONFIGURATION
from pygls.server import LanguageServer
from pygls.uris import from_fs_path

from yls import code_actions
from yls import icons
from yls import linting
from yls import utils
from yls.version import __version__
from yls.completer import Completer
from yls.hookspecs import ErrorMessage
from yls.hover import Hoverer
from yls.plugin_manager_provider import PluginManagerProvider
from yls.yaramod_provider import YaramodProvider

log = logging.getLogger(__name__)

utils.setup_logging()

# NOTE: All yaramod parsing can fail, create wrapper
# if we fail fallback to cached YaraFile (last valid)


class YaraLanguageServer(LanguageServer):
    """YaraLanguageServer implementation."""

    COMMAND_SCAN = "yls.scan"
    COMMAND_SCAN_ALL = "yls.scan_all"
    COMMAND_EVAL_SET_CONTEXT = "yls.eval_set_context"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        log.debug("[__init__] LanguageServer constructor")

        # Yaramod parser provider
        self.ymod = YaramodProvider.instance()

        # Completion manager
        self.completer = Completer(self)

        # Hover manager
        self.hoverer = Hoverer(self)

        # Show debugging information on hover
        self.debug_hover = False

        # Lint the file when editing the document
        self.did_change_lint = False

        # Cached version of yara file used for completions
        # NOTE: We need to create dict not only one variable
        self.last_valid_yara_file = None

        self.register_plugin_commands()

    def register_plugin_commands(self) -> None:
        """Initialize the custom commands from plugins."""

        async def command_wrapper(command: str, ls: YaraLanguageServer, params: Any) -> Any:
            """Generic command hadler that delegates the custom commands to plugins."""
            log.info(f"Executing registered {command=} from plugins with {params=}")
            return await utils.pluggy_results(
                PluginManagerProvider.instance().hook.yls_execute_command(
                    command=command, ls=ls, params=params
                )
            )

        # Get the list of commands to register
        commands_to_register = utils.flatten_list(
            PluginManagerProvider.instance().hook.yls_supported_commands(ls=self)
        )
        for command in commands_to_register:
            func = functools.partial(command_wrapper, command)
            self.command(command)(func)

    def did_change_configuration(self) -> None:
        """Server changed the configuration.

        This function will fetch the latest configuration and set the YLS state accordingly.
        """

        def _config_callback(config: Any) -> None:
            try:
                conf = config[0]
                log.debug(f"[did_change_configuration] yls configuration is: {config[0]}")
                self.debug_hover = conf.debug.hover

            except Exception as e:  # pylint: disable=broad-except
                log.error(f"[did_change_configuration] Error occurred: {e}")

        # Request the configuration from the client for "yls"
        self.get_configuration(
            lsp_types.ConfigurationParams(
                items=[lsp_types.ConfigurationItem(scope_uri="", section="yls")]
            ),
            _config_callback,
        )

    def get_current_rule(
        self, uri: str, position: lsp_types.Position, yara_file: yaramod.YaraFile | None = None
    ) -> yaramod.Rule | None:
        """Get the last defined rule for given cursor position."""
        doc_path = pathlib.Path(self.workspace.get_document(uri).path)
        log.debug(f"[GET_CURRENT_RULE] Position={position}, Document={doc_path}")

        parsed_yfile = yara_file or utils.yaramod_parse_file(str(doc_path))
        if parsed_yfile is None:
            return None

        last_rule = None
        for rule in parsed_yfile.rules:
            if (
                rule.location.file_path
                and doc_path.exists()
                and doc_path.samefile(rule.location.file_path)
                and rule.location.begin.line > position.line
            ):
                return last_rule
            last_rule = rule
        return last_rule

    def get_references(
        self, uri: str, word: str, cursor: lsp_types.Position | None = None
    ) -> list[lsp_types.Location]:
        """Return list of locations that textually match given word."""
        text_doc = self.workspace.get_document(uri)
        source = text_doc.source
        res = []
        for m in re.finditer(re.escape(word), source):
            offset = m.start()
            line_counter = 0
            match_len = m.end() - m.start()
            for line in source.splitlines(keepends=True):
                line_len = len(line)
                if offset >= line_len:
                    offset -= line_len
                    line_counter += 1
                else:
                    # NOTE: Also we should check the character
                    if cursor and cursor.line == line_counter:
                        # Ignore this match
                        break

                    res.append(
                        lsp_types.Location(
                            uri=uri,
                            range=utils.range_from_coords(
                                (line_counter, offset), (line_counter, offset + match_len)
                            ),
                        )
                    )
                    break

        return res

    def show_error_message(self, msg: str, log_msg: str | None = None) -> None:
        """Show error message to user (also log it)."""
        log.error(f"[SHOW_ERROR_MESSAGE] {log_msg or msg}")
        self.show_message(msg, lsp_types.MessageType.Error)


# The main YLS Server instance
SERVER = YaraLanguageServer("yara-language-server", f"v{__version__}")


@SERVER.feature(WORKSPACE_DID_CHANGE_CONFIGURATION)
def did_change_configuration(ls: YaraLanguageServer, _params: Any) -> None:
    """Configuration was changed.

    This notification is somehow not being triggered. See `set_traceback` comment.
    """
    utils.log_command(WORKSPACE_DID_CHANGE_CONFIGURATION)
    log.debug("[DID_CHANGE_CONFIGURATION] Configuration was changed")
    ls.did_change_configuration()


@SERVER.feature("$/setTraceNotification")
def set_traceback(ls: YaraLanguageServer, params: Any) -> None:
    """Set traceback notification.

    This feature is declared manually because the pygls does not support it yet.
    It is proposed in the 3.16 version. Params include `TraceValue` which can be
    one of `{'off', 'message', 'verbose'}`.

    Based on tests it looks like this is send in the event of configuration change
    instead of WORKSPACE_DID_CHANGE_CONFIGURATION.
    """
    log.debug(
        "[SET_TRACE_NOTIFICATION] Received setTraceNotification, "
        "this could mean that the configuration was changed."
    )
    log.debug(params)
    ls.did_change_configuration()


@SERVER.feature(INITIALIZED)
def initiliazed(ls: YaraLanguageServer, _params: Any) -> None:
    """Connection is initialized."""
    utils.log_command(INITIALIZED)
    log.debug("[INITIALIZED] Connection was established")
    ls.did_change_configuration()
    # NOTE: In the future we can parse all files in the workspace


@SERVER.feature(COMPLETION, lsp_types.CompletionOptions(trigger_characters=["."]))
def completion(
    ls: YaraLanguageServer, params: lsp_types.CompletionParams
) -> lsp_types.CompletionList:
    """Code completion."""
    utils.log_command(COMPLETION)

    return ls.completer.complete(params)


@SERVER.feature(SIGNATURE_HELP, lsp_types.SignatureHelpOptions(trigger_characters=["("]))
def signature_help(
    ls: YaraLanguageServer, params: lsp_types.CompletionParams
) -> lsp_types.SignatureHelp | None:
    """Signature help."""
    utils.log_command(SIGNATURE_HELP)

    return ls.completer.signature_help(params)


@SERVER.feature(HOVER)
async def hover(
    ls: YaraLanguageServer, params: lsp_types.TextDocumentPositionParams
) -> lsp_types.Hover | None:
    """Cursor over information."""
    utils.log_command(HOVER)

    return await ls.hoverer.hover(params)


def lint(
    ls: YaraLanguageServer,
    params: lsp_types.DidOpenTextDocumentParams
    | lsp_types.DidChangeTextDocumentParams
    | lsp_types.DidSaveTextDocumentParams,
) -> None:
    """Lint and publish diagnostics."""
    # NOTE: DiagnosticRelatedInformation can be used to show the redefinition of a rule/string
    # Represents a related message and source code location for a diagnostic. This should be
    # used to point to code locations that cause or are related to a diagnostics, e.g when
    # duplicating a symbol in a scope.

    text_doc = ls.workspace.get_document(params.text_document.uri)
    log.info(f'[LINT] Lint request start for file "{text_doc.path}"')

    # Save the last valid yarafile, that can be used as a fallback in subsequent requests
    yara_file = utils.yaramod_parse_file(text_doc.path)
    if yara_file is not None:
        ls.last_valid_yara_file = yara_file

    diag = linting.get_diagnostics(text_doc)

    ls.publish_diagnostics(text_doc.uri, diag)


@SERVER.feature(TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: YaraLanguageServer, params: lsp_types.DidOpenTextDocumentParams) -> None:
    """The document was opened."""
    utils.log_command(TEXT_DOCUMENT_DID_OPEN)
    lint(ls, params)


@SERVER.feature(TEXT_DOCUMENT_DID_SAVE)
def did_save(ls: YaraLanguageServer, params: lsp_types.DidSaveTextDocumentParams) -> None:
    """The document was saved."""
    utils.log_command(TEXT_DOCUMENT_DID_SAVE)
    lint(ls, params)


@SERVER.feature(TEXT_DOCUMENT_DID_CHANGE)
def did_change(ls: YaraLanguageServer, params: lsp_types.DidChangeTextDocumentParams) -> None:
    """The document was changed."""
    utils.log_command(TEXT_DOCUMENT_DID_CHANGE)
    if ls.did_change_lint:
        lint(ls, params)


@SERVER.feature(FORMATTING)
def formatting(
    ls: YaraLanguageServer, params: lsp_types.DocumentFormattingParams
) -> list[lsp_types.TextEdit]:
    """Format the whole buffer."""
    utils.log_command(FORMATTING)

    document = ls.workspace.get_document(params.text_document.uri)
    source = document.source
    path_str = document.path
    path = pathlib.Path(path_str)

    # Check if the file exists also on the filesystem, not only in the editor buffer.
    if not path.exists():
        ls.show_message("Please save the file before formatting.", lsp_types.MessageType.Warning)
        return []

    # Open current file from the disk using `binary` mode in order to preserve
    # original new-lines of the file.
    with open(path_str, "rb") as disk_yfile:
        disk_source = disk_yfile.read()

    # Compare contents with the editor buffer converted to bytes, in case they
    # are not the same the file was not saved to the disk and we should not proceed
    if source.encode() != disk_source:
        ls.show_message("Please save the file before formatting.", lsp_types.MessageType.Warning)
        return []

    res: list[lsp_types.TextEdit] = PluginManagerProvider.instance().hook.yls_formatting(
        ls=ls, params=params, document=document
    )

    return res


@SERVER.feature(DEFINITION)
def definition(
    ls: YaraLanguageServer, params: lsp_types.TextDocumentPositionParams
) -> list[lsp_types.Location] | None:
    """Jump to definition."""
    utils.log_command(DEFINITION)
    text_doc = ls.workspace.get_document(params.text_document.uri)
    token = utils.cursor_token(text_doc, params.position)
    if not token:
        return None

    res = []

    log.debug(f'[DEFINITION] Cursor in on token "{token}" with type "{token.type}"')
    if token.type == yaramod.TokenType.StringId:
        log.debug(f'[DEFINITION] Searching for "{token.text}" string definition')

        rule = ls.get_current_rule(params.text_document.uri, params.position)
        if rule is None:
            return None
        log.debug('[DEFINITION] Current rule "{rule}" with name "{rule.name}"')

        for string in rule.strings:
            if string.identifier == token.pure_text:
                res.append(
                    lsp_types.Location(
                        uri=params.text_document.uri,
                        range=utils.range_from_coords(
                            (string.location.begin.line - 1, string.location.begin.column - 1),
                            (string.location.end.line - 1, string.location.begin.column - 1),
                        ),
                    )
                )
                # Since strings cannot be redefined in a single rule there is
                # no reason to continue this loop and immediately return
                break
    elif token.type == yaramod.TokenType.Id:
        log.debug(f'[DEFINITION] Searching for "{token.text}" rule definition')
        path = ls.workspace.get_document(params.text_document.uri).path
        yara_file = utils.yaramod_parse_file(path)
        if yara_file is None:
            return []

        for rule in yara_file.rules:
            if rule.name == token.pure_text:
                res.append(
                    lsp_types.Location(
                        uri=from_fs_path(rule.location.file_path),
                        range=utils.range_from_coords(
                            (rule.location.begin.line - 1, rule.location.begin.column - 1),
                            (rule.location.end.line - 1, rule.location.end.column),
                        ),
                    )
                )

    return res


@SERVER.feature(REFERENCES)
def references(
    ls: YaraLanguageServer, params: lsp_types.ReferenceParams
) -> list[lsp_types.Location]:
    """Provide a list of references for the object under the cursor."""
    utils.log_command(REFERENCES)
    text_doc = ls.workspace.get_document(params.text_document.uri)
    cursor_string = utils.cursor_word(text_doc, params.position)
    log.debug(f'[REFERENCES] Searching for references of "{cursor_string}"')
    if cursor_string:
        return ls.get_references(params.text_document.uri, cursor_string, cursor=params.position)
    return []


@SERVER.feature(DOCUMENT_HIGHLIGHT)
def document_highlight(
    ls: YaraLanguageServer, params: lsp_types.TextDocumentPositionParams
) -> list[lsp_types.DocumentHighlight]:
    """Highlight references of the object under the cursor."""
    utils.log_command(DOCUMENT_HIGHLIGHT)
    text_doc = ls.workspace.get_document(params.text_document.uri)
    token = utils.cursor_token(text_doc, params.position)
    if not token:
        return []

    if token.type not in [
        yaramod.TokenType.Id,
        yaramod.TokenType.RuleName,
        yaramod.TokenType.StringId,
        yaramod.TokenType.StringIdAfterNewline,
    ]:
        return []

    refs = ls.get_references(params.text_document.uri, token.pure_text)
    res = [
        lsp_types.DocumentHighlight(
            range=utils.range_from_coords(
                (ref.range.start.line, ref.range.start.character),
                (ref.range.end.line, ref.range.end.character),
            )
        )
        for ref in refs
    ]

    return res


# NOTE: For now unimplemented
# @SERVER.feature(WORKSPACE_SYMBOL)
# def workspace_symbol(
#     ls: YaraLanguageServer, params: lsp_types.WorkspaceSymbolParams
# ) -> Optional[List[lsp_types.SymbolInformation]]:
#     """Create list of symbols in the current workspace."""
#     utils.log_command(WORKSPACE_SYMBOL)
#     # NOTE: This needs to find all *.yar files in the workspace and provide information on them
#     return None


@SERVER.feature(DOCUMENT_SYMBOL)
def document_symbol(
    ls: YaraLanguageServer, params: lsp_types.DocumentSymbolParams
) -> list[lsp_types.DocumentSymbol]:
    """Provide a list of symbols in the current document."""
    utils.log_command(DOCUMENT_SYMBOL)
    text_doc = ls.workspace.get_document(params.text_document.uri)

    res: list[lsp_types.DocumentSymbol] = []
    parsed_yfile = utils.yaramod_parse_file(text_doc.path)
    if parsed_yfile is None:
        return []

    for rule in utils.yaramod_rules_in_file(parsed_yfile):

        # Construct the string information for this rule. This is necessary because yls is
        # creating the whole document symbol hierarchy instead of flat list
        rule_strings: list[lsp_types.DocumentSymbol] = []
        for string in rule.strings:
            rule_strings.append(
                lsp_types.DocumentSymbol(
                    name=string.identifier,
                    detail=string.text,
                    kind=lsp_types.SymbolKind.String,
                    range=utils.range_from_coords(
                        (string.location.begin.line - 1, string.location.begin.column - 1),
                        (string.location.end.line, string.location.end.column),
                    ),
                    selection_range=utils.range_from_coords(
                        (string.location.begin.line - 1, string.location.begin.column - 1),
                        (string.location.end.line, string.location.end.column),
                    ),
                )
            )

        res.append(
            lsp_types.DocumentSymbol(
                name=rule.name,
                kind=lsp_types.SymbolKind.Class,
                range=utils.range_from_coords(
                    (rule.location.begin.line - 1, rule.location.begin.column),
                    (rule.location.end.line - 1, rule.location.end.column),
                ),
                selection_range=utils.range_from_coords(
                    (rule.location.begin.line - 1, rule.location.begin.column),
                    (rule.location.begin.line - 1, rule.location.begin.column),
                ),
                children=rule_strings,
            )
        )

    return res


@SERVER.feature(CODE_ACTION)
def code_action(
    ls: YaraLanguageServer, params: lsp_types.CodeActionParams
) -> list[lsp_types.Command | lsp_types.CodeAction] | None:
    """List available code actions for given context."""
    utils.log_command(CODE_ACTION)

    # Provide hoverer service with selected text range context
    ls.hoverer.selected_range = params.range
    return code_actions.from_params(ls, params)


def code_lens_eval(yara_file: yaramod.YaraFile) -> list[lsp_types.CodeLens]:
    """Create evaluation code lenses from YaraFile."""
    yls_eval_enabled = any(PluginManagerProvider.instance().hook.yls_eval_enabled())
    if not yls_eval_enabled:
        return []

    res = []
    for rule in utils.yaramod_rules_in_file(yara_file):
        for meta in rule.metas:
            # Consider only hash metas that have valid hash as value
            if meta.key != "hash" and not utils.is_sha256_hash(meta.value.pure_text):
                continue

            # Create code lens for debugging
            lens = lsp_types.CodeLens(
                range=utils.range_from_coords(
                    (meta.token_key.location.begin.line - 1, meta.token_key.location.begin.column),
                    (meta.token_value.location.end.line - 1, meta.token_value.location.end.column),
                ),
                command=lsp_types.Command(
                    title=f"{icons.SEARCH} Select hash for context",
                    command=YaraLanguageServer.COMMAND_EVAL_SET_CONTEXT,
                    arguments=[
                        meta.value.pure_text,
                        utils.extract_rule_context_from_yarafile(yara_file, rule),
                    ],
                ),
            )
            res.append(lens)

    return res


def code_lens_scan(yara_file: yaramod.YaraFile, uri: str) -> list[lsp_types.CodeLens]:
    """Create scannig code lenses from YaraFile."""
    yls_scan_enabled = any(PluginManagerProvider.instance().hook.yls_scan_enabled())
    if not yls_scan_enabled:
        return []

    res = []
    for rule in utils.yaramod_rules_in_file(yara_file):
        if not utils.yaramod_rule_has_hashes(rule):
            continue

        # Create code lens for scans
        lens_scan = lsp_types.CodeLens(
            range=utils.range_from_yaramod_token(rule.token_first),
            command=lsp_types.Command(
                title=f"{icons.PLAY} Scan",
                command=YaraLanguageServer.COMMAND_SCAN,
                arguments=[uri, rule.name],
            ),
        )
        res.append(lens_scan)

    return res


@SERVER.feature(CODE_LENS)
def code_lens(ls: YaraLanguageServer, params: lsp_types.CodeLensParams) -> list[lsp_types.CodeLens]:
    utils.log_command(CODE_LENS)

    text_doc = ls.workspace.get_document(params.text_document.uri)
    path = text_doc.path

    yara_file = utils.yaramod_parse_file(path)
    if yara_file is None:
        return []

    res = []
    res.extend(
        utils.flatten_list(
            PluginManagerProvider.instance().hook.yls_code_lens(ls=ls, params=params)
        )
    )

    res.extend(code_lens_eval(yara_file))
    res.extend(code_lens_scan(yara_file, params.text_document.uri))

    return res


@SERVER.command(YaraLanguageServer.COMMAND_SCAN)
async def command_scan(ls: YaraLanguageServer, args: list[Any]) -> None:
    utils.log_command(YaraLanguageServer.COMMAND_SCAN)
    log.debug(f"{args=}")

    if len(args) != 2:
        return

    file_uri = args[0]
    rule_name = args[1]
    document = ls.workspace.get_document(file_uri)

    scan_results = await utils.pluggy_results(
        PluginManagerProvider.instance().hook.yls_scan(
            ls=ls, document=document, rule_name=rule_name
        )
    )

    for diagnostics in scan_results:
        ls.publish_diagnostics(document.uri, diagnostics)


@SERVER.command(YaraLanguageServer.COMMAND_SCAN_ALL)
async def command_scan_all(ls: YaraLanguageServer, args: list[Any]) -> None:
    utils.log_command(YaraLanguageServer.COMMAND_SCAN_ALL)
    log.debug(f"{args=}")

    if len(args) != 1:
        return
    file_uri = args[0]

    document = ls.workspace.get_document(file_uri)

    scan_results = await utils.pluggy_results(
        PluginManagerProvider.instance().hook.yls_scan(ls=ls, document=document, rule_name=None)
    )

    for diagnostics in scan_results:
        ls.publish_diagnostics(document.uri, diagnostics)


@SERVER.command(YaraLanguageServer.COMMAND_EVAL_SET_CONTEXT)
async def command_eval_set_context(ls: YaraLanguageServer, args: list[Any]) -> None:
    utils.log_command(YaraLanguageServer.COMMAND_EVAL_SET_CONTEXT)
    log.debug(f"{args=}")

    if len(args) != 2 or not utils.is_sha256_hash(args[0]):
        return

    _hash = args[0]
    ruleset = args[1]

    res_set_contexts = await utils.pluggy_results(
        PluginManagerProvider.instance().hook.yls_eval_set_context(
            ls=ls, _hash=_hash, ruleset=ruleset
        )
    )

    res_success = next((res for res in res_set_contexts if not isinstance(res, ErrorMessage)), None)

    if res_success:
        res_success.show(ls)
    else:
        for i, res_set_context in enumerate(res_set_contexts):
            if len(res_set_contexts) > 1:
                res_set_context.message = f"{utils.DEBUGGER_SOURCES[i]}: {res_set_context.message}"
            log.debug(res_set_context.message)
            res_set_context.show(ls)


def main() -> None:
    """YLS entry point."""

    # Parse command line arguments
    args = utils.create_options_parser().parse_args()

    utils.set_logging_level(args.verbose)
    utils.logging_prolog(PluginManagerProvider.instance())

    SERVER.start_io()


if __name__ == "__main__":
    main()
