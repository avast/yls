# pylint: disable=duplicate-code,redefined-outer-name
# type: ignore

from __future__ import annotations

import asyncio
import logging
import os
import pathlib
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from threading import Thread
from typing import Any
from typing import List
from unittest.mock import patch

import pygls.protocol
import pytest
import pytest_yls.utils as _utils
import yaramod
from pygls.lsp import LSP_METHODS_MAP
from pygls.lsp import methods
from pygls.lsp import types
from pygls.server import LanguageServer
from tenacity import retry
from tenacity import stop_after_delay
from tenacity import wait_fixed

from yls.completion import CompletionCache
from yls.server import SERVER
from yls.server import YaraLanguageServer
from yls.yaramod_provider import YaramodProvider

SCHEMA_JSON_KEY = pytest.StashKey[str]()

# Enable logging, so that when the test fails they can be inspected
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger("pygls").propagate = True

log = logging.getLogger(__name__)


def pytest_addoption(parser):
    group = parser.getgroup("yls")
    group.addoption(
        "--yls-notification-timeout",
        action="store",
        dest="yls_notification_timeout",
        help="Notification timeout for YLS tests.",
    )
    group.addoption(
        "--yls-call-timeout",
        action="store",
        dest="yls_call_timeout",
        help="Call timeout for YLS tests.",
    )


class Context:
    """Testing context"""

    client: LanguageServer
    server: YaraLanguageServer
    cursor_pos: types.Position | None = None

    # Config from the client (editor)
    config: dict[str, Any]

    NOTIFICATION_TIMEOUT_SECONDS = 2.00
    CALL_TIMEOUT_SECONDS = 2.00
    LANGUAGE_ID = "yara"
    CURSOR_SYMBOL = "<$>"

    def __init__(
        self,
        client: LanguageServer,
        server: YaraLanguageServer,
        tmp_path: Path,
        pytest_config: Any,
        files: dict[str, str] | None = None,
        is_valid_yara_rules_repo: bool = False,
        config: dict[str, Any] | None = None,
    ):
        self.client = client
        self.server = server
        self.cursor_pos = None
        self.files = files or {}
        self.config = config or {}
        self.is_valid_yara_rules_repo = is_valid_yara_rules_repo
        self.notification_timeout_seconds = (
            int(pytest_config.getoption("yls_notification_timeout"))
            if pytest_config.getoption("yls_notification_timeout")
            else self.NOTIFICATION_TIMEOUT_SECONDS
        )
        self.call_timeout_seconds = (
            int(pytest_config.getoption("yls_call_timeout"))
            if pytest_config.getoption("yls_call_timeout")
            else self.CALL_TIMEOUT_SECONDS
        )

        log.info(f"{self.notification_timeout_seconds=}")
        log.info(f"{self.call_timeout_seconds=}")

        # Path for the test sandbox directory
        self.tmp_path = tmp_path

        if self.is_valid_yara_rules_repo:
            new_files = {}
            yara_rules_root = pathlib.PurePath("yara-rules")
            subprocess.run(
                ["git", "init", str(tmp_path / yara_rules_root)], capture_output=True, check=True
            )
            for name, contents in self.files.items():
                new_name = yara_rules_root / pathlib.PurePath(name)
                new_files[str(new_name)] = contents

            schema_json = pytest_config.stash.get(SCHEMA_JSON_KEY, "")
            new_files[str(yara_rules_root / "schema.json")] = schema_json
            self.files = new_files

        for name, contents in self.files.items():
            yar_file = self.tmp_path / name

            # Create directories if they don't exist
            yar_file.parent.mkdir(parents=True, exist_ok=True)

            new_text, cursor_pos = _utils.find_cursor(contents)
            yar_file.write_text(new_text)
            self.cursor_pos = cursor_pos or self.cursor_pos

        # Reset the captured notifications
        self.client.yls_notifications = defaultdict(list)

        # Initialize Language Server
        _ = self.send_request(
            methods.INITIALIZE,
            types.InitializeParams(
                process_id=1234,
                root_uri=self.tmp_path.as_uri(),
                capabilities=types.ClientCapabilities(),
            ),
        )

        # Open the file
        name = next(iter(self.files))
        self.open_file(name)

        # Setup the editor configuration
        self.client.editor_config = self.config

    def open_file(self, name: str) -> None:
        path = self.tmp_path / name
        if not path.exists():
            raise ValueError(
                f'USAGE ERROR: File "{name}" does not exists -> Please open one of prepared files'
            )

        self.notify(
            methods.TEXT_DOCUMENT_DID_OPEN,
            types.DidOpenTextDocumentParams(
                textDocument=types.TextDocumentItem(
                    uri=path.as_uri(),
                    language_id=Context.LANGUAGE_ID,
                    version=1,
                    text=path.read_text(),
                )
            ),
        )
        self.opened_file = path

    def send_request(self, feature: str, params: Any) -> Any:
        return self.client.lsp.send_request(feature, params).result(self.call_timeout_seconds)

    def notify(self, feature: str, params: Any) -> None:
        self.client.lsp.notify(feature, params)

    def wait_for_notification(self, feature_name: str) -> Any:
        @retry(
            stop=stop_after_delay(self.notification_timeout_seconds),
            wait=wait_fixed(self.notification_timeout_seconds / 10),
        )
        def get_notification(feature_name: str) -> Any:
            return self.client.yls_notifications[feature_name].pop(0)

        return get_notification(feature_name)

    def get_nofications(self, feature_name: str, skip_wait: bool = False) -> Any:
        if not skip_wait:
            time.sleep(self.notification_timeout_seconds)

        return self.client.yls_notifications[feature_name]

    def get_cursor_position(self) -> types.Position | None:
        if self.cursor_pos is None:
            raise ValueError("No cursor in current workspace is set")
        return self.cursor_pos

    def get_cursor_range(self) -> types.Range | None:
        if self.cursor_pos is None:
            raise ValueError("No cursor in current workspace is set")
        return types.Range(
            start=self.cursor_pos,
            end=types.Position(line=self.cursor_pos.line, character=self.cursor_pos.character + 1),
        )

    def get_file_path(self, name: str) -> Path:
        try:
            return self.tmp_path / name
        except KeyError as e:
            raise ValueError("File is not valid for this test-case.") from e

    def get_diagnostics(self) -> list[types.Diagnostic]:
        """Construct a list of Diagnostic objects for the file."""
        response = self.wait_for_notification(methods.TEXT_DOCUMENT_PUBLISH_DIAGNOSTICS)

        res = []
        # Construct the Diagnostic objects from the raw response
        for diag in response.diagnostics:
            start = diag.range.start
            end = diag.range.end
            _range = types.Range(
                start=types.Position(line=start.line, character=start.character),
                end=types.Position(line=end.line, character=end.character),
            )
            res.append(
                types.Diagnostic(
                    range=_range, message=diag.message, severity=diag.severity, source=diag.source
                )
            )

        return res


def pytest_configure(config: Any) -> None:
    config.addinivalue_line(
        "markers", "sleep: mark test that sleeps and waits for the notification"
    )
    config.addinivalue_line("markers", "slow: mark test that is slow")


@pytest.fixture(scope="session")
def ymod() -> yaramod.Yaramod:
    return YaramodProvider.instance()


@pytest.fixture()
def completion_cache(ymod) -> CompletionCache:
    return CompletionCache.from_yaramod(ymod)


@pytest.fixture
def yls_prepare(client_server: Any, tmp_path: Any, pytestconfig) -> Any:
    client, server = client_server

    def prep(contents: str) -> Context:
        yar_file = tmp_path / "file.yar"
        yar_file.write_text(contents)

        return Context(client, server, tmp_path, pytestconfig, {yar_file: contents}, False)

    return prep


@pytest.fixture
def yls_prepare_with_settings(client_server: Any, tmp_path: Any, pytestconfig) -> Any:
    client, server = client_server

    def prep(
        files: dict[str, str] | None = None,
        is_valid_yara_rules_repo: bool = False,
        config: dict[str, Any] | None = None,
    ) -> Context:
        return Context(
            client, server, tmp_path, pytestconfig, files, is_valid_yara_rules_repo, config=config
        )

    return prep


def reset_hooks(ls: LanguageServer) -> None:
    """Hook client (in this case editor) functionalities to be able to test them.

    Hooked functions just store the parameters, that will be later tested."""
    ls.yls_notifications = defaultdict(list)

    # Hook notifications
    _hook_feature(ls, methods.TEXT_DOCUMENT_PUBLISH_DIAGNOSTICS)
    _hook_feature(ls, methods.WINDOW_SHOW_MESSAGE)


def _hook_feature(ls: LanguageServer, feature_name: str) -> None:
    @ls.feature(feature_name)
    def hook(ls: LanguageServer, params: Any) -> None:
        ls.yls_notifications[feature_name].append(params)


def configuration_hook(ls, params):
    """WORKSPACE_CONFIGURATION hook"""
    editor_config = ls.editor_config
    items = params.items
    assert len(items) >= 1, "we currently only support single requests"
    config = editor_config
    item = items[0].section
    try:
        for part in item.split("."):
            config = config[part]
    except KeyError:
        config = None

    return [config]


@pytest.fixture(scope="session")
def client_server() -> Any:
    """A fixture to setup a client/server"""

    # Client to Server pipe
    c2s_r, c2s_w = os.pipe()
    # Server to client pipe
    s2c_r, s2c_w = os.pipe()

    # Setup server
    server = SERVER
    server_thread = Thread(
        target=server.start_io, args=(os.fdopen(c2s_r, "rb"), os.fdopen(s2c_w, "wb"))
    )

    server_thread.daemon = True
    server_thread.start()

    # Add thread id to the server (just for testing)
    server.thread_id = server_thread.ident

    # Setup client
    client = LanguageServer(asyncio.new_event_loop())

    reset_hooks(client)

    client.editor_config = {}

    # Hook configuration requests
    client.feature(methods.WORKSPACE_CONFIGURATION)(configuration_hook)

    client_thread = Thread(
        target=start_editor, args=(client, os.fdopen(s2c_r, "rb"), os.fdopen(c2s_w, "wb"))
    )

    client_thread.daemon = True
    client_thread.start()

    yield client, server

    client.lsp.notify(methods.EXIT)
    server.lsp.notify(methods.EXIT)
    client_thread.join()
    server_thread.join()


def start_editor(client, stdin, stdout):
    """Hook client editor) methods for configuration.

    We need to do this kind of setup because it is really hard to change LSP_METHODS_MAP.
    If you want to change the configuration just call Context.set_configuration().
    """
    log.info("[TESTS] Setting up the client (editor) hooks...")
    original_deserialize_params = pygls.protocol.deserialize_params

    def _deserialize_params(data, get_params_type):
        method = data.get("method")
        params = data.get("params")
        if method == methods.WORKSPACE_CONFIGURATION and params is not None:
            log.warning("[TESTS] We are altering the return value for deserialize_params")
            data["params"] = pygls.protocol.dict_to_object(**params)
            return data

        return original_deserialize_params(data, get_params_type)

    original_get_method_return_type = pygls.lsp.get_method_return_type

    # pylint: disable=dangerous-default-value
    def _get_method_return_type(method_name, lsp_methods_map=LSP_METHODS_MAP):
        if method_name == methods.WORKSPACE_CONFIGURATION:
            log.warning("[TESTS] We are altering the return value for get_method_return_type")
            return List[Any]

        return original_get_method_return_type(method_name, lsp_methods_map)

    patch("pygls.protocol.deserialize_params", _deserialize_params).start()
    patch("pygls.protocol.get_method_return_type", _get_method_return_type).start()

    client.start_io(stdin, stdout)
