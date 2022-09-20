from __future__ import annotations

from glob import glob
import logging
import os
import re
from typing import Any

import yari

from yls import utils
from yls.hookspecs import InfoMessage, ErrorMessage, PopupMessage

log = logging.getLogger(__name__)


class Debugger:
    def __init__(self) -> None:
        self.samples_dir: str | None = None
        self.context_rule_name: str | None = None
        self.ctxs: dict[str, yari.Context] = {}

    async def set_context(self, sample_hash: str, ruleset: str) -> PopupMessage:
        log.debug(f"[DEBUGGER] Setting context on bundled YARI to {sample_hash}")
        self.ctxs = {}

        self.context_rule_name = re.findall(r"(?<=^rule )\w+(?= {$)", ruleset, re.MULTILINE)[-1]

        if not self.samples_dir:
            return ErrorMessage("Samples folder is not set")

        files = glob(os.path.join(self.samples_dir, "**", sample_hash + "*"), recursive=True)

        log.debug(
            f"[DEBUGGER] Found sample and module files for hash \"{sample_hash}\": {', '.join(files)}"
        )
        if not files:
            return ErrorMessage(f"Sample with hash {sample_hash} not found in local directory")

        # Sort files into groups by type of source
        sample, module = None, None
        for f in files:
            if f.endswith(sample_hash) and not sample:
                sample = f
            elif not module:
                module = f
            else:
                break

        if sample:
            self.ctxs["SAMPLE"] = yari.Context(  # pylint: disable=no-member
                sample=sample, rule_string=ruleset
            )

            if module:
                self.ctxs["CUCKOO"] = yari.Context(  # pylint: disable=no-member
                    sample=sample, module_data={"cuckoo": module}, rule_string=ruleset
                )

        return InfoMessage(
            f"Connection to debugger established with context(\n\t{sample_hash},\n\t{utils.truncate_message(ruleset)}\n)"
        )

    def set_samples_dir(self, _dir: str) -> str:
        log.debug(f'[DEBUGGER] Samples directory has been set to: "{_dir}"')
        self.samples_dir = _dir
        return _dir

    def eval(self, expr: str) -> str | PopupMessage:
        if not self.ctxs:
            return ErrorMessage("YARI is not ready to evaluate... Ignoring evaluation request")

        if self.context_rule_name:
            expr = f"{self.context_rule_name}|{expr}"

        result = ""
        for source, ctx in self.ctxs.items():
            res = ctx.eval(expr)
            log.debug(f"[DEBUGGER] source {source} returned value {res}")
            result += self.display_eval_response(source, res)
        return result

    @classmethod
    def display_eval_response(cls, source: str, value: Any) -> str:
        """Convert EvalResponse to string."""
        return f"- {cls.display_context_source(source)} -> {cls.display_py_object(value)}\n"

    @staticmethod
    def display_context_source(source: str) -> str:
        """Convert context source to string."""
        return f"context({source})"

    @staticmethod
    def display_py_object(value: Any) -> str:
        """Convert YrValue to string."""
        res = ""
        if isinstance(value, int):
            res = f"Integer ({value}, {hex(value)}) -> {bool(value)}"
        elif isinstance(value, str):
            res = f"String ({value}) -> {bool(value)}"
        elif isinstance(value, float):
            res = f"Float ({value}) -> {bool(value)}"
        else:
            log.warning(f"Unknown type of value {value}")

        return res


class DebuggerProvider:
    """Singleton class providing Debugger object."""

    debugger = None

    @classmethod
    def instance(cls) -> Debugger:
        """Return singleton instance."""
        if cls.debugger is None:
            cls.debugger = Debugger()
        return cls.debugger
