from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yari

from yls import utils
from yls.hookspecs import ErrorMessage
from yls.hookspecs import InfoMessage
from yls.hookspecs import PopupMessage

log = logging.getLogger(__name__)


class Debugger:
    def __init__(self) -> None:
        self.context_rule_name: str | None = None
        self.ctxs: dict[str, yari.Context] = {}

    async def set_context(self, ls: Any, sample_hash: str, ruleset: str) -> PopupMessage:
        log.debug(f"[DEBUGGER] Setting context on bundled YARI to {sample_hash}")
        self.ctxs = {}

        self.context_rule_name = re.findall(r"(?<=^rule )\w+(?= {$)", ruleset, re.MULTILINE)[-1]

        samples_dir = await self.get_samples_dir(ls)
        if samples_dir is None:
            return ErrorMessage("Samples folder is not set")

        files = list(samples_dir.rglob(f"{sample_hash}*"))

        log.debug(f'[DEBUGGER] Found sample and module files for hash "{sample_hash}": {files}')
        if not files:
            return ErrorMessage(f"Sample {sample_hash} not found in {samples_dir}")

        # Sort files into groups by type of source
        sample: str | None = None
        module: str | None = None
        for f in files:
            if f.name == sample_hash and not sample:
                sample = str(f)
            elif not module:
                module = str(f)
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

    def eval(self, expr: str) -> str | PopupMessage:
        log.info(f"[DEBUGGER] Evaluating {expr}")
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

    @staticmethod
    async def get_samples_dir(ls: Any) -> Path | None:
        samples_dir_config = await utils.get_config_from_editor(ls, "yls.yari.samplesDirectory")
        log.debug(f"[DEBUGGER] Got {samples_dir_config=}")
        samples_dir_path = Path(samples_dir_config)

        if not samples_dir_path.is_dir():
            log.debug("[DEBUGGER] Samples dir does not exist or is not a directory")
            return None

        if len(list(samples_dir_path.iterdir())) == 0:
            log.debug("[DEBUGGER] Samples dir is empty")
            return None

        return samples_dir_path


class DebuggerProvider:
    """Singleton class providing Debugger object."""

    debugger = None

    @classmethod
    def instance(cls) -> Debugger:
        """Return singleton instance."""
        if cls.debugger is None:
            cls.debugger = Debugger()
        return cls.debugger
