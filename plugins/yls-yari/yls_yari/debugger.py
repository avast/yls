from __future__ import annotations
from glob import glob
import logging
import os
import re
import yari
from typing import Any, Optional

import pygls.lsp.types as lsp_types
from yls import hookimpl
from yls.hookspecs import EvalError
from yls.hookspecs import PluggyRes

log = logging.getLogger(__name__)

class Debugger:
    def __init__(self) -> None:
        self.samples_dir: Optional[str] = None
        self.context_rule_name: Optional[str] = None
        self.ctxs: dict[yari.Context] = {}

    async def set_context(self, sample_hash: str, ruleset: str) -> str | EvalError:
        log.debug(f"[DEBUGGER] Setting context on bundled YARI to {sample_hash}")
        self.ctxs = {}
        self.ctxs["GENERIC"] = yari.Context(rule_string=ruleset)

        self.context_rule_name = re.findall(
            r"(?<=^rule )\w+(?= {$)", ruleset, re.MULTILINE
        )[-1]

        if not self.samples_dir:
            return EvalError(
                f"Samples folder is not set",
                lsp_types.MessageType.Error,
            )
        else:
            files = glob(os.path.join(self.samples_dir, "**", sample_hash + "*"), recursive=True)
            log.debug(f"[DEBUGGER] Found sample and module files for hash \"{sample_hash}\": {', '.join(files)}")
            # TODO: what if more samples with the same hash are found
            if files:
                for f in files:
                    if f.endswith(sample_hash):
                        self.ctxs["SAMPLE"] = yari.Context(sample=f, rule_string=ruleset)
                    else:
                        # TODO: support other modules
                        self.ctxs["CUCKOO"] = yari.Context(module_data={"cuckoo": f}, rule_string=ruleset)
                return sample_hash

                return EvalError(
                    f"Connection to debugger established with context({sample_hash}, {ruleset})",
                    lsp_types.MessageType.Info,
                )
            else:
                return EvalError(
                f"Sample with hash {sample_hash} not found in local directory",
                lsp_types.MessageType.Error,
            )


    def set_samples_dir(self, _dir: str) -> str:
        log.debug(f"[DEBUGGER] Samples directory has been set to: \"{_dir}\"")
        self.samples_dir = _dir
        return _dir

    def eval(self, expr: str) -> Any | EvalError:
        if not self.ctxs:
            return EvalError(
                "YARI is not ready to evaluate... Ignoring evaluation request"
            )

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

DEBUGGER = Debugger()


@hookimpl
def yls_eval_set_samples_dir(
    ls: Any, _dir: str  # pylint: disable=unused-argument
) -> str:
    return DEBUGGER.set_samples_dir(_dir)


@hookimpl
def yls_eval(
    ls: Any,  # pylint: disable=unused-argument
    expr: str,
) -> PluggyRes[str | EvalError]:
    return DEBUGGER.eval(expr)


@hookimpl
def yls_eval_set_context(
    ls: Any, _hash: str, ruleset: str  # pylint: disable=unused-argument
) -> PluggyRes[str | EvalError]:
    return DEBUGGER.set_context(_hash, ruleset)


@hookimpl
def yls_eval_enabled() -> bool:
    return True
