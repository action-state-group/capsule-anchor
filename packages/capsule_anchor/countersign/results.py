# SPDX-License-Identifier: Apache-2.0
"""The five-result vocabulary every check in this module returns.

Deliberately never pass/fail and never rolled up into a single score --
a statement lists each check's own result, always. A result is one of
exactly these five words; nothing else is ever written to a statement.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

Result = Literal["established", "failed", "not present", "not checked", "inconclusive"]

RESULTS: tuple[Result, ...] = (
    "established",
    "failed",
    "not present",
    "not checked",
    "inconclusive",
)


class CheckResult(BaseModel):
    """One check's outcome: ``{name, result, detail}``.

    ``detail`` names the thing that makes ``result`` true -- the checkpoint
    index, the sequence gap, the missing rotation record -- never a bare
    restatement of ``result``.
    """

    name: str
    result: Result
    detail: str = ""
