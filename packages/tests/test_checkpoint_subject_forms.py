# SPDX-License-Identifier: Apache-2.0
"""CWT `sub` forms of a CLL checkpoint (checkpointed-local-log -02).

-02 makes `sub` the log id (== `iss`), constant across every checkpoint of a
log; the pre-02 form `<iss>#<log_size>` must still verify. Anything else is
refused. The pinned CLL vectors (`vectors/cll-cose-vectors.json`, copied from
checkpointed-local-log `checkpoint-conformance-vectors/cose-vectors.json`)
carry both forms of the same statement.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from capsule_anchor.anchoring.checkpoint_cose import (
    NotACheckpointError,
    parse_and_verify_checkpoint_cose,
)
from fastapi.testclient import TestClient

from .test_checkpoints_and_register_witness_host import (
    _checkpoint_cose,
    _post_checkpoint,
    key,  # noqa: F401 -- fixture
)
from capsule_anchor.app import create_app

_VECTORS = json.loads((Path(__file__).parent / "vectors" / "cll-cose-vectors.json").read_text())["cases"]


@pytest.fixture()
def client():
    return TestClient(create_app())


@pytest.mark.parametrize("case", _VECTORS, ids=lambda c: c["name"])
@pytest.mark.parametrize("field", ["cose_hex", "pre02_cose_hex"])
def test_pinned_cll_vectors_verify(case, field):
    claims = parse_and_verify_checkpoint_cose(bytes.fromhex(case[field]))
    assert claims["kind"] == "mmr_checkpoint"
    assert claims["mmr_size"] > 0


def test_constant_log_id_subject_accepted(client, key):  # noqa: F811
    cose = _checkpoint_cose(key, log_id="log-S", mmr_size=10, subject="log-S")
    status, _ = _post_checkpoint(client, cose)
    assert status == 200


def test_pre02_per_checkpoint_subject_still_accepted(client, key):  # noqa: F811
    cose = _checkpoint_cose(key, log_id="log-S", mmr_size=10, subject="log-S#10")
    status, _ = _post_checkpoint(client, cose)
    assert status == 200


@pytest.mark.parametrize(
    "subject", ["other-log", "other-log#10", "log-S#9", "log-S#", "log-S#10#10", ""]
)
def test_foreign_subject_refused_400(client, key, subject):  # noqa: F811
    cose = _checkpoint_cose(key, log_id="log-S", mmr_size=10, subject=subject)
    status, body = _post_checkpoint(client, cose)
    assert status == 400
    assert "subject" in body["detail"].lower()


def test_parse_rejects_foreign_subject(key):  # noqa: F811
    cose = _checkpoint_cose(key, log_id="log-S", mmr_size=10, subject="log-T")
    with pytest.raises(NotACheckpointError, match="neither the log id"):
        parse_and_verify_checkpoint_cose(cose)
