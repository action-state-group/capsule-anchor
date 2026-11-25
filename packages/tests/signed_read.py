"""Test helper: the read headers a log's key holder sends to
``GET /checkpoints/{log_id}`` (``capsule_anchor.anchoring.checkpoint_read``)."""

from __future__ import annotations

import base64
import time

from capsule_anchor.anchoring.checkpoint_read import (
    READ_SIGNATURE_HEADER,
    READ_TIME_HEADER,
    read_message,
)


def signed_read_headers(private_key, log_id: str, at: int | None = None) -> dict[str, str]:
    t = str(int(time.time()) if at is None else at)
    signature = private_key.sign(read_message(log_id, t))
    return {
        READ_TIME_HEADER: t,
        READ_SIGNATURE_HEADER: base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }
