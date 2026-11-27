# SPDX-License-Identifier: Apache-2.0
"""ci/witness-monitor/probe.py: when the hosted-witness monitor calls the witness unhealthy (#109)."""

from __future__ import annotations

import importlib.util
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "ci" / "witness-monitor" / "probe.py"
_spec = importlib.util.spec_from_file_location("witness_monitor_probe", _PATH)
probe = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = probe  # dataclasses look their module up there
_spec.loader.exec_module(probe)

S = probe.Sample


def run(samples, capsys, *args):
    """main() over canned samples; returns (exit code, printed lines, gaps slept)."""
    it, slept = iter(samples), []
    code = probe.main(["--samples", str(len(samples)), *args], get=lambda url, t: next(it),
                      sleep=slept.append)
    return code, capsys.readouterr().out.splitlines(), slept


@pytest.mark.parametrize("samples,ok", [
    ([S(200, 0.2), S(200, 0.3), S(200, 0.1)], True),  # all fast
    ([S(200, 9.0), S(200, 0.3), S(200, 0.1)], True),  # one slow of three
    ([S(200, 9.0), S(200, 6.0), S(200, 0.1)], False),  # two slow
    ([S(200, 5.0), S(200, 5.0), S(200, 5.0)], True),  # exactly the limit is not slow
    ([S(200, 5.01), S(200, 5.01), S(200, 0.1)], False),  # just over it
    ([S(200, 0.2), S(500, 0.3), S(200, 0.1)], False),  # an error status
    ([S(200, 0.2), S(None, 30.0, "TimeoutError: timed out"), S(200, 0.1)], False),  # a timeout
    ([S(None, 0.1, "SSLError: bad cert"), S(200, 0.3), S(200, 0.1)], False),  # TLS or connection
])
def test_verdict_and_one_line_per_sample(samples, ok, capsys):
    code, lines, slept = run(samples, capsys)
    assert code == (0 if ok else 1)
    assert len(lines) == 4  # every sample is printed, then the verdict
    assert lines[-1].startswith("healthy: " if ok else "UNHEALTHY: ")
    assert slept == [10.0, 10.0]


def test_limit_zero_fails_a_healthy_witness(capsys):
    """workflow_dispatch's limit 0 is the monitor's test alert: any answer is slow."""
    code, lines, _ = run([S(200, 0.01)] * 3, capsys, "--limit", "0")
    assert code == 1 and "longer than 0 s" in lines[-1]


def test_no_response_line_names_the_error(capsys):
    _, lines, _ = run([S(None, 30.0, "TimeoutError: timed out")], capsys)
    assert lines[0] == "probe 1: no response (TimeoutError: timed out) in 30.00 s"


def test_bad_counts_are_refused():
    with pytest.raises(SystemExit):
        probe.main(["--samples", "0"])


class _Handler(BaseHTTPRequestHandler):
    status, delay, mode = 200, 0.0, "ok"

    def do_GET(self):  # noqa: N802
        if self.path == "/landing":
            self.send_response(200)
            self.end_headers()
            return
        time.sleep(self.delay)
        if self.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "/landing")
            self.end_headers()
        elif self.mode == "trickle":  # a byte every 0.1 s, each within the socket timeout
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.1)
        elif self.mode == "slow-headers":  # each header line within the socket timeout, all of them past the limit
            self.send_response(200)
            for i in range(15):
                self.send_header(f"X-Slow-{i}", "1")
                self.flush_headers()
                time.sleep(0.1)
            self.end_headers()
            self.wfile.write(b"{}")
        elif self.mode == "truncated":  # closes before the declared length
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(b"{}")
            self.close_connection = True
        else:
            self.send_response(self.status)
            self.end_headers()
            self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()
    _Handler.status, _Handler.delay, _Handler.mode = 200, 0.0, "ok"


def _url(srv):
    return f"http://127.0.0.1:{srv.server_address[1]}/health"


def test_fetch_ok_and_error_status(server):
    assert probe.fetch(_url(server), 5).status == 200
    _Handler.status = 503
    assert probe.fetch(_url(server), 5).status == 503


def test_fetch_timeout(server):
    _Handler.delay = 1.0
    s = probe.fetch(_url(server), 0.2)
    assert s.status is None and s.error


def test_fetch_connection_refused():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    s = probe.fetch(f"http://127.0.0.1:{port}/health", 2)
    assert s.status is None and s.error


def test_fetch_does_not_follow_a_redirect(server):
    """A /health that redirects to a page answering 200 is not healthy."""
    _Handler.mode = "redirect"
    assert probe.fetch(_url(server), 5).status == 302


def test_fetch_bounds_the_whole_answer(server):
    """A body trickled in under the socket timeout still ends the sample at the overall limit."""
    _Handler.mode = "trickle"
    s = probe.fetch(_url(server), 1.0)
    assert s.status is None and "no full answer" in s.error and s.seconds < 3


def test_fetch_truncated_answer_is_a_failed_sample(server):
    _Handler.mode = "truncated"
    s = probe.fetch(_url(server), 5)
    assert s.status is None and "IncompleteRead" in s.error


def test_fetch_bounds_trickled_headers(server):
    _Handler.mode = "slow-headers"
    s = probe.fetch(_url(server), 1.0)
    assert s.status is None and "no full answer" in s.error and s.seconds < 2
