"""Tests for the real URL profiler (HTTP fingerprinting)."""
import http.server
import threading

import pytest

from core.profiling.profiler import profile_url


class _FingerprintHandler(http.server.BaseHTTPRequestHandler):
    """A tiny local server that mimics a technology stack for fingerprinting."""

    server_version = "nginx/1.24"
    sys_version = ""

    def do_GET(self):
        if self.path == "/":
            body = (
                b"<html><head><title>Test Site</title>"
                b'<meta name="generator" content="WordPress 6.0">'
                b"</head><body>wp-content/themes/theme</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "nginx/1.24")
            self.send_header("X-Powered-By", "PHP/8.1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):  # silence
        pass


@pytest.fixture(scope="module")
def live_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FingerprintHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_profile_url_detects_stack(live_server):
    profile = profile_url(live_server)
    assert profile.target.value == live_server
    # server + x-powered-by detected
    assert any("nginx" in t for t in profile.technologies)
    assert any("php" in t for t in profile.technologies)
    # wordpress detected from body
    assert "wordpress" in profile.frameworks
    # indicators include status/title/server
    joined = " ".join(profile.indicators)
    assert "status:200" in joined
    assert "server:nginx" in joined
    assert "title:Test Site" in joined
    assert "wp-content" in joined


def test_profile_url_never_raises_on_bad_url():
    profile = profile_url("http://127.0.0.1:1/")  # connection refused
    assert profile.target.value == "http://127.0.0.1:1/"
    assert "unreachable" in " ".join(profile.indicators)
    assert profile.technologies == []
