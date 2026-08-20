"""RedForge dashboard — minimal web UI skeleton (Phase 9).

Serves a static HTML dashboard + a small JSON API over findings. Uses only the
Python standard library (http.server) so it has zero dependencies and runs
anywhere. A FastAPI/full framework can replace it later without changing the
core.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from core.findings.models import Finding

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>RedForge Dashboard</title>
<style>
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --accent:#f78166; --border:#30363d; --card:#161b22; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:20px 24px; border-bottom:1px solid var(--border); }
  header h1 { margin:0; font-size:20px; }
  header p { margin:4px 0 0; color:var(--muted); font-size:13px; }
  main { padding:24px; max-width:960px; margin:0 auto; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; min-width:120px; }
  .card .num { font-size:28px; font-weight:600; }
  .card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-size:14px; }
  th { color:var(--muted); font-size:12px; text-transform:uppercase; }
  .sev { padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
  .critical { background:#7f1d1d; color:#fca5a5; }
  .high { background:#78350f; color:#fdba74; }
  .medium { background:#713f12; color:#fde047; }
  .low { background:#14532d; color:#86efac; }
  .informational { background:#1e293b; color:#94a3b8; }
</style>
</head>
<body>
<header>
  <h1>RedForge <span style="color:var(--accent)">Dashboard</span></h1>
  <p>Findings · Evidence · Skill Library · Tool Status — Phase 9 skeleton</p>
</header>
<main>
  <div class="cards" id="cards"></div>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Component</th><th>Status</th><th>Confidence</th></tr></thead>
    <tbody id="findings"></tbody>
  </table>
</main>
<script>
async function load() {
  const r = await fetch('/api/findings');
  const data = await r.json();
  const counts = {critical:0, high:0, medium:0, low:0, informational:0};
  data.findings.forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);
  document.getElementById('cards').innerHTML = Object.entries(counts)
    .map(([k,v]) => `<div class="card"><div class="num">${v}</div><div class="label">${k}</div></div>`).join('');
  document.getElementById('findings').innerHTML = data.findings.map(f => `
    <tr>
      <td><span class="sev ${f.severity}">${f.severity}</span></td>
      <td>${f.title}</td>
      <td>${f.affected_component || '—'}</td>
      <td>${f.status}</td>
      <td>${f.confidence}</td>
    </tr>`).join('');
}
load();
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    findings: list[Finding] = []

    def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/api/findings":
            payload = json.dumps({"findings": [f.to_dict() for f in self.findings]}).encode()
            self._send(payload, "application/json")
        elif self.path in ("/", "/index.html"):
            self._send(INDEX_HTML.encode(), "text/html; charset=utf-8")
        else:
            self._send(b"not found", "text/plain", 404)

    def log_message(self, *args) -> None:  # silence default logging
        pass


def serve(findings: list[Finding], host: str = "127.0.0.1", port: int = 8000) -> None:
    DashboardHandler.findings = findings
    server = HTTPServer((host, port), DashboardHandler)
    print(f"RedForge dashboard running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
