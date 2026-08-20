"""
Deliberately vulnerable Flask app — FIXTURE for the real Semgrep Docker E2E test.

This file contains REAL, well-known vulnerability patterns that Semgrep's
built-in rules (p/python, p/flask, p/security-audit) detect:

  1. eval() of user input            (bandit B307 / semgrep python.lang.security.audit.eval-exec)
  2. subprocess with shell=True      (semgrep python.lang.security.audit.subprocess-shell-true)
  3. SQL query string concatenation  (semgrep python.flask.security.sql-injection...)
  4. hardcoded password              (semgrep python.lang.security.audit.hardcoded-password)

This is INTENTIONALLY insecure and is only used as a deterministic fixture.
Never deploy or copy this into production code.
"""
import subprocess

from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "super-secret-password"


@app.route("/run")
def run_command():
    """RCE: eval on user-supplied expression."""
    expr = request.args.get("expr", "")
    return str(eval(expr))


@app.route("/exec")
def exec_command():
    """RCE: subprocess with shell=True."""
    cmd = request.args.get("cmd", "echo hi")
    return subprocess.check_output(cmd, shell=True)


@app.route("/search")
def search():
    """SQLi: string concatenation into a query."""
    q = request.args.get("q", "")
    conn = app.config.get("db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE name = '" + q + "'")
    return str(cur.fetchall())


if __name__ == "__main__":
    app.run(debug=True)
