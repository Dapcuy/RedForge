# Tiny deterministic test runtime for the Docker E2E test.
#
# This image is intentionally minimal: a single Python script that reads a file
# from /workspace (the mounted source tree), verifies it, and prints a JSON
# result. It exercises:
#   - workspace mounting (read-only /workspace)
#   - container execution
#   - artifact/evidence capture from stdout
#
# It is NOT a production tool image — production images live in runtimes/.
#
# NOTE: no ENTRYPOINT is set. The runtime passes the tool entrypoint as the
# container command, so the full invocation is:
#   docker run ... redforge/test-runtime /usr/local/bin/e2e_tool.py /workspace/app.py
FROM python:3.11-slim

COPY e2e_tool.py /usr/local/bin/e2e_tool.py
RUN chmod +x /usr/local/bin/e2e_tool.py

WORKDIR /work
