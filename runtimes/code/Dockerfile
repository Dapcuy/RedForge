# Code runtime: source-code security (static analysis + dependency scanning).
#
# Pinned Semgrep version: 1.95.0 (see tools/semgrep.tool.yaml).
# The version installed here MUST match the manifest's runtime.version.
FROM redforge/base:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN pip install --no-cache-dir semgrep==1.95.0

WORKDIR /work

CMD ["/bin/bash"]
