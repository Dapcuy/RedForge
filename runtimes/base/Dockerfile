# Base runtime: shared OS + Python + Node + Go + common tooling.
# All domain runtimes build on top of this image.
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1

# Shared toolchain: python (pipx), node, go, curl, git, ca-certificates.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
        nodejs npm \
        golang-go \
        pipx \
    && rm -rf /var/lib/apt/lists/*

# Common Python-based security tools available to every domain.
RUN pip install --no-cache-dir httpx

WORKDIR /work

CMD ["/bin/bash"]
