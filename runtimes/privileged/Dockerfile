# Privileged runtime: tools needing host/network access (nmap, raw sockets).
# Gated by policy.allow_privileged_runtime — never run by default.
FROM redforge/base:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["/bin/bash"]
