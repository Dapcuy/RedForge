# Web runtime: web/application security tools.
#
# Pinned tool versions (must match tools/*.tool.yaml manifests):
#   nuclei 3.3.7   (tools/nuclei.tool.yaml)
#   httpx  1.6.9   (tools/httpx.tool.yaml)  — projectdiscovery/httpx (Go)
#   ffuf   2.1.0   (tools/ffuf.tool.yaml)
FROM redforge/base:latest

ENV DEBIAN_FRONTEND=noninteractive

# nuclei + httpx + ffuf pinned via go install @version.
RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.7 \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
    && go install -v github.com/ffuf/ffuf/v2@v2.1.0 \
    && cp "$(go env GOPATH)/bin/nuclei" /usr/local/bin/nuclei \
    && cp "$(go env GOPATH)/bin/httpx" /usr/local/bin/httpx \
    && cp "$(go env GOPATH)/bin/ffuf" /usr/local/bin/ffuf

WORKDIR /work

CMD ["/bin/bash"]
