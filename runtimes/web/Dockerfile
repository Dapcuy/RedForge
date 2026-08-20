# Web runtime: web/application security tools.
FROM redforge/base:latest

ENV DEBIAN_FRONTEND=noninteractive

# httpx (python) already in base; add nuclei + ffuf.
RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && cp "$(go env GOPATH)/bin/nuclei" /usr/local/bin/nuclei \
    && cp "$(go env GOPATH)/bin/ffuf" /usr/local/bin/ffuf

WORKDIR /work

CMD ["/bin/bash"]
