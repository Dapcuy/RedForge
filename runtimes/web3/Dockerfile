# Web3 runtime: EVM / Solidity security tooling.
FROM redforge/base:latest

ENV DEBIAN_FRONTEND=noninteractive

# Foundry (forge, cast, anvil, chisel) + Slither via pip.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git \
    && rm -rf /var/lib/apt/lists/* \
    && curl -L https://foundry.paradigm.xyz | bash \
    && "$HOME/.foundry/bin/foundryup" \
    && pip install --no-cache-dir slither-analyzer \
    && ln -s "$HOME/.foundry/bin/forge" /usr/local/bin/forge \
    && ln -s "$HOME/.foundry/bin/cast" /usr/local/bin/cast \
    && ln -s "$HOME/.foundry/bin/anvil" /usr/local/bin/anvil

ENV PATH="/root/.foundry/bin:${PATH}"

WORKDIR /work

CMD ["/bin/bash"]
