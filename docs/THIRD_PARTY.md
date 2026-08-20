# Third-Party Inspiration & Licensing

RedForge draws **methodology and ideas** from several projects. We do **not**
copy third-party source code or `SKILL.md` content into this repository. This
document records the sources of inspiration and their licenses so that
attribution and licensing obligations are clear.

## Sources of inspiration (methodology only)

| Project | What we take | License |
|---------|--------------|---------|
| [Anthropic Cybersecurity Skills](https://github.com/anthropics/skills) | the concept of `SKILL.md` as a knowledge/instruction layer | Apache-2.0 |
| [Strix](https://github.com/usestrix/strix) | dynamic security agent patterns | MIT |
| [open·kritt](https://github.com/knc-systems/open-kritt) | code-security research orchestration (break → parallel agents → dedup → validate → report) | (verify before reuse) |
| [Pashov — ai-web3-security](https://github.com/pashov/ai-web3-security) | Web3 audit methodology: X-Ray, multi-pass, fuzzing, invariant testing, PoC | (verify before reuse) |
| [Pashov — skills](https://github.com/pashov/skills) | how a Web3 audit is decomposed into stages/skills | (verify before reuse) |
| [Caido](https://caido.io) | HTTP/web traffic analysis as a *capability* (commercial product; we only integrate via its API) | proprietary |
| [Docker](https://www.docker.com) | execution environment / isolation | Apache-2.0 (engine) |

## Policy

1. **No third-party code** is vendored into `core/`, `agents/`, `integrations/`,
   or `skills/` without an explicit license review and attribution.
2. **No third-party `SKILL.md` content** is copied. Our skill format and content
   are authored for RedForge and share only the general *concept* of
   skill-based knowledge.
3. **Tool manifests** reference third-party tools (nuclei, slither, foundry,
   etc.) by name and runtime image only. We ship orchestration, not the tools;
   each tool retains its own license and is pulled from its official source.
4. Before reusing any upstream artifact (a skill, a detector, a template), check
   its license and add explicit attribution here.

## Tool licenses (referenced, not bundled)

| Tool | License |
|------|---------|
| [nuclei](https://github.com/projectdiscovery/nuclei) | MIT |
| [httpx](https://github.com/projectdiscovery/httpx) | MIT |
| [ffuf](https://github.com/ffuf/ffuf) | MIT |
| [nmap](https://nmap.org) | NPSL (modified GPLv2; see nmap legal) |
| [semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 (core) |
| [Slither](https://github.com/crytic/slither) | AGPL-3.0 |
| [Foundry](https://github.com/foundry-rs/foundry) | MIT/Apache-2.0 |
| [Echidna](https://github.com/crytic/echidna) | AGPL-3.0 |
| [Mythril](https://github.com/Consensys/mythril) | MIT |

> **Note on AGPL tools (Slither, Echidna):** these run inside isolated runtime
> containers and are not linked into RedForge. RedForge's own core is
> licensed AGPL-3.0 (see `LICENSE`), consistent with orchestrating AGPL tools.
