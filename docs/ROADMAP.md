# RedForge Roadmap — Status

> Updated: all 10 milestones implemented. See commit history for per-phase detail.

## Milestones

```
01. Architecture        ✅
02. Docker Runtime      ✅
03. Tool Registry       ✅
04. Skill Engine        ✅
05. Evidence/Finding    ✅
06. Code Analysis       ✅
07. Web Dynamic Test    ✅
08. Web3/EVM Security   ✅
09. Multi-Agent         ✅
10. Web Dashboard       ✅
```

## Remaining (post-milestone hardening)

- Build + smoke-test the actual Docker runtime images (needs Docker Desktop running).
- Wire live Hermes/LLM agents into the multi-agent dispatcher (adapters exist).
- Persist evidence/findings to disk (SQLite) beyond the in-memory stores.
- Full dashboard with project/target/scan management.
- Real URL fingerprinting (headers/paths) for `profile --url`.
