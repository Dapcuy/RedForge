# Integrations — External Capability Adapters

Adapters for external tools that plug into RedForge as **capabilities**, not as the center of the platform.

```
integrations/
├── caido/   # HTTP/web traffic analysis (evidence source)
└── strix/   # dynamic security testing (evidence source)
```

- **Caido** — HTTP traffic analysis capability. It is *not* "AI"; it is a tool in the ecosystem.
- **Strix** — dynamic security testing capability (source + running target → dynamic analysis).

See [`docs/architecture/VISION.md`](../docs/architecture/VISION.md) for positioning, and [`EVIDENCE_SPEC.md`](../docs/architecture/EVIDENCE_SPEC.md) for how their output becomes evidence.

*No adapters implemented yet — that is Phase 5 (Web Dynamic Security).*
