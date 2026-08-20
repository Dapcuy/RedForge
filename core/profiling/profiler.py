"""Target Profiler: build a TargetProfile from a local source directory.

Detection is marker-file based (fast, deterministic, no network). Each marker
contributes languages / frameworks / technologies / indicators that feed the
Skill Resolver.
"""
from __future__ import annotations

import os

from ..models import Target, TargetKind, TargetProfile

# marker file -> (languages, frameworks, technologies, indicators)
_MARKERS: dict[str, tuple[list[str], list[str], list[str], list[str]]] = {
    "package.json": (["javascript"], [], ["nodejs"], []),
    "next.config.js": ([], ["nextjs"], ["react"], [".next/"]),
    "next.config.mjs": ([], ["nextjs"], ["react"], [".next/"]),
    "tailwind.config.js": ([], [], ["tailwind"], []),
    "requirements.txt": (["python"], [], [], []),
    "pyproject.toml": (["python"], [], [], []),
    "manage.py": ([], ["django"], ["python"], []),
    "settings.py": ([], ["django"], ["python"], []),
    "composer.json": (["php"], [], [], []),
    "artisan": ([], ["laravel"], ["php"], []),
    "pom.xml": (["java"], [], [], []),
    "build.gradle": (["java", "kotlin"], [], [], []),
    "Cargo.toml": (["rust"], [], [], []),
    "go.mod": (["go"], [], [], []),
    "foundry.toml": ([], ["foundry", "solidity"], ["evm"], []),
    "hardhat.config.js": ([], ["hardhat", "solidity"], ["evm"], []),
    "hardhat.config.ts": ([], ["hardhat", "solidity"], ["evm"], []),
    "truffle-config.js": ([], ["truffle", "solidity"], ["evm"], []),
    "Dockerfile": ([], [], ["docker"], []),
    "docker-compose.yml": ([], [], ["docker"], []),
}

# file extension -> language (used to enrich profile.languages)
_EXT_LANG: dict[str, str] = {
    ".sol": "solidity",
    ".js": "javascript",
    ".ts": "typescript",
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
}


class Profiler:
    def __init__(self, root: str) -> None:
        self.root = root

    def _markers(self) -> dict[str, bool]:
        found: dict[str, bool] = {}
        for dirpath, _dirs, files in os.walk(self.root):
            # skip noise dirs
            if any(seg in {".git", "node_modules", ".venv", "venv", "target", "dist", "build"} for seg in dirpath.split(os.sep)):
                continue
            for fname in files:
                if fname in _MARKERS and fname not in found:
                    found[fname] = True
        return found

    def _extensions(self) -> set[str]:
        exts: set[str] = set()
        for dirpath, _dirs, files in os.walk(self.root):
            if any(seg in {".git", "node_modules", ".venv", "venv", "target", "dist", "build"} for seg in dirpath.split(os.sep)):
                continue
            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext in _EXT_LANG:
                    exts.add(ext)
        return exts

    def profile(self, target: Target) -> TargetProfile:
        langs: set[str] = set()
        fws: set[str] = set()
        techs: set[str] = set()
        inds: set[str] = set()

        for marker, present in self._markers().items():
            if not present:
                continue
            l, f, t, i = _MARKERS[marker]
            langs.update(l)
            fws.update(f)
            techs.update(t)
            inds.update(i)

        for ext in self._extensions():
            langs.add(_EXT_LANG[ext])

        # nodejs implies javascript
        if "nodejs" in techs and "javascript" not in langs:
            langs.add("javascript")

        return TargetProfile(
            target=target,
            technologies=sorted(techs),
            frameworks=sorted(fws),
            indicators=sorted(inds),
            languages=sorted(langs),
        )


def profile_directory(path: str, target_value: str | None = None) -> TargetProfile:
    """Convenience: profile a local source directory."""
    profiler = Profiler(path)
    return profiler.profile(Target(TargetKind.SOURCE_DIR, target_value or path))


def profile_url(url: str) -> TargetProfile:
    """Stub for URL fingerprinting (headers/paths).

    Phase 5 wires this to real HTTP fingerprinting. For now it returns a
    minimal profile with the URL as the only indicator.
    """
    return TargetProfile(
        target=Target(TargetKind.URL, url),
        indicators=[url],
    )
