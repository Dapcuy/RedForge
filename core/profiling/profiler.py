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


def profile_url(url: str, timeout_s: float = 10.0) -> TargetProfile:
    """Profile a live URL by HTTP fingerprinting.

    Detects (best-effort, stdlib only):
      - server header
      - X-Powered-By / technology headers
      - generator meta / title hints
      - framework indicators (wp-content, next, etc.)

    Fails soft: on any network/HTTP error it returns a minimal profile with
    the URL as the only indicator (never raises — the orchestrator/policy
    decides whether the target is reachable/authorized).
    """
    import re
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen

    technologies: set[str] = set()
    frameworks: set[str] = set()
    indicators: list[str] = [url]

    req = Request(url, headers={"User-Agent": "RedForge-Profiler/0.1"})
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            status = getattr(resp, "status", 0)
            headers = dict(resp.headers.items())
            try:
                body = resp.read(65536).decode("utf-8", errors="replace")
            except Exception:
                body = ""
    except HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        body = ""
    except (URLError, OSError, ValueError):
        indicators.append(f"unreachable:{url}")
        return TargetProfile(
            target=Target(TargetKind.URL, url),
            technologies=[],
            frameworks=[],
            indicators=indicators,
            languages=[],
        )

    indicators.append(f"status:{status}")

    def _hdr(name: str) -> str:
        """Case-insensitive header lookup."""
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return ""

    server = _hdr("server")
    if server:
        technologies.add(server.lower().split("/")[0])
        indicators.append(f"server:{server}")

    powered = _hdr("x-powered-by")
    if powered:
        tech = powered.lower()
        technologies.add(tech)
        indicators.append(f"x-powered-by:{powered}")

    if "wp-content" in body or "wordpress" in body.lower():
        frameworks.add("wordpress")
        technologies.add("php")
        indicators.append("wp-content")
    if "next" in _hdr("x-nextjs").lower() or "/_next/" in body:
        frameworks.add("nextjs")
        technologies.add("react")
        indicators.append("nextjs")
    if "csrf" in body.lower() and ("django" in body.lower() or "csrftoken" in _hdr("set-cookie").lower()):
        frameworks.add("django")
        technologies.add("python")
        indicators.append("django-csrftoken")

    m = re.search(r"<title>([^<]{1,120})</title>", body, re.IGNORECASE)
    if m:
        indicators.append(f"title:{m.group(1).strip()}")

    return TargetProfile(
        target=Target(TargetKind.URL, url),
        technologies=sorted(technologies),
        frameworks=sorted(frameworks),
        indicators=sorted(set(indicators)),
        languages=[],
    )
