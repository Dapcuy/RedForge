"""Tests for the target profiler and the code-security planner."""

from core.orchestrator.planner import break_repository_into_tasks
from core.profiling.profiler import profile_directory


def _write(tmp_path, relpath, content=""):
    p = tmp_path / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_profiler_detects_nextjs(tmp_path):
    _write(tmp_path, "package.json", "{}")
    _write(tmp_path, "next.config.js", "")
    _write(tmp_path, "pages/index.js", "")
    _write(tmp_path, "api/route.py", "")

    profile = profile_directory(str(tmp_path))
    assert "nodejs" in profile.technologies
    assert "nextjs" in profile.frameworks
    assert "react" in profile.technologies
    assert "javascript" in profile.languages
    assert "python" in profile.languages


def test_profiler_detects_django(tmp_path):
    _write(tmp_path, "manage.py", "")
    _write(tmp_path, "requirements.txt", "")
    profile = profile_directory(str(tmp_path))
    assert "django" in profile.frameworks
    assert "python" in profile.technologies
    assert "python" in profile.languages


def test_profiler_detects_foundry(tmp_path):
    _write(tmp_path, "foundry.toml", "")
    _write(tmp_path, "src/Token.sol", "")
    profile = profile_directory(str(tmp_path))
    assert "solidity" in profile.frameworks
    assert "evm" in profile.technologies
    assert "solidity" in profile.languages


def test_profiler_skips_noise_dirs(tmp_path):
    _write(tmp_path, "node_modules/dep/package.json", "{}")
    _write(tmp_path, "package.json", "{}")
    profile = profile_directory(str(tmp_path))
    assert "nodejs" in profile.technologies  # from the top-level package.json
    # node_modules package.json is skipped, but it wouldn't change the result anyway


def test_planner_breaks_repo_into_areas(tmp_path):
    _write(tmp_path, "frontend/app.js", "")
    _write(tmp_path, "frontend/App.tsx", "")
    _write(tmp_path, "backend/server.py", "")
    _write(tmp_path, "backend/main.go", "")
    _write(tmp_path, "contracts/Token.sol", "")
    _write(tmp_path, "Dockerfile", "")

    profile = profile_directory(str(tmp_path))
    plan = break_repository_into_tasks(str(tmp_path), profile)

    areas = {t.area for t in plan.tasks}
    assert "frontend" in areas
    assert "backend" in areas
    assert "web3" in areas
    assert "config" in areas

    # web3 task should need solidity-analysis
    web3_task = next(t for t in plan.tasks if t.area == "web3")
    assert "solidity-analysis" in web3_task.capabilities


def test_planner_empty_repo(tmp_path):
    profile = profile_directory(str(tmp_path))
    plan = break_repository_into_tasks(str(tmp_path), profile)
    assert plan.tasks == []
