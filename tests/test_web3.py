"""Tests for the Web3/Solidity pipeline (X-Ray -> static -> finding)."""

from core.findings.models import Severity
from core.web3.pipeline import Web3Pipeline, xray_solidity

REENTRANT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

SAFE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Counter {
    uint256 public count;

    function increment() public {
        count += 1;
    }
}
"""


def _write_sol(tmp_path, name, src):
    p = tmp_path / "src" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")


def test_xray_finds_contract(tmp_path):
    _write_sol(tmp_path, "Vault.sol", REENTRANT)
    result = xray_solidity(str(tmp_path))
    names = [c.name for c in result.contracts]
    assert "Vault" in names
    vault = next(c for c in result.contracts if c.name == "Vault")
    assert "withdraw" in vault.functions
    assert "balances" in vault.state_vars
    assert len(vault.external_calls) > 0


def test_xray_ignores_non_sol(tmp_path):
    _write_sol(tmp_path, "readme.md", REENTRANT)
    result = xray_solidity(str(tmp_path))
    assert result.contracts == []


def test_pipeline_detects_reentrancy(tmp_path):
    _write_sol(tmp_path, "Vault.sol", REENTRANT)
    pipe = Web3Pipeline(str(tmp_path), "run-1")
    findings = pipe.run()
    # external call + state var -> candidate reentrancy
    assert any("reentrancy" in f.title.lower() for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_pipeline_no_false_positive(tmp_path):
    _write_sol(tmp_path, "Counter.sol", SAFE)
    pipe = Web3Pipeline(str(tmp_path), "run-2")
    findings = pipe.run()
    # Counter has a state var but no external call -> no reentrancy candidate
    assert findings == []


def test_pipeline_ai_review_hook(tmp_path):
    _write_sol(tmp_path, "Counter.sol", SAFE)
    pipe = Web3Pipeline(str(tmp_path), "run-3")

    def fake_ai_review(contract):
        return [{"title": "AI-flagged issue", "severity": "medium", "root_cause": "reasoning"}]

    pipe.ai_review_hook = fake_ai_review
    findings = pipe.run()
    assert any(f.title == "AI-flagged issue" for f in findings)


def test_pipeline_fuzz_hook_emits_evidence(tmp_path):
    _write_sol(tmp_path, "Counter.sol", SAFE)
    pipe = Web3Pipeline(str(tmp_path), "run-4")

    def fake_fuzz(contract):
        return "invariant broken: count"

    pipe.fuzz_hook = fake_fuzz
    pipe.run()
    assert any(e.tool == "echidna" for e in pipe.evidence)
