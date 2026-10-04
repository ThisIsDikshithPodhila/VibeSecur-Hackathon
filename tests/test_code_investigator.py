"""LLM code findings are only reported as grounded after checks against Git."""
import json
import subprocess

import httpx

from vibesecur.assessment import EnsembleAssessment, _result
from vibesecur.code_investigator import CodeInvestigator
from vibesecur.investigation import _code_finding, _code_markdown


class Security:
    def __init__(self):
        self.revoked = []

    def issue_model_lease(self, task_id, model, **kwargs):
        return "lease"

    def revoke_task(self, task_id):
        self.revoked.append(task_id)


def _repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "payment_app").mkdir(parents=True)
    (repo / "payment_app" / "app.py").write_text(
        "def payment(command):\n    approved = command.get('approvalId')\n    return approved\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                    "commit", "-qm", "seed"], check=True)
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()
    return str(repo), head




EDIT = {"path": "payment_app/app.py", "find": "approved = command.get('approvalId')\n",
        "replace": "approved = command.get('approvalId') and command.get('exact')\n"}


def _transport(findings):
    replies = [
        {"tool_calls": [{"id": "1", "type": "function", "function": {
            "name": "read_file", "arguments": json.dumps({"path": "payment_app/app.py",
                                                          "start": 1, "end": 3})}}]},
        {"tool_calls": [{"id": "2", "type": "function", "function": {
            "name": "submit_findings", "arguments": json.dumps(findings)}}]},
    ]
    seen = []

    def handler(request):
        body = json.loads(request.content)
        seen.append(body)
        return httpx.Response(200, json={"choices": [{"message": replies[len(seen) - 1]}]})
    return httpx.MockTransport(handler), seen


def test_grounded_findings_and_applicable_patch(tmp_path):
    repo, head = _repo(tmp_path)
    transport, seen = _transport({
        "rootCause": "Only approvalId is checked.", "confidence": "high",
        "citations": [{"path": "payment_app/app.py", "line": 2,
                       "quote": "approved = command.get('approvalId')"}],
        "remediationPlan": ["Compare every approved field"], "edits": [EDIT]})
    security = Security()
    result = CodeInvestigator(security, "http://broker/model/v1", "openai/gpt-6-luna", repo, head,
                              transport=transport)({"incident": "x"})
    assert result["grounded"] is True and result["patch"]["status"] == "applies"
    assert "+    approved = command.get('approvalId') and command.get('exact')" in result["patch"]["patch"]
    assert "2: " in seen[1]["messages"][-1]["content"]
    assert result["steps"] == [{"tool": "read_file", "args": {
        "path": "payment_app/app.py", "start": "1", "end": "3"}}]
    assert security.revoked
    finding = _code_finding(result)
    assert "citations verified" in _code_markdown(finding)


def test_fabricated_citation_and_out_of_scope_patch_are_flagged(tmp_path):
    repo, head = _repo(tmp_path)
    transport, _ = _transport({
        "rootCause": "Invented.", "confidence": "high",
        "citations": [{"path": "payment_app/app.py", "line": 2, "quote": "no such line"}],
        "remediationPlan": [], "edits": [{**EDIT, "path": "tests/x.py"}]})
    result = CodeInvestigator(Security(), "http://broker/model/v1", "gpt-6-luna", repo, head,
                              transport=transport)({})
    assert result["grounded"] is False
    assert result["patch"]["status"] == "rejected"


def test_tools_cannot_read_outside_pinned_prefixes(tmp_path):
    repo, head = _repo(tmp_path)
    investigator = CodeInvestigator(Security(), "http://b", "m", repo, head)
    assert investigator.tool("read_file", {"path": "../etc/passwd", "start": 1, "end": 2}).startswith("error")
    assert "payment_app/app.py:2" in investigator.tool("grep", {"pattern": "approvalId"})


def test_ensemble_mismatch_wins_and_records_components():
    source = {"sourceId": "inv", "kind": "supplier_document", "origin": "/documents/invoice"}
    def suitable(*_):
        return _result("available", source, 0, label="suitable", score=0.9)
    def mismatch(*_):
        return _result("available", source, 0, label="purpose_mismatch", score=0.8)
    def broken(*_):
        raise RuntimeError
    result = EnsembleAssessment([suitable, broken, mismatch])({}, {}, source)
    assert result["label"] == "purpose_mismatch" and len(result["components"]) == 3
    assert EnsembleAssessment([broken])({}, {}, source)["status"] == "unavailable"
