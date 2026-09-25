import json

import httpx

from vibesecur.assessment import JEV_MODEL, JevAssessment
from vibesecur.supervision import _valid_assessment

SOURCE = {"sourceId": "procurement-record-1", "kind": "procurement_record", "text": "Approved purpose: laptops."}


def _assessor(handler):
    return JevAssessment("key", transport=httpx.MockTransport(handler))


def test_jev_answer_becomes_typed_advisory_assessment():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"answers": {"purpose": {
            "type": "choice", "choice": "purpose_mismatch",
            "probabilities": {"suitable": 0.07, "purpose_mismatch": 0.93}}}})

    result = _assessor(handler).assess({"purpose": "laptops"}, {"description": "pay new beneficiary"}, SOURCE)
    assert seen["model"] == JEV_MODEL and set(seen["state"]) == {"mission", "action", "source"}
    assert result["status"] == "available" and result["label"] == "purpose_mismatch"
    assert result["rawScore"] == 0.93 and result["modelRevision"] == JEV_MODEL
    assert _valid_assessment(result, SOURCE)


def test_jev_failure_or_malformed_answer_is_unavailable():
    for response in (httpx.Response(500), httpx.Response(200, json={"answers": {"purpose": {
            "choice": "approve", "probabilities": {"approve": 1.0}}}})):
        result = _assessor(lambda request, r=response: r).assess({}, {}, SOURCE)
        assert result["status"] == "unavailable" and result["label"] is None
        assert _valid_assessment(result, SOURCE)
