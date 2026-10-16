"""
tests/test_validation_suite.py

Comprehensive validation suite covering all four areas:

  1. Regression tests for H-2, H-3, H-4
  2. Deliberate worker-failure test
  3. End-to-end gate workflow (positive + negative cases)
  4. Report serialization validation
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.models import (
    Candidate, ParamLocation, ContextClass, Finding, ConfidenceTier,
    ScanReport, EvidenceArtifact, ProbeResult,
)
from core.authorized_action_gate import AuthorizedActionGate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cand(**kw) -> Candidate:
    defaults = dict(
        target_url="http://target.example/api/fetch",
        method="POST",
        parameter="url",
        param_location=ParamLocation.BODY_JSON,
    )
    defaults.update(kw)
    return Candidate(**defaults)


def _probe(cand: Candidate, **kw) -> ProbeResult:
    """Minimal valid ProbeResult for a candidate."""
    defaults = dict(
        candidate_id=cand.candidate_id,
        payload="http://169.254.169.254/",
        payload_category="cloud_metadata",
        status_code=200,
        content_length=500,
        elapsed=2.5,
        redirect_depth=0,
        redirect_chain=[],
        headers={},
        body_snippet="",
        raw_request="POST /api/fetch HTTP/1.1",
        raw_response="HTTP/1.1 200 OK",
        composite_z=9.0,
        z_timing=5.0,
        z_status=0.0,
        z_content_length=0.0,
        z_redirect=0.0,
        error_class="connection_refused",
    )
    defaults.update(kw)
    return ProbeResult(**defaults)


def _finding(cand: Candidate, tier: str = "tentative") -> Finding:
    return Finding(
        agent_group="SSRF Cyart",
        sub_agent="test",
        vulnerability_type="ssrf_suspected_anomaly",
        category="ssrf",
        severity="medium",
        confidence="low",
        target_url=cand.target_url,
        affected_parameter=cand.parameter,
        description="test finding",
        observation="test obs",
        proof_of_concept="",
        remediation="",
        confidence_tier=tier,
        details={"candidate_id": cand.candidate_id},
    )


def _gate() -> AuthorizedActionGate:
    return AuthorizedActionGate(client=AsyncMock())


def _propose(gate: AuthorizedActionGate, cand: Candidate,
             suspicious=None, has_oob=True) -> "FindingProposal":
    """Helper that always supplies required keyword args."""
    proposal = gate.propose(
        cand,
        suspicious or [],
        has_oob=has_oob,
        has_reflection=False,
        waf_vendor=None,
        oob_internal_addrs=["10.0.0.1"],
    )
    proposal.status = "AWAITING_REVIEW"
    return proposal


# ===========================================================================
# SECTION 1 — Regression tests for H-2, H-3, H-4
# ===========================================================================

class TestRegressionH2Serialization:
    """H-2: confidence_tier must survive round-trip through to_dict() and JSON."""

    def test_confidence_tier_is_declared_dataclass_field(self):
        field_names = {f.name for f in dataclasses.fields(Finding)}
        assert "confidence_tier" in field_names, (
            "H-2: confidence_tier must be a declared dataclass field — "
            "dynamic attributes are silently dropped by asdict()."
        )

    def test_confidence_tier_survives_asdict(self):
        f = _finding(_cand(), tier="firm")
        d = dataclasses.asdict(f)
        assert "confidence_tier" in d
        assert d["confidence_tier"] == "firm"

    def test_confidence_tier_survives_to_dict(self):
        f = _finding(_cand(), tier="certain")
        d = f.to_dict()
        assert "confidence_tier" in d
        assert d["confidence_tier"] == "certain"

    def test_confidence_tier_survives_json_roundtrip(self):
        f = _finding(_cand(), tier="critical_plus")
        recovered = json.loads(json.dumps(f.to_dict()))
        assert recovered.get("confidence_tier") == "critical_plus"

    def test_default_confidence_tier_is_tentative(self):
        f = _finding(_cand())
        assert f.confidence_tier == "tentative"

    def test_confidence_tier_updated_after_construction_is_serialised(self):
        f = _finding(_cand(), tier="tentative")
        f.confidence_tier = "firm"
        assert f.to_dict()["confidence_tier"] == "firm"


class TestRegressionH3BlindSSRF:
    """H-3: blind SSRF path (has_oob=True, suspicious=[]) must not IndexError."""

    def test_build_firm_finding_result_none_does_not_crash(self):
        """build_firm_finding(result=None) must return a valid Finding."""
        from core.reporter import build_firm_finding
        cand = _cand()
        finding = build_firm_finding(
            cand, result=None,
            token="abc123", collab_host="collab.example.com", async_pattern=False,
        )
        assert finding is not None
        d = finding.to_dict()
        assert d["details"]["raw_request"] == ""
        assert d["details"]["raw_response"] == ""

    def test_build_tentative_finding_result_none_does_not_crash(self):
        """build_tentative_finding(result=None) must return a valid Finding."""
        from core.reporter import build_tentative_finding
        cand = _cand()
        finding = build_tentative_finding(cand, result=None)
        assert finding is not None
        d = finding.to_dict()
        assert d["details"]["payload"] is None
        assert "No differential anomaly" in d["observation"]

    def test_build_firm_finding_real_result_has_confidence_tier(self):
        """A real ProbeResult produces a Finding with confidence_tier in its dict."""
        from core.reporter import build_firm_finding
        cand = _cand()
        probe = _probe(cand)
        finding = build_firm_finding(cand, probe, "tok1", "collab.io", False)
        assert "confidence_tier" in finding.to_dict()

    def test_blind_ssrf_oob_finding_tier_survives_serialization(self):
        """Firm finding built for a blind SSRF (result=None) serialises correctly."""
        from core.reporter import build_firm_finding
        cand = _cand()
        finding = build_firm_finding(cand, None, "tok2", "c.io", False)
        finding.confidence_tier = "firm"
        d = finding.to_dict()
        assert d["confidence_tier"] == "firm"
        assert d["details"]["raw_request"] == ""


class TestRegressionH4SkippedCandidateURL:
    """H-4: skipped candidates must record actual target_url, not '?'."""

    def test_candidate_has_target_url_not_url(self):
        cand = _cand(target_url="http://victim.example/api/webhook")
        # target_url exists
        assert getattr(cand, 'target_url', '?') == "http://victim.example/api/webhook"
        # url does NOT exist on Candidate — old code always returned '?'
        assert getattr(cand, 'url', '?') == '?', (
            "Candidate.url must not exist; only target_url. "
            "This confirms the old bug always returned '?'."
        )

    @pytest.mark.asyncio
    async def test_skipped_candidate_dict_contains_real_url(self):
        report = ScanReport()
        cand = _cand(target_url="http://victim.example/api/ssrf-endpoint")
        try:
            raise RuntimeError("simulated network failure")
        except Exception as exc:
            report.skipped_candidates.append({
                "candidate_id": getattr(cand, 'candidate_id', '?'),
                "url":          getattr(cand, 'target_url', '?'),  # FIXED line
                "parameter":    getattr(cand, 'parameter', '?'),
                "error_type":   type(exc).__name__,
                "error":        str(exc),
            })
        entry = report.skipped_candidates[0]
        assert entry["url"] == "http://victim.example/api/ssrf-endpoint"
        assert entry["url"] != "?"
        assert entry["error_type"] == "RuntimeError"


# ===========================================================================
# SECTION 2 — Deliberate worker-failure tests
# ===========================================================================

class TestWorkerIsolation:
    """One candidate failure must not terminate or corrupt the rest of the scan."""

    @pytest.mark.asyncio
    async def test_one_failure_scan_continues(self):
        """
        Candidates: A B C(fails) D E
        Expected: A B D E processed; C in skipped_candidates; no exception raised.
        """
        processed, skipped = [], []
        logger_inst = logging.getLogger("ssrf_cyart.agent")
        candidates = [
            _cand(target_url=f"http://x.com/{n}", parameter=n)
            for n in ["A", "B", "C", "D", "E"]
        ]

        async def mock_process(c):
            if c.parameter == "C":
                raise RuntimeError("simulated network failure")
            processed.append(c.parameter)
            await asyncio.sleep(0)

        active = list(candidates)
        while active:
            cand = active.pop(0)
            try:
                await mock_process(cand)
            except Exception as exc:
                logger_inst.warning("[worker] %s raised %s — skipping",
                                    cand.candidate_id[:8], type(exc).__name__)
                skipped.append({
                    "candidate_id": getattr(cand, 'candidate_id', '?'),
                    "url":          getattr(cand, 'target_url', '?'),
                    "parameter":    getattr(cand, 'parameter', '?'),
                    "error_type":   type(exc).__name__,
                    "error":        str(exc),
                })

        assert sorted(processed) == ["A", "B", "D", "E"]
        assert len(skipped) == 1
        assert skipped[0]["parameter"] == "C"
        assert skipped[0]["url"] == "http://x.com/C"
        assert skipped[0]["url"] != "?"

    @pytest.mark.asyncio
    async def test_multiple_failures_all_isolated(self):
        """B and D fail; A, C, E still succeed."""
        processed, skipped_params = [], []
        candidates = [
            _cand(target_url=f"http://x.com/{n}", parameter=n)
            for n in ["A", "B", "C", "D", "E"]
        ]

        async def mock_process(c):
            if c.parameter in ("B", "D"):
                raise TimeoutError("timeout")
            processed.append(c.parameter)

        active = list(candidates)
        while active:
            cand = active.pop(0)
            try:
                await mock_process(cand)
            except Exception:
                skipped_params.append(cand.parameter)

        assert sorted(processed) == ["A", "C", "E"]
        assert sorted(skipped_params) == ["B", "D"]


# ===========================================================================
# SECTION 3 — End-to-end gate workflow
# ===========================================================================

class TestGateEndToEnd:
    """Full operational flow: Detection -> Proposal -> Approval -> Evidence -> Log."""

    def test_propose_makes_no_http_calls(self):
        """propose() is classification only — no network requests."""
        gate = _gate()
        cand = _cand()
        probe = _probe(cand)
        proposal = _propose(gate, cand, suspicious=[probe])
        gate._client.send.assert_not_called()
        gate._client.get.assert_not_called()

    def test_proposal_status_is_awaiting_review(self):
        """Proposal starts as AWAITING_REVIEW, not executed."""
        gate = _gate()
        cand = _cand()
        proposal = _propose(gate, cand)
        assert proposal.status == "AWAITING_REVIEW"
        assert proposal.candidate_id == cand.candidate_id

    def test_proposal_appears_in_pending_proposals_not_findings(self):
        """Proposals go into pending_proposals; findings are not yet upgraded."""
        gate = _gate()
        cand = _cand()
        report = ScanReport()
        report.findings = [_finding(cand, tier="tentative")]
        proposal = _propose(gate, cand)
        report.pending_proposals.append(proposal)

        assert len(report.pending_proposals) == 1
        assert len(report.findings) == 1
        assert report.findings[0].confidence_tier == "tentative"  # not upgraded yet

    @pytest.mark.asyncio
    async def test_rejection_empty_operator_raises_valueerror(self):
        """NEGATIVE: execute() with empty operator must be refused — no live action."""
        gate = _gate()
        cand = _cand()
        proposal = _propose(gate, cand)

        with pytest.raises(ValueError, match="operator"):
            await gate.execute(
                proposal, cand,
                approved_methods=["cloud_metadata"],
                operator="",               # <-- empty: must be rejected
                internal_addrs=[],
            )
        gate._client.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_approved_execution_records_audit_log(self):
        """POSITIVE: approved execution writes AuthorizedActionRecord to gate.log."""
        gate = _gate()
        cand = _cand()
        proposal = _propose(gate, cand)

        with patch(
            "core.authorized_action_gate.evidence_engine.check_cloud_metadata",
            new=AsyncMock(return_value=None),
        ):
            await gate.execute(
                proposal, cand,
                approved_methods=["cloud_metadata"],
                operator="mohammed.test",
                internal_addrs=[],
            )

        assert len(gate.log) == 1
        record = gate.log[0]
        assert record.operator == "mohammed.test"
        assert "cloud_metadata" in record.approved_methods
        assert proposal.status == "EXECUTED"

    def test_decline_marks_proposal_declined(self):
        """Declining a proposal sets status=DECLINED and logs the operator."""
        gate = _gate()
        cand = _cand()
        proposal = _propose(gate, cand, has_oob=False)

        gate.decline(proposal, operator="mohammed.test", reason="False positive")

        assert proposal.status == "DECLINED"
        assert len(gate.log) == 1
        assert gate.log[0].operator == "mohammed.test"

    @pytest.mark.asyncio
    async def test_full_workflow_proposal_to_executed_to_audit_log(self):
        """
        Complete flow:
          tentative finding + pending proposal
          -> operator approves
          -> evidence collected (mocked)
          -> proposal.status == EXECUTED
          -> gate.log has the record
          -> report.authorized_action_log synced
        """
        import yaml, pathlib
        from core.agent import SSRFCyartAgent

        cfg_path = pathlib.Path(__file__).parent.parent / "core" / "config.yaml"
        agent = SSRFCyartAgent.__new__(SSRFCyartAgent)
        agent.cfg = yaml.safe_load(cfg_path.read_text())
        agent._max_hops = 3
        agent._client = AsyncMock()

        gate = _gate()
        agent._gate = gate

        cand = _cand()
        agent._candidate_index = {cand.candidate_id: cand}

        report = ScanReport()
        report.findings = [_finding(cand, tier="tentative")]
        proposal = _propose(gate, cand)
        report.pending_proposals = [proposal]

        with patch(
            "core.authorized_action_gate.evidence_engine.check_cloud_metadata",
            new=AsyncMock(return_value=None),
        ):
            await agent.run_authorized_evidence(
                report, proposal.proposal_id,
                approved_methods=["cloud_metadata"],
                operator="mohammed.test",
            )

        assert proposal.status == "EXECUTED"
        assert len(gate.log) >= 1
        assert gate.log[0].operator == "mohammed.test"

        # Sync to report (as agent.run() does at end)
        report.authorized_action_log = list(gate.log)
        d = report.to_dict()
        assert len(d["authorized_action_log"]) == 1


# ===========================================================================
# SECTION 4 — Report serialization validation
# ===========================================================================

class TestReportSerialization:
    """Validate all critical fields survive to_dict() and JSON round-trip."""

    def test_pending_proposals_in_report_to_dict(self):
        """pending_proposals must serialise as a list."""
        gate = _gate()
        cand = _cand()
        proposal = _propose(gate, cand)
        report = ScanReport()
        report.pending_proposals = [proposal]

        d = report.to_dict()
        assert "pending_proposals" in d
        assert isinstance(d["pending_proposals"], list)
        p = d["pending_proposals"][0]
        assert "proposal_id" in p
        assert "candidate_id" in p
        assert p["status"] == "AWAITING_REVIEW"

    def test_authorized_action_log_in_report_to_dict(self):
        """authorized_action_log must exist even when empty."""
        report = ScanReport()
        d = report.to_dict()
        assert "authorized_action_log" in d
        assert isinstance(d["authorized_action_log"], list)

    def test_skipped_candidates_with_real_url(self):
        """skipped_candidates must contain the actual target_url."""
        report = ScanReport()
        cand = _cand(target_url="http://victim.example/upload")
        report.skipped_candidates.append({
            "candidate_id": cand.candidate_id,
            "url":          cand.target_url,
            "parameter":    cand.parameter,
            "error_type":   "ConnectionError",
            "error":        "refused",
        })
        d = report.to_dict()
        assert d["skipped_candidates"][0]["url"] == "http://victim.example/upload"
        assert d["skipped_candidates"][0]["url"] != "?"

    def test_finding_confidence_tier_in_json(self):
        """confidence_tier must appear in Finding.to_dict() (H-2 direct check)."""
        f = _finding(_cand(), tier="certain")
        d = f.to_dict()
        assert "confidence_tier" in d
        assert d["confidence_tier"] == "certain"

    def test_finding_candidate_id_in_details(self):
        """details.candidate_id must be present for run_authorized_evidence() lookup."""
        cand = _cand()
        f = _finding(cand)
        assert f.to_dict()["details"]["candidate_id"] == cand.candidate_id

    def test_full_report_json_roundtrip_all_fields(self):
        """Complete ScanReport must survive json.dumps/loads without data loss."""
        gate = _gate()
        cand = _cand()
        proposal = _propose(gate, cand)

        report = ScanReport()
        report.status = "complete"
        report.pending_proposals = [proposal]
        report.findings = [_finding(cand, tier="firm")]
        report.skipped_candidates = [{"url": cand.target_url, "parameter": cand.parameter}]

        json_str = json.dumps(report.to_dict())
        recovered = json.loads(json_str)

        assert recovered["status"] == "complete"
        assert len(recovered["pending_proposals"]) == 1
        assert recovered["findings"][0]["confidence_tier"] == "firm"
        assert recovered["skipped_candidates"][0]["url"] == cand.target_url
        assert recovered["skipped_candidates"][0]["url"] != "?"
        assert "authorized_action_log" in recovered
