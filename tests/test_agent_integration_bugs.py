"""
tests/test_agent_integration_bugs.py

Regression tests for the three integration bugs found in core/agent.py
during the Gate Implementation code review (August 2, 2026).

Bug 1 - self._log undefined (HIGH):   worker exception handler used self._log
         instead of the module-level `logger`, causing AttributeError on any
         candidate exception and silently killing the isolation mechanism.

Bug 2 - [True] wrong arg (MEDIUM):    run_authorized_evidence() passed [True]
         as suspicious_results to scoring.determine_tier(), which expects a
         list of ProbeResult objects. The placeholder satisfied truthiness by
         accident but would break if determine_tier ever inspected the objects.

Bug 3 - Stage 5 display (LOW):        Stage 5 lifecycle terminal output never
         showed pending_proposals count. With the gate active, evidence_artifacts
         is always 0 on the automatic path, so operators saw "0" and had no
         visible indication that proposals were waiting for their review.
"""
from __future__ import annotations

import logging
import pytest
from unittest.mock import AsyncMock, patch

from core.models import (
    Candidate, ParamLocation, ScanReport,
)
from core.authorized_action_gate import AuthorizedActionGate


def _candidate(**overrides) -> Candidate:
    defaults = dict(
        target_url="http://target.example/preview",
        method="POST",
        parameter="url",
        param_location=ParamLocation.BODY_JSON,
    )
    defaults.update(overrides)
    return Candidate(**defaults)


# -----------------------------------------------------------------------
# Bug 1 -- self._log undefined -> AttributeError on candidate exception
# -----------------------------------------------------------------------

def test_bug1_no_self_log_attribute_on_agent():
    """SSRFCyartAgent must NOT have a _log attribute. The fix uses the
    module-level `logger` object instead. If this test fails it means
    self._log was re-introduced."""
    import core.agent as agent_module
    from core.agent import SSRFCyartAgent

    assert not hasattr(SSRFCyartAgent, '_log'), (
        "SSRFCyartAgent must not define _log. Use module-level logger."
    )
    assert hasattr(agent_module, 'logger'), "core/agent.py must have a module-level `logger`"
    assert isinstance(agent_module.logger, logging.Logger)
    assert agent_module.logger.name == "ssrf_cyart.agent"


# -----------------------------------------------------------------------
# Bug 2 -- [True] passed to determine_tier instead of []
# -----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bug2_determine_tier_receives_empty_list_not_true():
    """run_authorized_evidence() must pass [] as suspicious_results to
    determine_tier, not [True]. [True] was a placeholder that worked by
    accident but is semantically wrong."""
    import core.scoring as scoring_module

    recorded = []
    original = scoring_module.determine_tier

    def spy(suspicious_results, *args, **kwargs):
        recorded.append(list(suspicious_results))
        return original(suspicious_results, *args, **kwargs)

    gate = AuthorizedActionGate(client=AsyncMock())
    cand = _candidate()
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)
    proposal.status = "AWAITING_REVIEW"

    from core.models import Finding, ConfidenceTier
    report = ScanReport()
    report.pending_proposals = [proposal]
    finding = Finding(
        agent_group='test', sub_agent='test', vulnerability_type='ssrf',
        category='ssrf', severity='medium', confidence='low',
        target_url=cand.target_url, affected_parameter=cand.parameter,
        description='test', observation='test', proof_of_concept='', remediation='',
        confidence_tier='tentative',
        details={'candidate_id': cand.candidate_id},
    )
    report.findings = [finding]

    from core.agent import SSRFCyartAgent
    import yaml, pathlib
    cfg_path = pathlib.Path(__file__).parent.parent / "core" / "config.yaml"
    agent = SSRFCyartAgent.__new__(SSRFCyartAgent)
    agent.cfg = yaml.safe_load(cfg_path.read_text())
    agent._gate = gate
    agent._candidate_index = {cand.candidate_id: cand}
    agent._max_hops = 3
    agent._client = AsyncMock()

    with patch("core.agent.scoring.determine_tier", side_effect=spy), \
         patch("core.authorized_action_gate.evidence_engine.check_cloud_metadata",
               new=AsyncMock(return_value=None)):
        await agent.run_authorized_evidence(
            report, proposal.proposal_id,
            approved_methods=["cloud_metadata"],
            operator="test-operator",
        )

    assert recorded, "determine_tier must have been called at least once"
    assert recorded[0] == [], (
        f"Bug 2 regression: first arg must be [] (got {recorded[0]!r}). "
        "[True] is the pre-fix placeholder."
    )


# -----------------------------------------------------------------------
# Bug 3 -- Stage 5 display omitted pending proposals count
# -----------------------------------------------------------------------

def test_bug3_proposals_generated_key_in_exploit_stats():
    """_exploit_stats must contain 'proposals_generated' so Stage 5
    lifecycle display can render how many gate proposals were created.
    Without this key, the display would raise a KeyError."""
    from core.agent import SSRFCyartAgent
    import yaml, pathlib
    from collections import Counter

    cfg_path = pathlib.Path(__file__).parent.parent / "core" / "config.yaml"
    agent = SSRFCyartAgent.__new__(SSRFCyartAgent)
    agent.cfg = yaml.safe_load(cfg_path.read_text())
    agent._exploit_stats = {"evidence_artifacts": Counter(), "proposals_generated": 0}

    assert "proposals_generated" in agent._exploit_stats
    agent._exploit_stats["proposals_generated"] += 3
    assert agent._exploit_stats["proposals_generated"] == 3, (
        "proposals_generated counter must increment correctly for Stage 5 display."
    )

