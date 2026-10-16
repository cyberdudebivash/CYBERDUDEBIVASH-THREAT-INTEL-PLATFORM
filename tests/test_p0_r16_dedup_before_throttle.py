"""P0 R16: rate-limit delay belongs after local reject gates, not before them.

Exact observed trigger: sentinel-blogger run #2522 spent three seconds per
locally rejected feed candidate and exceeded the 1,200-second engine budget.
Static structure tests do not consume network or Cloudflare quota.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "agent" / "sentinel_blogger.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def _called(node, name):
    return any(
        isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id == name
        for x in ast.walk(node)
    )


def _delay(node):
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and (
        isinstance(node.value.func, ast.Attribute)
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == "time"
        and node.value.func.attr == "sleep"
    )


def _phase2_entry_loop():
    matches = [
        node for node in ast.walk(TREE)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name) and node.target.id == "entry"
        and isinstance(node.iter, ast.Name) and node.iter.id == "entries"
        and _called(node, "process_entry")
    ]
    assert len(matches) == 1, "multi-feed candidate processing loop must be unambiguous"
    return matches[0]


def test_phase2_no_unconditional_sleep_before_first_local_duplicate_filter():
    loop = _phase2_entry_loop()
    assert not _delay(loop.body[0]), "rejected candidates must not consume API pacing"
    throttle_indices = [i for i, n in enumerate(loop.body) if _delay(n)]
    assert len(throttle_indices) == 1


def test_throttle_occurs_only_after_all_local_rejection_filters():
    loop = _phase2_entry_loop()
    delay_index = next(i for i, n in enumerate(loop.body) if _delay(n))
    # Structural checks: a delayed accepted candidate follows the short-
    # circuiting quality/temporal/dedup branches.
    assert delay_index >= 6
    preceding = ast.get_source_segment(SOURCE, loop.body[0])
    assert "_intel_engine" in preceding
    earlier = "\n".join(ast.get_source_segment(SOURCE, n) or "" for n in loop.body[:delay_index])
    for marker in ("is_duplicate", "is_temporally_relevant", "_quality_gate", "_sst", "_fps"):
        assert marker in earlier


def test_throttle_remains_immediately_before_processing():
    loop = _phase2_entry_loop()
    idx = next(i for i, n in enumerate(loop.body) if _delay(n))
    assert isinstance(loop.body[idx + 1], ast.Try)
    assert _called(loop.body[idx + 1], "process_entry")
    throttle = loop.body[idx].value
    assert len(throttle.args) == 1
    assert isinstance(throttle.args[0], ast.Name)
    assert throttle.args[0].id == "RATE_LIMIT_DELAY"


def test_delay_configuration_not_diluted_to_force_green():
    import sys
    sys.path.insert(0, str(ROOT))
    from agent.config import RATE_LIMIT_DELAY
    assert RATE_LIMIT_DELAY == 3

def test_ingestion_fence_precedes_all_stage3_enrichment():
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    fence_start = workflow.index('- name: "P0 - Stage 1-3 Ingestion Health Fence')
    stale_guard = workflow.index('- name: "STAGE 1-3b - Stale Source Guard', fence_start)
    enrichment = workflow.index('- name: "STAGE 3.1 - APEX AI Feed Enrichment', stale_guard)
    assert fence_start < stale_guard < enrichment


def test_fence_fails_closed_on_real_outcome_and_health_not_masked_conclusion():
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    beginning = workflow.index('- name: "P0 - Stage 1-3 Ingestion Health Fence')
    ending = workflow.index('- name: "STAGE 1-3b - Stale Source Guard', beginning)
    body = workflow[beginning:ending]
    assert 'id: p0-ingestion-health-fence' in body
    assert 'if: ${{ !cancelled() }}' in body
    assert 'steps.pipeline_stage_1_3.outcome' in body
    assert 'steps.pipeline_stage_1_3.conclusion' not in body
    assert 'PIPELINE_HEALTH:-UNKNOWN' in body
    assert '"$STAGE_OUTCOME" != "success"' in body
    assert '"$HEALTH" != "HEALTHY"' in body
    assert 'exit 1' in body


def test_fence_does_not_reduce_existing_cost_or_content_authorization_gates():
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    assert 'STAGE 3.3 - Report Validation Gate (HARD FAIL)' in workflow
    assert 'STAGE 3.6 - R2 Upload Integrity Verifier (HARD FAIL)' in workflow
    assert 'P0 - Report Publishing Release Verdict' in workflow
    assert 'STAGE 5.9.3 - Pipeline Health Terminal Gate' in workflow

def test_health_recorder_produces_explicit_degraded_state_before_fence():
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    status_start = workflow.index('- name: "STAGE 1-3 STATUS GATE')
    fence_start = workflow.index('- name: "P0 - Stage 1-3 Ingestion Health Fence', status_start)
    status = workflow[status_start:fence_start]
    assert 'steps.pipeline_stage_1_3.outcome' in status
    assert 'echo "PIPELINE_HEALTH=DEGRADED" >> $GITHUB_ENV' in status
    assert 'echo "PIPELINE_HEALTH=HEALTHY" >> $GITHUB_ENV' in status
    assert "pipeline_health.json" in status

def test_final_mandate_fail_closed_after_ingestion_and_before_snapshot():
    source = (ROOT / "scripts/run_pipeline.py").read_text(encoding="utf-8")
    after_sync = source.index('stage_sync_root_feed_json()          # FINAL:')
    mandate = source.index('mandate_verdict = run_script(', after_sync)
    snapshot = source.index('Phase 3.95', mandate)
    assert after_sync < mandate < snapshot
    invocation = source[mandate:snapshot]
    assert 'scripts/sentinel_apex_mandate_enforcer.py' in invocation
    assert '"--report"' not in invocation
    assert '"--fix"' not in invocation
    assert 'allow_fail=False' in invocation
    assert 'mandate_verdict.returncode != 0' in invocation
    assert 'raise RuntimeError(' in invocation
    assert '_stage_done("mandate_enforcement")' in invocation


def test_mandate_enforcement_cannot_succeed_by_logging_nonzero_exit():
    source = (ROOT / "scripts/run_pipeline.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    guarded = [
        node for node in ast.walk(module)
        if isinstance(node, ast.If)
        and "mandate_verdict.returncode != 0" in
            (ast.get_source_segment(source, node.test) or "")
    ]
    assert len(guarded) == 1
    assert any(isinstance(node, ast.Raise) for item in guarded[0].body for node in ast.walk(item))
    assert not any(isinstance(node, ast.Pass) for item in guarded[0].body for node in ast.walk(item))
