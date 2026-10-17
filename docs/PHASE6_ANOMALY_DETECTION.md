# PHASE 6 — Behavioral Anomaly Detection

> **Z-AgentShield** · Real-Time Security Layer for Enterprise AI Agents
> _"Let AI act. Keep every action under control."_

---

## Overview

Phase 6 adds a lightweight, **deterministic, explainable** behavioral anomaly
detection layer to Z-AgentShield. It analyses sliding-window patterns in recent
agent activity and raises typed anomaly signals that are fed into the existing
risk-scoring and policy-evaluation pipeline.

The module uses **no external dependencies, no trained ML models, and no
external APIs**. All rules are threshold-based and human-auditable.

---

## Module Location

| Path | Purpose |
|------|---------|
| `src/zagentshield/anomalies/detector.py` | Core detector, config, and signal types |
| `src/zagentshield/anomalies/__init__.py` | Public re-exports |
| `tests/test_anomaly_detector.py` | 17 unit tests (17/17 pass) |
| `docs/PHASE6_ANOMALY_DETECTION.md` | This document |

**Modified in Phase 6 (backward-compatible):**

| Path | Change |
|------|--------|
| `src/zagentshield/db/repository.py` | Added `get_agent_recent_events()` method |
| `src/zagentshield/policies/risk_scoring.py` | Optional `anomaly_signals` parameter on `evaluate_risk()` |
| `src/zagentshield/policies/engine.py` | Optional `anomaly_assessment` parameter on `evaluate()` |
| `src/zagentshield/core/gate.py` | Optional `anomaly_detector` parameter on `DecisionGate.__init__()` |

---

## Detection Rules and Configurable Thresholds

All rules share a single sliding time window (`window_seconds`). Defaults are
conservative; tune via `AnomalyConfig`.

### AnomalyConfig — all fields with defaults

```python
@dataclass
class AnomalyConfig:
    window_seconds: int = 60              # Observation window for all rules
    velocity_threshold: int = 10          # Max requests before VELOCITY_SPIKE
    denied_action_threshold: int = 3      # Max BLOCKs before REPEATED_DENIED
    resource_probing_threshold: int = 4   # Max distinct resources before RESOURCE_PROBING
    bulk_action_threshold: int = 3        # Max EXPORT/ADMIN ops before BULK_ACTION_BURST
    min_baseline_events: int = 20         # Minimum history for BASELINE_DEVIATION
    baseline_deviation_multiplier: float = 2.5  # sigma multiplier above historical mean
    max_history_events_to_inspect: int = 200    # Bounds in-memory / query load
```

### Rule 1 — VELOCITY_SPIKE

| Item | Value |
|------|-------|
| **Trigger** | Total requests by this agent in window >= velocity_threshold (current req +1) |
| **Default threshold** | 10 requests / 60 s |
| **Severity** | HIGH |
| **Risk delta** | +25.0 |

### Rule 2 — REPEATED_DENIED

| Item | Value |
|------|-------|
| **Trigger** | BLOCK verdicts in window >= denied_action_threshold |
| **Default threshold** | 3 BLOCKs / 60 s |
| **Severity** | CRITICAL |
| **Risk delta** | +35.0 |

### Rule 3 — RESOURCE_PROBING

| Item | Value |
|------|-------|
| **Trigger** | Distinct resources targeted in window >= resource_probing_threshold |
| **Default threshold** | 4 distinct resources / 60 s |
| **Severity** | HIGH |
| **Risk delta** | +25.0 |

### Rule 4 — BULK_ACTION_BURST

| Item | Value |
|------|-------|
| **Trigger** | EXPORT or ADMIN ops in window >= bulk_action_threshold |
| **Default threshold** | 3 bulk ops / 60 s |
| **Severity** | HIGH |
| **Risk delta** | +30.0 |

### Rule 5 — BASELINE_DEVIATION (optional)

| Item | Value |
|------|-------|
| **Trigger** | Current window count > mean + (multiplier * sigma) AND count > 3 |
| **Data requirement** | >= min_baseline_events (default 20) |
| **Severity** | MEDIUM |
| **Risk delta** | +15.0 |

Automatically skipped when insufficient historical data is available.

---

## Signal Format

```python
@dataclass
class AnomalySignal:
    code: AnomalyCode           # Stable enum: VELOCITY_SPIKE, REPEATED_DENIED, etc.
    severity: RiskLevel         # LOW | MEDIUM | HIGH | CRITICAL
    risk_score_delta: float     # Additive contribution (capped at 50.0 aggregate)
    message: str                # Human-readable explanation (no raw params stored)
    details: Dict[str, Any]     # Counts, thresholds, window duration only

@dataclass
class AnomalyAssessment:
    is_anomalous: bool
    signals: List[AnomalySignal]
    composite_risk_delta: float     # Capped at 50.0
    highest_severity: Optional[RiskLevel]
    reasons: List[str]
```

---

## Integration with Risk Scoring and DecisionGate

```
AgentRequest --> AnomalyDetector.detect_anomalies()
                        |
                 AnomalyAssessment
                        |
         +--------------+-------------------+
         v                                  v
 PolicyEngine.evaluate()          RiskScorer.evaluate_risk()
 (optional anomaly_assessment)    (optional anomaly_signals)
         |                                  |
         +----------------+-----------------+
                          v
                    DecisionGate
                (final ALLOW/REVIEW/BLOCK)
```

### Escalation rules (PolicyEngine)

| Condition | Outcome |
|-----------|---------|
| CRITICAL anomaly + candidate ALLOW | Escalated to BLOCK |
| HIGH anomaly + candidate ALLOW | Escalated to REVIEW |
| Candidate is already BLOCK | Never weakened — preserved |
| Candidate is REVIEW | Kept as REVIEW |

**BLOCK cannot become ALLOW under any anomaly logic.**

### DecisionGate wiring

```python
gate = DecisionGate(
    policy_engine=engine,
    repository=repo,
    anomaly_detector=AnomalyDetector(config=AnomalyConfig(), repository=repo),
)
```

`anomaly_detector` is optional (defaults to None). Existing gate usage unchanged.

---

## Failure Behavior

| Scenario | Behavior |
|----------|----------|
| Detector raises any exception | Caught; returns AnomalyAssessment with DETECTOR_ERROR signal (+20.0 delta). Never implicit ALLOW. |
| Repository unavailable | Proceeds with empty history; baseline rule skipped. |
| Corrupt / missing timestamps | Unparseable events silently skipped. |
| Out-of-order timestamps | Events sorted chronologically before windowing. |
| No historical data | Clean non-anomalous assessment; baseline rule skipped. |

---

## State Retention and Concurrency

| Topic | Behavior |
|-------|----------|
| In-process state | Detector holds no mutable state between requests. Fully stateless. |
| Historical data | Read from `security_events` SQLite table via `get_agent_recent_events()`. |
| Query bound | `max_history_events_to_inspect` (default 200) limits rows per evaluation. |
| Sensitive data | Signal messages contain only counts/thresholds. Raw parameters NEVER stored. |
| Distribution | **Single-process / single-database only.** Multi-instance deployments require a shared state store. |

---

## False-Positive Limitations

| Rule | Known FP scenario |
|------|------------------|
| VELOCITY_SPIKE | Legitimate burst batch jobs will trigger unless threshold is raised. |
| RESOURCE_PROBING | Data-pipeline agents legitimately touching many resources. |
| BULK_ACTION_BURST | Scheduled nightly exports. Raise window or threshold for batch agents. |
| BASELINE_DEVIATION | New agents lack sufficient history; rule automatically skipped. |
| REPEATED_DENIED | Low FP risk — repeated BLOCKs are inherently suspicious. |

---

## What Is Implemented vs. Planned

### Implemented (Phase 6)
- [x] Five deterministic, explainable detection rules
- [x] AnomalySignal, AnomalyAssessment, AnomalyCode, AnomalyConfig types
- [x] Injectable clock for deterministic tests
- [x] UTC-aware timestamp parsing with safe fallback
- [x] Out-of-order event sorting
- [x] Current-request deduplication guard
- [x] Bounded history query (max_history_events_to_inspect)
- [x] Fail-safe exception containment (DETECTOR_ERROR signal)
- [x] Risk-scorer integration (additive anomaly deltas)
- [x] PolicyEngine escalation (ALLOW -> REVIEW -> BLOCK via anomaly severity)
- [x] DecisionGate optional wiring
- [x] 17 unit tests — 74/74 total tests pass (57 regression + 17 new)

### Planned / Not Yet Implemented
- [ ] Per-agent threshold overrides
- [ ] Distributed / multi-node anomaly aggregation
- [ ] Real-time alerting / webhook emission
- [ ] Dashboard visualization (Phase 8)
- [ ] Adaptive thresholds based on rolling history

---

## Test Coverage Summary

```
tests/test_anomaly_detector.py — 17 tests, all pass

TestAnomalyDetector (15 tests):
  test_normal_behavior_produces_no_anomaly
  test_request_velocity_threshold
  test_repeated_denied_action_threshold
  test_resource_probing_detection
  test_bulk_action_burst_detection
  test_boundary_conditions_time_window
  test_utc_and_timezone_aware_timestamps
  test_missing_or_corrupt_timestamps_handled_safely
  test_out_of_order_timestamps
  test_injected_clock_deterministic_results
  test_empty_history_produces_no_anomaly
  test_insufficient_baseline_data_skips_baseline_rule
  test_detector_exception_handling_fails_safely
  test_duplicate_request_id_not_counted_twice
  test_no_sensitive_parameters_stored_by_detector

TestAnomalyGateIntegration (2 tests):
  test_anomaly_escalates_routine_allow_to_review
  test_block_cannot_become_allow_due_to_anomaly_logic
```

Run command:
```powershell
$env:PYTHONPATH="src"; python -m unittest discover -s tests -p "test_*.py" -v
```

Expected result: Ran 74 tests -- OK

---

_Phase 6 complete. Phase 7 (FastAPI gateway) has NOT been started._
