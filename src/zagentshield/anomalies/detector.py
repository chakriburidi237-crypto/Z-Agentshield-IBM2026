"""Behavioral anomaly detection module for Z-AgentShield.

Evaluates AI agent activity against temporal sliding-window thresholds and baselines:
- Request velocity spikes
- Repeated denied / blocked action attempts
- Multi-resource probing
- High-frequency bulk or administrative bursts
- Statistical baseline deviation
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import logging
import math
from typing import Any, Callable, Dict, List, Optional, Set

from zagentshield.core.enums import ActionCategory, ActionVerdict, RiskLevel
from zagentshield.core.models import AgentRequest
from zagentshield.db.repository import SecurityEventRecord, SecurityRepository

logger = logging.getLogger("zagentshield.anomalies")


class AnomalyCode(str, Enum):
    """Stable classification codes for detected behavioral anomalies."""

    VELOCITY_SPIKE = "VELOCITY_SPIKE"
    REPEATED_DENIED = "REPEATED_DENIED"
    RESOURCE_PROBING = "RESOURCE_PROBING"
    BULK_ACTION_BURST = "BULK_ACTION_BURST"
    BASELINE_DEVIATION = "BASELINE_DEVIATION"
    DETECTOR_ERROR = "DETECTOR_ERROR"


@dataclass
class AnomalySignal:
    """An explainable behavioral anomaly signal."""

    code: AnomalyCode
    severity: RiskLevel
    risk_score_delta: float
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyAssessment:
    """Outcome of behavioral anomaly evaluation for an agent request."""

    is_anomalous: bool
    signals: List[AnomalySignal] = field(default_factory=list)
    composite_risk_delta: float = 0.0
    highest_severity: Optional[RiskLevel] = None
    reasons: List[str] = field(default_factory=list)


@dataclass
class AnomalyConfig:
    """Tunable thresholds for sliding-window anomaly rules."""

    window_seconds: int = 60
    velocity_threshold: int = 10
    denied_action_threshold: int = 3
    resource_probing_threshold: int = 4
    bulk_action_threshold: int = 3
    min_baseline_events: int = 20
    baseline_deviation_multiplier: float = 2.5
    max_history_events_to_inspect: int = 200


def _parse_utc_timestamp(ts: Any) -> Optional[datetime]:
    """Parse an arbitrary timestamp into a timezone-aware UTC datetime."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts)
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


class AnomalyDetector:
    """Lightweight, deterministic behavioral anomaly detector for AI Agents."""

    def __init__(
        self,
        config: Optional[AnomalyConfig] = None,
        repository: Optional[SecurityRepository] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.config = config or AnomalyConfig()
        self.repository = repository
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def detect_anomalies(
        self,
        request: AgentRequest,
        events: Optional[List[SecurityEventRecord]] = None,
    ) -> AnomalyAssessment:
        """Analyze an intercepted agent request against recent historical behavior.
        
        Args:
            request: The intercepted AgentRequest.
            events: Optional pre-loaded history records. If None, queries repository.
            
        Returns:
            AnomalyAssessment containing detected signals and risk contributions.
        """
        try:
            return self._evaluate_internal(request, events)
        except Exception as e:
            logger.error("Anomaly detector internal failure on request '%s': %s", request.request_id, e)
            # Fail safely: generate an explicit detector error signal rather than implicit allow
            err_signal = AnomalySignal(
                code=AnomalyCode.DETECTOR_ERROR,
                severity=RiskLevel.MEDIUM,
                risk_score_delta=20.0,
                message=f"Anomaly detection evaluation error: {e}",
                details={"error": str(e)},
            )
            return AnomalyAssessment(
                is_anomalous=True,
                signals=[err_signal],
                composite_risk_delta=20.0,
                highest_severity=RiskLevel.MEDIUM,
                reasons=[err_signal.message],
            )

    def _evaluate_internal(
        self,
        request: AgentRequest,
        events: Optional[List[SecurityEventRecord]] = None,
    ) -> AnomalyAssessment:
        now_dt = _parse_utc_timestamp(request.timestamp) or self.clock()
        signals: List[AnomalySignal] = []

        # Step 1: Retrieve historical events for this agent
        raw_events: List[SecurityEventRecord] = []
        if events is not None:
            raw_events = events
        elif self.repository is not None:
            # Query recent events bounded by max_history_events_to_inspect
            since_time = now_dt - timedelta(seconds=self.config.window_seconds * 10)
            raw_events = self.repository.get_agent_recent_events(
                agent_id=request.agent_id,
                since_iso=since_time.isoformat(),
                limit=self.config.max_history_events_to_inspect,
            )

        # Step 2: Clean, parse timestamps, and deduplicate current request_id
        parsed_events: List[tuple[datetime, SecurityEventRecord]] = []
        for ev in raw_events:
            # Avoid duplicate counting of the current request if retried or pre-recorded
            if ev.request_id == request.request_id:
                continue
            ev_dt = _parse_utc_timestamp(ev.timestamp)
            if ev_dt is not None:
                parsed_events.append((ev_dt, ev))

        # Sort chronologically to safely handle out-of-order storage
        parsed_events.sort(key=lambda item: item[0])

        # Step 3: Extract sliding window events
        window_start = now_dt - timedelta(seconds=self.config.window_seconds)
        window_events = [ev for dt, ev in parsed_events if dt >= window_start and dt <= now_dt]

        # ----------------------------------------------------------------------
        # Rule 1: Request Velocity Spike
        # ----------------------------------------------------------------------
        total_recent_requests = len(window_events) + 1  # Include current request
        if total_recent_requests >= self.config.velocity_threshold:
            signals.append(
                AnomalySignal(
                    code=AnomalyCode.VELOCITY_SPIKE,
                    severity=RiskLevel.HIGH,
                    risk_score_delta=25.0,
                    message=(
                        f"Agent '{request.agent_id}' velocity spike: {total_recent_requests} requests "
                        f"in {self.config.window_seconds}s (threshold: {self.config.velocity_threshold})"
                    ),
                    details={
                        "recent_count": total_recent_requests,
                        "threshold": self.config.velocity_threshold,
                        "window_seconds": self.config.window_seconds,
                    },
                )
            )

        # ----------------------------------------------------------------------
        # Rule 2: Repeated Denied / Blocked Actions
        # ----------------------------------------------------------------------
        blocked_count = sum(1 for ev in window_events if ev.verdict == ActionVerdict.BLOCK.value)
        if blocked_count >= self.config.denied_action_threshold:
            signals.append(
                AnomalySignal(
                    code=AnomalyCode.REPEATED_DENIED,
                    severity=RiskLevel.CRITICAL,
                    risk_score_delta=35.0,
                    message=(
                        f"Agent '{request.agent_id}' repeated violations: {blocked_count} blocked "
                        f"actions in {self.config.window_seconds}s (threshold: {self.config.denied_action_threshold})"
                    ),
                    details={
                        "blocked_count": blocked_count,
                        "threshold": self.config.denied_action_threshold,
                        "window_seconds": self.config.window_seconds,
                    },
                )
            )

        # ----------------------------------------------------------------------
        # Rule 3: Multi-Resource Probing
        # ----------------------------------------------------------------------
        distinct_resources: Set[str] = {ev.resource for ev in window_events}
        distinct_resources.add(request.resource)
        if len(distinct_resources) >= self.config.resource_probing_threshold:
            signals.append(
                AnomalySignal(
                    code=AnomalyCode.RESOURCE_PROBING,
                    severity=RiskLevel.HIGH,
                    risk_score_delta=25.0,
                    message=(
                        f"Agent '{request.agent_id}' resource probing: targeted {len(distinct_resources)} distinct "
                        f"resources in {self.config.window_seconds}s (threshold: {self.config.resource_probing_threshold})"
                    ),
                    details={
                        "distinct_resources_count": len(distinct_resources),
                        "threshold": self.config.resource_probing_threshold,
                        "window_seconds": self.config.window_seconds,
                    },
                )
            )

        # ----------------------------------------------------------------------
        # Rule 4: High-Frequency Bulk / Admin Action Burst
        # ----------------------------------------------------------------------
        bulk_categories = {ActionCategory.EXPORT.value, ActionCategory.ADMIN.value}
        bulk_count = sum(1 for ev in window_events if ev.category in bulk_categories)
        if request.category.value in bulk_categories:
            bulk_count += 1

        if bulk_count >= self.config.bulk_action_threshold:
            signals.append(
                AnomalySignal(
                    code=AnomalyCode.BULK_ACTION_BURST,
                    severity=RiskLevel.HIGH,
                    risk_score_delta=30.0,
                    message=(
                        f"Bulk/Admin action burst detected: {bulk_count} operations in "
                        f"{self.config.window_seconds}s (threshold: {self.config.bulk_action_threshold})"
                    ),
                    details={
                        "bulk_count": bulk_count,
                        "threshold": self.config.bulk_action_threshold,
                        "window_seconds": self.config.window_seconds,
                    },
                )
            )

        # ----------------------------------------------------------------------
        # Rule 5: Historical Baseline Deviation
        # ----------------------------------------------------------------------
        # Requires sufficient baseline history (>= min_baseline_events)
        if len(parsed_events) >= self.config.min_baseline_events:
            baseline_signal = self._evaluate_baseline_deviation(
                parsed_events=parsed_events,
                current_window_count=len(window_events) + 1,
                now_dt=now_dt,
            )
            if baseline_signal is not None:
                signals.append(baseline_signal)

        # ----------------------------------------------------------------------
        # Step 4: Aggregate Assessment
        # ----------------------------------------------------------------------
        is_anomalous = len(signals) > 0
        composite_delta = min(50.0, sum(s.risk_score_delta for s in signals))
        highest_severity: Optional[RiskLevel] = None

        if signals:
            severity_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            highest_severity = max(signals, key=lambda s: severity_order.index(s.severity)).severity

        reasons = [s.message for s in signals]

        return AnomalyAssessment(
            is_anomalous=is_anomalous,
            signals=signals,
            composite_risk_delta=composite_delta,
            highest_severity=highest_severity,
            reasons=reasons,
        )

    def _evaluate_baseline_deviation(
        self,
        parsed_events: List[tuple[datetime, SecurityEventRecord]],
        current_window_count: int,
        now_dt: datetime,
    ) -> Optional[AnomalySignal]:
        """Compare current window activity against historical event counts per window."""
        if not parsed_events:
            return None

        oldest_dt = parsed_events[0][0]
        total_span_seconds = max(1.0, (now_dt - oldest_dt).total_seconds())
        num_windows = max(1.0, total_span_seconds / self.config.window_seconds)

        # Partition events into counts per window interval
        window_counts: List[int] = [0] * max(1, int(num_windows))
        for dt, _ in parsed_events:
            elapsed = (dt - oldest_dt).total_seconds()
            idx = min(len(window_counts) - 1, max(0, int(elapsed // self.config.window_seconds)))
            window_counts[idx] += 1

        mean_count = sum(window_counts) / len(window_counts)
        variance = sum((c - mean_count) ** 2 for c in window_counts) / len(window_counts)
        std_dev = math.sqrt(variance)

        threshold = mean_count + (self.config.baseline_deviation_multiplier * std_dev)

        if current_window_count > threshold and current_window_count > 3:
            return AnomalySignal(
                code=AnomalyCode.BASELINE_DEVIATION,
                severity=RiskLevel.MEDIUM,
                risk_score_delta=15.0,
                message=(
                    f"Statistical baseline deviation: {current_window_count} requests in window exceeds "
                    f"historical average ({mean_count:.1f} ± {std_dev:.1f})"
                ),
                details={
                    "current_window_count": current_window_count,
                    "historical_mean": round(mean_count, 2),
                    "historical_std_dev": round(std_dev, 2),
                    "threshold": round(threshold, 2),
                },
            )

        return None
