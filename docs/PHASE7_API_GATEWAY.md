# Phase 7 — FastAPI Security Gateway

The gateway exposes the Phase 1–6 policy, decision, audit, anomaly, and review
services over HTTP. It validates input, delegates policy evaluation to the
existing engine, persists evaluations through the existing audit logger, and
returns the recorded decision without executing the requested operation.

## Run the gateway

From the repository root, set the source directory on `PYTHONPATH` and run:

```powershell
$env:PYTHONPATH = "src"
uvicorn zagentshield.api.app:app --host 127.0.0.1 --port 8000
```

The `app` ASGI object is created on import. The default database, policy engine,
and anomaly detector are initialized lazily on the first request. Tests should
use `create_app(services=...)` to inject isolated services.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Return minimal service status and version. |
| `POST` | `/api/v1/intercept` | Validate and evaluate an agent action. A `REVIEW` result includes a review ticket ID. |
| `GET` | `/api/v1/decisions/{request_id}` | Retrieve a recorded decision by request ID. |
| `GET` | `/api/v1/reviews?limit=50` | List pending review tickets; `limit` is bounded to 1–200. |
| `POST` | `/api/v1/reviews/{ticket_id}/decision` | Record an `APPROVED` or `REJECTED` decision and optional reviewer notes. |
| `GET` | `/api/v1/audit/logs?limit=50&offset=0&verdict=BLOCK` | List paginated, sanitized audit events. `verdict` is optional and accepts `ALLOW`, `REVIEW`, or `BLOCK`. |

`POST /api/v1/intercept` accepts the core `InterceptRequest` schema. Extra
fields are rejected. Caller-supplied
`claimed_permissions` are not treated as trusted authorization. Repeating a
request with a previously recorded `request_id` returns the stored decision
instead of evaluating and recording it again. The API does not accept an
execution callback and never executes the protected operation.

Review decisions only update the review ticket's state; approving a ticket does
not execute it. Any later operation must use the existing
`DecisionGate.execute_approved_ticket` workflow with an explicit approved
ticket and the application's authorized reviewer identity.

## Reviewer identity and deployment boundary

Review decisions and audit-log reads require `X-Reviewer-Id`. The API does not
verify credentials or roles itself: this header is an integration boundary, not
authentication. **Do not expose these routes directly to untrusted clients.**
Deploy behind an authentication proxy/API gateway that validates identity,
authorizes reviewers, strips any inbound `X-Reviewer-Id`, and injects the
verified reviewer identity. Do not derive reviewer identity or administrator
privileges from request JSON.

The pending-review listing and decision lookup are not authenticated by this
gateway. Restrict network access to them at the same trusted ingress boundary
when their metadata is sensitive.

## Response and failure behavior

Interception responses contain the verdict, risk summary, reasons, rule IDs,
and request ID; raw parameters are not returned. Audit responses omit
`parameters_redacted` entirely. Validation errors use a generic message rather
than reflecting invalid input. Unexpected internal details and stack traces
are not returned.

Policy-evaluation and audit-persistence failures return an error and do not
produce an `ALLOW`. The audit logger redacts sensitive parameter values before
persistence. The existing redaction is defense in depth and is not a guarantee
that arbitrary user content contains no sensitive information.

## Tests

Run the focused gateway tests from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -p "test_api.py" -v
```

Run the full suite with:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -p "test_*.py" -v
```

The reviewer-header integration must be replaced or backed by a real
authentication and authorization layer before production exposure.
