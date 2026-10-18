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
| `POST` | `/api/v1/auth/login` | Issue a signed bearer token for a configured local account. |
| `POST` | `/api/v1/intercept` | Validate and evaluate an agent action. A `REVIEW` result includes a review ticket ID. |
| `GET` | `/api/v1/decisions/{request_id}` | Retrieve a recorded decision by request ID. |
| `GET` | `/api/v1/reviews?limit=50` | List pending review tickets; authenticated and bounded to 1–200. |
| `POST` | `/api/v1/reviews/{ticket_id}/decision` | Record an `APPROVED` or `REJECTED` decision and optional reviewer notes. |
| `GET` | `/api/v1/audit/logs?limit=50&offset=0&verdict=BLOCK` | List authenticated, paginated, sanitized audit events. |
| `GET` | `/api/v1/audit/integrity` | Authenticated verification of the SHA-256 links recorded in the audit chain. |
| `POST` | `/api/v1/security/prompt-scan` | Apply explainable deterministic rules without persisting or echoing the prompt. |
| `GET` | `/api/v1/system/telemetry` | Return local platform metadata and bounded measured fields. |

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

The review queue, review decisions, audit logs, and integrity verification
require a signed bearer token issued by `/api/v1/auth/login`. Users and roles
are read only from server-side `AUTH_USERS_JSON`; password hashes are
PBKDF2-SHA256, and tokens are signed with `AUTH_TOKEN_SECRET`. Caller-supplied
`X-Reviewer-Id` values and request-body role claims do not establish identity.
The configurable token lifetime defaults to 900 seconds and is bounded to
60–86400 seconds.

Generate one local demo account record with
`$env:PYTHONPATH="src"; .\.venv\Scripts\python.exe scripts\create_local_auth_config.py`
and copy the output into the ignored `.env`. If authentication is unconfigured,
privileged routes return unavailable/unauthenticated errors rather than
allowing access. SOC Analyst and Security Admin are supported, server-assigned
roles; both currently can use the review and audit workflow. This local
authentication is a development/demo integration, not a production identity
provider. Keep the gateway on trusted networks and use a proper identity
provider before production deployment.

Decision lookup and interception are public gateway endpoints. Do not expose
them to an untrusted network without deployment-specific authentication,
authorization, and rate limiting.

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

Approval only changes the persisted review ticket and adds a chained audit
entry; it does not execute the original action. The SHA-256 chain detects
record/link changes but is not immutable against an operator who can rewrite
the database, and older records are not retroactively chained. No LinuxONE
deployment, trusted resource registry, or production identity provider is
verified by this repository.
