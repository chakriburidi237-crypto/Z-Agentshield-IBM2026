# Three-minute demo script

## Before recording

- Start the local runner so the API and dashboard use its isolated temporary
  SQLite database.
- Confirm `/health`, `/docs`, and the dashboard load.
- Use synthetic request IDs and no customer information.
- Do not approve, reject, or delete a review ticket during the demo.
- The default gateway has no trusted resource classifier. Therefore an API
  policy `ALLOW` is intentionally converted to `BLOCK`; do not present a
  policy preview `ALLOW` as a real authorization decision.

## Timed outline

### 0:00-0:30 - Problem and architecture

Introduce the problem of agent actions needing consistent evaluation, review,
and recording. Show the architecture diagram and state clearly that this
prototype evaluates decisions but does not execute downstream actions.

### 0:30-1:10 - Dashboard overview

Open <http://localhost:8501>. Point out the live API health status, persisted
database metrics, and note that record provenance is not tracked in the current
schema. Visit the five dashboard tabs. Explain that the review queue is
read-only until trusted reviewer authentication is integrated.

### 1:10-1:45 - Policy simulator

Use the default synthetic public-read form and submit it. Show the policy
preview result and explain that it is non-persistent, uses an unverified
resource input, and cannot authorize or execute the request. If the preview
shows `ALLOW`, explicitly distinguish it from the gateway result.

### 1:45-2:35 - Swagger API

Open <http://127.0.0.1:8000/docs> and show `POST /api/v1/intercept`.
Submit a synthetic export request:

```json
{
  "request_id": "demo-review-001",
  "agent_id": "agent-demo",
  "action": "bulk_export_demo",
  "category": "EXPORT",
  "resource": "data://synthetic/demo",
  "parameters": {"record_count": 3}
}
```

The current policy may return `REVIEW` for this resource/action combination.
Show the pending ticket in the review queue; leave it pending. If the policy
configuration changes and the verdict differs, report the actual result.

If demonstrating a gateway `ALLOW` or `BLOCK`, use only an installed,
verified classifier and policy. No trusted resource classifier is currently
configured, so a policy `ALLOW` should return `BLOCK`. The configured mandatory
destructive-operation rule can be previewed with `drop_demo_table` in category
`ADMIN`, but never send it to a real enterprise system.

### 2:35-3:00 - Audit and limitations

Show the new synthetic audit record and its decision. Do not expose raw
parameters. Close by stating the unconfigured reviewer identity integration,
resource-classification requirement, and absence of actual LinuxONE deployment
evidence.

## Persistent state

Requests sent to the gateway create audit records and `REVIEW` requests create
pending tickets. The local runner isolates them in its temporary database;
stopping the services and confirming cleanup removes that isolated database.
The simulator itself does not persist or create tickets.
