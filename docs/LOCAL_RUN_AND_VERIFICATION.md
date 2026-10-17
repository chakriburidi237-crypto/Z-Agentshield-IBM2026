# Local Run and Verification (Windows 11)

## Environment inspected

The project environment is `.venv\Scripts\python.exe` (Python 3.14.7), and it
contains the required FastAPI, Uvicorn, Streamlit, Pydantic, PyYAML,
scikit-learn, pandas, NumPy, and requests packages. The startup script prefers
this interpreter. It does not assume a globally installed Python executable
and does not install packages.

If `.venv` is absent, `run_zagentshield.bat` uses the first `python.exe` on
`PATH`. To explicitly choose another existing interpreter, set this variable
in the launching terminal, without embedding quotes in its value:

```powershell
$env:ZAGENTSHIELD_PYTHON = "C:\path\to\your\python.exe"
```

The runner checks that interpreter and imports the required packages before
starting either service. If imports are missing, install from the repository
root into the selected interpreter:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## One-command start

Run at the repository root:

```powershell
.\scripts\run_zagentshield.bat
```

The batch file changes to the repository root, sets `PYTHONPATH` to `src`,
binds the local services to loopback, checks that ports 8000 and 8501 are
available, and launches each service in a separate titled terminal:

- API: `python -m uvicorn zagentshield.api.app:app --host 127.0.0.1 --port 8000`
- Dashboard: `python -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501`

The actual executable is selected from `.venv`, `ZAGENTSHIELD_PYTHON`, or
`PATH`; the command shown above describes the module arguments. The script
sets `APP_ENV=development` for this local loopback run, then waits for the
gateway root identity and `/health` response before displaying
`ONLINE`; it then waits for Streamlit's `/_stcore/health` endpoint. A failed
check is reported as an error, not an online service.

On port conflict, the runner shows the listening PID and exits without
starting or terminating processes. Free the port yourself if appropriate.
Once startup completes, the runner opens:

| Service | URL |
| --- | --- |
| Dashboard | <http://localhost:8501> |
| Swagger UI | <http://127.0.0.1:8000/docs> |
| API health | <http://127.0.0.1:8000/health> |
| API root | <http://127.0.0.1:8000/> |

Swagger UI and `/openapi.json` are registered only in development mode.
`APP_ENV=demo`, `APP_ENV=production`, and other non-development values disable
both server routes; the root response then reports `"docs": null`. The local
configuration defaults to demo mode, which also disables those routes. The
local runner explicitly enables development mode on loopback. For separate
local development, set `$env:APP_ENV = "development"` in the API terminal
before starting Uvicorn. Do not use development mode as a deployment security
control: the project does not authenticate documentation access.

The dashboard performs its own gateway health request to `127.0.0.1:8000` and
shows the result in the sidebar. Open the dashboard to visually confirm that
it displays the gateway as online; an HTTP response alone is not visual
verification.

The gateway has no trusted resource classifier configured by default.
Therefore, any policy `ALLOW` result is converted to `BLOCK` until a trusted,
server-controlled classifier is injected. A caller-supplied resource label is
not sufficient evidence of the target resource.

## Configuration and database initialization

The relevant variables, all represented in `.env.example`, are:

- `HOST`, `PORT`: API bind address and port (the local runner sets
  `127.0.0.1` and `8000`).
- `DASHBOARD_HOST`, `DASHBOARD_PORT`: dashboard settings (the runner binds
  `127.0.0.1:8501`).
- `DATABASE_PATH`: SQLite location.
- `POLICY_CONFIG_PATH`: policy YAML path.
- `RISK_THRESHOLD_REVIEW`, `RISK_THRESHOLD_BLOCK`: policy risk thresholds.
- `ANOMALY_WINDOW_SECONDS`, `ANOMALY_BURST_THRESHOLD`, and
  `ISOLATION_FOREST_CONTAMINATION`: anomaly detector settings.
- `APP_ENV`, `APP_NAME`, `LOG_LEVEL`, `DEBUG`, `REDACT_SECRETS`, and
  `REDACT_PII`: runtime and redaction settings.

The API creates its SQLite schema lazily on its first service request. The
dashboard initializes the configured database on startup. The normal
standalone default is `data\zagentshield.db` with policies from
`config\policies.yaml`.

For isolation, the one-command runner sets `DATABASE_PATH` to a unique SQLite
file in `%TEMP%` and sets the policy path to the repository configuration.
Both child processes inherit these settings. Interception and verification
records from that run therefore do not alter the project's normal database.

## Separate startup

Use two PowerShell terminals at the repository root. In the API terminal:

```powershell
$env:APP_ENV = "development"
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m uvicorn zagentshield.api.app:app --host 127.0.0.1 --port 8000
```

In the dashboard terminal:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

When started separately, both services read the same process environment and
`.env` settings. If no `DATABASE_PATH` is configured, they use the project
default and initialize `data\zagentshield.db`. Keep the two server terminals
open.

## Live verification

With both services running, execute:

```powershell
.\.venv\Scripts\python.exe scripts\verify_zagentshield.py
```

The verifier uses synthetic request IDs and a synthetic API-key marker. It
checks root and health identity/version, Swagger UI, OpenAPI JSON and required
paths, live public-read and bulk-export interception, the configured policy's
baseline verdict, duplicate request behavior, decision lookup, pending-review
listing, unauthenticated review decision rejection, audit authorization and
redaction, and dashboard HTTP health.

The verifier compares requests against the configured policy and the default
fail-closed resource-classification gate. Its gateway URL can be overridden
with `ZAGENTSHIELD_GATEWAY_URL` to test an isolated local API on another port.

**Latest verification:** 18 live checks passed and 0 failed (exit code 0) on
2026-10-17. The run used temporary API/dashboard services on ports 8001/8502
and a disposable SQLite database. The synthetic audit events and pending
review created by the verifier were removed when that temporary database was
cleaned up. The regular services on ports 8000/8501 remained running.

The dashboard reads persisted records directly from the configured SQLite
database and intentionally does not display request parameter payloads. The
schema does not record whether events came from synthetic tests or operational
traffic. Dashboard review decisions remain disabled until trusted reviewer
authentication is integrated; the API `X-Reviewer-Id` header alone is not
authentication.

The overview aggregates exact SQLite event totals for its selected time window.
The audit table supports time, verdict, and agent filters with bounded
pagination; event-type filtering is unavailable because the schema has no event
type field. Analytics use up to the 500 newest matching events, so the UI
labels their sample size and warns when older matching records are omitted.
The dashboard health panel checks the configured gateway and database
separately. A browser response alone is not treated as service health.
Agent inventory and policy/access management screens are omitted because no
authoritative inventory or authorized configuration API exists.

The verifier never approves or rejects a ticket. If policy returns `REVIEW`,
it checks that the new synthetic ticket is pending and that a decision request
without reviewer identity is rejected. Its audit-log check sends the local
`X-Reviewer-Id` integration header; this project does not cryptographically
authenticate that header. Use only on loopback behind a trusted identity and
authorization layer before any external exposure.

The verifier returns exit code 1 if any required live check fails. It prints
the dashboard URL for manual inspection and explicitly does not claim that an
HTTP response proves visual correctness.

**Persistent state:** live interception is an audit operation. A verifier run
can create up to two synthetic audit events and one synthetic pending review
ticket if policy returns `REVIEW`. The one-command runner isolates these in its
temporary database. When running the verifier against the normal database,
these synthetic audit records remain there; do not use real customer data.

## Unit tests

Run the project's unittest suite with a Python environment that has the test
dependencies installed. On this machine, the PATH Python 3.13 environment was
verified to run the suite. The project `.venv` is Python 3.14.7 and its
installed Starlette test client currently lacks `httpx2`, so the suite fails
during import there unless that test dependency is added. The startup runner
continues to use `.venv` for the API and dashboard.

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -p "test_*.py" -v
$testExitCode = $LASTEXITCODE
Write-Output "Test process exit code: $testExitCode"
```

## Stop and clean up

Run:

```powershell
.\scripts\stop_zagentshield.bat
```

The script deliberately does not terminate processes by port, process name, or
window title. Follow its instructions and press Ctrl+C in both Gateway and
Dashboard terminals. Confirm only after both have stopped. If either fixed
port is still listening, the script leaves the temporary database untouched.
Once both ports are clear, it removes only the recorded per-run SQLite file
and its exact `-wal` and `-shm` sidecar paths. Services started manually must
also be stopped with Ctrl+C in their own terminals.

## Troubleshooting

- **8000/8501 occupied:** the runner prints the listener PID and exits without
  killing it. Identify it and free the port manually if appropriate.
- **Python not found:** create/activate the project's `.venv`, or set
  `ZAGENTSHIELD_PYTHON` to an existing interpreter path.
- **Missing dependency:** the runner prints the install command for the
  selected interpreter. It never installs packages automatically.
- **Gateway fails to start:** inspect the Gateway terminal, verify
  `config\policies.yaml`, and check that both `/` and `/health` answer on port
  8000. The runner does not call the API online if those checks fail.
- **Dashboard fails to start:** inspect the Dashboard terminal and ensure the
  selected interpreter has Streamlit. Verify `/_stcore/health` on port 8501.
- **Gateway appears offline in the dashboard:** confirm that the API is on
  `127.0.0.1:8000` and that `PORT` is not set to a different value in the
  launching environment.
- **Reviewer identity:** `X-Reviewer-Id` is an integration boundary, not an
  identity provider. Do not expose reviewer or audit routes to untrusted
  clients without upstream authentication and authorization.
