# IBM Z Datathon submission checklist

Use this as a preparation checklist only. It does not assert that a submission
has been made or that the project satisfies the event rules.

## Project deliverables

- [x] Source code and configuration in the current working tree.
- [x] README with local run instructions and explicit limitations.
- [x] Architecture overview: [ARCHITECTURE.md](ARCHITECTURE.md).
- [x] Three-minute demo outline: [DEMO_SCRIPT.md](DEMO_SCRIPT.md).
- [x] Windows local startup guide: [LOCAL_RUN_AND_VERIFICATION.md](LOCAL_RUN_AND_VERIFICATION.md).
- [x] Source repository URL provided and verified public:
  <https://github.com/chakriburidi237-crypto/Z--AgentShield-IBM-2026>.
  The remote `main` currently contains only a bare README; this local project
  worktree is not connected to or published on that remote.
- [ ] Authorize and publish the completed local source to the submission
  repository; no commit or push has been made.
- [x] Create and verify a source-only ZIP: [Z-AgentShield-submission-source-2026-10-17.zip](../../Z-AgentShield-submission-source-2026-10-17.zip).
  The archive excludes `.git`, virtual environments, local databases, local
  secrets, and editor-specific settings. It does not preserve Git history.
- [ ] Confirm required pitch-deck PDF filename and export final PDF: **TODO**.
- [ ] Record and review a demo video of no more than three minutes: **TODO**.
- [x] Team name provided: **Team Z Innovators**.
- [ ] Confirm the remaining submission metadata: **TODO**.

## Licensing and third-party material

- [x] Apache-2.0 license selected and added in [LICENSE](../LICENSE), with
  copyright notice for Team Z Innovators.
- [x] No third-party images, binaries, or package sources are vendored; Python
  dependencies are listed in `requirements.txt` and remain under their
  respective upstream licenses.
- [x] Dashboard branding SVGs are original, locally maintained project assets;
  they are not fetched from an external image URL at runtime.

## IBM platform evidence

- [ ] Perform and verify an actual IBM LinuxONE / `s390x` deployment if the
  event requires one.
- [ ] Capture genuine platform/runtime evidence from that deployment and
  include it in the submission if required.
- [ ] Do not use a Dockerfile, local Windows run, emulation, or this checklist
  as proof of an IBM LinuxONE deployment.

## Security and demo readiness

- [ ] Integrate a trusted resource classifier before claiming gateway `ALLOW`
  decisions. The default gateway blocks policy ALLOW results.
- [ ] Integrate trusted reviewer authentication before enabling review
  decisions or exposing privileged endpoints.
- [x] Run the final test suite: 184 tests passed, 0 failed; exit code 0
  (2026-10-17, PATH Python 3.13.15).
- [x] Run isolated live API/dashboard verification: 18 checks passed, 0 failed;
  exit code 0. Two synthetic audit events and one pending review were created
  only in a disposable database, then cleaned up.
- [x] Verify the demo plan and live verifier use synthetic requests only and
  never approve/reject the review ticket.
- [x] Review the audit/redaction and data-provenance limitations; do not submit
  real customer data.

## Datathon eligibility and development history

- [ ] Confirm the official hacking-window rule and the project's eligibility
  with event organizers. Existing work and repository history predate this
  submission-preparation task; no claim is made that all code was created
  during the official window.
- [ ] Preserve existing commit timestamps and history. Do not backdate commits,
  rewrite history to conceal prior work, or misrepresent contribution timing.
