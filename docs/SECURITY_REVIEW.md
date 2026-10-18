
# Phase 5 Security Architecture & Decision Gate Review

**Project:** Z-AgentShield  
**Document:** Decision Gating Logic & Execution Interception Security Review  
**Status:** Validated in Development Environment  

---

## 1. Decision-Gate Flow

The `DecisionGate` acts as a fail-closed execution boundary positioned between AI agent requests and protected enterprise actions.

```
┌─────────────────────────────────┐
│     Incoming AgentRequest       │
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│   1. Idempotency Check (DB)     │ ─── [ Duplicate request_id ] ───> BLOCK (No re-execution)
└─────────────────────────────────┘
                 │ (New request)
                 ▼
┌─────────────────────────────────┐
│ 2. Server Authorization Lookup  │ (Uses server-side trusted_permissions;
└─────────────────────────────────┘  ignores agent claimed_permissions)
                 │
                 ▼
┌─────────────────────────────────┐
│  3. Policy Engine Evaluation    │ ─── [ Engine Exception ] ───────> BLOCK (Fail-closed)
└─────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ 4. Audit Persistence (Logger)   │ ─── [ Audit Error / DB Full ] ──> BLOCK (Fail-closed)
└─────────────────────────────────┘
                 │ (Audit saved & sanitized)
                 ▼
         [ Check Verdict ]
         ├─── BLOCK   ─────────────────────────────────────────────> Deny execution (Callback not called)
         ├─── REVIEW  ────> Create Review Ticket ──────────────────> Deny execution (Callback not called)
         └─── ALLOW   ────> Verify All Checks Passed ──────────────> Execute Protected Operation Callback
```

---

## 2. Trusted vs. Untrusted Authorization Inputs

- **Untrusted Input (`AgentRequest.claimed_permissions`):**  
  Field provided by the caller or AI agent payload. In Zero-Trust architectures, agents are treated as untrusted clients. The policy engine and decision gate completely ignore claimed permissions when determining authorization. Setting `claimed_permissions=["admin.all"]` or arbitrary parameters grants zero access.
- **Trusted Input (`trusted_permissions` / `TrustedAuthorizer`):**  
  Server-controlled verified credentials passed from an authentication boundary or server-side authorization verifier. Access is granted only when all `required_permissions` in a matching allow rule are present in this server-verified set.

---

## 3. Why REVIEW and BLOCK Never Execute Callbacks

- **Defense-in-Depth:** In `DecisionGate.intercept_and_execute()`, execution of the protected `operation` callback occurs **only** within an explicit `if active_evaluation.verdict == ActionVerdict.ALLOW:` block.
- **REVIEW Handling:** Actions that escalate to human review produce a `GateResult(allowed=False, verdict=ActionVerdict.REVIEW)`. The callback is never invoked. The review ticket is persisted in the database in `PENDING` status. Execution can only be triggered later through an explicit `execute_approved_ticket()` call verifying that human operators have transitioned the ticket to `APPROVED`.
- **BLOCK Handling:** Prohibited, unauthorized, or default-denied actions produce `GateResult(allowed=False, verdict=ActionVerdict.BLOCK)`. The callback is never invoked.

---

## 4. Audit-Failure Behavior (Fail-Closed)

Audit logging is a prerequisite for execution authorization, not an asynchronous best-effort side effect.
- Before an `ALLOW` verdict can trigger callback execution, `audit_logger.log_evaluation(request, evaluation)` is invoked.
- If the audit database is unavailable, disk is full, or an `AuditLoggingError` occurs, the exception is caught, logged, and the gate returns `_fail_closed()` with `allowed=False` and `verdict=ActionVerdict.BLOCK`.
- **Rule:** A security system must never swallow an audit persistence failure to allow a transaction.

---

## 5. Duplicate-Request & Idempotency Behavior

- When a request is received, the gate queries the database for `existing_event = repository.get_security_event(request.request_id)`.
- If a security event with the same `request_id` already exists, the gate halts processing immediately and returns `allowed=False`.
- This prevents replay attacks, accidental double-submissions, and repeated side-effect execution of state-modifying agent actions.

---

## 6. Assumptions and Known Limitations

1. **Identity Provider Integration:**  
   Currently, `trusted_permissions` are supplied as server-controlled sets or through a `TrustedAuthorizer` callable. There is no active cryptographic OAuth2/OIDC token verification or enterprise SSO gateway integration in this phase.
2. **Synchronous Execution:**  
   The decision gate operates synchronously within the Python process. Distributed locking or multi-region synchronization across cluster nodes requires external coordination (e.g., Redis or distributed SQL).
3. **Not Claimed as Production-Ready:**  
   This implementation demonstrates core gate interception, state transitions, and audit boundaries under unit tests. It has not undergone formal penetration testing or high-concurrency stress testing.
4. **LinuxONE / IBM Z Architecture:**  
   Hardware-specific acceleration (such as IBM z16 on-chip AI acceleration or Crypto Express HSM integration) is planned for future phases and is not active in this development environment.
