# Z-AgentShield: IBM LinuxONE (s390x) Deployment Guide

**Subtitle:** Real-Time Security Layer for Enterprise AI Agents  
**Target Architecture:** IBM LinuxONE / IBM zSystems (`linux/s390x`)  
**Container Engines:** Podman, Docker, Red Hat OpenShift Container Platform (OCP)  

---

## 1. Executive Summary

As enterprise autonomous AI agents interact with core transactional systems (banking mainframes, ERP databases, healthcare records), deploying a low-latency, hardware-accelerated security mediation proxy directly on IBM LinuxONE provides distinct architectural advantages:

1. **Co-location with Mission-Critical Data:** Placing Z-AgentShield on the same LinuxONE partition (or adjacent LPAR) as Db2/CICS eliminates WAN egress risks and network latency.
2. **Integrated Hardware Cryptography (CPACF):** Built-in cryptographic offloading accelerates SHA-256 integrity verification and TLS termination without CPU overhead.
3. **Pervasive Encryption:** Protection for SQLite audit logs and review queues using encrypted LVM or IBM Secure Execution for Linux.

---

## 2. Multi-Architecture Container Build (`linux/s390x`)

Z-AgentShield is packaged with a multi-architecture `Dockerfile` adhering to POSIX standards and standard C runtime libraries without architecture-specific assembly.

### Building with Docker Buildx
```bash
# Enable QEMU multi-architecture emulation (if building from x86_64 build server)
docker run --privileged --rm tonistiemi/binfmt --install all

# Initialize buildx builder
docker buildx create --name ibmz-builder --use
docker buildx inspect --bootstrap

# Build and push s390x container image
docker buildx build \
  --platform linux/s390x,linux/amd64 \
  -t myregistry.ibm.com/security/zagentshield:latest \
  --push .
```

### Native Build with Podman on Red Hat Enterprise Linux for s390x
```bash
# On RHEL 8 / 9 on IBM zSystems
podman build -t zagentshield:latest -f Dockerfile .
```

---

## 3. Production Deployment Architecture

```
                 [ Autonomous AI Agent Fleet ]
                               │
               mTLS / HTTP Interception Protocol
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ IBM LinuxONE / zSystems Enterprise LPAR                    │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ Z-AgentShield Container Pod                         │   │
│   │                                                     │   │
│   │  [ FastAPI Gateway :8000 ]                          │   │
│   │     ├─ Input Validation (Pydantic v2)               │   │
│   │     ├─ Regex PII Redaction & Secret Masking         │   │
│   │     ├─ Deterministic Policy Engine (DENY/REV/ALLOW) │   │
│   │     └─ IsolationForest Anomaly Detector             │   │
│   │                                                     │   │
│   │  [ Streamlit SOC Console :8501 ]                    │   │
│   │     └─ Human-in-the-Loop Approval Queue             │   │
│   │                                                     │   │
│   │  [ SQLite Encrypted WAL Database ]                  │   │
│   └─────────────────────────────────────────────────────┘   │
│                               │                             │
│                  ALLOW Gated Execution Bridge               │
│                               ▼                             │
│   [ Enterprise Core: Db2, CICS, Core Banking APIs ]         │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Running the Stack

### Using Docker Compose
```bash
# Launch Gateway and Operations Dashboard
docker-compose up -d

# Verify Gateway Health
curl -s http://localhost:8000/health | jq .

# Access Streamlit Operations Dashboard
# Browser: http://<linuxone-ip>:8501
```

### Running with Native Podman (Rootless Enterprise Security)
```bash
# Run Gateway
podman run -d --name zagentshield-gateway \
  -p 8000:8000 \
  -v /var/data/zagentshield:/app/data:Z \
  -e APP_ENV=production \
  zagentshield:latest

# Run Dashboard
podman run -d --name zagentshield-dashboard \
  -p 8501:8501 \
  -v /var/data/zagentshield:/app/data:Z \
  zagentshield:latest \
  streamlit run dashboard/app.py --server.port=8501 --server.address=0.0.0.0
```

---

## 5. Security & Isolation Best Practices

- **Non-Root Execution:** The container runs as unprivileged UID `10001` (`appuser`).
- **Read-Only Root Filesystem:** Container root can be mounted read-only, mounting only `/app/data` as a writable volume for SQLite WAL files.
- **Fail-Closed Design:** In the event of an audit logger failure or database disk exhaustion, the decision gate defaults to `BLOCK`, guaranteeing that unlogged actions are never permitted.
- **Hardware Enclave (IBM Secure Execution):** For zero-trust compliance, run the container workload inside an IBM Secure Execution KVM guest, isolating host administrators from agent decision payloads.
