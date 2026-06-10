# FIT5163 — Secure Lightweight LLM Agent Collaboration Platform

A multi-agent platform where a **Planner** agent decomposes a user query into
sub-tasks, sends them to one or more **Executor** agents over an untrusted
local TCP channel, and receives **signed, structured results**.
All communication is secured with industry-standard cryptographic primitives.

---

## Project Structure

```
FIT5163/
├── agents/
│   ├── planner_agent.py      # PlannerAgent: query decomposition + secure send
│   └── executor_agent.py     # ExecutorAgent: summarise_text / classify_text tasks
├── platform_core/
│   ├── router.py             # SecurePlatform: encrypt, sign, verify, replay-protect
│   ├── crypto.py             # AES-256-GCM encrypt / decrypt helpers
│   ├── auth.py               # Ed25519 sign / verify + RSA-OAEP encrypt / decrypt
│   ├── message_schema.py     # Pydantic models: Message, SecureEnvelope, KeyEnvelope
│   ├── transport.py          # TCP socket helpers (framed JSON, timeouts)
│   ├── logger.py             # Audit logger (file + console, INFO / WARNING / ERROR)
│   └── validator.py          # Pydantic message validation wrapper
├── keys/                     # Key material — regenerate with setup_keys.py
│   └── .gitkeep              # Keeps the folder tracked; actual key files are gitignored
├── logs/
│   └── communication.log     # Audit trail written at runtime (auto-created)
├── main.py                   # Planner entry point (run AFTER starting the Executor)
├── main_executor.py          # Executor server (AES key received dynamically from Planner)
├── executor_server.py        # Executor server (AES key pre-loaded from keys/aes.key)
├── setup_keys.py             # One-time key generation — run this first on a clean machine
├── demo_security.py          # Six in-process security property demos (no network needed)
├── test_replay_attack.py     # Replay protection unit tests
├── test_confidentiality.py   # Confidentiality / encryption verification test
├── test_lightweight.py       # Size and timing overhead measurement
└── requirements.txt
```

---

## Security Architecture

| Property | Mechanism |
|---|---|
| **Confidentiality** | AES-256-GCM encrypts every message payload. Plaintext never crosses the socket. |
| **Integrity** | AES-GCM authentication tag detects any bit-flip in the ciphertext. |
| **Authenticity** | Ed25519 digital signatures bind each envelope to its sender's private key. |
| **Non-repudiation** | Executor signs every result; Planner verifies the signature before accepting it. |
| **Freshness / Replay protection** | Messages include a UTC timestamp and a UUID. The receiver keeps a 5-minute sliding-window cache of seen message IDs and rejects duplicates. |
| **Hybrid key distribution** | The shared AES session key is RSA-2048-OAEP encrypted so it is never sent in the clear. |

### Message flow (localhost TCP / IPC)

```
Planner                                       Executor
  │  ── KeyEnvelope ──────────────────────────► │
  │     (RSA-OAEP encrypted AES key,            │
  │      Ed25519 signed)                        │
  │ ◄── {"status": "aes_key_received"} ──────── │
  │                                             │
  │  ── SecureEnvelope ────────────────────────► │
  │     (AES-GCM encrypted task, Ed25519 sig)   │
  │ ◄── SecureEnvelope ──────────────────────── │
  │     (AES-GCM encrypted result, Ed25519 sig) │
  │     Planner verifies signature + decrypts   │
```

The Planner and Executor communicate exclusively over **localhost TCP sockets**
(`127.0.0.1:9001`), satisfying the assignment requirement for IPC / local-network
communication over an untrusted channel.

---

## Setup (Windows)

### 1. Create and activate a virtual environment

```
python -m venv .venv
.venv\Scripts\activate
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

> Requires Python 3.10+.
> `ollama` is listed as a dependency but is **optional** — the platform
> automatically falls back to keyword-matching if Ollama is not installed or
> not running.

### 3. Generate cryptographic keys

Run **once** on a clean machine to create all Ed25519, RSA-2048, and AES-256
key files in `keys/`:

```
python setup_keys.py
```

Expected output:
```
Generated signature keys for planner_1
Generated signature keys for executor_1
Generated RSA keys for planner_1
Generated RSA keys for executor_1
Generated AES-256 key.
```

If keys already exist the script prints `"… already exists."` and skips
regeneration.

---

## Demo 1 — Security Properties (no network required)

This demo runs entirely in-process and covers all six security properties
required by the rubric.  **Run this first** — it does not need the Executor
server to be started.

```
python demo_security.py
```

| # | Scenario | Property demonstrated |
|---|---|---|
| 1 | Normal secure message flow | Confidentiality, authenticity |
| 2 | Tampered ciphertext rejected | Integrity (AES-GCM authentication tag) |
| 3 | Invalid signature rejected | Authenticity (Ed25519 verification) |
| 4 | Replayed message rejected | Freshness (timestamp window + ID cache) |
| 5 | Signed executor result verified | Non-repudiation |
| 6 | AES session key distributed via RSA | Hybrid encryption (RSA-OAEP) |

Expected output (every line prints `[PASS]`):

```
==============================================================
  FIT5163 Secure Multi-Agent Platform — Security Demo
==============================================================
------------------------------------------------------------
Scenario 1: Normal secure Planner → Executor message flow
  Plaintext payload : {"task_type": "classify_text", "input": "..."}
  Envelope nonce    : 3f8a1c...
  Envelope ciphertext (first 32 hex): 7d2e9f...
  Plaintext visible in envelope: False   ← must be False
  Decrypted payload : {"task_type": "classify_text", "input": "..."}
[PASS] Scenario 1: normal communication succeeded.
------------------------------------------------------------
Scenario 2: Tampered ciphertext is rejected
  ...
  Attacker re-signed envelope : signature is valid over tampered data
  → Only the AES-GCM tag can stop this attack
[PASS] Tampered ciphertext (re-signed by attacker)
       Rejected with: AES-GCM decryption failed: ...
...
[PASS] Scenario 6: AES session key distributed and received correctly.
==============================================================
All scenarios completed.
==============================================================
```

---

## Demo 2 — Real Network Demo (Planner ↔ Executor over localhost TCP)

This demo satisfies the assignment requirement for IPC / socket communication
between Planner and Executor agents.  Open **two terminals** in the project
root with the virtual environment activated.

### Terminal 1 — Start the Executor server

```
python main_executor.py
```

The executor starts with **no AES key** and waits for the Planner to distribute
one via an RSA-encrypted KeyEnvelope.  Output:

```
[Server] Executor listening on 127.0.0.1:9001
```

### Terminal 2 — Run the Planner

```
python main.py
```

### Expected Planner output

```
[Planner] Distributing AES key to executor_1...
[RSA] Encrypting shared AES key...
[Planner] AES key successfully distributed and acknowledged.

[Planner] Decomposing query: "This product is excellent and very fast."
[Planner] Decomposed into 2 task(s): ['summarise_text', 'classify_text']
[AES-GCM] Encrypting payload...
[AES-GCM] Decrypting payload...
...

==================================================
Final results from Executor:
==================================================

[Task 1]
{
  "status": "success",
  "task_type": "summarise_text",
  "result": {
    "summary": "The product receives high praise for its quality and speed."
  }
}

[Task 2]
{
  "status": "success",
  "task_type": "classify_text",
  "result": {
    "label": "positive"
  }
}
==================================================
```

> **Without Ollama:** the executor uses keyword-matching fallbacks and still
> produces valid, signed results.

---

## Other Test Scripts

```
python test_confidentiality.py   # plaintext is not visible in the encrypted envelope
python test_replay_attack.py     # replay protection (message + KeyEnvelope)
python test_lightweight.py       # crypto processing time and size overhead
```

---

## Viewing the Audit Log

All events are appended to `logs/communication.log`.

**Windows (Command Prompt / PowerShell):**
```
type logs\communication.log
```

**Filter by level:**
```
findstr "WARNING" logs\communication.log
findstr "INFO"    logs\communication.log
```

Sample entries:
```
2025-06-10 12:00:01 - INFO    - planner_1 → executor_1: AES-GCM encrypted + Ed25519 signed message <uuid>
2025-06-10 12:00:01 - INFO    - executor_1 ✓ verified and decrypted message <uuid> from planner_1 (signature OK, AES-GCM tag OK, no replay)
2025-06-10 12:00:02 - WARNING - executor_1 REJECTED message from planner_1: AES-GCM decryption failed: ciphertext integrity check did not pass
2025-06-10 12:00:03 - WARNING - executor_1 REJECTED duplicate message_id from planner_1 (id=<uuid>)
```

---

## Complete Run Sequence (clean machine)

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python setup_keys.py
python demo_security.py
python test_confidentiality.py
python test_replay_attack.py
python test_lightweight.py
```

Then the live network demo (two terminals):
```
# Terminal 1
python main_executor.py

# Terminal 2
python main.py
```

Then review the audit log:
```
type logs\communication.log
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `FileNotFoundError: Key file not found: keys/…` | Run `python setup_keys.py` first |
| `No module named 'ollama'` | Run `pip install ollama` or ignore — fallback is automatic |
| `[WinError 10048] Address already in use` | Wait a few seconds and restart the Executor; `SO_REUSEADDR` is set |
| Planner hangs / connection refused | Make sure the Executor (`main_executor.py`) is running before the Planner |
| `AES key has not been distributed yet` | Use `main_executor.py`, not `executor_server.py`, when running `main.py` |
