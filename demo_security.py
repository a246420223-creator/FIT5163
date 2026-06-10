"""
Comprehensive security properties demonstration.

Covers all six properties required by the FIT5163 rubric WITHOUT needing
a live network connection -- all tests run in-process using two SecurePlatform
instances that share the pre-generated key material in keys/.

Run:  python demo_security.py

Expected outcome: every scenario prints [PASS].
Check logs/communication.log afterwards for the full audit trail, including
WARNING entries for every rejected / tampered message.

Scenarios
---------
1. Normal secure message flow           (confidentiality + authenticity)
2. Tampered ciphertext rejected         (integrity -- AES-GCM tag)
3. Invalid signature rejected           (authenticity -- Ed25519)
4. Replayed message rejected            (freshness -- timestamp + ID cache)
5. Signed executor result verified      (non-repudiation)
6. AES session key distribution         (hybrid encryption -- RSA-OAEP)
"""

import json
from datetime import datetime, timezone
from uuid import uuid4

from platform_core.auth import load_private_key, load_public_key
from platform_core.crypto import load_aes_key
from platform_core.message_schema import Message
from platform_core.router import SecurePlatform

SEP = "-" * 62


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _load_all_keys():
    """Return (aes_key, public_keys, rsa_public_keys) loaded from keys/."""
    return (
        load_aes_key("keys/aes.key"),
        {
            "planner_1":  load_public_key("keys/planner_1_public.pem"),
            "executor_1": load_public_key("keys/executor_1_public.pem"),
        },
        {
            "planner_1":  load_public_key("keys/planner_1_rsa_public.pem"),
            "executor_1": load_public_key("keys/executor_1_rsa_public.pem"),
        },
    )


def _build_platforms(aes_key=None, executor_aes_key=None):
    """
    Create a paired (planner, executor) SecurePlatform.

    Pass executor_aes_key=None to simulate the executor starting without a
    session key (used in the key-distribution scenario).
    """
    shared_aes, public_keys, rsa_public_keys = _load_all_keys()
    if aes_key is None:
        aes_key = shared_aes
    if executor_aes_key is None:
        executor_aes_key = aes_key

    planner = SecurePlatform(
        agent_id="planner_1",
        aes_key=aes_key,
        private_key=load_private_key("keys/planner_1_private.pem"),
        public_keys=public_keys,
        rsa_private_key=load_private_key("keys/planner_1_rsa_private.pem"),
        rsa_public_keys=rsa_public_keys,
    )
    executor = SecurePlatform(
        agent_id="executor_1",
        aes_key=executor_aes_key,
        private_key=load_private_key("keys/executor_1_private.pem"),
        public_keys=public_keys,
        rsa_private_key=load_private_key("keys/executor_1_rsa_private.pem"),
        rsa_public_keys=rsa_public_keys,
    )
    return planner, executor


def _make_message(sender: str, receiver: str, task_type: str, text: str) -> Message:
    return Message(
        message_id=str(uuid4()),
        sender=sender,
        receiver=receiver,
        timestamp=datetime.now(timezone.utc),
        message_type="task_request",
        task_id=str(uuid4()),
        payload={"task_type": task_type, "input": text},
    )


def _expect_rejected(fn, label: str, keyword: str = "") -> bool:
    """
    Call fn().  Expect a ValueError (optionally containing *keyword*).
    Print [PASS] / [FAIL] and return True on pass.
    """
    try:
        fn()
    except ValueError as exc:
        if keyword and keyword.lower() not in str(exc).lower():
            print(f"[FAIL] {label}: wrong error -- {exc}")
            return False
        print(f"[PASS] {label}")
        print(f"       Rejected with: {exc}")
        return True
    except Exception as exc:
        print(f"[FAIL] {label}: unexpected {type(exc).__name__}: {exc}")
        return False
    print(f"[FAIL] {label}: message was accepted -- should have been rejected.")
    return False


# ------------------------------------------------------------------
# Scenario 1 -- Normal secure message flow
# ------------------------------------------------------------------

def demo_normal_flow():
    print(SEP)
    print("Scenario 1: Normal secure Planner -> Executor message flow")
    print(SEP)

    planner, executor = _build_platforms()
    msg = _make_message("planner_1", "executor_1",
                        "classify_text", "This product is excellent and very fast.")

    print(f"  Plaintext payload : {json.dumps(msg.payload)}")

    envelope = planner.secure_wrap(msg)
    print(f"  Envelope nonce    : {envelope['nonce'][:24]}...")
    print(f"  Ciphertext (first 32 hex): {envelope['ciphertext'][:32]}...")
    print(f"  Plaintext visible in envelope: "
          f"{msg.payload['input'] in str(envelope)}   <-- must be False")

    decrypted = executor.secure_unwrap(envelope)
    assert decrypted.payload == msg.payload, "Decrypted payload mismatch!"

    print(f"  Decrypted payload : {json.dumps(decrypted.payload)}")
    print("[PASS] Scenario 1: normal communication succeeded.")


# ------------------------------------------------------------------
# Scenario 2 -- Tampered ciphertext rejected (AES-GCM integrity tag)
# ------------------------------------------------------------------

def demo_tampered_ciphertext():
    print(SEP)
    print("Scenario 2: Tampered ciphertext is rejected")
    print("           (AES-GCM authentication tag detects bit-flip)")
    print(SEP)

    planner, executor = _build_platforms()
    msg = _make_message("planner_1", "executor_1", "summarise_text", "Tamper test.")
    envelope = planner.secure_wrap(msg)

    # Flip the last two hex characters of the ciphertext.
    original = envelope["ciphertext"]
    flipped  = original[:-2] + ("00" if original[-2:] != "00" else "ff")
    envelope["ciphertext"] = flipped

    # The Ed25519 signature covers the ciphertext field, so a naive tamper
    # would also break the signature check.  To isolate and demonstrate the
    # AES-GCM authentication tag specifically, we re-sign the tampered envelope
    # with the planner's private key -- exactly as a strong attacker would try.
    # Even with a valid signature, the AES-GCM tag still rejects the tampered
    # ciphertext because the tag is computed over the plaintext+AAD inside the
    # AEAD cipher and cannot be forged without the AES key.
    from platform_core.auth import sign_data as _sign_data
    tampered_sig_bytes = planner._envelope_signature_data(envelope)
    envelope["signature"] = _sign_data(planner.private_key, tampered_sig_bytes)

    print(f"  Original ciphertext tail   : ...{original[-8:]}")
    print(f"  Tampered ciphertext tail   : ...{flipped[-8:]}")
    print("  Attacker re-signed envelope : signature is valid over tampered data")
    print("  -> Only the AES-GCM tag can stop this attack")

    _expect_rejected(
        lambda: executor.secure_unwrap(envelope),
        "Tampered ciphertext (re-signed by attacker)",
        keyword="AES-GCM"
    )


# ------------------------------------------------------------------
# Scenario 3 -- Invalid signature rejected (Ed25519 authenticity)
# ------------------------------------------------------------------

def demo_invalid_signature():
    print(SEP)
    print("Scenario 3: Invalid signature is rejected")
    print("           (Ed25519 verification catches forged/corrupted signature)")
    print(SEP)

    planner, executor = _build_platforms()
    msg = _make_message("planner_1", "executor_1", "classify_text", "Signature test.")
    envelope = planner.secure_wrap(msg)

    # Corrupt the last 4 hex chars of the Ed25519 signature.
    original_sig = envelope["signature"]
    corrupted    = original_sig[:-4] + ("0000" if original_sig[-4:] != "0000" else "ffff")
    envelope["signature"] = corrupted

    print(f"  Original signature tail : ...{original_sig[-8:]}")
    print(f"  Corrupted signature tail: ...{corrupted[-8:]}")

    _expect_rejected(
        lambda: executor.secure_unwrap(envelope),
        "Invalid signature",
        keyword="Invalid digital signature"
    )


# ------------------------------------------------------------------
# Scenario 4 -- Replay attack rejected (timestamp + message-ID cache)
# ------------------------------------------------------------------

def demo_replay_protection():
    print(SEP)
    print("Scenario 4: Replayed message is rejected")
    print("           (timestamp window + message-ID deduplication cache)")
    print(SEP)

    planner, executor = _build_platforms()
    msg = _make_message("planner_1", "executor_1", "summarise_text", "Replay test.")
    envelope = planner.secure_wrap(msg)

    # First delivery must succeed.
    executor.secure_unwrap(envelope)
    print("[PASS] First delivery: accepted.")

    # Second delivery of the identical envelope must be rejected.
    _expect_rejected(
        lambda: executor.secure_unwrap(envelope),
        "Replayed message",
        keyword="Replay attack detected"
    )


# ------------------------------------------------------------------
# Scenario 5 -- Signed executor result verified by planner
#              (non-repudiation / verifiability)
# ------------------------------------------------------------------

def demo_signed_result_verification():
    print(SEP)
    print("Scenario 5: Executor result is signed; planner verifies it")
    print("           (Ed25519 non-repudiation -- executor cannot deny the result)")
    print(SEP)

    planner, executor = _build_platforms()

    # Planner sends a task.
    task_msg = _make_message("planner_1", "executor_1",
                             "classify_text", "Great service, very happy.")
    task_envelope = planner.secure_wrap(task_msg)

    # Executor receives and processes the task.
    received = executor.secure_unwrap(task_envelope)
    print(f"  Executor received task : {received.payload['task_type']}")

    # Executor signs and encrypts its result.
    result_msg = Message(
        message_id=str(uuid4()),
        sender="executor_1",
        receiver="planner_1",
        timestamp=datetime.now(timezone.utc),
        message_type="task_response",
        task_id=received.task_id,
        payload={
            "status":    "success",
            "task_type": "classify_text",
            "result":    {"label": "positive"},
        },
    )
    result_envelope = executor.secure_wrap(result_msg)
    print(f"  Result signature (first 32 hex): {result_envelope['signature'][:32]}...")

    # Planner verifies the signature and decrypts.
    verified = planner.secure_unwrap(result_envelope)
    print(f"  Verified result payload: {json.dumps(verified.payload)}")
    print("[PASS] Scenario 5: signed executor result verified by planner.")

    # Show that altering the result after signing is detected.
    print()
    print("  -> Attempting to verify a result with a forged signature...")
    result_envelope["signature"] = "deadbeef" * 16
    _expect_rejected(
        lambda: planner.secure_unwrap(result_envelope),
        "Forged result signature",
        keyword="Invalid digital signature"
    )


# ------------------------------------------------------------------
# Scenario 6 -- AES session-key distribution via RSA-OAEP
# ------------------------------------------------------------------

def demo_key_distribution():
    print(SEP)
    print("Scenario 6: AES session key distributed via RSA-OAEP")
    print("           (hybrid encryption -- RSA wraps AES, AES encrypts messages)")
    print(SEP)

    shared_aes, public_keys, rsa_public_keys = _load_all_keys()

    # Planner has the AES key; executor starts without one.
    planner = SecurePlatform(
        agent_id="planner_1",
        aes_key=shared_aes,
        private_key=load_private_key("keys/planner_1_private.pem"),
        public_keys=public_keys,
        rsa_private_key=load_private_key("keys/planner_1_rsa_private.pem"),
        rsa_public_keys=rsa_public_keys,
    )
    executor = SecurePlatform(
        agent_id="executor_1",
        aes_key=None,
        private_key=load_private_key("keys/executor_1_private.pem"),
        public_keys=public_keys,
        rsa_private_key=load_private_key("keys/executor_1_rsa_private.pem"),
        rsa_public_keys=rsa_public_keys,
    )

    print(f"  Executor AES key before distribution : {executor.aes_key}")

    key_envelope = planner.distribute_aes_key("executor_1")
    print(f"  RSA-encrypted AES key (first 32 hex): "
          f"{key_envelope['encrypted_aes_key'][:32]}...")
    print(f"  KeyEnvelope Ed25519 signature (first 32 hex): "
          f"{key_envelope['signature'][:32]}...")

    executor.receive_aes_key(key_envelope)
    print(f"  Executor AES key after distribution  : {executor.aes_key.hex()[:32]}...")

    assert executor.aes_key == shared_aes, "AES key mismatch after distribution!"
    print("[PASS] Scenario 6: AES session key distributed and received correctly.")

    # Bonus: verify that replaying the KeyEnvelope is rejected.
    print()
    print("  -> Attempting to replay the KeyEnvelope...")
    _expect_rejected(
        lambda: executor.receive_aes_key(key_envelope),
        "Replayed KeyEnvelope",
        keyword="Replay attack detected"
    )


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main():
    print("=" * 62)
    print("  FIT5163 Secure Multi-Agent Platform -- Security Demo")
    print("=" * 62)

    demo_normal_flow()
    demo_tampered_ciphertext()
    demo_invalid_signature()
    demo_replay_protection()
    demo_signed_result_verification()
    demo_key_distribution()

    print()
    print("=" * 62)
    print("All scenarios completed.")
    print("Audit trail written to: logs/communication.log")
    print("  findstr WARNING logs\\communication.log   -- security rejections")
    print("  findstr INFO    logs\\communication.log   -- normal events")
    print("=" * 62)


if __name__ == "__main__":
    main()
