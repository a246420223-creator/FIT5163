"""
Confidentiality test.

Verifies that the plaintext task payload is NOT visible anywhere in the
SecureEnvelope that would be transmitted over the socket.

Run:  python test_confidentiality.py
"""

import json
from datetime import datetime, timezone
from uuid import uuid4

from platform_core.message_schema import Message
from platform_core.crypto import load_aes_key
from platform_core.auth import load_private_key, load_public_key
from platform_core.router import SecurePlatform


def test_confidentiality():
    aes_key = load_aes_key("keys/aes.key")

    public_keys = {
        "planner_1": load_public_key("keys/planner_1_public.pem"),
        "executor_1": load_public_key("keys/executor_1_public.pem"),
    }

    platform = SecurePlatform(
        agent_id="planner_1",
        aes_key=aes_key,
        private_key=load_private_key("keys/planner_1_private.pem"),
        public_keys=public_keys,
    )

    secret_input = "This is a secret task message."

    message = Message(
        message_id=str(uuid4()),
        sender="planner_1",
        receiver="executor_1",
        timestamp=datetime.now(timezone.utc),
        message_type="task_request",
        task_id=str(uuid4()),
        payload={"task_type": "summarise_text", "input": secret_input},
    )

    envelope = platform.secure_wrap(message)

    print("=== Confidentiality Test ===\n")
    print("Original plaintext message:")
    print(message.model_dump_json(indent=2))

    print("\nEncrypted SecureEnvelope transmitted over the channel:")
    print(json.dumps(envelope, indent=2))

    visible = secret_input in str(envelope)
    print(f"\nSecret input visible in envelope: {visible}")

    assert not visible, "FAIL: plaintext is visible in the envelope -- confidentiality broken."
    print("\n[PASS] Confidentiality: the plaintext payload is NOT visible in the envelope.")


if __name__ == "__main__":
    test_confidentiality()
