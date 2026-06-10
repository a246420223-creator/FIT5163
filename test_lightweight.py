"""
Lightweight overhead test.

Measures the size and processing-time overhead introduced by the security
layer (AES-GCM encryption + Ed25519 signing / verification).

Run:  python test_lightweight.py
"""

import time
from datetime import datetime, timezone
from uuid import uuid4

from platform_core.message_schema import Message
from platform_core.crypto import load_aes_key
from platform_core.auth import load_private_key, load_public_key
from platform_core.router import SecurePlatform


def _byte_size(obj) -> int:
    return len(str(obj).encode("utf-8"))


def main():
    aes_key = load_aes_key("keys/aes.key")

    public_keys = {
        "planner_1": load_public_key("keys/planner_1_public.pem"),
        "executor_1": load_public_key("keys/executor_1_public.pem"),
    }

    planner_platform = SecurePlatform(
        agent_id="planner_1",
        aes_key=aes_key,
        private_key=load_private_key("keys/planner_1_private.pem"),
        public_keys=public_keys,
    )

    executor_platform = SecurePlatform(
        agent_id="executor_1",
        aes_key=aes_key,
        private_key=load_private_key("keys/executor_1_private.pem"),
        public_keys=public_keys,
    )

    message = Message(
        message_id=str(uuid4()),
        sender="planner_1",
        receiver="executor_1",
        timestamp=datetime.now(timezone.utc),
        message_type="task_request",
        task_id=str(uuid4()),
        payload={
            "task_type": "summarise_text",
            "input": "This is a test message for measuring lightweight secure communication.",
        },
    )

    plain_size = _byte_size(message.model_dump())

    t0 = time.perf_counter()
    envelope = planner_platform.secure_wrap(message)
    wrap_ms = (time.perf_counter() - t0) * 1000

    encrypted_size = _byte_size(envelope)

    t0 = time.perf_counter()
    decrypted = executor_platform.secure_unwrap(envelope)
    unwrap_ms = (time.perf_counter() - t0) * 1000

    print("===== Lightweight Platform Overhead Test =====")
    print(f"Plain message size    : {plain_size} bytes")
    print(f"Encrypted envelope    : {encrypted_size} bytes")
    print(f"Size overhead         : +{encrypted_size - plain_size} bytes "
          f"({(encrypted_size / plain_size - 1) * 100:.0f}%)")
    print()
    print(f"Encrypt + sign        : {wrap_ms:.4f} ms")
    print(f"Verify + decrypt      : {unwrap_ms:.4f} ms")
    print(f"Total crypto time     : {wrap_ms + unwrap_ms:.4f} ms")
    print()
    print("Decrypted payload:")
    print(decrypted.payload)


if __name__ == "__main__":
    main()
