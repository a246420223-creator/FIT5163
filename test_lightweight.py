import time
import sys
from datetime import datetime
from uuid import uuid4

from platform_core.message_schema import Message
from platform_core.crypto import load_aes_key
from platform_core.auth import load_private_key, load_public_key
from platform_core.router import SecurePlatform


def get_size_bytes(obj):
    return len(str(obj).encode("utf-8"))


def main():
    aes_key = load_aes_key("keys/aes.key")

    public_keys = {
        "planner_1": load_public_key("keys/planner_1_public.pem"),
        "executor_1": load_public_key("keys/executor_1_public.pem")
    }

    planner_platform = SecurePlatform(
        agent_id="planner_1",
        aes_key=aes_key,
        private_key=load_private_key("keys/planner_1_private.pem"),
        public_keys=public_keys
    )

    executor_platform = SecurePlatform(
        agent_id="executor_1",
        aes_key=aes_key,
        private_key=load_private_key("keys/executor_1_private.pem"),
        public_keys=public_keys
    )

    message = Message(
        message_id=str(uuid4()),
        sender="planner_1",
        receiver="executor_1",
        timestamp=datetime.utcnow(),
        message_type="task_request",
        task_id=str(uuid4()),
        payload={
            "task_type": "summarise_text",
            "input": "This is a test message for measuring lightweight secure communication."
        }
    )

    plain_size = get_size_bytes(message.model_dump())

    start = time.perf_counter()
    envelope = planner_platform.secure_wrap(message)
    wrap_time = time.perf_counter() - start

    encrypted_size = get_size_bytes(envelope)

    start = time.perf_counter()
    decrypted_message = executor_platform.secure_unwrap(envelope)
    unwrap_time = time.perf_counter() - start

    print("===== Lightweight Platform Test =====")
    print(f"Plain message size: {plain_size} bytes")
    print(f"Encrypted envelope size: {encrypted_size} bytes")
    print(f"Message size overhead: {encrypted_size - plain_size} bytes")
    print()
    print(f"Encrypt + sign time: {wrap_time * 1000:.4f} ms")
    print(f"Verify + decrypt time: {unwrap_time * 1000:.4f} ms")
    print(f"Total crypto processing time: {(wrap_time + unwrap_time) * 1000:.4f} ms")
    print()
    print("Decrypted payload:")
    print(decrypted_message.payload)


if __name__ == "__main__":
    main()