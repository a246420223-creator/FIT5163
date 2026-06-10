from datetime import datetime, timezone
from uuid import uuid4

from platform_core.auth import load_private_key, load_public_key
from platform_core.crypto import load_aes_key
from platform_core.message_schema import Message
from platform_core.router import SecurePlatform


def build_public_keys():
    return {
        "planner_1": load_public_key("keys/planner_1_public.pem"),
        "executor_1": load_public_key("keys/executor_1_public.pem")
    }


def build_rsa_public_keys():
    return {
        "planner_1": load_public_key("keys/planner_1_rsa_public.pem"),
        "executor_1": load_public_key("keys/executor_1_rsa_public.pem")
    }


def expect_replay_rejected(action, label: str):
    try:
        action()
    except ValueError as exc:
        if "Replay attack detected" not in str(exc):
            raise

        print(f"[PASS] {label} rejected: {exc}")
        return

    raise AssertionError(f"{label} was accepted, but it should have been rejected.")


def test_secure_message_replay():
    aes_key = load_aes_key("keys/aes.key")
    public_keys = build_public_keys()

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
        timestamp=datetime.now(timezone.utc),
        message_type="task_request",
        task_id=str(uuid4()),
        payload={
            "task_type": "summarise_text",
            "input": "Replay protection test message."
        }
    )

    envelope = planner_platform.secure_wrap(message)

    executor_platform.secure_unwrap(envelope)
    print("[PASS] First secure message accepted.")

    expect_replay_rejected(
        lambda: executor_platform.secure_unwrap(envelope),
        "Replayed secure message"
    )


def test_key_envelope_replay():
    aes_key = load_aes_key("keys/aes.key")
    public_keys = build_public_keys()
    rsa_public_keys = build_rsa_public_keys()

    planner_platform = SecurePlatform(
        agent_id="planner_1",
        aes_key=aes_key,
        private_key=load_private_key("keys/planner_1_private.pem"),
        public_keys=public_keys,
        rsa_private_key=load_private_key("keys/planner_1_rsa_private.pem"),
        rsa_public_keys=rsa_public_keys
    )

    executor_platform = SecurePlatform(
        agent_id="executor_1",
        private_key=load_private_key("keys/executor_1_private.pem"),
        public_keys=public_keys,
        rsa_private_key=load_private_key("keys/executor_1_rsa_private.pem"),
        rsa_public_keys=rsa_public_keys
    )

    envelope = planner_platform.distribute_aes_key("executor_1")

    executor_platform.receive_aes_key(envelope)
    print("[PASS] First KeyEnvelope accepted.")

    expect_replay_rejected(
        lambda: executor_platform.receive_aes_key(envelope),
        "Replayed KeyEnvelope"
    )


def main():
    test_secure_message_replay()
    test_key_envelope_replay()
    print("Replay attack protection tests passed.")


if __name__ == "__main__":
    main()
