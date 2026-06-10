"""
Executor server — AES key pre-loaded from keys/aes.key.

Alternative to main_executor.py for testing without the key-distribution
handshake.  Both Planner (main.py) and Executor must share the same aes.key
file for this mode to work.

The AES key can still be updated at runtime via a KeyEnvelope from Planner.
"""

from datetime import datetime, timezone
from uuid import uuid4

from agents.executor_agent import ExecutorAgent
from platform_core.message_schema import Message
from platform_core.auth import load_private_key, load_public_key
from platform_core.crypto import load_aes_key
from platform_core.router import SecurePlatform
from platform_core.transport import start_server
from platform_core.logger import log_event, log_warning, log_error


def main():
    executor_private_key = load_private_key("keys/executor_1_private.pem")
    rsa_private_key      = load_private_key("keys/executor_1_rsa_private.pem")

    public_keys = {
        "planner_1":  load_public_key("keys/planner_1_public.pem"),
        "executor_1": load_public_key("keys/executor_1_public.pem"),
    }
    rsa_public_keys = {
        "planner_1":  load_public_key("keys/planner_1_rsa_public.pem"),
        "executor_1": load_public_key("keys/executor_1_rsa_public.pem"),
    }

    aes_key = load_aes_key("keys/aes.key")

    platform = SecurePlatform(
        agent_id="executor_1",
        private_key=executor_private_key,
        public_keys=public_keys,
        rsa_private_key=rsa_private_key,
        rsa_public_keys=rsa_public_keys,
        aes_key=aes_key,
    )

    executor = ExecutorAgent(agent_id="executor_1")

    def handle_request(envelope: dict) -> dict:
        try:
            # Accept a KeyEnvelope to update the session key (optional).
            if "encrypted_aes_key" in envelope:
                platform.receive_aes_key(envelope)
                return {"status": "aes_key_received"}

            # Normal SecureEnvelope: decrypt, validate, process, sign response.
            request_message = platform.secure_unwrap(envelope)

            result = executor.process_task(request_message.payload)

            response_message = Message(
                message_id=str(uuid4()),
                sender="executor_1",
                receiver=request_message.sender,
                timestamp=datetime.now(timezone.utc),
                message_type="task_result",
                task_id=request_message.task_id,
                payload=result,
            )

            response_envelope = platform.secure_wrap(response_message)
            log_event(
                f"executor_1 sent signed response for task {request_message.task_id} "
                f"to {request_message.sender}"
            )
            return response_envelope

        except ValueError as exc:
            log_warning(f"executor_1 rejected request: {exc}")
            return {"status": "error", "reason": "Request rejected by security layer."}

        except Exception as exc:
            log_error(f"executor_1 unexpected error: {exc}")
            return {"status": "error", "reason": "Internal server error."}

    start_server(host="127.0.0.1", port=9001, handler_function=handle_request)


if __name__ == "__main__":
    main()
