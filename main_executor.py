"""
Executor server — AES key received from Planner at runtime.

Start this process first, then run main.py (Planner).

Flow:
  1. Executor starts with aes_key=None.
  2. Planner sends a RSA-encrypted KeyEnvelope.
  3. Executor decrypts and stores the AES session key.
  4. Subsequent SecureEnvelopes are decrypted with the shared AES key,
     processed by ExecutorAgent, and the signed result is returned.
"""

from datetime import datetime, timezone
from uuid import uuid4

from agents.executor_agent import ExecutorAgent
from platform_core.message_schema import Message
from platform_core.auth import load_private_key, load_public_key
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

    # Executor starts with no AES key — it must be received from Planner
    # via a RSA-OAEP KeyEnvelope before any task messages can be processed.
    platform = SecurePlatform(
        agent_id="executor_1",
        private_key=executor_private_key,
        public_keys=public_keys,
        rsa_private_key=rsa_private_key,
        rsa_public_keys=rsa_public_keys,
        aes_key=None,
    )

    executor = ExecutorAgent(agent_id="executor_1")

    def handle_request(envelope: dict) -> dict:
        try:
            # --- Key distribution handshake ----------------------------------
            if "encrypted_aes_key" in envelope:
                platform.receive_aes_key(envelope)
                return {"status": "aes_key_received"}

            # --- Guard: AES key must arrive before any task message ----------
            if platform.aes_key is None:
                log_warning("executor_1 rejected message: AES key not yet distributed.")
                return {"status": "error", "reason": "AES key has not been distributed yet."}

            # --- Normal task message -----------------------------------------
            # secure_unwrap verifies signature, AES-GCM tag, metadata, and
            # replay protection.  Any failure raises ValueError.
            request_message = platform.secure_unwrap(envelope)

            result = executor.process_task(request_message.payload)

            response_message = Message(
                message_id=str(uuid4()),
                sender="executor_1",
                receiver=request_message.sender,
                timestamp=datetime.now(timezone.utc),
                message_type="task_response",
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
            # Security violation (tampered message, bad signature, replay, etc.)
            # Log the real reason locally but return a generic message to the
            # peer so internal details are not leaked over the wire.
            log_warning(f"executor_1 rejected request: {exc}")
            return {"status": "error", "reason": "Request rejected by security layer."}

        except Exception as exc:
            log_error(f"executor_1 unexpected error: {exc}")
            return {"status": "error", "reason": "Internal server error."}

    start_server(host="127.0.0.1", port=9001, handler_function=handle_request)


if __name__ == "__main__":
    main()
