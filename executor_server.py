from datetime import datetime
from uuid import uuid4

from agents.executor_agent import ExecutorAgent

from platform_core.message_schema import Message

from platform_core.auth import (
    load_private_key,
    load_public_key
)

from platform_core.router import SecurePlatform
from platform_core.transport import start_server


def main():

    executor_private_key = load_private_key(
        "keys/executor_1_private.pem"
    )

    rsa_private_key = load_private_key(
        "keys/executor_1_rsa_private.pem"
    )

    public_keys = {
        "planner_1": load_public_key(
            "keys/planner_1_public.pem"
        ),

        "executor_1": load_public_key(
            "keys/executor_1_public.pem"
        )
    }

    rsa_public_keys = {
        "planner_1": load_public_key(
            "keys/planner_1_rsa_public.pem"
        ),

        "executor_1": load_public_key(
            "keys/executor_1_rsa_public.pem"
        )
    }

    platform = SecurePlatform(
        agent_id="executor_1",

        private_key=executor_private_key,
        public_keys=public_keys,

        rsa_private_key=rsa_private_key,
        rsa_public_keys=rsa_public_keys
    )

    executor = ExecutorAgent(
        agent_id="executor_1"
    )

    def handle_request(envelope: dict) -> dict:

        request_message = platform.secure_unwrap(
            envelope
        )

        result = executor.process_task(
            request_message.payload
        )

        response_message = Message(
            message_id=str(uuid4()),

            sender="executor_1",

            receiver=request_message.sender,

            timestamp=datetime.utcnow(),

            message_type="task_result",

            task_id=request_message.task_id,

            payload=result
        )

        response_envelope = platform.secure_wrap(
            response_message
        )

        return response_envelope

    start_server(
        host="127.0.0.1",
        port=9001,
        handler_function=handle_request
    )


if __name__ == "__main__":
    main()