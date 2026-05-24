import json

from agents.planner_agent import PlannerAgent

from platform_core.auth import (
    load_private_key,
    load_public_key
)

from platform_core.crypto import load_aes_key
from platform_core.router import SecurePlatform
from platform_core.transport import send_message


EXECUTOR_HOST = "127.0.0.1"
EXECUTOR_PORT = 9001


def main():

    planner_private_key = load_private_key(
        "keys/planner_1_private.pem"
    )

    rsa_private_key = load_private_key(
        "keys/planner_1_rsa_private.pem"
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

    aes_key = load_aes_key("keys/aes.key")

    platform = SecurePlatform(
        agent_id="planner_1",

        private_key=planner_private_key,
        public_keys=public_keys,

        rsa_private_key=rsa_private_key,
        rsa_public_keys=rsa_public_keys,

        aes_key=aes_key
    )

    # --- Step 1: distribute the shared AES key to Executor via RSA KeyEnvelope ---
    print("\n[Planner] Distributing AES key to executor_1...")

    key_envelope = platform.distribute_aes_key("executor_1")

    key_response = send_message(
        host=EXECUTOR_HOST,
        port=EXECUTOR_PORT,
        message=key_envelope
    )

    if key_response.get("status") != "aes_key_received":
        raise RuntimeError(
            f"AES key distribution failed. Executor responded: {key_response}"
        )

    print("[Planner] AES key successfully distributed and acknowledged.\n")

    # --- Step 2: run the planner with encrypted task messages ---
    planner = PlannerAgent(
        agent_id="planner_1",
        platform=platform,
        executor_host=EXECUTOR_HOST,
        executor_port=EXECUTOR_PORT
    )

    user_query = "This product is excellent and very fast."

    results = planner.handle_user_query(user_query)

    # --- Step 3: print structured results ---
    print("\n" + "=" * 50)
    print("Final results from Executor:")
    print("=" * 50)

    for i, result in enumerate(results, start=1):
        print(f"\n[Task {i}]")
        print(json.dumps(result, indent=2))

    print("=" * 50)


if __name__ == "__main__":
    main()
