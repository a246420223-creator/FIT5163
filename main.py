from agents.planner_agent import PlannerAgent

from platform_core.auth import (
    load_private_key,
    load_public_key
)

from platform_core.router import SecurePlatform


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

    platform = SecurePlatform(
        agent_id="planner_1",

        private_key=planner_private_key,
        public_keys=public_keys,

        rsa_private_key=rsa_private_key,
        rsa_public_keys=rsa_public_keys
    )

    planner = PlannerAgent(
        agent_id="planner_1",
        platform=platform,
        executor_host="127.0.0.1",
        executor_port=9001
    )

    user_query = "This product is excellent and very fast."

    results = planner.handle_user_query(
        user_query
    )

    print("\nFinal results:")

    for result in results:
        print(result)


if __name__ == "__main__":
    main()