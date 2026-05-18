from datetime import datetime
from uuid import uuid4

from platform_core.message_schema import Message


class PlannerAgent:
    def __init__(self, agent_id: str, platform, executor_host: str, executor_port: int):
        self.agent_id = agent_id
        self.platform = platform
        self.executor_host = executor_host
        self.executor_port = executor_port

    def decompose_query(self, user_query: str) -> list:
        tasks = []

        tasks.append({
            "task_id": str(uuid4()),
            "task_type": "summarise_text",
            "input": user_query
        })

        tasks.append({
            "task_id": str(uuid4()),
            "task_type": "classify_text",
            "input": user_query
        })

        return tasks

    def handle_user_query(self, user_query: str) -> list:
        tasks = self.decompose_query(user_query)
        results = []

        for task in tasks:
            message = Message(
                message_id=str(uuid4()),
                sender=self.agent_id,
                receiver="executor_1",
                timestamp=datetime.utcnow(),
                message_type="task_request",
                task_id=task["task_id"],
                payload=task
            )

            response = self.platform.send_secure_message(
                message=message,
                host=self.executor_host,
                port=self.executor_port
            )

            results.append(response.payload)

        return results