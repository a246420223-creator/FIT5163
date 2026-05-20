from datetime import datetime
from uuid import uuid4
import ollama
import json

from platform_core.message_schema import Message


class PlannerAgent:
    def __init__(self, agent_id: str, platform, executor_host: str, executor_port: int):
        self.agent_id = agent_id
        self.platform = platform
        self.executor_host = executor_host
        self.executor_port = executor_port

    def decompose_query(self, user_query: str) -> list:

        prompt = f"""
You are an AI planner agent.

Your job is to break the user request into tasks.

Available task types:
- summarise_text
- classify_text

Rules:
- Return ONLY valid JSON
- Return a JSON list
- Do not explain anything
- Each task must contain:
    - task_type
    - input

Example output:
[
    {{
        "task_type": "summarise_text",
        "input": "example text"
    }},
    {{
        "task_type": "classify_text",
        "input": "example text"
    }}
]

User request:
{user_query}
"""

        response = ollama.chat(
            model="llama3",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        content = response["message"]["content"]

        try:
            parsed_tasks = json.loads(content)

            tasks = []

            for task in parsed_tasks:
                tasks.append({
                    "task_id": str(uuid4()),
                    "task_type": task["task_type"],
                    "input": task["input"]
                })

            return tasks

        except Exception as e:
            print("Planner AI parsing failed:", e)

            return [{
                "task_id": str(uuid4()),
                "task_type": "summarise_text",
                "input": user_query
            }]

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