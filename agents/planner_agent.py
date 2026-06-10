"""
Planner Agent.

Responsibilities:
  1. Receive a user query.
  2. Decompose it into at least two sub-tasks (summarise_text + classify_text).
  3. Send each task to the Executor as an encrypted, signed SecureEnvelope.
  4. Collect and return the verified, decrypted results.

LLM integration: uses Ollama (llama3) when available.  If Ollama is not
installed or not running, the agent falls back to a deterministic two-task
decomposition so the demo still runs without any LLM service.
"""

import json
from datetime import datetime, timezone
from uuid import uuid4

from platform_core.message_schema import Message
from platform_core.logger import log_event, log_warning

# Ollama is an optional dependency.  Import it lazily so the rest of the
# platform works even when the package is not installed.
try:
    import ollama as _ollama
    _OLLAMA_AVAILABLE = True
except ImportError:
    _OLLAMA_AVAILABLE = False


class PlannerAgent:

    def __init__(
        self,
        agent_id: str,
        platform,
        executor_host: str,
        executor_port: int
    ):
        self.agent_id = agent_id
        self.platform = platform
        self.executor_host = executor_host
        self.executor_port = executor_port

    # ------------------------------------------------------------------
    # Query decomposition
    # ------------------------------------------------------------------

    def decompose_query(self, user_query: str) -> list:
        """
        Break *user_query* into a list of task dicts, each containing:
          - task_id   (UUID string)
          - task_type ("summarise_text" or "classify_text")
          - input     (the text to process)

        Tries Ollama first; falls back to a deterministic two-task split.
        """
        if _OLLAMA_AVAILABLE:
            try:
                return self._decompose_with_ollama(user_query)
            except Exception as exc:
                log_warning(f"[Planner] Ollama decomposition failed ({exc}); using fallback.")
                print("[Planner] Ollama unavailable or returned invalid JSON -- using fallback.")

        return self._fallback_decompose(user_query)

    def _decompose_with_ollama(self, user_query: str) -> list:
        prompt = f"""You are an AI planner agent.

Your job is to break the user request into tasks.

Available task types:
- summarise_text
- classify_text

Rules:
- Return ONLY valid JSON
- Return a JSON list with EXACTLY two tasks: one summarise_text and one classify_text
- Do not explain anything
- Each task must contain: task_type, input

Example output:
[
    {{"task_type": "summarise_text", "input": "example text"}},
    {{"task_type": "classify_text",  "input": "example text"}}
]

User request:
{user_query}
"""
        response = _ollama.chat(
            model="llama3",
            messages=[{"role": "user", "content": prompt}]
        )
        content = response["message"]["content"]
        parsed = json.loads(content)

        tasks = [
            {
                "task_id":   str(uuid4()),
                "task_type": task["task_type"],
                "input":     task["input"],
            }
            for task in parsed
        ]

        # Guarantee at least two tasks even if the model returned only one.
        if len(tasks) < 2:
            tasks.append({
                "task_id":   str(uuid4()),
                "task_type": "classify_text",
                "input":     user_query,
            })

        return tasks

    def _fallback_decompose(self, user_query: str) -> list:
        """Always produces exactly two tasks without any LLM call."""
        return [
            {
                "task_id":   str(uuid4()),
                "task_type": "summarise_text",
                "input":     user_query,
            },
            {
                "task_id":   str(uuid4()),
                "task_type": "classify_text",
                "input":     user_query,
            },
        ]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def handle_user_query(self, user_query: str) -> list:
        """
        Decompose *user_query* into tasks, send each one to the Executor over
        a secure channel, verify the signed responses, and return the results.
        """
        print(f"\n[Planner] Decomposing query: \"{user_query}\"")
        tasks = self.decompose_query(user_query)
        print(f"[Planner] Decomposed into {len(tasks)} task(s): "
              f"{[t['task_type'] for t in tasks]}")

        results = []

        for task in tasks:
            message = Message(
                message_id=str(uuid4()),
                sender=self.agent_id,
                receiver="executor_1",
                timestamp=datetime.now(timezone.utc),
                message_type="task_request",
                task_id=task["task_id"],
                payload=task,
            )

            log_event(
                f"{self.agent_id} sending task {task['task_type']} "
                f"(task_id={task['task_id']}) to executor_1"
            )

            response = self.platform.send_secure_message(
                message=message,
                host=self.executor_host,
                port=self.executor_port,
            )

            log_event(
                f"{self.agent_id} received signed result for task "
                f"{task['task_type']} (task_id={task['task_id']})"
            )

            results.append(response.payload)

        return results
