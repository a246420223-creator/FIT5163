class ExecutorAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def process_task(self, task: dict) -> dict:
        task_type = task.get("task_type")
        text = task.get("input", "")

        if task_type == "summarise_text":
            words = text.split()
            summary = " ".join(words[:12]) + "..."

            return {
                "status": "success",
                "task_type": task_type,
                "result": {
                    "summary": summary
                }
            }

        elif task_type == "classify_text":
            negative_words = ["bad", "angry", "late", "poor", "problem"]
            positive_words = ["good", "great", "happy", "excellent", "fast"]

            lower_text = text.lower()

            if any(word in lower_text for word in negative_words):
                label = "negative"
            elif any(word in lower_text for word in positive_words):
                label = "positive"
            else:
                label = "neutral"

            return {
                "status": "success",
                "task_type": task_type,
                "result": {
                    "label": label
                }
            }

        else:
            return {
                "status": "error",
                "error": f"Unknown task type: {task_type}"
            }