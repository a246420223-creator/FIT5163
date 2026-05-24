import ollama


class ExecutorAgent:

    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def _call_ollama(self, prompt: str) -> str:
        response = ollama.chat(
            model="llama3",
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"].strip()

    def summarise_text(self, text: str) -> dict:
        try:
            prompt = (
                "Summarise the following text in one concise sentence. "
                "Return only the summary, nothing else.\n\n"
                f"Text: {text}"
            )
            summary = self._call_ollama(prompt)

        except Exception as e:
            print(f"[Executor] Ollama summarise_text failed ({e}), using fallback.")
            words = text.split()
            summary = " ".join(words[:12]) + "..."

        return {
            "status": "success",
            "task_type": "summarise_text",
            "result": {
                "summary": summary
            }
        }

    def classify_text(self, text: str) -> dict:
        try:
            prompt = (
                "Classify the sentiment of the following text. "
                "Return only one word: positive, negative, or neutral. Nothing else.\n\n"
                f"Text: {text}"
            )
            label = self._call_ollama(prompt).lower().rstrip(".")

            if label not in ("positive", "negative", "neutral"):
                label = "neutral"

        except Exception as e:
            print(f"[Executor] Ollama classify_text failed ({e}), using fallback.")
            negative_words = ["bad", "angry", "late", "poor", "problem"]
            positive_words = ["good", "great", "happy", "excellent", "fast"]

            lower_text = text.lower()
            if any(w in lower_text for w in negative_words):
                label = "negative"
            elif any(w in lower_text for w in positive_words):
                label = "positive"
            else:
                label = "neutral"

        return {
            "status": "success",
            "task_type": "classify_text",
            "result": {
                "label": label
            }
        }

    def process_task(self, task: dict) -> dict:
        task_type = task.get("task_type")
        text = task.get("input", "")

        if task_type == "summarise_text":
            return self.summarise_text(text)

        elif task_type == "classify_text":
            return self.classify_text(text)

        else:
            return {
                "status": "error",
                "error": f"Unknown task type: {task_type}"
            }
