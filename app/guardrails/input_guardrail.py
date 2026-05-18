# app/guardrails/input_guardrail.py
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MODEL_LMSYS_DISTILBERT
from groq import Groq
from config import Config

class InputGuardrail:
    def __init__(self):
        # Layer 1: Local ML Model (caches huggingface files to disk on initial sequence compile)
        self.local_scanner = PromptInjection(threshold=0.5, model=MODEL_LMSYS_DISTILBERT)
        # Layer 2: API Fallback Interface Client
        self.groq_client = Groq(api_key=Config.GROQ_API_KEY)

    def scan(self, user_input: str) -> tuple[bool, str]:
        """
        Runs dual-layer checks on user input strings.
        Returns: (is_safe, error_reason)
        """
        # --- Layer 1 Execution ---
        _, is_valid, risk_score = self.local_scanner.scan(user_input)
        if not is_valid:
            return False, f"Prompt injection detected by llm-guard Layer 1 (Risk Score: {risk_score})"

        # --- Layer 2 Execution ---
        try:
            chat_completion = self.groq_client.chat.completions.create(
                messages=[{"role": "user", "content": user_input}],
                model=Config.PROMPT_GUARD_MODEL,
                temperature=0.0,
                max_tokens=10
            )
            verdict = chat_completion.choices[0].message.content.strip()
            if "INJECTION" in verdict.upper():
                return False, "Prompt injection flagged by Groq Llama Prompt Guard 2 (Layer 2)"
        except Exception:
            # Maintain processing continuity under external telemetry connection drop faults
            pass

        return True, ""