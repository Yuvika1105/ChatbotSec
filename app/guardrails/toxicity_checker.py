# app/guardrails/toxicity_checker.py
import json
from llm_guard.output_scanners import Toxicity as ToxicityScanner
from groq import Groq
from config import Config

class ToxicityChecker:
    def __init__(self):
        self.local_scanner = ToxicityScanner(threshold=0.5)
        self.groq_client = Groq(api_key=Config.GROQ_API_KEY)

    def is_toxic(self, llm_response: str) -> tuple[bool, str]:
        """Runs dual-layer scans on system response text arrays."""
        # Layer 1 Check
        _, is_valid, risk_score = self.local_scanner.scan(prompt="", output=llm_response)
        if not is_valid:
            return True, f"Toxic content detected by llm-guard Layer 1 (Risk Score: {risk_score})"

        # Layer 2 Check
        try:
            policy_prompt = (
                "Analyze the text below. If it violates policies against harassment, toxic slurs, "
                "or dangerous instruction content, return JSON with violation=1. Otherwise violation=0.\n"
                "Format strictly as: {\"violation\": 0, \"category\": \"\", \"rationale\": \"\"}\n"
                f"Content:\n{llm_response}"
            )
            completion = self.groq_client.chat.completions.create(
                messages=[{"role": "user", "content": policy_prompt}],
                model=Config.SAFEGUARD_MODEL,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            data = json.loads(completion.choices[0].message.content)
            if data.get("violation", 0) == 1:
                return True, f"Groq Safeguard Violation: {data.get('category')} - {data.get('rationale')}"
        except Exception:
            pass

        return False, ""