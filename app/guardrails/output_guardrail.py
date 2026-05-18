# app/guardrails/output_guardrail.py
from app.guardrails.toxicity_checker import ToxicityChecker
from app.guardrails.pii_detector import PIIDetector

class OutputGuardrail:
    def __init__(self):
        self.toxicity_checker = ToxicityChecker()
        self.pii_detector = PIIDetector()

    def evaluate(self, raw_output: str) -> tuple[bool, str, str]:
        """
        Coordinates full validation routines across generated strings.
        Returns: (is_safe, processed_clean_text, alert_reason)
        """
        # Run step A verification
        toxic_flag, reason = self.toxicity_checker.is_toxic(raw_output)
        if toxic_flag:
            return False, "", reason
            
        # Run step B scrub execution rules
        clean_text = self.pii_detector.mask_text(raw_output)
        return True, clean_text, ""