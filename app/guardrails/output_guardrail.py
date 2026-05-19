# app/guardrails/output_guardrail.py
#
# Composes the ToxicityChecker and PIIDetector into a single output
# guardrail that the chatbot calls on every LLM response.
#
# Processing order
# ────────────────
# 1. Toxicity check (two layers).
#    If toxic → BLOCK immediately.  Return a safe fallback message.
#    The raw LLM text is never shown to the user.
#
# 2. PII masking (Presidio).
#    Applied even when toxicity check passes.
#    Replaces PII tokens before the text reaches the caller.
#
# OWASP LLM Top 10: LLM02 – Insecure Output Handling
#                   LLM06 – Sensitive Information Disclosure
# NIST AI RMF:      Manage 2.2 – output harm mitigation

import logging

from app.guardrails.toxicity_checker import ToxicityChecker
from app.guardrails.pii_detector import PIIDetector

logger = logging.getLogger(__name__)

# The message shown to the user when the output is blocked for toxicity.
# Keep this neutral — do not reveal which specific policy was violated.
TOXICITY_FALLBACK = (
    "I'm sorry, I can't provide that response. "
    "Please rephrase your question or contact HR directly for assistance."
)


class OutputGuardrail:
    """Composes toxicity checking and PII masking for LLM output.

    Usage::

        guardrail = OutputGuardrail()
        result = guardrail.process(llm_response)

        # Always use result["safe_text"] — never the raw LLM output.
        print(result["safe_text"])
    """

    def __init__(self) -> None:
        self._toxicity_checker = ToxicityChecker()
        self._pii_detector = PIIDetector()

    # ── Public interface ─────────────────────────────────────────────────────

    def process(self, llm_response: str) -> dict:
        """Run toxicity check then PII masking on *llm_response*.

        Parameters
        ----------
        llm_response: The raw text returned by the LLM.

        Returns
        -------
        dict with keys:
            safe_text (str)        – The text to return to the user.
                                     Either the masked response or the
                                     TOXICITY_FALLBACK string.
            blocked (bool)         – True when the response was blocked
                                     for toxicity.
            toxicity_result (dict) – Full verdict from ToxicityChecker.
            pii_result (dict)      – Full result from PIIDetector.
            summary (str)          – One-line audit summary.
        """
        # ── Step 1: Toxicity check ───────────────────────────────────────────
        toxicity_result = self._toxicity_checker.scan(llm_response)

        if not toxicity_result["safe"]:
            # Block the response immediately.  Do not proceed to PII masking.
            logger.warning(
                "Output blocked | layer=%s | reason=%s",
                toxicity_result["layer"],
                toxicity_result["reason"],
            )
            return {
                "safe_text": TOXICITY_FALLBACK,
                "blocked": True,
                "toxicity_result": toxicity_result,
                "pii_result": {
                    "masked_text": TOXICITY_FALLBACK,
                    "pii_detected": False,
                    "entity_count": 0,
                    "entities_found": [],
                },
                "summary": f"BLOCKED — {toxicity_result['reason']}",
            }

        # ── Step 2: PII masking ──────────────────────────────────────────────
        pii_result = self._pii_detector.mask(llm_response)

        if pii_result["pii_detected"]:
            logger.info(
                "PII masked in output | entities=%s",
                pii_result["entities_found"],
            )
            summary = (
                f"Output passed toxicity — PII masked "
                f"({pii_result['entity_count']} entities: "
                f"{', '.join(pii_result['entities_found'])})."
            )
        else:
            summary = "Output passed all guardrails — clean response."

        return {
            "safe_text": pii_result["masked_text"],
            "blocked": False,
            "toxicity_result": toxicity_result,
            "pii_result": pii_result,
            "summary": summary,
        }