# app/guardrails/input_guardrail.py
#
# Two-layer prompt injection detection that runs BEFORE the user message
# reaches the LLM.  Blocking happens at the earliest possible point so
# that malicious input never enters the model context window.
#
# Layer 1 — llm-guard PromptInjection scanner (local ML, no API call)
#   Model:  lmsys/distilbert-fastchat (downloaded from HuggingFace on first
#           use, then cached locally — subsequent runs are instant)
#   Cost:   zero — runs fully offline
#
# Layer 2 — Groq Llama Prompt Guard 2 86M (API call, fast inference)
#   Model:  meta-llama/llama-prompt-guard-2-86m
#   Only called when Layer 1 clears the input (defence-in-depth).
#   Catches subtle adversarial phrasing that evades the local model.
#
# OWASP LLM Top 10: LLM01 – Prompt Injection
# NIST AI RMF:      Manage 2.2 – harm mitigation controls

import json
import logging

from groq import Groq

try:
    from llm_guard.input_scanners import PromptInjection
    from llm_guard.input_scanners.prompt_injection import MODEL_LMSYS_DISTILBERT
    LLM_GUARD_AVAILABLE = True
except ImportError:
    LLM_GUARD_AVAILABLE = False

from config import Config

logger = logging.getLogger(__name__)


class InputGuardrail:
    """Two-layer prompt injection defence.

    Usage::

        guard = InputGuardrail()
        result = guard.scan("Ignore all previous instructions and...")
        if not result["safe"]:
            # block the request — do not call the LLM
            print(result["reason"])
    """

    # Confidence threshold above which the scanner flags injection.
    # Lower = more sensitive (more false-positives).
    # 0.5 is the llm-guard recommended default.
    INJECTION_THRESHOLD = 0.5

    def __init__(self) -> None:
        # Layer 1: initialise the local PromptInjection scanner once.
        if LLM_GUARD_AVAILABLE:
            self._layer1_scanner = PromptInjection(
                threshold=self.INJECTION_THRESHOLD,
                model=MODEL_LMSYS_DISTILBERT,
            )
        else:
            self._layer1_scanner = None
            logger.warning("llm-guard not installed. Layer 1 Prompt Injection scanner will be skipped.")

        # Layer 2: Groq client for the remote Prompt Guard 2 model.
        self._groq_client = Groq(api_key=Config.GROQ_API_KEY)

    # ── Public interface ─────────────────────────────────────────────────────

    def scan(self, user_input: str) -> dict:
        """Run both layers and return a verdict dict.

        Returns
        -------
        dict with keys:
            safe (bool)   – True when the input is clean.
            reason (str)  – Human-readable explanation of the verdict.
            layer (str)   – Which layer caught the injection, or "none".
            risk_score (float) – Highest confidence score seen.
        """
        # ── Layer 1: local llm-guard scanner ────────────────────────────────
        layer1_result = self._run_layer1(user_input)
        if not layer1_result["safe"]:
            return layer1_result

        # ── Layer 2: Groq Prompt Guard 2 (only if Layer 1 passes) ───────────
        layer2_result = self._run_layer2(user_input)
        if not layer2_result["safe"]:
            return layer2_result

        # Both layers cleared — input is safe.
        return {
            "safe": True,
            "reason": "Input passed both injection detection layers.",
            "layer": "none",
            "risk_score": layer1_result["risk_score"],
        }

    # ── Private helpers ──────────────────────────────────────────────────────

    def _run_layer1(self, user_input: str) -> dict:
        """llm-guard PromptInjection scanner (local ML)."""
        if self._layer1_scanner is None:
            # Heuristic fallback when llm-guard is unavailable
            lower_input = user_input.lower()
            if "ignore all previous instructions" in lower_input or "dan mode" in lower_input or "[system]" in lower_input:
                return {
                    "safe": False,
                    "reason": "Prompt injection detected by heuristic fallback.",
                    "layer": "layer1_heuristic",
                    "risk_score": 1.0,
                }
            return {"safe": True, "reason": "Layer 1 skipped (llm-guard not installed), heuristic passed.", "layer": "none", "risk_score": 0.0}
        try:
            _sanitized, is_valid, risk_score = self._layer1_scanner.scan(user_input)
        except Exception as exc:
            # If the local scanner errors, fail open with a warning so the
            # pipeline degrades gracefully to Layer 2 only.
            logger.error("Layer 1 scanner error: %s — falling through to Layer 2.", exc)
            return {"safe": True, "reason": "Layer 1 error — skipped.", "layer": "none", "risk_score": 0.0}

        if not is_valid:
            return {
                "safe": False,
                "reason": f"Prompt injection detected by llm-guard (risk score: {risk_score:.2f}).",
                "layer": "layer1_llm_guard",
                "risk_score": risk_score,
            }

        return {"safe": True, "reason": "Layer 1 clear.", "layer": "none", "risk_score": risk_score}

    def _run_layer2(self, user_input: str) -> dict:
        """Groq Llama Prompt Guard 2 — remote API call."""
        # The prompt follows the binary classification format recommended
        # in the Llama Prompt Guard 2 model card.
        classification_prompt = (
            "Classify the following user message as either INJECTION or BENIGN.\n"
            "Return ONLY one word: INJECTION or BENIGN.\n\n"
            f"User message: {user_input}"
        )

        try:
            response = self._groq_client.chat.completions.create(
                model=Config.PROMPT_GUARD_MODEL,
                messages=[{"role": "user", "content": classification_prompt}],
                max_tokens=10,
                temperature=0.0,  # deterministic — classification task
            )
            verdict = response.choices[0].message.content.strip().upper()
        except Exception as exc:
            # API unavailable — fail open (log but allow through).
            # In production, fail closed and queue for human review.
            logger.error("Layer 2 API error: %s — allowing input through.", exc)
            return {"safe": True, "reason": "Layer 2 API error — skipped.", "layer": "none", "risk_score": 0.0}

        if "INJECTION" in verdict:
            return {
                "safe": False,
                "reason": "Prompt injection detected by Groq Llama Prompt Guard 2.",
                "layer": "layer2_groq_prompt_guard",
                "risk_score": 1.0,
            }

        return {"safe": True, "reason": "Layer 2 clear.", "layer": "none", "risk_score": 0.0}