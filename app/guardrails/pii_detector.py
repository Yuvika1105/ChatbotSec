# app/guardrails/pii_detector.py
#
# PII detection and masking using Microsoft Presidio.
# Applied to the LLM output BEFORE it is returned to the user.
# This ensures that even if the model inadvertently echoes PII from
# its training data or from the prompt, the user never sees it raw.
#
# Supported entity types (subset — Presidio detects 50+ by default):
#   PERSON, EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD,
#   IBAN_CODE, IP_ADDRESS, URL, LOCATION, DATE_TIME, NRP, MEDICAL_LICENSE
#
# Each detected entity is replaced with a placeholder token, e.g.:
#   "Call John on 555-1234, SSN 123-45-6789"
#   → "Call <PERSON> on <PHONE_NUMBER>, SSN <US_SSN>"
#
# OWASP LLM Top 10: LLM06 – Sensitive Information Disclosure
# NIST AI RMF:      Govern 1.6 – data privacy and protection

import logging

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

logger = logging.getLogger(__name__)

# ── Entity types to detect and mask ─────────────────────────────────────────
# Add or remove entities based on your organisation's data classification
# policy.  Full list: https://microsoft.github.io/presidio/supported_entities/
ENTITIES_TO_DETECT = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "LOCATION",
    "DATE_TIME",
    "NRP",               # Nationality, Religious, Political groups
    "MEDICAL_LICENSE",
    "US_BANK_NUMBER",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
]


class PIIDetector:
    """Detects and masks PII in text using Microsoft Presidio.

    Usage::

        detector = PIIDetector()

        # Mask PII in LLM output before showing to user
        result = detector.mask(llm_response)
        if result["pii_detected"]:
            print(f"Masked {result['entity_count']} PII entities")
        safe_text = result["masked_text"]

        # Detect PII in user input for logging / warning purposes
        findings = detector.detect(user_input)
    """

    def __init__(self) -> None:
        # AnalyzerEngine loads the spaCy en_core_web_lg model on first init.
        # This takes a few seconds on cold start; subsequent calls are fast.
        # Run `python -m spacy download en_core_web_lg` before first use.
        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

        # Operator config: replace every detected entity with a typed token.
        # e.g. <PERSON>, <US_SSN>, <CREDIT_CARD>
        # Using "replace" (not "hash" or "redact") so that the masked text
        # remains grammatically readable and the entity type is visible.
        self._operators = {
            entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
            for entity in ENTITIES_TO_DETECT
        }
        # Catch-all for any entity type not in our list.
        self._operators["DEFAULT"] = OperatorConfig("replace", {"new_value": "<REDACTED>"})

    # ── Public interface ─────────────────────────────────────────────────────

    def mask(self, text: str) -> dict:
        """Detect and replace all PII entities in *text*.

        Parameters
        ----------
        text: The string to scan (typically the raw LLM response).

        Returns
        -------
        dict with keys:
            masked_text (str)    – Text with PII replaced by tokens.
            pii_detected (bool)  – True if any PII was found.
            entity_count (int)   – Number of distinct PII spans found.
            entities_found (list)– List of entity type strings detected.
        """
        if not text or not text.strip():
            return {
                "masked_text": text,
                "pii_detected": False,
                "entity_count": 0,
                "entities_found": [],
            }

        try:
            analyzer_results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=ENTITIES_TO_DETECT,
                # score_threshold: only flag entities the model is confident about
                score_threshold=0.5,
            )
        except Exception as exc:
            logger.error("Presidio analyzer error: %s — returning original text.", exc)
            return {
                "masked_text": text,
                "pii_detected": False,
                "entity_count": 0,
                "entities_found": [],
            }

        if not analyzer_results:
            return {
                "masked_text": text,
                "pii_detected": False,
                "entity_count": 0,
                "entities_found": [],
            }

        try:
            anonymized = self._anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=self._operators,
            )
            masked_text = anonymized.text
        except Exception as exc:
            logger.error("Presidio anonymizer error: %s — returning original text.", exc)
            masked_text = text

        entities_found = list({r.entity_type for r in analyzer_results})

        if entities_found:
            logger.info(
                "PII masked | entities=%s | original_length=%d | masked_length=%d",
                entities_found,
                len(text),
                len(masked_text),
            )

        return {
            "masked_text": masked_text,
            "pii_detected": bool(entities_found),
            "entity_count": len(analyzer_results),
            "entities_found": entities_found,
        }

    def detect(self, text: str) -> list[dict]:
        """Detect PII in *text* without masking — for input scanning / logging.

        Returns a list of dicts, one per detected PII span::

            [{"entity_type": "US_SSN", "score": 0.85, "start": 10, "end": 21}]
        """
        if not text or not text.strip():
            return []

        try:
            results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=ENTITIES_TO_DETECT,
                score_threshold=0.5,
            )
        except Exception as exc:
            logger.error("Presidio detect error: %s", exc)
            return []

        return [
            {
                "entity_type": r.entity_type,
                "score": round(r.score, 3),
                "start": r.start,
                "end": r.end,
            }
            for r in results
        ]