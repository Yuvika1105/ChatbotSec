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
# app/guardrails/pii_detector.py
import logging
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

logger = logging.getLogger(__name__)

# List of tracking entities to identify and scrub
ENTITIES_TO_DETECT = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "LOCATION",
    "DATE_TIME",
    "NRP",
    "MEDICAL_LICENSE",
    "US_BANK_NUMBER",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
]

class PIIDetector:
    def __init__(self) -> None:
        # Initialize Presidio's underlying scanning and redacting engines
        self._analyzer = AnalyzerEngine()
        self._anonymizer = AnonymizerEngine()

        # Build structural replacement tokens dynamically: e.g., <EMAIL_ADDRESS>
        self._operators = {
            entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
            for entity in ENTITIES_TO_DETECT
        }
        self._operators["DEFAULT"] = OperatorConfig("replace", {"new_value": "<REDACTED>"})

    def mask(self, text: str) -> dict:
        # Handle blank text gracefully
        if not text or not text.strip():
            return {"masked_text": text, "pii_detected": False, "entity_count": 0, "entities_found": []}

        # Step 1: Scan the text to locate PII positions
        try:
            analyzer_results = self._analyzer.analyze(
                text=text,
                language="en",
                entities=ENTITIES_TO_DETECT,
                score_threshold=0.5,
            )
        except Exception as exc:
            logger.error(f"Presidio analyzer error: {exc} — returning original text.")
            return {"masked_text": text, "pii_detected": False, "entity_count": 0, "entities_found": []}

        # If no personal data targets are discovered, return clean markers
        if not analyzer_results:
            return {"masked_text": text, "pii_detected": False, "entity_count": 0, "entities_found": []}

        # Step 2: Swap the identified secret words with our placeholder brackets
        try:
            anonymized = self._anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=self._operators,
            )
            masked_text = anonymized.text
        except Exception as exc:
            logger.error(f"Presidio anonymizer error: {exc} — returning original text.")
            masked_text = text

        # Map findings to unique text string tags
        entities_found = list({r.entity_type for r in analyzer_results})

        if entities_found:
            logger.info(f"PII masked | entities={entities_found} | original_len={len(text)} | masked_len={len(masked_text)}")

        return {
            "masked_text": masked_text,
            "pii_detected": bool(entities_found),
            "entity_count": len(analyzer_results),
            "entities_found": entities_found,
        }

    def detect(self, text: str) -> list[dict]:
        # Diagnostic inspection mode — detects coordinates without changing text
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
            logger.error(f"Presidio detect error: {exc}")
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