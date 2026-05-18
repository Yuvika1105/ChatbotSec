# app/guardrails/pii_detector.py
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

class PIIDetector:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

    def mask_text(self, text: str) -> str:
        """Locates and replaces private entity blocks inside plain string segments."""
        analysis_results = self.analyzer.analyze(text=text, language="en")
        anonymized_result = self.anonymizer.anonymize(text=text, analyzer_results=analysis_results)
        return anonymized_result.text