# app/audit_logging/audit_logger.py
import json
from datetime import datetime, timezone
from config import Config

class AuditLogger:
    @staticmethod
    def log_event(user_id: str, event_type: str, is_safe: bool, reason: str, input_text: str, output_text: str):
        """Appends a complete structure state transaction item line entry out to audit storage blocks."""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "user_id": user_id,
            "module": "chatbot",
            "event_type": event_type,
            "is_safe": is_safe,
            "reason": reason,
            "input_preview": input_text[:30] + "..." if len(input_text) > 30 else input_text,
            "output_preview": output_text[:30] + "..." if len(output_text) > 30 else output_text
        }
        
        with open(Config.AUDIT_LOG_PATH, "a", encoding="utf-8") as file:
            file.write(json.dumps(log_entry) + "\n")