# config.py
import os
from dotenv import load_dotenv

# Initialize tracking environment parameters
load_dotenv()

class Config:
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    
    # Core Infrastructure Model Routings
    MAIN_MODEL = "llama-3.3-70b-versatile"
    PROMPT_GUARD_MODEL = "meta-llama/llama-prompt-guard-2-86m"
    SAFEGUARD_MODEL = "openai/gpt-oss-safeguard-20b"
    
    # System Destination File Scopes
    AUDIT_LOG_PATH = os.path.join("logs", "audit.jsonl")

# Set environment variables from Config for guardrail reusability
# This allows guardrails to work with environment variables while maintaining backward compatibility
os.environ.setdefault("GROQ_API_KEY", Config.GROQ_API_KEY or "")
os.environ.setdefault("PROMPT_GUARD_MODEL", Config.PROMPT_GUARD_MODEL)
os.environ.setdefault("SAFEGUARD_MODEL", Config.SAFEGUARD_MODEL)

# Enforce logging storage path structure directory creation dynamically
os.makedirs("logs", exist_ok=True)