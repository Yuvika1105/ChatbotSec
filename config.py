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

# Enforce logging storage path structure directory creation dynamically
os.makedirs("logs", exist_ok=True)