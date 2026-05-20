# Guardrails Module — Reusable Security Components

This directory contains **reusable security guardrails** designed to protect LLM applications from prompt injection, toxicity, and PII exposure. These components can be used standalone in any project.

## Features

- **InputGuardrail**: Two-layer prompt injection detection
  - Layer 1: Local `llm-guard` ML model (offline, zero cost)
  - Layer 2: Groq Llama Prompt Guard 2 API (cloud-based, fast)

- **OutputGuardrail**: Two-layer output protection
  - Toxicity checking (local ML + cloud API)
  - PII detection & masking (Microsoft Presidio)

- **ToxicityChecker**: Standalone toxicity scanner with fallback
- **PIIDetector**: Standalone PII detection and masking

## Installation

### 1. Install Dependencies

```bash
pip install groq llm-guard presidio-analyzer presidio-anonymizer python-dotenv langchain-groq
```

### 2. Configure Environment Variables

Create a `.env` file with:

```env
GROQ_API_KEY=your_groq_api_key_here
PROMPT_GUARD_MODEL=meta-llama/llama-prompt-guard-2-86m
SAFEGUARD_MODEL=openai/gpt-oss-safeguard-20b
```

## Usage

### Using InputGuardrail (Standalone)

```python
from app.guardrails.input_guardrail import InputGuardrail

# Option 1: Use environment variables (recommended for reusability)
guardrail = InputGuardrail()

# Option 2: Pass API key directly (for custom configurations)
guardrail = InputGuardrail(
    groq_api_key="your_api_key",
    prompt_guard_model="meta-llama/llama-prompt-guard-2-86m"
)

# Scan user input
result = guardrail.scan("What is the leave policy?")
if result["safe"]:
    print("✓ Input is safe")
else:
    print(f"✗ Blocked: {result['reason']}")
```

### Using OutputGuardrail (Standalone)

```python
from app.guardrails.output_guardrail import OutputGuardrail

# Option 1: Use environment variables
guardrail = OutputGuardrail()

# Option 2: Pass custom API keys
guardrail = OutputGuardrail(
    groq_api_key="your_api_key",
    safeguard_model="openai/gpt-oss-safeguard-20b"
)

# Process LLM output
result = guardrail.process("The employee's SSN is 123-45-6789")
print(f"Safe text: {result['safe_text']}")
print(f"Blocked: {result['blocked']}")
print(f"Summary: {result['summary']}")
```

### Using PIIDetector (Standalone)

```python
from app.guardrails.pii_detector import PIIDetector

detector = PIIDetector()
result = detector.mask("John Doe's email is john@company.com")

print(result["masked_text"])  # <PERSON>'s email is <EMAIL_ADDRESS>
print(result["entities_found"])  # ["PERSON", "EMAIL_ADDRESS"]
```

### Using ToxicityChecker (Standalone)

```python
from app.guardrails.toxicity_checker import ToxicityChecker

# Option 1: Use environment variables
checker = ToxicityChecker()

# Option 2: Pass custom API key
checker = ToxicityChecker(
    groq_api_key="your_api_key",
    safeguard_model="openai/gpt-oss-safeguard-20b"
)

result = checker.scan("This is a helpful response")
if result["safe"]:
    print("✓ Output is safe")
else:
    print(f"✗ Blocked: {result['reason']}")
```

## Integration in Your Project

### Step 1: Copy Guardrail Files
Copy the guardrail files to your project:
```
your_project/
├── guardrails/
│   ├── input_guardrail.py
│   ├── output_guardrail.py
│   ├── toxicity_checker.py
│   └── pii_detector.py
```

### Step 2: Set Environment Variables
Create a `.env` file in your project root with Groq API credentials.

### Step 3: Import and Use
```python
from guardrails.input_guardrail import InputGuardrail
from guardrails.output_guardrail import OutputGuardrail

# Your existing code
input_guard = InputGuardrail()
output_guard = OutputGuardrail()

# Use them in your LLM pipeline
safe_input = input_guard.scan(user_message)
safe_output = output_guard.process(llm_response)
```

## Configuration

### Environment Variables
- `GROQ_API_KEY`: Required. Your Groq API key (get from https://console.groq.com)
- `PROMPT_GUARD_MODEL`: Optional. Prompt guard model (defaults to `meta-llama/llama-prompt-guard-2-86m`)
- `SAFEGUARD_MODEL`: Optional. Toxicity model (defaults to `openai/gpt-oss-safeguard-20b`)

### Constructor Parameters
All guardrail classes accept optional parameters:
```python
InputGuardrail(groq_api_key=..., prompt_guard_model=...)
OutputGuardrail(groq_api_key=..., safeguard_model=...)
ToxicityChecker(groq_api_key=..., safeguard_model=...)
```

## Security Compliance

These guardrails help meet security standards:
- **OWASP LLM Top 10**:
  - LLM01: Prompt Injection (InputGuardrail)
  - LLM02: Insecure Output Handling (OutputGuardrail)
  - LLM06: Sensitive Information Disclosure (PIIDetector)

- **NIST AI RMF**:
  - Manage 2.2: Harm mitigation controls
  - Govern 1.6: Data privacy and protection

## Performance Notes

- **Layer 1 (Local ML)**: Runs offline, instant after first download
- **Layer 2 (Cloud API)**: API call required, ~100-500ms depending on load
- **PII Detection**: ~50-200ms depending on text length

## Troubleshooting

### "Groq API key not provided"
```python
# Make sure to set GROQ_API_KEY environment variable:
import os
os.environ["GROQ_API_KEY"] = "your_key_here"

# Or pass directly:
guardrail = InputGuardrail(groq_api_key="your_key_here")
```

### "llm-guard not installed"
```bash
pip install llm-guard
```

### "Presidio analyzer error"
Ensure Presidio is installed and spaCy models are available:
```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_md
```

## Support

For issues or questions, refer to:
- Groq API Docs: https://console.groq.com/docs
- llm-guard: https://github.com/protectai/llm-guard
- Presidio: https://microsoft.github.io/presidio/
