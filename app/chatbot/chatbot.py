# app/chatbot/chatbot.py
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from config import Config
from app.auth.rbac import RBAC
from app.guardrails.input_guardrail import InputGuardrail
from app.guardrails.output_guardrail import OutputGuardrail
from app.audit_logging.audit_logger import AuditLogger

class SecuredChatbot:
    def __init__(self):
        self.input_guard = InputGuardrail()
        self.output_guard = OutputGuardrail()
        
        # Deploy standard LangChain Expressions infrastructure configurations
        self.llm = ChatGroq(model=Config.MAIN_MODEL, temperature=0.3, groq_api_key=Config.GROQ_API_KEY)
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "You are an internal operations chatbot assistant for AcmeCorp. Speak professionally."),
            ("user", "{user_input}")
        ])
        self.chain = self.prompt | self.llm | StrOutputParser()

    def process_message(self, user_id: str, message: str) -> str:
        # Step 1: Authorization validation
        if not RBAC.authorize_chatbot(user_id):
            err_reason = "Unauthorized channel system access profile check failed via matrix controls."
            AuditLogger.log_event(user_id, "access_denied", False, err_reason, message, "")
            return "Security Alert: Access denied due to infrastructure credential constraints."

        # Step 2: Incoming Ingestion Boundary Verification
        safe_input, input_reason = self.input_guard.scan(message)
        if not safe_input:
            AuditLogger.log_event(user_id, "request_blocked", False, input_reason, message, "")
            return f"Security Exception Rule Triggered: {input_reason}"

        # Step 3: Run baseline model transaction calls
        try:
            model_completion = self.chain.invoke({"user_input": message})
        except Exception as api_fault:
            fault_text = f"API Inference Connection drop fault: {str(api_fault)}"
            AuditLogger.log_event(user_id, "system_error", False, fault_text, message, "")
            return "System Error: Processing aborted due to cloud service validation failures."

        # Step 4: Validate Outbound Response Blocks
        safe_output, finalized_clean_text, output_reason = self.output_guard.evaluate(model_completion)
        if not safe_output:
            AuditLogger.log_event(user_id, "response_blocked", False, output_reason, message, "")
            return "Security Alert: System output text strings redacted due to policy violations."

        # Step 5: Finalize successful transactions logging writes
        AuditLogger.log_event(user_id, "request_fulfilled", True, "Transaction success", message, finalized_clean_text)
        return finalized_clean_text