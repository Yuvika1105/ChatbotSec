# tests/test_chatbot.py
import pytest
import os
import json
from app.chatbot.chatbot import SecuredChatbot
from config import Config

@pytest.fixture
def active_bot():
    return SecuredChatbot()

def test_unauthorized_guest_access_denied(active_bot):
    """Verify that user ID u005 (guest) is explicitly denied execution keys."""
    guest_uid = "u005"
    query = "Hello, what are my account variables?"
    
    response = active_bot.process_message(user_id=guest_uid, message=query)
    assert "permissions do not grant chatbot access" in response

    # Check that a record was added to your audit log framework automatically
    assert os.path.exists(Config.AUDIT_LOG_PATH)
    with open(Config.AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        last_line = json.loads(f.readlines()[-1])
        assert last_line["user_id"] == guest_uid
        assert last_line["event_type"] == "access_denied"

def test_authorized_user_flow_logging(active_bot, monkeypatch):
    """Verify that an authorized employee ID populates transaction trail logs."""
    admin_uid = "u001"
    query = "Test clean system operational loop trigger."
    
    # Mock out the core LangChain API network calls to run tests instantly for free
    def mock_invoke(*args, **kwargs):
        return "This is a safe mock system completion response."
    
    monkeypatch.setattr(active_bot.chain, "invoke", mock_invoke)
    
    response = active_bot.process_message(user_id=admin_uid, message=query)
    assert "safe mock system" in response.lower()
    
    # Verify transaction log integrity records
    with open(Config.AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        last_line = json.loads(f.readlines()[-1])
        assert last_line["user_id"] == admin_uid
        assert last_line["is_safe"] is True