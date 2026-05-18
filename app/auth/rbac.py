class RBAC:
    # 5 Roles, 5 Distinct Users static infrastructure assignment
    USER_DIRECTORY = {
        "u001": {"name": "Admin User", "role": "admin", "has_chat": True},
        "u002": {"name": "HR Specialist", "role": "hr_user", "has_chat": True},
        "u003": {"name": "Finance Analyst", "role": "finance_user", "has_chat": True},
        "u004": {"name": "IT Administrator", "role": "it_user", "has_chat": True},
        "u005": {"name": "External Guest", "role": "guest", "has_chat": False}
    }

    @classmethod
    def authorize_chatbot(cls, user_id: str) -> bool:
        """Determines if a given user profile string has baseline chatbot access keys."""
        user = cls.USER_DIRECTORY.get(user_id)
        if not user:
            return False
        return user.get("has_chat", False)