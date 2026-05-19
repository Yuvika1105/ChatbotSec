# app/auth/rbac.py
#
# Role-based access control for the GenAI security chatbot.
# Defines the user directory, role permissions, and access checks
# that gate every request before it reaches the LLM.
#
# OWASP LLM Top 10: mitigates LLM08 (Excessive Agency)
# NIST AI RMF:      Govern 1.1 – accountability and role definition


class RBAC:
    """Central RBAC registry.

    Five roles control which tools, tables, and documents each user
    can access.  Week 1 only uses the chatbot column; RAG and SQL
    columns are wired in later weeks.

    Role        Users    Chatbot   RAG              SQL
    ─────────── ──────   ────────  ───────────────  ──────────────────
    admin       1        ✅        all docs          all tables
    hr_user     2        ✅        HR + Leave docs   employees, tickets
    finance     3        ✅        Finance docs      sales, products
    it_user     4        ✅        IT Security docs  tickets
    guest       5        ✅        none              none
    """

    # ── Role definitions ────────────────────────────────────────────────────

    ROLES: dict[str, dict] = {
        "admin": {
            "can_use_chatbot": True,
            "rag_document_groups": ["hr", "finance", "it", "legal", "all"],
            "sql_tables": ["employees", "sales", "products", "tickets", "all"],
            "description": "Full access to all systems and documents.",
        },
        "hr_user": {
            "can_use_chatbot": True,
            "rag_document_groups": ["hr", "leave"],
            "sql_tables": ["employees", "tickets"],
            "description": "Access to HR policies and employee data.",
        },
        "finance_user": {
            "can_use_chatbot": True,
            "rag_document_groups": ["finance"],
            "sql_tables": ["sales", "products"],
            "description": "Access to financial documents and sales tables.",
        },
        "it_user": {
            "can_use_chatbot": True,
            "rag_document_groups": ["it_security"],
            "sql_tables": ["tickets"],
            "description": "Access to IT security guidelines and tickets.",
        },
        "guest": {
            "can_use_chatbot": True,
            "rag_document_groups": [],
            "sql_tables": [],
            "description": "Public FAQ access only — RAG and SQL are restricted.",
        },
    }

    # ── User directory ───────────────────────────────────────────────────────

    USER_DIRECTORY: dict[str, dict] = {
        "1": {"role": "admin"},
        "2": {"role": "hr_user"},
        "3": {"role": "finance_user"},
        "4": {"role": "it_user"},
        "5": {"role": "guest"},
    }

    # ── Access checks ────────────────────────────────────────────────────────

    @classmethod
    def get_user(cls, user_id: str) -> dict | None:
        """Return the user record for *user_id*, or None if unknown."""
        return cls.USER_DIRECTORY.get(user_id)

    @classmethod
    def get_role(cls, user_id: str) -> str | None:
        """Return the role name for *user_id*, or None if unknown."""
        user = cls.get_user(user_id)
        return user["role"] if user else None

    @classmethod
    def can_use_chatbot(cls, user_id: str) -> bool:
        """Return True when the user is allowed to send messages to the LLM.

        Guests are blocked at this layer before any LLM call is made.
        Unknown user IDs are also denied (fail-closed).
        """
        role_name = cls.get_role(user_id)
        if role_name is None:
            return False  # unknown user — deny by default
        role = cls.ROLES.get(role_name, {})
        return bool(role.get("can_use_chatbot", False))

    @classmethod
    def get_rag_document_groups(cls, user_id: str) -> list[str]:
        """Return the list of document groups this user may query via RAG."""
        role_name = cls.get_role(user_id)
        if role_name is None:
            return []
        return cls.ROLES.get(role_name, {}).get("rag_document_groups", [])

    @classmethod
    def get_sql_tables(cls, user_id: str) -> list[str]:
        """Return the list of SQL tables this user may query."""
        role_name = cls.get_role(user_id)
        if role_name is None:
            return []
        return cls.ROLES.get(role_name, {}).get("sql_tables", [])