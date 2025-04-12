from typing import Optional
from ..models.models import User
from datetime import datetime

class TestAccountService:
    def __init__(self):
        # Predefined test accounts
        self.test_accounts = {
            "test_user": {
                "email": "test@example.com",
                "username": "test_user",
                "hashed_password": "test123",  # In real scenario, this would be hashed
                "is_active": True,
                "is_admin": False,
                "created_at": datetime.utcnow()
            },
            "test_admin": {
                "email": "admin@example.com",
                "username": "test_admin",
                "hashed_password": "admin123",  # In real scenario, this would be hashed
                "is_active": True,
                "is_admin": True,
                "created_at": datetime.utcnow()
            }
        }
    
    def get_test_user(self, username: str) -> Optional[User]:
        """Get a test user by username"""
        if username in self.test_accounts:
            account_data = self.test_accounts[username]
            user = User(
                email=account_data["email"],
                username=account_data["username"],
                hashed_password=account_data["hashed_password"],
                is_active=account_data["is_active"],
                is_admin=account_data["is_admin"],
                created_at=account_data["created_at"]
            )
            return user
        return None
    
    def verify_test_password(self, username: str, password: str) -> bool:
        """Verify test account password"""
        if username in self.test_accounts:
            return password == self.test_accounts[username]["hashed_password"]
        return False

test_account_service = TestAccountService()