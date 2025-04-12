from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
from .db_manager import DatabaseManager

class UserManagement:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.ph = PasswordHasher()

    def create_user(self, username, email, password):
        try:
            # Generate a random salt
            salt = secrets.token_hex(16)
            
            # Hash password with Argon2
            hashed_password = self._hash_password(password, salt)
            
            # Save user to database with salt
            self.db_manager.save_user(username, email, f"{salt}:{hashed_password}")
            print(f"User {username} created successfully.")
            return True
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            return False

    def authenticate_user(self, username, password):
        try:
            # Check for test accounts first
            test_user = test_account_service.get_test_user(username)
            if test_user is not None:
                return test_account_service.verify_test_password(username, password)

            # Regular user authentication
            user = self.db_manager.get_user(username)
            if not user:
                return False

            # Extract salt and hash
            stored_password = user['password']
            salt, hash_value = stored_password.split(':')

            # Verify password
            return self._verify_password(password, salt, hash_value)
        except Exception as e:
            print(f"Error authenticating user: {str(e)}")
            return False

    def _hash_password(self, password, salt):
        # Combine password with salt and hash using Argon2
        salted_password = f"{password}{salt}"
        return self.ph.hash(salted_password)

    def _verify_password(self, password, salt, hash_value):
        try:
            # Combine password with salt and verify
            salted_password = f"{password}{salt}"
            self.ph.verify(hash_value, salted_password)
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            print(f"Error verifying password: {str(e)}")
            return False

    def change_password(self, username, old_password, new_password):
        try:
            if self.authenticate_user(username, old_password):
                # Generate new salt and hash for the new password
                new_salt = secrets.token_hex(16)
                new_hash = self._hash_password(new_password, new_salt)
                
                # Update password in database
                self.db_manager.update_user_password(username, f"{new_salt}:{new_hash}")
                return True
            return False
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return False