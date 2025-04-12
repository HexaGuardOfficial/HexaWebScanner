from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from ..config.settings import settings
from ..services.db_manager import db_manager
from ..models.models import User
from ..services.test_account_service import test_account_service

class AuthService:
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        return self.pwd_context.hash(password)
    
    def create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    
    def decode_token(self, token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            return payload
        except JWTError:
            return None
    
    async def get_current_user(self, token: str = Depends(oauth2_scheme), db=Depends(db_manager.get_db)) -> User:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        payload = self.decode_token(token)
        if payload is None:
            raise credentials_exception
            
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        # Check for test accounts first
        test_user = test_account_service.get_test_user(username)
        if test_user is not None:
            return test_user
            
        # Regular user authentication
        user = db_manager.get_user_by_username(db, username)
        if user is None:
            raise credentials_exception
            
        return user
    
    async def get_current_active_user(self, current_user: User = Depends(get_current_user)) -> User:
        if not current_user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user
    
    async def get_current_admin_user(self, current_user: User = Depends(get_current_user)) -> User:
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The user doesn't have enough privileges"
            )
        return current_user

auth_service = AuthService()