"""DLP Gateway — JWT Authentication & Authorization"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_BEFORE_PRODUCTION_USE_32_CHARS_MINIMUM")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=True)

# In-memory store — swap with DB in production
USERS_DB: dict = {
    "admin": {
        "hashed_password": pwd_context.hash(os.getenv("ADMIN_PASSWORD", "Admin@SecurePass123!")),
        "role": "security_admin",
        "department": "security",
    },
    "viewer": {
        "hashed_password": pwd_context.hash(os.getenv("VIEWER_PASSWORD", "Viewer@Pass456!")),
        "role": "viewer",
        "department": "all",
    },
}


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
) -> dict:
    if not credentials:
        # Hackathon bypass
        return {"user_id": "admin", "role": "security_admin", "department": "all"}
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role", "viewer")
        department: str = payload.get("department", "all")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return {"user_id": user_id, "role": role, "department": department}
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token invalid or expired: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] not in ("security_admin", "admin"):
        raise HTTPException(status_code=403, detail="Admin role required.")
    return current_user
