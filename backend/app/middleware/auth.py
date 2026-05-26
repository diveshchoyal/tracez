"""TraceZ Backend — Authentication Dependencies."""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from app.database import get_db, User
from app.utils.crypto import decode_jwt_token

# API Key header extraction for extension calls
api_key_header = APIKeyHeader(name="X-TraceZ-API-Key", auto_error=False)

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """
    Authenticate the current user using either:
    1. A JWT in the 'tracez_session' cookie
    2. A JWT in the 'Authorization: Bearer <token>' header
    3. An API key in the 'X-TraceZ-API-Key' header
    """
    token = None
    
    # 1. Check cookies (for Admin Panel / Web Dashboard)
    if "tracez_session" in request.cookies:
        token = request.cookies["tracez_session"]
        
    # 2. Check Authorization Header (for API / Extension clients)
    elif "Authorization" in request.headers:
        auth_header = request.headers["Authorization"]
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            
    # 3. If a JWT token was found, decode and validate it
    if token:
        payload = decode_jwt_token(token)
        if not payload or "sub" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session token."
            )
        
        email = payload["sub"]
        user = db.query(User).filter(User.email == email, User.is_active == True).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive."
            )
        return user

    # 4. Check API Key (primarily for Extension API calls)
    api_key = request.headers.get("X-TraceZ-API-Key")
    if api_key:
        user = db.query(User).filter(User.api_key == api_key, User.is_active == True).first()
        if user:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key."
        )
        
    # No credentials provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication credentials not found."
    )

def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    """Verify that the authenticated user has ADMIN privileges."""
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Admin privileges required."
        )
    return current_user
