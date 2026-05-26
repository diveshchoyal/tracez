"""TraceZ Backend — Authentication Router."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from app.database import get_db, User, AuditLog
from app.utils.crypto import hash_password, verify_password, create_jwt_token, generate_api_key
from app.utils.validators import validate_email, validate_password_strength
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# --- Request / Response Schemas ---

class UserSignup(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    api_key: str
    created_at: datetime

    class Config:
        from_attributes = True

# --- Endpoints ---

@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: UserSignup, request: Request, db: Session = Depends(get_db)):
    """Register a new user and generate their personal API key."""
    # Validate email formatting
    if not validate_email(payload.email):
        raise HTTPException(status_code=400, detail="Invalid email format.")
        
    # Validate password complexity
    pwd_valid, pwd_msg = validate_password_strength(payload.password)
    if not pwd_valid:
        raise HTTPException(status_code=400, detail=pwd_msg)
        
    # Check if user already exists
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
        
    # Create the user
    new_user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        api_key=generate_api_key(),
        role="USER",
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Audit log
    client_ip = request.client.host if request.client else "unknown"
    audit = AuditLog(
        user_id=new_user.id,
        action="user_signup",
        ip_address=client_ip,
        details=f"User signed up: {new_user.email}"
    )
    db.add(audit)
    db.commit()
    
    return new_user

@router.post("/login")
def login(payload: UserLogin, response: Response, request: Request, db: Session = Depends(get_db)):
    """Authenticate and issue a JWT token via body and cookie."""
    # Find user
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password) or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
        
    # Generate JWT token
    token = create_jwt_token(data={"sub": user.email, "role": user.role})
    
    # Set httpOnly cookie for session management (mitigate XSS/forgery risk)
    response.set_cookie(
        key="tracez_session",
        value=token,
        httponly=True,
        secure=False,  # Set to True in production (HTTPS)
        samesite="lax",
        max_age=12 * 3600  # 12 hours
    )

    response.set_cookie(
        key="session_user",
        value=user.email,
        httponly=True,
        samesite="lax",
        max_age=12 * 3600
    )
    
    # Audit log
    client_ip = request.client.host if request.client else "unknown"
    audit = AuditLog(
        user_id=user.id,
        action="user_login",
        ip_address=client_ip,
        details=f"Successful login for role: {user.role}"
    )
    db.add(audit)
    db.commit()
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "api_key": user.api_key
        }
    }

@router.post("/logout")
def logout(response: Response, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Clear session cookies to log out the user."""
    response.delete_cookie(key="tracez_session")
    response.delete_cookie(key="session_user")
    
    # Audit log
    client_ip = request.client.host if request.client else "unknown"
    audit = AuditLog(
        user_id=current_user.id,
        action="user_logout",
        ip_address=client_ip,
        details="User logged out"
    )
    db.add(audit)
    db.commit()
    
    return {"detail": "Successfully logged out."}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Retrieve details of the currently authenticated user."""
    return current_user
