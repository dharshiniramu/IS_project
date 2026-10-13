from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .database import get_db
from .deps import get_current_user, require_role
from .models import User, UserRole
from .schemas import TokenResponse, UserCreate, UserLogin, UserResponse
from .security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse)
def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    normalized_username = payload.username.strip()
    normalized_email = payload.email.lower().strip()
    existing_user = db.query(User).filter((User.username == normalized_username) | (User.email == normalized_email)).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already registered")

    user = User(
        username=normalized_username,
        email=normalized_email,
        password_hash=hash_password(payload.password),
        role=UserRole.user,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login_user(payload: UserLogin, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token({"sub": user.email, "role": user.role.value})
    return TokenResponse(access_token=token, user=user)


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.get("/admin/users", response_model=list[UserResponse], dependencies=[Depends(require_role(UserRole.admin.value))])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return db.query(User).order_by(User.created_at.desc()).all()
