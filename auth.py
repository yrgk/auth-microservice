from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext

from models import User
from cookie import OAuth2PasswordBearerWithCookie
from database import engine
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_TIME
from schemas import UserBase

EXPIRATION_TIME = timedelta(days=int(ACCESS_TOKEN_EXPIRE_TIME))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="/token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    with Session(engine) as db:
        return db.query(User.id, User.username, User.email).filter(User.username == username).first()


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_cookie(user: UserBase):
    access_token_expires = timedelta(days=int(ACCESS_TOKEN_EXPIRE_TIME))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    new_response = JSONResponse({"message": "success", "status_code": 200})
    new_response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return new_response


def verify_access_token(token: str):
    try:
        decoded_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_data
    except JWTError:
        return None


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=14)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def delete_access_token():
    response = JSONResponse({"message": "success", "status_code": 200})
    response.delete_cookie(key='access_token')
    return response


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    decoded_data = verify_access_token(token)
    if not decoded_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = get_user(username=decoded_data["sub"])
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    return user