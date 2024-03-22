from datetime import timedelta
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from auth import authenticate_user, create_access_token, get_current_user
from models import User
from config import ACCESS_TOKEN_EXPIRE_TIME
from schemas import Token, UserAdd, UserBase
from database import get_db, Base, engine


app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Base.metadata.create_all(engine)


@app.post("/register", response_model=UserBase)
async def register(data: UserAdd, db: Session = Depends(get_db)):
    if data.email in db.query(User.email).all():
        raise HTTPException(status_code=409, detail="this email is already taken")

    if data.username in db.query(User.username).all():
        raise HTTPException(status_code=409, detail="this username is already taken")

    hashed_password = pwd_context.hash(data.password)

    new_user = User(
        username=data.username,
        email=data.email,
        password=hashed_password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_TIME))
    # access_token = create_access_token(
    #     data={"sub": new_user.username}, expires_delta=access_token_expires
    # )
    # return Token(access_token=access_token, token_type="bearer")
    return new_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(days=int(ACCESS_TOKEN_EXPIRE_TIME))
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=UserBase)
async def read_users_me(current_user: Annotated[UserBase, Depends(get_current_user)]):
    return current_user


@app.get('/logout')
def logout():
    response = RedirectResponse(url='/',status_code=302)
    response.set_cookie(key='access_token',value='', httponly=True)
    return response