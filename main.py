from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from auth import (
    authenticate_user,
    create_cookie,
    get_current_user,
    get_private_user,
    get_user,
    verify_password,
    delete_access_token
)
from models import User
from schemas import UserAdd, UserBase, UserPrivate, SuccesfulResponse
from database import get_db, Base, engine


app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
Base.metadata.create_all(engine)


@app.post("/register", response_model=SuccesfulResponse)
async def register(data: UserAdd, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=409, detail="this email is already taken")

    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=409, detail="this username is already taken")

    hashed_password = pwd_context.hash(data.password)

    new_user = User(
        username=data.username,
        email=data.email,
        password=hashed_password
    )

    db.add(new_user)
    db.commit()

    return create_cookie(new_user)


@app.post("/token", response_model=SuccesfulResponse)
async def login(username: str, password: str):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return create_cookie(user)


@app.get("/user/me/", response_model=UserPrivate)
async def read_user_me(current_user: Annotated[UserBase, Depends(get_current_user)]):
    return current_user


@app.get('/user/{username}', response_model=UserPrivate)
async def read_user(user: Annotated[UserBase, Depends(get_private_user)]):
    if not user:
        raise HTTPException(status_code=404, detail={"message": "User not found", "status_code": 404})
    else:
        return user


@app.put('/user/change/username', response_model=SuccesfulResponse)
async def change_username(username: str, password: str, current_user: Annotated[UserBase, Depends(get_current_user)], db: Session = Depends(get_db)):
    if not verify_password(password, current_user.password):
        raise HTTPException(status_code=403, detail="Incorrect password")

    if username == current_user.username:
        return {"message": "success", "status_code": 200}

    if get_user(username):
        raise HTTPException(status_code=409, detail="this username is already taken")

    user = db.query(User).filter(User.username == current_user.username).first()
    user.username = username
    db.commit()
    db.refresh(user)

    return create_cookie(user)


@app.delete('/user/delete', response_model=SuccesfulResponse)
async def delete_user(password: str, current_user: Annotated[UserBase, Depends(get_current_user)], db: Session = Depends(get_db)):
    user = get_user(current_user.username)

    if not verify_password(password, current_user.password):
        raise HTTPException(status_code=403, detail="Incorrect password")

    db.delete(user)
    db.commit()

    return delete_access_token()


@app.get('/logout')
async def logout():
    return delete_access_token()