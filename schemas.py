from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    id: int
    username: str
    email: EmailStr
    password: str


class UserAdd(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserPrivate(BaseModel):
    id: int
    username: str
    email: EmailStr


class SuccesfulResponse(BaseModel):
    message: str
    status_code: int = 200