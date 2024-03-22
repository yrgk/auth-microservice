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


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []