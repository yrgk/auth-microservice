from sqlalchemy import Column, Integer, String

from database import Base


class User(Base):
    __tablename__ = 'AuthUser'
    id = Column(Integer, primary_key=True, autoincrement=True, unique=True, nullable=False)
    username = Column(String, index=True, unique=True, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)