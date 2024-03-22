import os
from dotenv import load_dotenv

load_dotenv()

USER = os.environ.get("USER")
PASSWORD = os.environ.get("PASSWORD")
HOST = os.environ.get("HOST")
PORT = os.environ.get("PORT")
NAME = os.environ.get("NAME")
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = os.environ.get("ALGORITHM")
ACCESS_TOKEN_EXPIRE_TIME = os.environ.get("ACCESS_TOKEN_EXPIRE_TIME")