from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import USER, PASSWORD, HOST, PORT, NAME

DATABASE_URL = f"postgresql://{USER}:{PASSWORD}@{HOST}/{NAME}"

engine = create_engine(DATABASE_URL, echo=True)

session = sessionmaker(autoflush=False, autocommit=False, bind=engine)
Base = declarative_base()

def get_db():
    db = session()
    try:
        yield db
    finally:
        db.close()