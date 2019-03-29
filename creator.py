from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Product, User

engine = create_engine('sqlite:///database.db?check_same_thread=False')
Base.metadata.create_all(engine)
Base.metadata.bind = engine
