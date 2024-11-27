import os
from sqlalchemy import create_engine, Integer, String, DateTime, func
from sqlalchemy.orm import sessionmaker
import atexit
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
import datetime


POSTGRES_USER = os.getenv('POSTGRES_USER', 'admin')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'Ckj;ysq_gfhjkm_2024')
POSTGRES_DB = os.getenv('POSTGRES_DB', 'hw-flask-sales-app')
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5431')

POSTGRES_DSN = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

engine = create_engine(POSTGRES_DSN)

Session = sessionmaker(bind=engine)

atexit.register(engine.dispose)

class Base(DeclarativeBase):
    
    @property
    def id_dict(self):
        return {'id': self.id}


class User(Base):
    __tablename__ = 'app_users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(72), index=True, unique=True)
    password: Mapped[str] = mapped_column(String(72), nullable=False)
    email: Mapped[str] = mapped_column(String(72), unique=True)
    registred_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                            server_default=func.now())
    
    @property
    def dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'registred_at': self.registred_at.isoformat()
        }

class Product(Base):
    __tablename__ = 'app_products'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(72), index=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    price: Mapped[int] = mapped_column(Integer, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    image: Mapped[str] = mapped_column(String(72), nullable=True)
    owner_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                            server_default=func.now())
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime,
                                                            server_default=func.now(),
                                                            onupdate=func.now())
    
    @property
    def dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'count': self.count,
            'image': self.image,
            'owner_id': self.owner_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

Base.metadata.create_all(engine)