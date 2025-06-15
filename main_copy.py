from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List
from sqlalchemy import create_engine, Column, Integer, String
#rom sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, declarative_base
import os
from dotenv import load_dotenv
from typing import List
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only. Replace with frontend origin in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_UR")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String, nullable=False)
    address = Column(String, nullable=False)
    payment = Column(String, nullable=False)
    book_list = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)


# models.py or in your main file



class OrderRequest(BaseModel):
    phone_number: str
    address: str
    payment: str
    book_list: List[str]



# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()





"""
@app.post("/orders/")
async def create_order(order: OrderRequest):
    print(order)
    return {"message": "Order received"}
"""
@app.post("/orders/")
def create_order(order: OrderRequest, db: Session = Depends(get_db)):
    print(order.phone_number)
    db_order = Order(
        phone_number=order.phone_number,
        address=order.address,
        payment = order.payment,
        book_list=",".join(order.book_list)
        
    )
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order

@app.get("/orders/")
def read_orders(db: Session = Depends(get_db)):
    return db.query(Order).all()

@app.put("/orders/{order_id}")
def update_order(order_id: int, order: OrderRequest, db: Session = Depends(get_db)):
    db_order = db.query(Order).filter(Order.id == order_id).first()
    if not db_order:
        raise HTTPException(status_code=404, detail="Order not found")
    db_order.phone_number = order.phone_number
    db_order.address = order.address
    db_order.book_list = ",".join(order.book_list)
    db.commit()
    return db_order

@app.delete("/orders/{order_id}")
def delete_order(order_id: int, db: Session = Depends(get_db)):
    db_order = db.query(Order).filter(Order.id == order_id).first()
    if not db_order:
        raise HTTPException(status_code=404, detail="Order not found")
    db.delete(db_order)
    db.commit()
    return {"message": "Order deleted"}
