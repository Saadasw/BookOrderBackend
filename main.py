from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Dict
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from datetime import datetime, timedelta
import os
import secrets
import json
from dotenv import load_dotenv
import http.client
from enum import Enum

# Load environment variables
load_dotenv()

# FastAPI app
app = FastAPI(title="Order Management with 2FA")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")  # Fixed typo
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security
security = HTTPBearer()

# ==================== Database Models ====================

class Order(Base):
    __tablename__ = "orders"
    
    id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String, nullable=False, index=True)
    address = Column(String, nullable=False)
    payment_method = Column(String, nullable=False)
    payment_status = Column(String, default="pending")
    book_list = Column(Text, nullable=False)  # JSON string
    total_amount = Column(Integer, default=0)
    order_status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    verified = Column(Boolean, default=False)

class VerificationSession(Base):
    __tablename__ = "verification_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    session_token = Column(String, unique=True, index=True)
    phone_number = Column(String, nullable=False)
    pin_id = Column(String, nullable=False)
    attempts = Column(Integer, default=0)
    verified = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    order_data = Column(Text)  # Temporarily store order data

# Create tables
Base.metadata.create_all(bind=engine)

# ==================== Pydantic Models ====================

class PaymentMethod(str, Enum):
    CASH_ON_DELIVERY = "cash_on_delivery"
    BKASH = "bkash"
    NAGAD = "nagad"
    CARD = "card"

class OrderStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    PROCESSING = "processing"
    SHIPPED = "shipped"
    DELIVERED = "delivered"
    CANCELLED = "cancelled"

class Book(BaseModel):
    id: str
    title: str
    price: float
    quantity: int = 1

class OrderRequest(BaseModel):
    phone_number: str = Field(..., pattern="^\\+?[0-9]\\d{1,14}$")
    address: str = Field(..., min_length=5)
    payment_method: PaymentMethod
    books: List[Book]
    
    @field_validator('books')
    def validate_books(cls, v):
        if not v:
            raise ValueError('At least one book must be ordered')
        return v

class VerificationRequest(BaseModel):
    session_token: str
    pin_code: str = Field(..., pattern="^\\d{4,8}$")

class OrderResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    phone_number: str
    address: str
    payment_method: str
    payment_status: str
    books: List[Book]
    total_amount: float
    order_status: str
    created_at: datetime
    verified: bool

# ==================== Infobip 2FA Client ====================

class Infobip2FAClient:
    def __init__(self):
        self.api_key = os.getenv("INFOBIP_API_KEY")
        self.base_url = os.getenv("INFOBIP_BASE_URL", "2mel1m.api.infobip.com")
        self.app_id = os.getenv("INFOBIP_APP_ID")
        self.message_id = os.getenv("INFOBIP_MESSAGE_ID")
        
        if not all([self.api_key, self.app_id, self.message_id]):
            raise ValueError("Infobip configuration incomplete")
    
    def send_pin(self, phone_number: str) -> Dict:
        conn = http.client.HTTPSConnection(self.base_url)
        
        payload = json.dumps({
            "applicationId": self.app_id,
            "messageId": self.message_id,
            "to": phone_number.replace("+", "")
        })
        
        headers = {
            'Authorization': f'App {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        try:
            conn.request("POST", "/2fa/2/pin", payload, headers)
            response = conn.getresponse()
            data = response.read().decode('utf-8')
            
            if response.status >= 400:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="SMS service temporarily unavailable"
                )
            
            return json.loads(data)
        finally:
            conn.close()
    
    def verify_pin(self, pin_id: str, pin_code: str) -> Dict:
        conn = http.client.HTTPSConnection(self.base_url)
        
        payload = json.dumps({"pin": str(pin_code)})
        headers = {
            'Authorization': f'App {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        try:
            conn.request("POST", f"/2fa/2/pin/{pin_id}/verify", payload, headers)
            response = conn.getresponse()
            data = response.read().decode('utf-8')
            
            if response.status >= 400:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Verification service temporarily unavailable"
                )
            
            return json.loads(data)
        finally:
            conn.close()

# Initialize 2FA client
two_fa_client = Infobip2FAClient()

# ==================== Dependencies ====================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_session(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> VerificationSession:
    token = credentials.credentials
    
    session = db.query(VerificationSession).filter(
        VerificationSession.session_token == token,
        VerificationSession.expires_at > datetime.utcnow()
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )
    
    return session

# ==================== API Endpoints ====================

@app.get("/")
def root():
    return {
        "message": "Order Management API with 2FA",
        "endpoints": {
            "POST /orders/initiate": "Start order with SMS verification",
            "POST /orders/verify": "Verify PIN and create order",
            "GET /orders/": "List all orders",
            "GET /orders/{order_id}": "Get specific order",
            "PUT /orders/{order_id}": "Update order (requires verification)",
            "DELETE /orders/{order_id}": "Cancel order (requires verification)"
        }
    }

@app.post("/orders/initiate", status_code=status.HTTP_202_ACCEPTED)
def initiate_order(order: OrderRequest, db: Session = Depends(get_db)):
    """
    Step 1: Initiate order and send SMS verification
    """
    # Check rate limiting (simple implementation)
    recent_sessions = db.query(VerificationSession).filter(
        VerificationSession.phone_number == order.phone_number,
        VerificationSession.created_at > datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    if recent_sessions >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification attempts. Please try again later."
        )
    
    # Calculate total amount
    total_amount = sum(book.price * book.quantity for book in order.books)
    
    # Send OTP
    try:
        sms_result = two_fa_client.send_pin(order.phone_number)
        pin_id = sms_result.get("pinId")
        
        if not pin_id:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to send verification code"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SMS service error: {str(e)}"
        )
    
    # Create verification session
    session_token = secrets.token_urlsafe(32)
    session = VerificationSession(
        session_token=session_token,
        phone_number=order.phone_number,
        pin_id=pin_id,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
        order_data=json.dumps({
            "phone_number": order.phone_number,
            "address": order.address,
            "payment_method": order.payment_method.value,
            "books": [book.dict() for book in order.books],
            "total_amount": total_amount
        })
    )
    
    db.add(session)
    db.commit()
    
    return {
        "message": "Verification code sent to your phone",
        "session_token": session_token,
        "expires_in_seconds": 600,
        "total_amount": total_amount
    }

@app.post("/orders/verify", response_model=OrderResponse)
def verify_and_create_order(
    verification: VerificationRequest,
    db: Session = Depends(get_db)
):
    """
    Step 2: Verify PIN and create the order
    """
    # Get session
    session = db.query(VerificationSession).filter(
        VerificationSession.session_token == verification.session_token,
        VerificationSession.expires_at > datetime.utcnow()
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )
    
    if session.verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Order already verified"
        )
    
    # Verify PIN
    try:
        verify_result = two_fa_client.verify_pin(session.pin_id, verification.pin_code)
        
        if not verify_result.get("verified"):
            session.attempts += 1
            db.commit()
            
            attempts_remaining = verify_result.get("attemptsRemaining", 0)
            if attempts_remaining == 0:
                db.delete(session)
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Maximum verification attempts exceeded"
                )
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid code. {attempts_remaining} attempts remaining."
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Verification service error"
        )
    
    # Mark session as verified
    session.verified = True
    
    # Create order
    order_data = json.loads(session.order_data)
    
    db_order = Order(
        phone_number=order_data["phone_number"],
        address=order_data["address"],
        payment_method=order_data["payment_method"],
        book_list=json.dumps(order_data["books"]),
        total_amount=int(order_data["total_amount"]),
        verified=True,
        order_status=OrderStatus.VERIFIED.value
    )
    
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    
    # Clean up session
    db.delete(session)
    db.commit()
    
    # Prepare response
    return OrderResponse(
        id=db_order.id,
        phone_number=db_order.phone_number,
        address=db_order.address,
        payment_method=db_order.payment_method,
        payment_status=db_order.payment_status,
        books=order_data["books"],
        total_amount=db_order.total_amount,
        order_status=db_order.order_status,
        created_at=db_order.created_at,
        verified=db_order.verified
    )

@app.post("/orders/resend-code")
def resend_verification_code(
    session_token: str,
    db: Session = Depends(get_db)
):
    """
    Resend verification code for existing session
    """
    session = db.query(VerificationSession).filter(
        VerificationSession.session_token == session_token,
        VerificationSession.expires_at > datetime.utcnow()
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired"
        )
    
    if session.verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Order already verified"
        )
    
    # Send new OTP
    try:
        sms_result = two_fa_client.send_pin(session.phone_number)
        session.pin_id = sms_result.get("pinId")
        session.attempts = 0
        session.expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()
        
        return {
            "message": "New verification code sent",
            "expires_in_seconds": 600
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to send verification code"
        )

@app.get("/orders/", response_model=List[OrderResponse])
def get_orders(
    skip: int = 0,
    limit: int = 100,
    phone_number: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Get list of orders (with optional filtering)
    """
    query = db.query(Order)
    
    if phone_number:
        query = query.filter(Order.phone_number == phone_number)
    
    orders = query.offset(skip).limit(limit).all()
    
    return [
        OrderResponse(
            id=order.id,
            phone_number=order.phone_number,
            address=order.address,
            payment_method=order.payment_method,
            payment_status=order.payment_status,
            books=json.loads(order.book_list),
            total_amount=order.total_amount,
            order_status=order.order_status,
            created_at=order.created_at,
            verified=order.verified
        )
        for order in orders
    ]

@app.get("/orders/{order_id}", response_model=OrderResponse)
def get_order(order_id: int, db: Session = Depends(get_db)):
    """
    Get specific order details
    """
    order = db.query(Order).filter(Order.id == order_id).first()
    
    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order not found"
        )
    
    return OrderResponse(
        id=order.id,
        phone_number=order.phone_number,
        address=order.address,
        payment_method=order.payment_method,
        payment_status=order.payment_status,
        books=json.loads(order.book_list),
        total_amount=order.total_amount,
        order_status=order.order_status,
        created_at=order.created_at,
        verified=order.verified
    )

@app.put("/orders/{order_id}/status")
def update_order_status(
    order_id: int,
    status: OrderStatus,
    session: VerificationSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Update order status (requires authentication)
    """
    order = db.query(Order).filter(
        Order.id == order_id,
        Order.phone_number == session.phone_number
    ).first()
    
    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order not found or unauthorized"
        )
    
    # Validate status transition
    current_status = OrderStatus(order.order_status)
    
    # Define valid transitions
    valid_transitions = {
        OrderStatus.VERIFIED: [OrderStatus.PROCESSING, OrderStatus.CANCELLED],
        OrderStatus.PROCESSING: [OrderStatus.SHIPPED, OrderStatus.CANCELLED],
        OrderStatus.SHIPPED: [OrderStatus.DELIVERED],
    }
    
    if status not in valid_transitions.get(current_status, []):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot transition from {current_status.value} to {status.value}"
        )
    
    order.order_status = status.value
    order.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": f"Order status updated to {status.value}"}

@app.delete("/orders/{order_id}")
def cancel_order(
    order_id: int,
    session: VerificationSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    """
    Cancel an order (requires authentication)
    """
    order = db.query(Order).filter(
        Order.id == order_id,
        Order.phone_number == session.phone_number
    ).first()
    
    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order not found or unauthorized"
        )
    
    if order.order_status in [OrderStatus.SHIPPED.value, OrderStatus.DELIVERED.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot cancel shipped or delivered orders"
        )
    
    order.order_status = OrderStatus.CANCELLED.value
    order.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Order cancelled successfully"}

# ==================== Admin Endpoints (for testing) ====================

@app.get("/admin/sessions", include_in_schema=False)
def get_all_sessions(db: Session = Depends(get_db)):
    """Debug endpoint to view all sessions"""
    if os.getenv("ENVIRONMENT") != "development":
        raise HTTPException(status_code=404)
    
    sessions = db.query(VerificationSession).all()
    return [
        {
            "id": s.id,
            "phone": s.phone_number,
            "verified": s.verified,
            "expires_at": s.expires_at,
            "attempts": s.attempts
        }
        for s in sessions
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)