# 📚 BookOrderBackend

Backend API for a secure book ordering system with SMS OTP verification using FastAPI and Infobip.

## 🌟 Features

- 📱 **SMS OTP Verification**: Two-factor authentication for all orders
- 🔐 **Secure Order Processing**: Phone verification required before order placement
- 🚦 **Rate Limiting**: Prevents abuse with intelligent request throttling
- 📊 **Order Management**: Complete CRUD operations with status tracking
- 💳 **Multiple Payment Methods**: Support for Cash, bKash, Nagad, and Card payments
- 📖 **RESTful API**: Clean, well-documented endpoints
- 🛡️ **Session Management**: Secure token-based authentication
- ⚡ **High Performance**: Built with FastAPI and Pydantic v2

## 🔗 Related Repository

Frontend: [BookOrderFrontend](https://github.com/yourusername/BookOrderFrontend)

## 🏗️ Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│                 │         │                  │         │                 │
│  Frontend App   │ ──API──▶│  FastAPI Backend │ ──SMS──▶│  Infobip API   │
│  (React/Vue)    │         │   (This Repo)    │         │   (2FA/OTP)     │
│                 │         │                  │         │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │                  │
                            │  Database        │
                            │  (PostgreSQL)    │
                            │                  │
                            └──────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Infobip account with API credentials
- PostgreSQL (optional, SQLite works for development)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/BookOrderBackend.git
cd BookOrderBackend
```

2. **Set up virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
```

Edit `.env` with your credentials:
```env
# Database
DATABASE_URL=sqlite:///./orders.db  # Or PostgreSQL URL

# Infobip Configuration (Required)
INFOBIP_API_KEY=your-api-key-here
INFOBIP_BASE_URL=your-base-url.api.infobip.com
INFOBIP_APP_ID=your-application-id
INFOBIP_MESSAGE_ID=your-message-template-id

# CORS (Update with your frontend URL)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

5. **Run the application**
```bash
python main.py
# Or: uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

## 📖 API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/orders/initiate` | Start order and send OTP |
| `POST` | `/orders/verify` | Verify OTP and create order |
| `GET` | `/orders/` | List all orders |
| `GET` | `/orders/{id}` | Get specific order |
| `POST` | `/orders/resend-code` | Resend verification code |
| `PUT` | `/orders/{id}/status` | Update order status |
| `DELETE` | `/orders/{id}` | Cancel order |

## 🔄 Order Flow

```mermaid
sequenceDiagram
    participant C as Customer
    participant F as Frontend
    participant B as Backend
    participant I as Infobip
    participant D as Database

    C->>F: Submit order details
    F->>B: POST /orders/initiate
    B->>I: Send OTP request
    I->>I: Generate OTP
    I->>C: SMS with OTP
    B->>D: Store session
    B->>F: Return session token
    
    C->>F: Enter OTP
    F->>B: POST /orders/verify
    B->>I: Verify OTP
    I->>B: Verification result
    B->>D: Create order
    B->>F: Return order details
    F->>C: Show confirmation
```

## 🗄️ Database Schema

### Orders Table
```sql
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    phone_number VARCHAR NOT NULL,
    address VARCHAR NOT NULL,
    payment_method VARCHAR NOT NULL,
    payment_status VARCHAR DEFAULT 'pending',
    book_list TEXT NOT NULL,  -- JSON
    total_amount INTEGER DEFAULT 0,
    order_status VARCHAR DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE
);
```

### Verification Sessions Table
```sql
CREATE TABLE verification_sessions (
    id SERIAL PRIMARY KEY,
    session_token VARCHAR UNIQUE NOT NULL,
    phone_number VARCHAR NOT NULL,
    pin_id VARCHAR NOT NULL,
    attempts INTEGER DEFAULT 0,
    verified BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    order_data TEXT  -- Temporary JSON storage
);
```

## 🛡️ Security Features

- **Rate Limiting**: 5 verification attempts per phone number per hour
- **Session Expiry**: 10-minute timeout for OTP verification
- **PIN Attempts**: Maximum 3 attempts per session
- **Input Validation**: Strict validation using Pydantic v2
- **CORS Protection**: Configurable allowed origins
- **Secure Tokens**: Cryptographically secure session tokens

## 🧪 Testing

### Run Test Suite
```bash
python test_2fa_flow.py
```

### Manual Testing with cURL

1. **Initiate Order**
```bash
curl -X POST http://localhost:8000/orders/initiate \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+8801234567890",
    "address": "123 Test Street, Dhaka, Bangladesh",
    "payment_method": "cash_on_delivery",
    "books": [
      {
        "id": "book-001",
        "title": "Python Programming",
        "price": 599,
        "quantity": 1
      }
    ]
  }'
```

2. **Verify OTP**
```bash
curl -X POST http://localhost:8000/orders/verify \
  -H "Content-Type: application/json" \
  -d '{
    "session_token": "your-session-token",
    "pin_code": "123456"
  }'
```

## 🐳 Docker Deployment

### Using Docker Compose
```bash
docker-compose up -d
```

### Using Docker
```bash
# Build
docker build -t bookorder-backend .

# Run
docker run -p 8000:8000 --env-file .env bookorder-backend
```

## 🚀 Production Deployment

### Environment Variables for Production
```env
DATABASE_URL=postgresql://user:pass@host:5432/dbname
ENVIRONMENT=production
SECRET_KEY=your-secret-key-here
ALLOWED_ORIGINS=https://yourdomain.com
```

### Deployment Options

1. **Heroku**
```bash
heroku create bookorder-api
heroku config:set INFOBIP_API_KEY=your-key
git push heroku main
```

2. **AWS EC2/ECS**
- Use the provided Dockerfile
- Set up RDS for PostgreSQL
- Configure security groups

3. **DigitalOcean App Platform**
- Connect GitHub repository
- Set environment variables
- Deploy automatically

## 📊 API Usage Examples

### JavaScript/React Frontend
```javascript
// Initialize order
const response = await fetch('http://localhost:8000/orders/initiate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    phone_number: '+8801234567890',
    address: '123 Main St, Dhaka',
    payment_method: 'bkash',
    books: [
      { id: '1', title: 'Book 1', price: 500, quantity: 1 }
    ]
  })
});

const { session_token } = await response.json();

// Verify OTP
const verifyResponse = await fetch('http://localhost:8000/orders/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    session_token,
    pin_code: userInput
  })
});
```

## 🔧 Configuration

### Infobip Setup
1. Create account at [Infobip](https://www.infobip.com)
2. Create 2FA application
3. Create message template
4. Get API credentials

### CORS Configuration
Update `ALLOWED_ORIGINS` in `.env` with your frontend URL:
```env
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

## 📈 Monitoring & Logging

- Application logs: Check console output
- Database queries: Enable SQLAlchemy logging
- API metrics: Use FastAPI middleware

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- FastAPI for the amazing framework
- Infobip for SMS services
- Pydantic for data validation

## 📞 Support

For issues and questions:
- Create an issue in this repository
- Email: your-email@example.com

---

Made with ❤️ for secure book ordering# BookOrderBackend
