A secure multi-organization threat intelligence sharing system with end-to-end encryption, digital signatures, and homomorphic analytics.

## Overview

Aegis enables organizations to securely share threat intelligence alerts while preserving privacy through:

- **Hybrid Encryption**: RSA + AES-GCM for alert confidentiality
- **Digital Signatures**: RSA-PSS for authenticity verification
- **Homomorphic Encryption**: Paillier encryption for privacy-preserving risk score aggregation
- **Password-Protected Keys**: Client-side decryption only
- **HMAC-Based Search**: Privacy-preserving alert discovery

## Features

- Organization registration with JWT-based authentication
- Encrypted alert submission and retrieval
- Privacy-preserving alert search using HMAC beacons
- Homomorphic aggregation of encrypted risk scores
- Analytics dashboard with server-signed responses
- Session management with auto-logout
- Account security (failed login attempts, lockouts)

## Tech Stack

**Backend:**
- FastAPI (Python)
- PostgreSQL
- Cryptography libraries (phe, cryptography)
- JWT authentication

**Frontend:**
- Vanilla JavaScript
- Chart.js for analytics
- Web Crypto API for client-side encryption

## Setup

### Prerequisites

- Python 3.8+
- PostgreSQL
- Node.js (for frontend dependencies)

### Installation

1. **Clone repository and install dependencies:**

```bash
pip install -r requirements.txt
```

2. **Configure environment:**

Create .env file:

```env
POSTGRES_DB=threatintel
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
JWT_SECRET_KEY=your_64_char_hex_key
```

3. **Initialize database:**

```bash
python src/app/db/init_db.py
```

4. **Generate Paillier keys:**

```bash
python src/scripts/init_paillier_keys.py
```

5. **Generate server signing keys:**

```bash
python src/scripts/generate_server_keys.py
```

### Running the Application

**Start backend server:**

```bash
python src/app/main.py
```

Server runs on `http://localhost:8000`

**Serve frontend:**

Use any HTTP server, e.g.:

```bash
python -m http.server 8080 --directory frontend
```

Access at `http://localhost:8080`

## Usage

### Registration

1. Navigate to register page
2. Provide organization ID, name, email, and password
3. Save the encrypted private key (displayed once)
4. Password is required for key decryption

### Submitting Alerts

1. Login with organization credentials
2. Navigate to "Submit Alert" tab
3. Fill alert details (type, severity, source, risk score, description)
4. Alert is encrypted client-side before submission
5. Digital signature proves authenticity

### Searching Alerts

1. Select alert type to generate HMAC beacon
2. System searches without revealing search terms
3. Results show matching alerts with submitter info
4. Decrypt your own alerts with your password

### Analytics

1. View aggregated statistics across all organizations
2. Risk scores aggregated using homomorphic encryption
3. Server signature verification ensures data integrity
4. Charts show trends, types, and risk levels

## Security Features

### Client-Side Encryption

- Private keys never leave client device
- Password-based key derivation (PBKDF2)
- AES-256-GCM for alert encryption
- RSA key wrapping for AES keys

### Server Security

- JWT access tokens (60 min expiry)
- Refresh tokens (7 day expiry)
- Failed login lockout (5 attempts, 30 min lockout)
- Audit logging for security events
- Connection pooling with timeout protection

### Privacy Preservation

- Server cannot decrypt alerts or private keys
- Homomorphic operations on encrypted data
- HMAC beacons for searchability without plaintext exposure
- Minimal metadata exposure

## API Endpoints

### Authentication

- `POST /api/v1/auth/login` - Obtain JWT tokens
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Revoke refresh token

### Organizations

- `POST /api/v1/orgs/register` - Register new organization
- `GET /api/v1/orgs/list` - List all organizations
- `GET /api/v1/orgs/{org_id}` - Get organization details
- `GET /api/v1/orgs/me/info` - Get own organization info
- `GET /api/v1/orgs/me/alerts` - Get own submitted alerts
- `GET /api/v1/orgs/me/encrypted-key` - Retrieve encrypted private key
- `GET /api/v1/orgs/paillier/public-key` - Get Paillier public key
- `GET /api/v1/orgs/server/public-key` - Get server's signature verification key

### Alerts

- `POST /api/v1/alerts/submit` - Submit encrypted alert
- `GET /api/v1/alerts/search` - Search by HMAC beacon
- `GET /api/v1/alerts/{alert_id}/decrypt` - Get alert for decryption
- `GET /api/v1/alerts/aggregate` - Aggregate encrypted risk scores
- `GET /api/v1/alerts/analytics/summary` - Get analytics dashboard data

## Database Schema

**organizations**: Org credentials, encrypted keys, account status

**rsa_keys**: Organization RSA public keys

**alerts**: Encrypted alert payloads, wrapped keys, signatures, Paillier ciphertexts

**refresh_tokens**: JWT refresh token management

**audit_logs**: Security event logging

## File Structure

```
├── frontend/              # Web interface
├── keys/                 # Cryptographic keys (gitignored)
├── src/
│   ├── app/
│   │   ├── api/v1/      # API routes
│   │   ├── crypto/      # Encryption utilities
│   │   ├── db/          # Database setup and migrations
│   │   ├── models/      # Pydantic models
│   │   └── utils/       # Helper functions
│   └── scripts/         # Initialization scripts
├── .env                 # Environment configuration
└── requirements.txt     # Python dependencies
```

## Configuration

Edit config.js to set:

- `API_BASE_URL`: Backend server URL
- `AUTO_LOGOUT_MINUTES`: Session timeout duration

## Development

### Reset Database

```bash
python src/scripts/reset_db.py
```

### Run Migrations

```bash
python src/app/db/migrate.py
```

### API Documentation

Access interactive API docs at `http://localhost:8000/docs` when server is running.
