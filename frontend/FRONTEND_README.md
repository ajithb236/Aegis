# Aegis Frontend

A clean, minimalistic web interface for the Aegis privacy-preserving alert exchange system.

## Features

- **Organization Registration**: Register new organizations with automatic RSA key generation
- **Authentication**: Token-based API authentication
- **Alert Submission**: Submit encrypted alerts with risk scores
- **Privacy-Preserving Search**: Search alerts using HMAC beacons
- **Homomorphic Aggregation**: View encrypted aggregate statistics
- **Organization Management**: View all organizations and manage your own

## Getting Started

### Prerequisites

1. Backend server must be running on `http://localhost:8000`
2. Modern web browser with JavaScript enabled

### Running the Frontend

#### Option 1: Simple HTTP Server (Python)
```bash
cd frontend
python -m http.server 8080
```

Then open: `http://localhost:8080`

#### Option 2: Node.js HTTP Server
```bash
cd frontend
npx http-server -p 8080
```

Then open: `http://localhost:8080`

#### Option 3: VS Code Live Server
1. Install "Live Server" extension in VS Code
2. Right-click `index.html` and select "Open with Live Server"

#### Option 4: Direct File
Simply open `index.html` directly in your browser (some features may require a server)

## Usage Flow

### 1. Register an Organization
- Navigate to "Register Organization" tab
- Enter unique organization ID (e.g., `org1`)
- Enter organization name
- Click "Register Organization"

### 2. Get API Token
- Navigate to "Get Token" tab
- Enter your organization ID
- Click "Get Token"
- Token will be stored for the session

### 3. Submit Alerts
- Navigate to "Submit Alert" tab
- Select alert type, severity, and source
- Enter risk score (0-100)
- Click "Submit Alert"

### 4. Search Alerts
- Navigate to "Search Alerts" tab
- Select alert type to search
- View matching alerts from all organizations

### 5. View Aggregates
- Navigate to "Aggregate Data" tab
- Click "Compute Aggregates"
- View encrypted aggregate statistics

### 6. Manage Organizations
- Navigate to "Organizations" tab
- List all organizations
- View your organization info
- View your submitted alerts

## Demo Workflow

Try this complete demo workflow:

1. **Register 3 Organizations**
   - org1 (Alpha Security)
   - org2 (Beta Intelligence)
   - org3 (Gamma Defense)

2. **Get Token for org1**

3. **Submit Multiple Alerts** (switch orgs as needed)
   - Malware alert (high, risk: 85)
   - Phishing alert (medium, risk: 60)
   - DDoS alert (critical, risk: 95)

4. **Search for Malware Alerts**
   - Should show alerts from all orgs

5. **View Aggregates**
   - See encrypted total and average risk scores

6. **Check Organization Stats**
   - View your submitted alerts count
