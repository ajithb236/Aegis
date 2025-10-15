# Aegis Frontend

Clean, minimalistic web interface for the Aegis privacy-preserving alert exchange system.

## Features

### Authentication
- **Organization Registration**: Create new organizations with automatic RSA keypair generation
- **Login System**: Token-based authentication for secure API access
- **Session Management**: Persistent sessions using browser storage

### Alert Management
- **Submit Alerts**: Encrypted alert submission with risk scores
- **Search Alerts**: Privacy-preserving search using HMAC beacons
- **View Alerts**: List all alerts submitted by your organization

### Analytics
- **Homomorphic Aggregation**: Compute statistics on encrypted risk scores
- **Organization Dashboard**: View submission statistics and registration details
- **Cross-Organization Analytics**: See aggregate data without compromising privacy

### Additional Features
- **Organization Directory**: Browse all registered organizations
- **Real-time Status**: Server connection monitoring
- **Responsive Design**: Works on desktop and mobile devices

## Quick Start

### 1. Start the Backend Server

```bash
cd d:\IS_Project\Aegis
python src\app\main.py
```

The server will start on `http://localhost:8000`

### 2. Access the Frontend

Open your browser and navigate to:
```
http://localhost:8000
```

The frontend is automatically served by FastAPI.

## Usage Guide

### First Time Setup

1. **Register Organization**
   - Click "Register" tab
   - Enter Organization ID (e.g., `org2`)
   - Enter Organization Name (e.g., `Beta Security Corp`)
   - Optionally add contact email
   - Click "Register Organization"
   - Keys will be generated and saved automatically

2. **Login**
   - After registration, you'll be auto-redirected to login
   - Or manually enter your Organization ID
   - Click "Login" to get an API token

### Working with Alerts

1. **Submit an Alert**
   - Select alert type (malware, phishing, DDoS, etc.)
   - Choose severity level
   - Select the source
   - Enter risk score (0-100)
   - Add optional description
   - Click "Submit Encrypted Alert"

2. **Search Alerts**
   - Select alert type to search for
   - Click "Search"
   - View matching alerts from all organizations

3. **View Your Alerts**
   - See all alerts submitted by your organization
   - Click "Refresh" to update the list

### Analytics

1. **Compute Aggregates**
   - Click "Compute Aggregates" button
   - View encrypted total and average risk scores
   - Results remain encrypted for privacy

2. **Organization Statistics**
   - View total alerts submitted
   - See registration date
   - Browse other organizations

## Important Notes

### Cryptographic Operations

**Current Limitation**: Full end-to-end encryption requires cryptographic libraries that are implemented in the Python client. The frontend currently shows the structure and API integration.

**For Production Use**:
- Implement WebCrypto API or use libraries like `phe-js` for Paillier encryption
- Add client-side key management
- Implement proper HMAC computation in JavaScript

**Recommended Workflow**:
- Use the **Python client** (`multi_org_client.py`) for full cryptographic functionality
- Use the **web frontend** for:
  - Organization management
  - Viewing submitted alerts
  - Computing aggregates on already-encrypted data
  - Monitoring system statistics

### Security Considerations

- **Tokens**: Currently stored in `sessionStorage` (cleared on browser close)
- **HTTPS**: Use HTTPS in production
- **CORS**: Configure `ALLOWED_ORIGINS` in backend settings
- **Keys**: Private keys are stored on the server (not ideal for production)

## API Integration

The frontend integrates with these API endpoints:

### Organizations
- `POST /api/v1/orgs/register` - Register new organization
- `POST /api/v1/orgs/token` - Get authentication token
- `GET /api/v1/orgs/list` - List all organizations
- `GET /api/v1/orgs/{org_id}` - Get organization details
- `GET /api/v1/orgs/me/info` - Get current org info
- `GET /api/v1/orgs/me/alerts` - Get current org alerts

### Alerts
- `POST /api/v1/alerts/submit` - Submit encrypted alert
- `GET /api/v1/alerts/search?hmac_beacon={beacon}` - Search alerts
- `GET /api/v1/alerts/aggregate` - Compute aggregates

### System
- `GET /health` - Health check

## File Structure

```
frontend/
├── index.html          # Main HTML structure
├── styles.css          # CSS styling
├── app.js              # JavaScript application logic
└── README.md           # This file
```

## Customization

### Colors
Edit CSS variables in `styles.css`:
```css
:root {
    --primary-color: #3b82f6;
    --primary-hover: #2563eb;
    /* ... other colors ... */
}
```

### API URL
Change in `app.js`:
```javascript
const API_BASE_URL = 'http://localhost:8000/api/v1';
```

### Auto-refresh Interval
Modify in `app.js`:
```javascript
setInterval(() => {
    if (currentUser.token) {
        loadOrgInfo();
    }
}, 30000); // 30 seconds
```

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

## Troubleshooting

### "Cannot connect to server"
- Ensure backend is running on `http://localhost:8000`
- Check CORS settings in backend
- Verify no firewall blocking

### "Organization not found"
- Make sure you registered the organization first
- Check organization ID spelling

### "Token expired"
- Logout and login again
- Backend may have restarted (tokens are in-memory)

### Search/Submit not working
- These features require full crypto implementation
- Use Python client for full functionality
- Frontend shows structure for future implementation

## Development

### Run in Development Mode

The frontend is served automatically by FastAPI with hot-reload.

### Debug Mode

Open browser developer tools (F12) to:
- View API requests/responses
- Check console for errors
- Monitor network traffic

## Production Deployment

### Recommendations

1. **Build Process**: Add minification and bundling
2. **HTTPS**: Always use HTTPS
3. **Environment Variables**: Use env vars for API URLs
4. **Crypto Libraries**: Implement full client-side encryption
5. **Error Handling**: Add comprehensive error boundaries
6. **Authentication**: Implement OAuth2 or similar
7. **State Management**: Consider React/Vue for complex state
8. **Testing**: Add unit and integration tests

## Future Enhancements

- [ ] Full client-side cryptographic operations
- [ ] Key management interface
- [ ] Real-time alert notifications
- [ ] Advanced filtering and sorting
- [ ] Data visualization (charts/graphs)
- [ ] Bulk operations
- [ ] Export functionality
- [ ] Admin panel for system management
- [ ] Multi-language support
- [ ] Dark mode theme

## License

Part of the Aegis project.
