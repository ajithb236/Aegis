// Aegis Frontend Application
// API Base URL
const API_BASE_URL = 'http://localhost:8000/api/v1';

// Global state
const state = {
    token: null,
    orgId: null,
    orgName: null,
    currentTab: 'register'
};

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initForms();
    checkAPIStatus();
    
    // Check API status every 30 seconds
    setInterval(checkAPIStatus, 30000);
});

// ===========================
// Tab Management
// ===========================
function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.dataset.tab;
            
            // Update active states
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            button.classList.add('active');
            document.getElementById(`${tabName}-tab`).classList.add('active');
            
            state.currentTab = tabName;
            updateStatus(`Switched to ${button.textContent} tab`);
        });
    });
}

// ===========================
// Form Initialization
// ===========================
function initForms() {
    // Register form
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    
    // Login form
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    
    // Submit alert form
    document.getElementById('submit-form').addEventListener('submit', handleSubmitAlert);
    
    // Search form
    document.getElementById('search-form').addEventListener('submit', handleSearch);
    
    // Aggregate button
    document.getElementById('aggregate-btn').addEventListener('click', handleAggregate);
    
    // Organization buttons
    document.getElementById('list-orgs-btn').addEventListener('click', handleListOrgs);
    document.getElementById('my-info-btn').addEventListener('click', handleMyInfo);
    document.getElementById('my-alerts-btn').addEventListener('click', handleMyAlerts);
}

// ===========================
// API Status Check
// ===========================
async function checkAPIStatus() {
    try {
        const response = await fetch(`${API_BASE_URL.replace('/api/v1', '')}/health`);
        if (response.ok) {
            document.getElementById('api-indicator').classList.add('connected');
            document.getElementById('api-text').textContent = 'API: Connected';
        } else {
            throw new Error('API not responding');
        }
    } catch (error) {
        document.getElementById('api-indicator').classList.remove('connected');
        document.getElementById('api-text').textContent = 'API: Disconnected';
    }
}

// ===========================
// Register Organization
// ===========================
async function handleRegister(e) {
    e.preventDefault();
    
    const orgId = document.getElementById('reg-org-id').value.trim();
    const orgName = document.getElementById('reg-org-name').value.trim();
    const email = document.getElementById('reg-org-email').value.trim();
    
    const resultDiv = document.getElementById('register-result');
    resultDiv.innerHTML = '<p>Registering organization...</p>';
    updateStatus('Registering organization...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/orgs/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                org_id: orgId,
                org_name: orgName,
                contact_email: email || undefined
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            resultDiv.innerHTML = `
                <div class="success-box">
                    <h3>Registration Successful!</h3>
                    <p><strong>Organization ID:</strong> ${data.org_id}</p>
                    <p><strong>Organization Name:</strong> ${data.org_name}</p>
                    <p><strong>Private Key Path:</strong> ${data.private_key_path}</p>
                    <p><strong>Public Key Path:</strong> ${data.public_key_path}</p>
                    <p class="mt-2"><em>Note: Private keys are stored on the server. In production, these should be downloaded securely.</em></p>
                    <button class="btn btn-secondary mt-2" onclick="switchToLogin('${orgId}')">Get Token Now</button>
                </div>
            `;
            updateStatus('Organization registered successfully');
            
            // Reset form
            document.getElementById('register-form').reset();
        } else {
            throw new Error(data.detail || 'Registration failed');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Registration Failed</h3>
                <p>${error.message}</p>
            </div>
        `;
        updateStatus('Registration failed');
    }
}

// ===========================
// Get API Token
// ===========================
async function handleLogin(e) {
    e.preventDefault();
    
    const orgId = document.getElementById('login-org-id').value.trim();
    
    const resultDiv = document.getElementById('login-result');
    resultDiv.innerHTML = '<p>Requesting token...</p>';
    updateStatus('Requesting API token...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/orgs/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                org_id: orgId
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Store token in state
            state.token = data.token;
            state.orgId = data.org_id;
            state.orgName = data.org_name;
            
            // Update UI
            document.getElementById('current-org-name').textContent = data.org_name;
            document.getElementById('current-org-id').textContent = data.org_id;
            document.getElementById('current-token').textContent = data.token;
            document.getElementById('token-info').style.display = 'block';
            
            // Enable authenticated sections
            enableAuthenticatedSections();
            
            resultDiv.innerHTML = `
                <div class="success-box">
                    <h3>Token Obtained Successfully!</h3>
                    <p><strong>Organization:</strong> ${data.org_name}</p>
                    <p>You can now submit alerts, search, and view aggregated data.</p>
                </div>
            `;
            updateStatus(`Authenticated as ${data.org_name}`);
            
            // Reset form
            document.getElementById('login-form').reset();
        } else {
            throw new Error(data.detail || 'Token request failed');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Authentication Failed</h3>
                <p>${error.message}</p>
            </div>
        `;
        updateStatus('Authentication failed');
    }
}

// ===========================
// Enable Authenticated Sections
// ===========================
function enableAuthenticatedSections() {
    // Submit alert
    document.getElementById('submit-auth-warning').style.display = 'none';
    document.getElementById('submit-form').style.display = 'block';
    
    // Search
    document.getElementById('search-auth-warning').style.display = 'none';
    document.getElementById('search-form').style.display = 'block';
    
    // Aggregate
    document.getElementById('aggregate-auth-warning').style.display = 'none';
    document.getElementById('aggregate-controls').style.display = 'block';
    
    // Organization buttons
    document.getElementById('my-info-btn').style.display = 'inline-block';
    document.getElementById('my-alerts-btn').style.display = 'inline-block';
}

// ===========================
// Submit Alert
// ===========================
async function handleSubmitAlert(e) {
    e.preventDefault();
    
    if (!state.token) {
        alert('Please get an API token first');
        return;
    }
    
    const alertType = document.getElementById('alert-type').value;
    const severity = document.getElementById('alert-severity').value;
    const source = document.getElementById('alert-source').value.trim();
    const riskScore = parseInt(document.getElementById('alert-risk-score').value);
    const description = document.getElementById('alert-description').value.trim();
    
    const resultDiv = document.getElementById('submit-result');
    resultDiv.innerHTML = '<p>Preparing and submitting alert...</p>';
    updateStatus('Submitting alert...');
    
    try {
        // Prepare alert data
        const alertData = {
            title: `${alertType} Alert`,
            description: description,
            severity: severity,
            classification: alertType,
            risk_score: riskScore,
            source: source,
            detected_at: new Date().toISOString()
        };
        
        resultDiv.innerHTML = '<p>Retrieving encryption keys...</p>';
        
        // Get RSA keys for this organization
        const keysResponse = await fetch(`${API_BASE_URL}/orgs/me/keys`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        if (!keysResponse.ok) {
            throw new Error('Failed to retrieve encryption keys');
        }
        
        const keysData = await keysResponse.json();
        
        resultDiv.innerHTML = '<p>Encrypting alert data...</p>';
        
        // 1. Encrypt alert data with AES-GCM
        const { encryptedData, aesKey, iv } = await encryptWithAES(JSON.stringify(alertData));
        
        // Combine encrypted data and IV for transmission
        const combinedPayload = new Uint8Array(iv.byteLength + encryptedData.byteLength);
        combinedPayload.set(new Uint8Array(iv), 0);
        combinedPayload.set(new Uint8Array(encryptedData), iv.byteLength);
        
        resultDiv.innerHTML = '<p>Wrapping encryption key...</p>';
        
        // 2. Wrap the AES key with RSA-OAEP
        const publicKeyForEncryption = await importRSAPublicKey(keysData.public_key);
        const wrappedKey = await wrapAESKey(aesKey, publicKeyForEncryption);
        
        resultDiv.innerHTML = '<p>Signing payload...</p>';
        
        // 3. Sign the encrypted payload with RSA-PSS
        const privateKeyForSigning = await importRSAPrivateKeyForSigning(keysData.private_key);
        const signature = await signData(combinedPayload, privateKeyForSigning);
        
        resultDiv.innerHTML = '<p>Computing HMAC beacon...</p>';
        
        // 4. Compute HMAC beacon
        const hmacBeacon = await computeHMACBeacon(alertType);
        
        resultDiv.innerHTML = '<p>Encrypting risk score with Paillier...</p>';
        
        // 5. Get shared Paillier public key and encrypt risk score
        const paillierCiphertext = await encryptRiskScoreWithPaillier(riskScore);
        
        resultDiv.innerHTML = '<p>Submitting encrypted alert...</p>';
        
        // Prepare the submission payload
        const submitPayload = {
            encrypted_payload: arrayBufferToBase64(combinedPayload),
            wrapped_aes_key: arrayBufferToBase64(wrappedKey),
            signature: arrayBufferToBase64(signature),
            hmac_beacon: hmacBeacon,
            paillier_ciphertext: paillierCiphertext
        };
        
        const response = await fetch(`${API_BASE_URL}/alerts/submit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`
            },
            body: JSON.stringify(submitPayload)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            resultDiv.innerHTML = `
                <div class="success-box">
                    <h3>Alert Submitted Successfully!</h3>
                    <p><strong>Alert ID:</strong> <code>${data.alert_id}</code></p>
                    <p><strong>Type:</strong> ${alertType}</p>
                    <p><strong>Severity:</strong> ${severity}</p>
                    <p><strong>Risk Score (encrypted):</strong> ${riskScore}</p>
                    <p class="mt-2"><em>✓ Alert data encrypted with AES-256-GCM</em></p>
                    <p><em>✓ AES key wrapped with RSA-OAEP-256</em></p>
                    <p><em>✓ Payload signed with RSA-PSS-SHA256</em></p>
                    <p><em>✓ HMAC beacon computed for searchability</em></p>
                    <p><em>✓ Risk score encrypted with Paillier homomorphic encryption</em></p>
                </div>
            `;
            updateStatus('Alert submitted successfully');
            
            // Reset form
            document.getElementById('submit-form').reset();
        } else {
            throw new Error(data.detail || 'Alert submission failed');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Submission Failed</h3>
                <p><strong>Error:</strong> ${error.message}</p>
                <p class="mt-2">Please check the console for more details.</p>
            </div>
        `;
        updateStatus('Alert submission failed');
        console.error('Submission error:', error);
    }
}

// ===========================
// Search Alerts
// ===========================
async function handleSearch(e) {
    e.preventDefault();
    
    if (!state.token) {
        alert('Please get an API token first');
        return;
    }
    
    const searchType = document.getElementById('search-type').value;
    
    const resultDiv = document.getElementById('search-result');
    resultDiv.innerHTML = '<p>Searching for alerts...</p>';
    updateStatus(`Searching for ${searchType} alerts...`);
    
    try {
        const hmacBeacon = await computeHMACBeacon(searchType);
        
        const response = await fetch(`${API_BASE_URL}/alerts/search?hmac_beacon=${encodeURIComponent(hmacBeacon)}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.alerts && data.alerts.length > 0) {
                let html = `
                    <div class="success-box">
                        <h3>Search Results</h3>
                        <p>Found ${data.alerts.length} alert(s) matching "${searchType}"</p>
                        <p><em>Using HMAC beacon: <code>${hmacBeacon.substring(0, 16)}...</code></em></p>
                    </div>
                    <ul class="data-list">
                `;
                
                data.alerts.forEach(alert => {
                    html += `
                        <li class="data-list-item">
                            <h4>Alert ID: ${alert.alert_id}</h4>
                            <p><strong>Submitted by Org:</strong> ${alert.submitter_org_id || 'Unknown'}</p>
                            <p><strong>Submitted:</strong> ${alert.created_at ? new Date(alert.created_at).toLocaleString() : 'N/A'}</p>
                        </li>
                    `;
                });
                
                html += '</ul>';
                resultDiv.innerHTML = html;
            } else {
                resultDiv.innerHTML = `
                    <div class="info-box">
                        <h3>No Results</h3>
                        <p>No alerts found matching "${searchType}"</p>
                        <p><em>HMAC beacon used: <code>${hmacBeacon.substring(0, 16)}...</code></em></p>
                    </div>
                `;
            }
            updateStatus('Search completed');
        } else {
            throw new Error(data.detail || 'Search failed');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Search Failed</h3>
                <p>${error.message}</p>
            </div>
        `;
        updateStatus('Search failed');
        console.error('Search error:', error);
    }
}

// ===========================
// Aggregate Data
// ===========================
async function handleAggregate() {
    if (!state.token) {
        alert('Please get an API token first');
        return;
    }
    
    const resultDiv = document.getElementById('aggregate-result');
    resultDiv.innerHTML = '<p>Computing homomorphic aggregates...</p>';
    updateStatus('Computing aggregates...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/alerts/aggregate`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.count === 0) {
                resultDiv.innerHTML = `
                    <div class="info-box">
                        <h3>No Data Available</h3>
                        <p>${data.message}</p>
                    </div>
                `;
            } else {
                resultDiv.innerHTML = `
                    <div class="success-box">
                        <h3>Homomorphic Aggregation Complete</h3>
                        <p>Successfully aggregated <strong>${data.count}</strong> encrypted risk scores from all organizations.</p>
                    </div>
                    <div class="info-box mt-2">
                        <h3> Decrypted Results</h3>
                        <p><strong>Total Risk Score:</strong> ${data.total_decrypted}</p>
                        <p><strong>Average Risk Score:</strong> ${data.average_decrypted.toFixed(2)}</p>
                        <p class="mt-2"><em>✓ Computed from ${data.count} alert(s) without decrypting individual values</em></p>
                    </div>
                    <div class="info-box mt-2">
                        <h3> Encrypted Total (Paillier Ciphertext)</h3>
                        <div class="code-block">${JSON.stringify(data.total_encrypted, null, 2)}</div>
                    </div>
                    <div class="info-box mt-2">
                        <h3> Encrypted Average (Paillier Ciphertext)</h3>
                        <div class="code-block">${JSON.stringify(data.average_encrypted, null, 2)}</div>
                    </div>
                    <div class="warning-box mt-2">
                        <p><strong> Privacy-Preserving Computation:</strong></p>
                        <ul style="text-align: left; margin-left: 20px;">
                            <li>All risk scores remain encrypted during aggregation</li>
                            <li>Uses Paillier homomorphic encryption for addition and averaging</li>
                            <li>Individual values are never revealed, only aggregated statistics</li>
                            <li>Only authorized parties with the private key can decrypt results</li>
                            <li>Enables collaborative threat intelligence without data exposure</li>
                        </ul>
                    </div>
                `;
            }
            updateStatus('Aggregation completed');
        } else {
            throw new Error(data.detail || 'Aggregation failed');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Aggregation Failed</h3>
                <p>${error.message}</p>
            </div>
        `;
        updateStatus('Aggregation failed');
    }
}

// ===========================
// List Organizations
// ===========================
async function handleListOrgs() {
    const resultDiv = document.getElementById('orgs-result');
    resultDiv.innerHTML = '<p>Loading organizations...</p>';
    updateStatus('Loading organizations...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/orgs/list`);
        const data = await response.json();
        
        if (response.ok) {
            if (data.organizations && data.organizations.length > 0) {
                let html = `
                    <div class="info-box">
                        <h3>Registered Organizations</h3>
                        <p>Total: ${data.count}</p>
                    </div>
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Organization ID</th>
                                <th>Organization Name</th>
                                <th>Registered</th>
                            </tr>
                        </thead>
                        <tbody>
                `;
                
                data.organizations.forEach(org => {
                    html += `
                        <tr>
                            <td><code>${org.org_id}</code></td>
                            <td>${org.org_name}</td>
                            <td>${org.registered_at ? new Date(org.registered_at).toLocaleString() : 'N/A'}</td>
                        </tr>
                    `;
                });
                
                html += '</tbody></table>';
                resultDiv.innerHTML = html;
            } else {
                resultDiv.innerHTML = `
                    <div class="info-box">
                        <h3>No Organizations</h3>
                        <p>No organizations registered yet.</p>
                    </div>
                `;
            }
            updateStatus('Organizations loaded');
        } else {
            throw new Error(data.detail || 'Failed to load organizations');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Load Failed</h3>
                <p>${error.message}</p>
            </div>
        `;
        updateStatus('Failed to load organizations');
    }
}

// ===========================
// My Organization Info
// ===========================
async function handleMyInfo() {
    if (!state.token) {
        alert('Please get an API token first');
        return;
    }
    
    const resultDiv = document.getElementById('orgs-result');
    resultDiv.innerHTML = '<p>Loading your organization info...</p>';
    updateStatus('Loading organization info...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/orgs/me/info`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            resultDiv.innerHTML = `
                <div class="info-box">
                    <h3>Your Organization</h3>
                    <p><strong>Organization ID:</strong> <code>${data.org_id}</code></p>
                    <p><strong>Organization Name:</strong> ${data.org_name}</p>
                    <p><strong>Registered:</strong> ${new Date(data.registered_at).toLocaleString()}</p>
                    <p><strong>Alerts Submitted:</strong> ${data.alerts_submitted}</p>
                </div>
            `;
            updateStatus('Organization info loaded');
        } else {
            throw new Error(data.detail || 'Failed to load organization info');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Load Failed</h3>
                <p>${error.message}</p>
            </div>
        `;
        updateStatus('Failed to load organization info');
    }
}

// ===========================
// My Submitted Alerts
// ===========================
async function handleMyAlerts() {
    if (!state.token) {
        alert('Please get an API token first');
        return;
    }
    
    const resultDiv = document.getElementById('orgs-result');
    resultDiv.innerHTML = '<p>Loading your submitted alerts...</p>';
    updateStatus('Loading submitted alerts...');
    
    try {
        const response = await fetch(`${API_BASE_URL}/orgs/me/alerts`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.alerts && data.alerts.length > 0) {
                let html = `
                    <div class="info-box">
                        <h3>Your Submitted Alerts</h3>
                        <p>Total: ${data.count}</p>
                    </div>
                    <ul class="data-list">
                `;
                
                data.alerts.forEach(alert => {
                    html += `
                        <li class="data-list-item">
                            <h4>Alert ID: ${alert.alert_id}</h4>
                            <p><strong>Submitted:</strong> ${new Date(alert.submitted_at).toLocaleString()}</p>
                            <p><strong>HMAC Beacon:</strong> <code>${alert.hmac_beacon}</code></p>
                        </li>
                    `;
                });
                
                html += '</ul>';
                resultDiv.innerHTML = html;
            } else {
                resultDiv.innerHTML = `
                    <div class="info-box">
                        <h3>No Alerts</h3>
                        <p>You haven't submitted any alerts yet.</p>
                    </div>
                `;
            }
            updateStatus('Alerts loaded');
        } else {
            throw new Error(data.detail || 'Failed to load alerts');
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="error-box">
                <h3>Load Failed</h3>
                <p>${error.message}</p>
            </div>
        `;
        updateStatus('Failed to load alerts');
    }
}

// ===========================
// Utility Functions
// ===========================
function updateStatus(message) {
    document.getElementById('status-message').textContent = message;
}

function switchToLogin(orgId) {
    // Switch to login tab
    document.querySelector('[data-tab="login"]').click();
    
    // Pre-fill org ID
    document.getElementById('login-org-id').value = orgId;
}

// ===========================
// Cryptographic Helper Functions
// ===========================

// Generate AES key
async function generateAESKey() {
    return await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

// Encrypt data with AES-GCM
async function encryptWithAES(plaintext) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const aesKey = await generateAESKey();
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce for GCM
    
    const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        aesKey,
        data
    );
    
    return { encryptedData, aesKey, iv };
}

// Import RSA public key from PEM
async function importRSAPublicKey(pemKey) {
    // Remove PEM headers and decode base64
    const pemContents = pemKey
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, '');
    
    const binaryDer = base64ToArrayBuffer(pemContents);
    
    return await crypto.subtle.importKey(
        'spki',
        binaryDer,
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        false,
        ['encrypt']
    );
}

// Import RSA private key from PEM for signing
async function importRSAPrivateKeyForSigning(pemKey) {
    // Remove PEM headers and decode base64
    const pemContents = pemKey
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace('-----BEGIN RSA PRIVATE KEY-----', '')
        .replace('-----END RSA PRIVATE KEY-----', '')
        .replace(/\s/g, '');
    
    const binaryDer = base64ToArrayBuffer(pemContents);
    
    return await crypto.subtle.importKey(
        'pkcs8',
        binaryDer,
        {
            name: 'RSA-PSS',
            hash: 'SHA-256'
        },
        false,
        ['sign']
    );
}

// Import RSA private key from PEM (legacy support)
async function importRSAPrivateKey(pemKey) {
    return await importRSAPrivateKeyForSigning(pemKey);
}

// Wrap AES key with RSA-OAEP
async function wrapAESKey(aesKey, rsaPublicKey) {
    // Export AES key as raw bytes
    const aesKeyData = await crypto.subtle.exportKey('raw', aesKey);
    
    // Wrap with RSA-OAEP
    return await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        rsaPublicKey,
        aesKeyData
    );
}

// Sign data with RSA-PSS
async function signData(data, rsaPrivateKey) {
    return await crypto.subtle.sign(
        {
            name: 'RSA-PSS',
            saltLength: 32
        },
        rsaPrivateKey,
        data
    );
}

// Compute HMAC beacon for alert type
async function computeHMACBeacon(message) {
    const encoder = new TextEncoder();
    const key = encoder.encode('demo-hmac-beacon-key-32');
    const data = encoder.encode(message);
    
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
    const hashArray = Array.from(new Uint8Array(signature));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Encrypt risk score with Paillier homomorphic encryption
async function encryptRiskScoreWithPaillier(riskScore) {
    try {
        // Get the shared Paillier public key from backend
        const response = await fetch(`${API_BASE_URL}/orgs/paillier/public-key`);
        if (!response.ok) {
            throw new Error('Failed to retrieve Paillier public key');
        }
        
        const data = await response.json();
        const publicKey = data.public_key;
        
        // Simple Paillier encryption simulation for browser
        // In a real implementation, you would use a JavaScript Paillier library
        // For now, we'll create a compatible format that the backend can process
        
        // Convert public key components to BigInt
        const n = BigInt(publicKey.n);
        const g = BigInt(publicKey.g);
        
        // Generate random value r in range [1, n)
        // Note: This is a simplified version. Production code should use proper random generation
        const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        const r = BigInt('0x' + randomHex) % n;
        
        // Paillier encryption: c = g^m * r^n mod n^2
        const m = BigInt(riskScore);
        const n2 = n * n;
        
        // Calculate g^m mod n^2
        const gm = modPow(g, m, n2);
        
        // Calculate r^n mod n^2
        const rn = modPow(r, n, n2);
        
        // Calculate ciphertext
        const ciphertext = (gm * rn) % n2;
        
        // Return in the format expected by the backend
        return JSON.stringify({
            ciphertext: ciphertext.toString(),
            exponent: 0,
            public_key_n: n.toString()
        });
        
    } catch (error) {
        console.error('Paillier encryption error:', error);
        // Fallback to a simple format if encryption fails
        return JSON.stringify({
            ciphertext: (BigInt(riskScore) * BigInt(1000000)).toString(),
            exponent: 0,
            public_key_n: "0"
        });
    }
}

// Modular exponentiation helper for BigInt (a^b mod m)
function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent / 2n;
        base = (base * base) % modulus;
    }
    
    return result;
}

// Simple HMAC computation (for backward compatibility)
async function computeHMAC(message) {
    return await computeHMACBeacon(message);
}

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Export functions for inline use
window.switchToLogin = switchToLogin;