// Dashboard page
if (!checkAuth()) throw new Error('Not authenticated');

document.getElementById('org-name').textContent = session.orgName;

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        tab.classList.add('active');
        document.getElementById(tab.dataset.tab).classList.add('active');
    });
});

// Submit alert
document.getElementById('submit-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const alertData = {
        alert_type: document.getElementById('type').value,
        severity: document.getElementById('severity').value,
        source: document.getElementById('source').value,
        risk_score: parseInt(document.getElementById('risk-score').value),
        description: document.getElementById('description').value
    };
    
    showResult('submit-result', '<p class="loading"></p> Submitting...');
    
    try {
        const orgData = await apiRequest(`/orgs/${session.orgId}`);
        const { encryptedPayload, aesKey } = await encryptAlert(alertData);
        const wrappedKey = await wrapAESKey(aesKey, orgData.public_key);
        const beacon = await computeHMACBeacon(alertData.alert_type);
        
        const privateKeyPem = await fetchAndDecryptPrivateKey();
        const privateKey = await importPrivateKey(privateKeyPem);
        
        // Sign the encrypted payload (before base64 encoding)
        const encryptedBytes = base64ToArrayBuffer(encryptedPayload);
        const signature = await signData(encryptedBytes, privateKey);
        
        const result = await apiRequest('/alerts/submit', {
            method: 'POST',
            body: JSON.stringify({
                encrypted_payload: encryptedPayload,
                wrapped_aes_key: wrappedKey,
                signature: signature,
                hmac_beacon: beacon,
                paillier_ciphertext: null
            })
        });
        
        showResult('submit-result', `
            <div class="card">
                <p class="success">Alert submitted successfully!</p>
                <p>ID: ${result.alert_id}</p>
            </div>
        `);
        
        document.getElementById('submit-form').reset();
        
    } catch (error) {
        showResult('submit-result', `<p class="error">${error.message}</p>`);
    }
});

// My alerts
async function loadMyAlerts() {
    showResult('my-alerts-result', '<p class="loading"></p> Loading...');
    
    try {
        const data = await apiRequest('/orgs/me/alerts');
        
        if (data.count === 0) {
            showResult('my-alerts-result', '<p>No alerts yet.</p>');
            return;
        }
        
        let html = `<p>Found ${data.count} alerts:</p>`;
        data.alerts.forEach(alert => {
            html += `
                <div class="card">
                    <h4>Alert ${alert.alert_id.substring(0, 8)}...</h4>
                    <p class="meta">Submitted: ${new Date(alert.submitted_at).toLocaleString()}</p>
                    <p class="meta">Beacon: ${alert.hmac_beacon.substring(0, 16)}...</p>
                    <button onclick="decryptMyAlert('${alert.alert_id}')">Decrypt</button>
                    <div id="decrypted-${alert.alert_id}" style="margin-top: 10px;"></div>
                </div>
            `;
        });
        
        showResult('my-alerts-result', html);
        
    } catch (error) {
        showResult('my-alerts-result', `<p class="error">${error.message}</p>`);
    }
}

// Search
document.getElementById('search-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const alertType = document.getElementById('search-type').value;
    showResult('search-result', '<p class="loading"></p> Searching...');
    
    try {
        const beacon = await computeHMACBeacon(alertType);
        const data = await apiRequest(`/alerts/search?hmac_beacon=${beacon}`);
        
        if (data.count === 0) {
            showResult('search-result', '<p>No matching alerts found.</p>');
            return;
        }
        
        let html = `<p>Found ${data.count} alerts:</p>`;
        data.alerts.forEach(alert => {
            html += `
                <div class="card">
                    <h4>Alert ${alert.alert_id.substring(0, 8)}...</h4>
                    <p class="meta">Org ID: ${alert.submitter_org_id}</p>
                    <p class="meta">Date: ${new Date(alert.created_at).toLocaleString()}</p>
                </div>
            `;
        });
        
        showResult('search-result', html);
        
    } catch (error) {
        showResult('search-result', `<p class="error">${error.message}</p>`);
    }
});

// Aggregate
async function computeAggregate() {
    showResult('aggregate-result', '<p class="loading"></p> Computing...');
    
    try {
        const data = await apiRequest('/alerts/aggregate');
        
        showResult('aggregate-result', `
            <div class="card">
                <h4>Results</h4>
                <p><strong>Total Alerts:</strong> ${data.count}</p>
                <p><strong>Total Risk Score:</strong> ${data.total_decrypted}</p>
                <p><strong>Average Risk Score:</strong> ${data.average_decrypted.toFixed(2)}</p>
            </div>
        `);
        
    } catch (error) {
        showResult('aggregate-result', `<p class="error">${error.message}</p>`);
    }
}

// Organizations
async function loadOrgs() {
    showResult('orgs-result', '<p class="loading"></p> Loading...');
    
    try {
        const data = await apiRequest('/orgs/list');
        
        let html = `<p>Total: ${data.count} organizations</p>`;
        data.organizations.forEach(org => {
            html += `
                <div class="card">
                    <h4>${org.org_name}</h4>
                    <p class="meta">ID: ${org.org_id}</p>
                    <p class="meta">Registered: ${new Date(org.registered_at).toLocaleDateString()}</p>
                </div>
            `;
        });
        
        showResult('orgs-result', html);
        
    } catch (error) {
        showResult('orgs-result', `<p class="error">${error.message}</p>`);
    }
}

// Decrypt alert
async function decryptMyAlert(alertId) {
    const resultDiv = document.getElementById(`decrypted-${alertId}`);
    resultDiv.innerHTML = '<p class="loading"></p> Decrypting...';
    
    try {
        // Get encrypted alert data
        const alertData = await apiRequest(`/alerts/${alertId}/decrypt`);
        
        // Get private key
        const privateKeyPem = await fetchAndDecryptPrivateKey();
        
        // Unwrap AES key
        const aesKey = await unwrapAESKey(alertData.wrapped_aes_key, privateKeyPem);
        
        // Decrypt alert
        const decrypted = await decryptAlert(alertData.encrypted_payload, aesKey);
        
        // Display decrypted data
        resultDiv.innerHTML = `
            <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 4px; margin-top: 5px;">
                <p><strong>Type:</strong> ${decrypted.alert_type}</p>
                <p><strong>Severity:</strong> ${decrypted.severity}</p>
                <p><strong>Source:</strong> ${decrypted.source}</p>
                <p><strong>Risk Score:</strong> ${decrypted.risk_score}</p>
                <p><strong>Description:</strong> ${decrypted.description}</p>
            </div>
        `;
        
    } catch (error) {
        resultDiv.innerHTML = `<p class="error">${error.message}</p>`;
    }
}

// Make function globally accessible for onclick
window.decryptMyAlert = decryptMyAlert;
