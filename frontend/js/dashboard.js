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
        
        const encryptedBytes = base64ToArrayBuffer(encryptedPayload);
        const signature = await signData(encryptedBytes, privateKey);
        
        let encryptedRiskScore = null;
        try {
            if (typeof paillierBigint !== 'undefined') {
                const paillierKeyData = await apiRequest('/orgs/paillier/public-key');
                const pubKey = new paillierBigint.PublicKey(
                    BigInt(paillierKeyData.public_key.n),
                    BigInt(paillierKeyData.public_key.g)
                );
                const encryptedRisk = pubKey.encrypt(BigInt(alertData.risk_score));
                encryptedRiskScore = JSON.stringify({
                    ciphertext: encryptedRisk.toString(),
                    exponent: 0,
                    public_key_n: paillierKeyData.public_key.n.toString()
                });
            }
        } catch (err) {
            console.warn('Paillier encryption failed:', err);
        }
        
        const result = await apiRequest('/alerts/submit', {
            method: 'POST',
            body: JSON.stringify({
                encrypted_payload: encryptedPayload,
                wrapped_aes_key: wrappedKey,
                signature: signature,
                hmac_beacon: beacon,
                paillier_ciphertext: encryptedRiskScore,
                alert_type: alertData.alert_type,
                severity: alertData.severity
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
    const resultDiv = document.getElementById(`decrypt-${alertId}`);
    resultDiv.innerHTML = '<p class="loading"></p> Decrypting...';
    
    try {
        const alertData = await apiRequest(`/alerts/${alertId}/decrypt`);
        const privateKeyPem = await fetchAndDecryptPrivateKey();
        const aesKey = await unwrapAESKey(alertData.wrapped_aes_key, privateKeyPem);
        const decrypted = await decryptAlert(alertData.encrypted_payload, aesKey);
        
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

window.decryptMyAlert = decryptMyAlert;

let typeChart, timelineChart, riskChart;

async function loadAnalytics() {
    const period = document.getElementById('analytics-period').value;
    showResult('analytics-result', '<p class="loading"></p> Loading...');
    
    try {
        const data = await apiRequest(`/alerts/analytics/summary?days=${period}`);
        
        let signatureStatus = '';
        if (data.signature) {
            try {
                const keyResponse = await fetch(`${API_BASE_URL}/orgs/server/public-key`);
                const keyData = await keyResponse.json();
                
                const dataToVerify = {...data};
                delete dataToVerify.signature;
                delete dataToVerify.signature_algorithm;
                
                const sortKeysRecursive = (obj) => {
                    if (obj === null) return obj;
                    if (typeof obj === 'number') {
                        return Math.round(obj * 100) / 100;
                    }
                    if (typeof obj !== 'object') return obj;
                    if (Array.isArray(obj)) {
                        return obj.map(sortKeysRecursive);
                    }
                    const sorted = {};
                    Object.keys(obj).sort().forEach(key => {
                        sorted[key] = sortKeysRecursive(obj[key]);
                    });
                    return sorted;
                };
                
                const sortedData = sortKeysRecursive(dataToVerify);
                const dataStr = JSON.stringify(sortedData);
                const isValid = await window.verifySignature(dataStr, data.signature, keyData.public_key);
                
                if (isValid) {
                    const sigPreview = data.signature.substring(0, 16);
                    signatureStatus = `<div style="color: #4CAF50; font-size: 0.9em; margin-bottom: 10px;">
                        ✓ Signature verified (${sigPreview}...)
                    </div>`;
                } else {
                    signatureStatus = `<div style="color: #f44336; font-size: 0.9em; margin-bottom: 10px;">
                        ✗ Signature verification failed
                    </div>`;
                }
            } catch (error) {
                console.error('Signature verification error:', error);
                signatureStatus = `<div style="color: #ff9800; font-size: 0.9em; margin-bottom: 10px;">
                    ⚠ Could not verify signature: ${error.message}
                </div>`;
            }
        }
        
        const avgRisk = data.risk_trends.length > 0
            ? data.risk_trends.reduce((sum, t) => sum + t.average_risk, 0) / data.risk_trends.length
            : 0;
        
        let html = `
            ${signatureStatus}
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>${data.total_alerts}</h3>
                    <p>Total Alerts</p>
                </div>
                <div class="stat-card">
                    <h3>${avgRisk.toFixed(1)}</h3>
                    <p>Avg Risk Score</p>
                </div>
                <div class="stat-card">
                    <h3>${data.participating_orgs}</h3>
                    <p>Organizations</p>
                </div>
            </div>
            <div class="charts-row">
                <div class="chart-box-half">
                    <h3>Daily Volume</h3>
                    <canvas id="timeline-chart"></canvas>
                </div>
                <div class="chart-box-half">
                    <h3>Risk Trends</h3>
                    <canvas id="risk-chart"></canvas>
                </div>
            </div>
            <div class="chart-box">
                <h3>Alert Types</h3>
                <canvas id="type-chart"></canvas>
            </div>
        `;
        
        showResult('analytics-result', html);
        
        setTimeout(() => {
            renderTypeChart(data.alerts_by_type);
            renderTimelineChart(data.daily_counts);
            renderRiskChart(data.risk_trends);
        }, 100);
        
    } catch (error) {
        showResult('analytics-result', `<p class="error">${error.message}</p>`);
    }
}

function renderTypeChart(typeData) {
    const ctx = document.getElementById('type-chart').getContext('2d');
    if (typeChart) typeChart.destroy();
    
    const types = Object.keys(typeData);
    const counts = Object.values(typeData);
    
    typeChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: types,
            datasets: [{
                data: counts,
                backgroundColor: ['#4a90e2', '#e24a4a', '#4ae290', '#e2d14a', '#9f4ae2', '#4ae2d1']
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'bottom' } }
        }
    });
}

function renderTimelineChart(dailyData) {
    const ctx = document.getElementById('timeline-chart').getContext('2d');
    if (timelineChart) timelineChart.destroy();
    
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: dailyData.map(d => new Date(d.date).toLocaleDateString()),
            datasets: [{
                label: 'Alerts',
                data: dailyData.map(d => d.count),
                borderColor: '#4a90e2',
                backgroundColor: 'rgba(74, 144, 226, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true } }
        }
    });
}

function renderRiskChart(riskData) {
    const ctx = document.getElementById('risk-chart').getContext('2d');
    if (riskChart) riskChart.destroy();
    
    riskChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: riskData.map(d => new Date(d.date).toLocaleDateString()),
            datasets: [{
                label: 'Avg Risk',
                data: riskData.map(d => d.average_risk),
                borderColor: '#e24a4a',
                backgroundColor: 'rgba(226, 74, 74, 0.1)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, max: 100 } }
        }
    });
}

window.loadAnalytics = loadAnalytics;
