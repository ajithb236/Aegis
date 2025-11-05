// Dashboard page
if (!checkAuth()) throw new Error('Not authenticated');

document.getElementById('org-name').textContent = session.orgName;

// Bootstrap: Load all required data in one request
let bootstrapData = null;
(async function loadBootstrap() {
    try {
        bootstrapData = await apiRequest('/orgs/me/bootstrap');
        sessionStorage.setItem('paillierKey', JSON.stringify(bootstrapData.paillier_public_key));
        sessionStorage.setItem('orgPublicKey', bootstrapData.public_key);
        sessionStorage.setItem('encryptedKeyData', JSON.stringify(bootstrapData.encrypted_key));
    } catch (error) {
        console.error('Bootstrap failed:', error);
    }
})();

// Tab switching with lazy loading
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        tab.classList.add('active');
        const targetTab = tab.dataset.tab;
        document.getElementById(targetTab).classList.add('active');
        
        // Lazy load data when tab is clicked
        if (targetTab === 'my-alerts') {
            loadMyAlerts();
        } else if (targetTab === 'shared-alerts') {
            loadSharedAlerts();
        } else if (targetTab === 'orgs') {
            loadOrgs();
        }
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
    
    const resultDiv = document.getElementById('submit-result');
    
    try {
        resultDiv.innerHTML = '<p>Submitting alert...</p>';
        
        const cachedPublicKey = sessionStorage.getItem('orgPublicKey');
        const { encryptedPayload, aesKey } = await encryptAlert(alertData);
        const wrappedKey = await wrapAESKey(aesKey, cachedPublicKey);
        const beacon = await computeHMACBeacon(alertData.alert_type);
        
        const privateKey = await getImportedPrivateKey();
        const encryptedBytes = base64ToArrayBuffer(encryptedPayload);
        const signature = await signData(encryptedBytes, privateKey);
        
        let encryptedRiskScore = null;
        try {
            if (typeof paillierBigint !== 'undefined') {
                const pubKey = getPaillierPublicKey();
                const encryptedRisk = pubKey.encrypt(BigInt(alertData.risk_score));
                const paillierKeyData = JSON.parse(sessionStorage.getItem('paillierKey'));
                encryptedRiskScore = JSON.stringify({
                    ciphertext: encryptedRisk.toString(),
                    exponent: 0,
                    public_key_n: paillierKeyData.n.toString()
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
                    <div class="card-actions">
                        <button onclick="decryptMyAlert('${alert.alert_id}')" class="btn-success"><i class="bi bi-unlock"></i> Decrypt</button>
                        <button onclick="shareAlert('${alert.alert_id}')" class="btn-secondary"><i class="bi bi-share"></i> Share</button>
                        <button onclick="viewShares('${alert.alert_id}')" class="btn-secondary"><i class="bi bi-people"></i> Shares</button>
                    </div>
                    <div id="decrypted-${alert.alert_id}" style="margin-top: 10px;"></div>
                    <div id="shares-${alert.alert_id}" style="margin-top: 10px;"></div>
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
        
        let html = `<p style="margin-bottom: 20px; font-size: 1rem;">Found ${data.count} matching alerts:</p>`;
        data.alerts.forEach(alert => {
            html += `
                <div class="card">
                    <h4><i class="bi bi-file-earmark-text"></i> Alert ${alert.alert_id.substring(0, 8)}...</h4>
                    <p class="meta"><i class="bi bi-building"></i> Organization: ${alert.submitter_org_id}</p>
                    <p class="meta"><i class="bi bi-clock"></i> Submitted: ${new Date(alert.created_at).toLocaleString()}</p>
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
        
        let html = `<p style="margin-bottom: 20px; font-size: 1rem;"><i class="bi bi-building"></i> Total: ${data.count} organizations registered</p>`;
        data.organizations.forEach(org => {
            html += `
                <div class="card">
                    <h4><i class="bi bi-building"></i> ${org.org_name}</h4>
                    <p class="meta"><i class="bi bi-key"></i> ID: <code style="background: var(--bg-lighter); padding: 2px 6px; border-radius: 3px;">${org.org_id}</code></p>
                    <p class="meta"><i class="bi bi-calendar"></i> Registered: ${new Date(org.registered_at).toLocaleDateString()}</p>
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
        const alertData = await apiRequest(`/alerts/${alertId}/decrypt`);
        const privateKeyPem = await fetchAndDecryptPrivateKey();
        const aesKey = await unwrapAESKey(alertData.wrapped_aes_key, privateKeyPem);
        const decrypted = await decryptAlert(alertData.encrypted_payload, aesKey);
        
        resultDiv.innerHTML = `
            <div class="decrypted-content">
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
                let serverPublicKey = sessionStorage.getItem('serverPublicKey');
                if (!serverPublicKey) {
                    const keyData = await apiRequest('/orgs/server/public-key');
                    serverPublicKey = keyData.public_key;
                    sessionStorage.setItem('serverPublicKey', serverPublicKey);
                }
                const keyData = { public_key: serverPublicKey };
                
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


// Share alert
async function shareAlert(alertId) {
    try {
        const orgsData = await apiRequest('/orgs/list');
        
        document.getElementById('share-alert-id').textContent = alertId.substring(0, 16) + '...';
        const select = document.getElementById('share-recipients');
        select.innerHTML = '';
        
        orgsData.organizations
            .filter(org => org.org_id !== session.orgId)
            .forEach(org => {
                const option = document.createElement('option');
                option.value = org.org_id;
                option.textContent = `${org.org_name} (${org.org_id})`;
                select.appendChild(option);
            });
        
        document.getElementById('share-modal').style.display = 'flex';
        
        document.getElementById('share-form').onsubmit = async (e) => {
            e.preventDefault();
            
            const selectedOrgs = Array.from(select.selectedOptions).map(opt => opt.value);
            
            if (selectedOrgs.length === 0) {
                showResult('share-result', '<p class="error">Select at least one organization</p>');
                return;
            }
            
            try {
                showResult('share-result', '<p>Unwrapping AES key...</p>');
                
                const alertData = await apiRequest(`/alerts/${alertId}/decrypt`);
                const privateKeyPem = await fetchAndDecryptPrivateKey();
                const aesKey = await unwrapAESKey(alertData.wrapped_aes_key, privateKeyPem);
                
                showResult('share-result', '<p>Fetching recipient public keys...</p>');
                
                const recipientKeys = {};
                for (const orgId of selectedOrgs) {
                    const keyData = await apiRequest(`/orgs/${orgId}/public-key`);
                    recipientKeys[orgId] = keyData.public_key;
                }
                
                showResult('share-result', '<p>Re-encrypting for recipients...</p>');
                
                const shares = {};
                for (const orgId of selectedOrgs) {
                    const wrappedKey = await wrapAESKeyForRecipient(aesKey, recipientKeys[orgId]);
                    shares[orgId] = wrappedKey;
                }
                
                showResult('share-result', '<p>Submitting shares...</p>');
                
                const result = await apiRequest(`/alerts/${alertId}/share`, {
                    method: 'POST',
                    body: JSON.stringify({ shares })
                });
                
                let message = `Shared with ${result.shared_with.length} organizations!`;
                if (result.restored && result.restored.length > 0) {
                    message += ` (Restored ${result.restored.length} previously revoked shares)`;
                }
                
                showResult('share-result', `<p class="success">${message}</p>`);
                setTimeout(closeShareModal, 2000);
                
            } catch (error) {
                showResult('share-result', `<p class="error">${error.message}</p>`);
            }
        };
        
    } catch (error) {
        alert('Failed to load organizations: ' + error.message);
    }
}

function closeShareModal() {
    document.getElementById('share-modal').style.display = 'none';
    document.getElementById('share-form').reset();
    document.getElementById('share-result').innerHTML = '';
}

window.shareAlert = shareAlert;
window.closeShareModal = closeShareModal;


// Shared alerts
async function loadSharedAlerts() {
    showResult('shared-alerts-result', '<p class="loading"></p> Loading...');
    
    try {
        const data = await apiRequest('/alerts/shared-with-me');
        
        if (data.count === 0) {
            showResult('shared-alerts-result', '<p>No alerts shared with you yet.</p>');
            return;
        }
        
        let html = `<p style="margin-bottom: 20px; font-size: 1rem;">${data.count} alerts shared with you:</p>`;
        data.alerts.forEach(alert => {
            html += `
                <div class="card">
                    <h4>${alert.alert_type} - ${alert.severity}</h4>
                    <p class="meta"><i class="bi bi-building"></i> Shared by: <strong>${alert.shared_by_name}</strong> (${alert.shared_by})</p>
                    <p class="meta"><i class="bi bi-clock"></i> Shared: ${new Date(alert.shared_at).toLocaleString()}</p>
                    <div class="card-actions">
                        <button type="button" onclick="decryptSharedAlert('${alert.alert_id}'); return false;" class="btn-success"><i class="bi bi-unlock"></i> Decrypt</button>
                    </div>
                    <div id="decrypted-shared-${alert.alert_id}"></div>
                </div>
            `;
        });
        
        showResult('shared-alerts-result', html);
        
    } catch (error) {
        showResult('shared-alerts-result', `<p class="error">${error.message}</p>`);
    }
}

async function decryptSharedAlert(alertId) {
    const resultDiv = document.getElementById(`decrypted-shared-${alertId}`);
    if (!resultDiv) return;
    
    resultDiv.innerHTML = '<p>Decrypting...</p>';
    
    try {
        const alertData = await apiRequest(`/alerts/${alertId}/get-shared`);
        const privateKeyPem = await fetchAndDecryptPrivateKey();
        const aesKey = await unwrapAESKey(alertData.wrapped_aes_key, privateKeyPem);
        const decrypted = await decryptAlert(alertData.encrypted_payload, aesKey);
        
        resultDiv.innerHTML = `
            <div class="decrypted-content">
                <p><strong>Type:</strong> ${decrypted.alert_type}</p>
                <p><strong>Severity:</strong> ${decrypted.severity}</p>
                <p><strong>Source:</strong> ${decrypted.source}</p>
                <p><strong>Risk Score:</strong> ${decrypted.risk_score}</p>
                <p><strong>Description:</strong> ${decrypted.description}</p>
            </div>
        `;
        
    } catch (error) {
        resultDiv.innerHTML = `<p class="error">Error: ${error.message}</p>`;
    }
}

async function viewShares(alertId) {
    const resultDiv = document.getElementById(`shares-${alertId}`);
    if (!resultDiv) return;
    
    resultDiv.innerHTML = '<p>Loading shares...</p>';
    
    try {
        const data = await apiRequest(`/alerts/${alertId}/shares`);
        
        if (data.shares.length === 0) {
            resultDiv.innerHTML = '<p style="color: #888; margin-top: 10px;">Not shared with anyone yet.</p>';
            return;
        }
        
        let html = '<div class="shares-container">';
        html += '<h5><i class="bi bi-people"></i> Shared With:</h5>';
        
        data.shares.forEach(share => {
            const statusClass = share.revoked ? 'revoked' : 'active';
            const statusText = share.revoked ? '(Revoked)' : '(Active)';
            const revokeBtn = !share.revoked 
                ? `<button onclick="revokeShare('${alertId}', '${share.org_id}')" class="btn-danger"><i class="bi bi-x-circle"></i> Revoke</button>`
                : '<span style="color: var(--text-dim); font-size: 0.85rem;">Access Revoked</span>';
            
            html += `
                <div class="share-item">
                    <div class="share-info">
                        <strong>${share.org_name}</strong>
                        <span class="share-status ${statusClass}">${statusText}</span>
                        <div style="font-size: 0.85rem; color: var(--text-dim); margin-top: 4px;">${share.org_id}</div>
                    </div>
                    ${revokeBtn}
                </div>
            `;
        });
        
        html += '</div>';
        resultDiv.innerHTML = html;
        
    } catch (error) {
        resultDiv.innerHTML = `<p class="error">Error: ${error.message}</p>`;
    }
}

async function revokeShare(alertId, recipientOrgId) {
    if (!confirm(`Revoke access for ${recipientOrgId}?`)) return;
    
    try {
        await apiRequest(`/alerts/${alertId}/share/${recipientOrgId}`, {
            method: 'DELETE'
        });
        
        viewShares(alertId);
        
    } catch (error) {
        alert(`Error revoking share: ${error.message}`);
    }
}

window.loadSharedAlerts = loadSharedAlerts;
window.decryptSharedAlert = decryptSharedAlert;
window.viewShares = viewShares;
window.revokeShare = revokeShare;
