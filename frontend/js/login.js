// Login page
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const orgId = document.getElementById('org-id').value.trim();
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ org_id: orgId, password })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Login failed');
        }
        
        const data = await response.json();
        
        // Store session
        sessionStorage.setItem('token', data.access_token);
        sessionStorage.setItem('refreshToken', data.refresh_token);
        sessionStorage.setItem('orgId', data.org_id);
        sessionStorage.setItem('orgName', data.org_name);
        sessionStorage.setItem('password', password);
        sessionStorage.setItem('lastActivity', Date.now());
        
        // Redirect to dashboard
        window.location.href = 'dashboard.html';
        
    } catch (error) {
        showMessage(error.message, 'error');
    }
});
