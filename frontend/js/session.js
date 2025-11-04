// Session management
const session = {
    get token() { return sessionStorage.getItem('token'); },
    get orgId() { return sessionStorage.getItem('orgId'); },
    get orgName() { return sessionStorage.getItem('orgName'); },
    get password() { return sessionStorage.getItem('password'); },
    updateActivity() { sessionStorage.setItem('lastActivity', Date.now()); }
};

function checkAuth() {
    if (!session.token) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

function checkInactivity() {
    const lastActivity = parseInt(sessionStorage.getItem('lastActivity'));
    const inactiveMinutes = (Date.now() - lastActivity) / 60000;
    
    if (inactiveMinutes >= AUTO_LOGOUT_MINUTES) {
        logout();
    }
}

function logout() {
    sessionStorage.clear();
    window.location.href = 'login.html';
}

// Activity monitor
if (session.token) {
    ['click', 'keypress', 'scroll'].forEach(event => {
        document.addEventListener(event, () => session.updateActivity());
    });
    
    setInterval(checkInactivity, 60000);
}
