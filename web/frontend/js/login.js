let authToken = null;

document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();            
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    document.getElementById('loginText').style.display = 'none';
    document.getElementById('loginSpinner').style.display = 'inline-block';
    document.getElementById('loginBtn').disabled = true;
    
    try {                
        const token = btoa(`${username}:${password}`);//Basic Authentication
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${token}`
            },
            body: JSON.stringify({ username, password })
        });
        
        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('siem_auth_token', data.token || token);//токен
            localStorage.setItem('siem_username', username);
            window.location.href = '/dashboard';
        } else {
            showError('Invalid username or password');
        }
    } catch (error) {
        showError('Login failed: ' + error.message);
    } finally {
        document.getElementById('loginText').style.display = 'inline-block';
        document.getElementById('loginSpinner').style.display = 'none';
        document.getElementById('loginBtn').disabled = false;
    }
});

function showError(message) {
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorAlert').style.display = 'block';
}

function hideError() {
    document.getElementById('errorAlert').style.display = 'none';
}

window.addEventListener('DOMContentLoaded', () => {//если уже авторизован
    if (localStorage.getItem('siem_auth_token')) {
        window.location.href = '/dashboard';
    }
});