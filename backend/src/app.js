const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Simple root test
app.get('/', (req, res) => {
  res.send('H4 Backend is live!');
});

// Health check API
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'H4 ERP Backend is running!',
    time: new Date().toISOString()
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});