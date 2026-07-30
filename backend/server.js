import dotenv from 'dotenv';
import { createApp } from './src/app.js';

dotenv.config();

const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  jsonLimit: process.env.JSON_LIMIT || '10mb',
  urlencodedLimit: process.env.URLENCODED_LIMIT || '10mb',
  compressionThreshold: Number(process.env.COMPRESSION_THRESHOLD) || 1024,
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
  rateLimitMaxRequests: Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
};

const app = createApp(config);

const PORT = process.env.SERVER_PORT || process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 H4 ERP Backend running on port ${PORT}`);
  console.log(`🌍 Environment: ${config.nodeEnv}`);
});