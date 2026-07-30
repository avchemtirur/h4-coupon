/**
 * H4 ERP Platform - Express Application Factory
 * 
 * Configures and returns a fully-configured Express application with:
 * - Security middleware (Helmet, CORS)
 * - Request processing (JSON, URL-encoded parsing)
 * - Logging and monitoring
 * - Rate limiting
 * - Static file serving
 * - Health endpoints
 * - Error handling
 * 
 * Middleware loading order is critical - do not shuffle!
 */

import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import compression from 'compression';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import healthRoutes from './routes/health.js';
import apiRoutes from './routes/api.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Create and configure Express application
 * 
 * @param {Object} config - Configuration object
 * @returns {express.Application} Configured Express app
 */
export function createApp(config = {}) {
  const app = express();

  // ============================================================
  // CONFIGURATION
  // ============================================================

  const isDevelopment = config.nodeEnv === 'development';
  const isProduction = config.nodeEnv === 'production';

  // Trust proxy (important for getting real IP behind reverse proxy)
  app.set('trust proxy', 1);

  // ============================================================
  // MIDDLEWARE STACK (ORDER MATTERS!)
  // ============================================================

  // 1. REQUEST IDENTIFICATION
  // ============================================================
  /**
   * Generate unique request ID for tracing
   * Used to track requests through entire system
   */
  app.use((req, res, next) => {
    req.id = crypto.randomUUID();
    req.requestStartTime = Date.now();
    res.setHeader('X-Request-ID', req.id);
    next();
  });

  // 2. REQUEST LOGGING (EARLY)
  // ============================================================
  /**
   * Log all incoming HTTP requests
   * Logs before other middleware modify the request
   */
  app.use((req, res, next) => {
    // Capture response finish to log status and duration
    res.on('finish', () => {
      const duration = Date.now() - req.requestStartTime;
      const statusCode = res.statusCode;
      const level = statusCode < 400 ? 'info' : statusCode < 500 ? 'warn' : 'error';

      const logMessage = `[${req.id}] ${req.method} ${req.path} ${statusCode} ${duration}ms`;
      
      if (isDevelopment) {
        console.log(
          level === 'info' ? '✓' : level === 'warn' ? '⚠' : '✗',
          logMessage,
        );
      }
    });

    next();
  });

  // 3. SECURITY HEADERS (HELMET)
  // ============================================================
  /**
   * Set HTTP security headers to prevent common attacks
   * Must run before CORS
   */
  app.use((req, res, next) => {
    // Strict Transport Security (HTTPS)
    res.setHeader(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains',
    );

    // Prevent MIME sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Prevent clickjacking (X-Frame-Options)
    res.setHeader('X-Frame-Options', 'DENY');

    // Legacy XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');

    // Content Security Policy
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    );

    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Permissions Policy (formerly Feature Policy)
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // Remove X-Powered-By header
    res.removeHeader('X-Powered-By');

    next();
  });

  // 4. CORS (AFTER SECURITY HEADERS)
  // ============================================================
  /**
   * Handle Cross-Origin Resource Sharing (CORS)
   * Validate origin, set CORS headers
   */
  const corsOptions = {
    origin: config.corsOrigin || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Request-ID',
      'X-API-Version',
    ],
    exposedHeaders: [
      'X-Request-ID',
      'X-Total-Count',
      'X-Response-Time',
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
    ],
    credentials: true,
    maxAge: 86400, // 24 hours
    preflightContinue: false,
    optionsSuccessStatus: 204,
  };

  app.use(cors(corsOptions));

  // 5. COMPRESSION (AFTER CORS)
  // ============================================================
  /**
   * Compress response bodies using gzip
   * Reduces transfer size by 60-80%
   */
  app.use(compression({
    filter: (req, res) => {
      // Skip compression for streaming or if client disables it
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    },
    level: 6, // 0-11, default 6 (good balance)
    threshold: config.compressionThreshold || 1024, // Min 1KB
    type: [
      'application/json',
      'application/javascript',
      'text/html',
      'text/plain',
      'text/css',
      'text/javascript',
    ],
  }));

  // 6. PARSERS (BEFORE ROUTES)
  // ============================================================
  /**
   * Parse incoming request bodies
   * JSON and URL-encoded form data
   */

  // JSON Parser
  app.use(express.json({
    limit: config.jsonLimit || '10mb',
    strict: true, // Only parse objects/arrays
    type: 'application/json',
  }));

  // URL-Encoded Parser
  app.use(express.urlencoded({
    limit: config.urlencodedLimit || '10mb',
    extended: true, // Use qs library for complex data
    parameterLimit: 50,
    type: 'application/x-www-form-urlencoded',
  }));

  // 7. RATE LIMITING (AFTER PARSERS)
  // ============================================================
  /**
   * Prevent abuse by limiting request rate per IP
   * Returns 429 Too Many Requests when exceeded
   */
  const globalLimiter = rateLimit({
    windowMs: config.rateLimitWindowMs || 60 * 1000, // 1 minute
    max: config.rateLimitMaxRequests || 100, // 100 requests per window
    message: 'Too many requests from this IP, please try again later',
    statusCode: 429,
    standardHeaders: true, // Return rate limit info in headers
    legacyHeaders: false, // Disable X-RateLimit headers
    keyGenerator: (req) => {
      // Use IP for rate limiting
      return req.ip || req.connection.remoteAddress;
    },
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === '/health' || req.path.startsWith('/health/');
    },
    handler: (req, res) => {
      res.status(429).json({
        error: {
          type: 'RateLimitError',
          message: 'Too many requests. Please try again later.',
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: req.rateLimit.resetTime,
          requestId: req.id,
        },
      });
    },
  });

  app.use(globalLimiter);

  // 8. STATIC FILES (AFTER RATE LIMIT)
  // ============================================================
  /**
   * Serve static assets (HTML, CSS, JS, images)
   * Efficiently with caching headers
   */
  const publicPath = join(__dirname, '../public');
  app.use(express.static(publicPath, {
    maxAge: isProduction ? '1d' : '0', // 1 day in production, no cache in dev
    etag: false,
    index: 'index.html',
    setHeaders: (res, path) => {
      // No cache for HTML (enables updates)
      if (path.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      }
      // Cache JS/CSS for 1 year (assume versioned filenames)
      if (path.endsWith('.js') || path.endsWith('.css')) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      }
      // Cache images for 1 month
      if (/\.(jpg|jpeg|png|gif|webp|svg)$/i.test(path)) {
        res.setHeader('Cache-Control', 'public, max-age=2592000');
      }
      // Cache fonts for 1 year
      if (/\.(woff|woff2|eot|ttf|otf)$/i.test(path)) {
        res.setHeader('Cache-Control', 'public, max-age=31536000');
      }
    },
  }));

  // 9. REQUEST CONTEXT ATTACHMENT
  // ============================================================
  /**
   * Attach utilities to request object for use in handlers
   */
  app.use((req, res, next) => {
    // Attach logger (uses console for now, can be upgraded)
    req.logger = {
      debug: (msg, data) => isDevelopment && console.log('🔍', msg, data),
      info: (msg, data) => console.log('ℹ️', msg, data),
      warn: (msg, data) => console.warn('⚠️', msg, data),
      error: (msg, data) => console.error('❌', msg, data),
    };

    // Attach config
    req.config = config;

    // Attach API version detection
    const versionMatch = req.path.match(/^\/api\/(v\d+)/);
    if (versionMatch) {
      req.apiVersion = versionMatch[1];
      req.apiVersionNumber = parseInt(versionMatch[1].substring(1), 10);
    } else {
      req.apiVersion = 'v1';
      req.apiVersionNumber = 1;
    }

    next();
  });

  // ============================================================
  // ROUTES
  // ============================================================

  // Health Check Routes
app.use('/health', healthRoutes);

// API Routes
app.use('/api', apiRoutes);

  // ============================================================
  // 404 HANDLER (BEFORE ERROR HANDLER)
  // ============================================================
  /**
   * Handle requests to undefined routes
   * Must be before global error handler
   */
  app.use((req, res, next) => {
    const error = new Error(`Route not found: ${req.method} ${req.path}`);
    error.statusCode = 404;
    error.code = 'NOT_FOUND';
    next(error);
  });

  // ============================================================
  // GLOBAL ERROR HANDLER (LAST)
  // ============================================================
  /**
   * Centralized error handling
   * Must be last middleware
   * 
   * @param {Error} err - Error object
   * @param {express.Request} req - Request object
   * @param {express.Response} res - Response object
   * @param {Function} next - Next middleware
   */
  app.use((err, req, res, next) => {
    // Determine HTTP status code
    const statusCode = err.statusCode || err.status || 500;
    const isDev = isDevelopment;

    // Log error
    req.logger.error(err.message, {
      statusCode,
      code: err.code || 'INTERNAL_SERVER_ERROR',
      path: req.path,
      method: req.method,
      requestId: req.id,
      ...(isDev && { stack: err.stack }),
    });

    // Prepare error response
    const errorResponse = {
      error: {
        type: err.type || 'ServerError',
        message: err.message,
        code: err.code || 'INTERNAL_SERVER_ERROR',
        requestId: req.id,
        timestamp: new Date().toISOString(),
        ...(isDev && { details: err.details }),
        ...(isDev && { stack: err.stack }),
      },
    };

    // Send error response
    res.status(statusCode).json(errorResponse);
  });

  // ============================================================
  // RETURN CONFIGURED APP
  // ============================================================

  return app;
}

export default createApp;