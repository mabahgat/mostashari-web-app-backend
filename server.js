require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { ClientSecretCredential } = require("@azure/identity");
const rateLimit = require('express-rate-limit');

// Configuration object
const config = {
  // Server settings
  server: {
    port: process.env.PORT || 8000,
    environment: process.env.NODE_ENV || 'development',
  },

  // Security settings
  security: {
    apiKey: process.env.BACKEND_API_KEY,
    corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    requireApiKey: process.env.REQUIRE_API_KEY !== 'false',
  },

  // Azure credentials
  azure: {
    tenant: process.env.AZURE_TENANT_ID,
    clientId: process.env.AZURE_CLIENT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
  },

  // Azure AI Agent settings
  agent: {
    projectEndpoint: process.env.AZURE_PROJECT_ENDPOINT || 'https://az-openai-law-1.services.ai.azure.com',
    projectName: process.env.AZURE_PROJECT_NAME || 'az-openai-law-1-project',
    agentName: process.env.AZURE_AGENT_NAME || 'agent-7dec-1',
    apiVersion: process.env.AZURE_API_VERSION || '2025-11-15-preview',
  },

  // Logging settings
  logging: {
    verbose: process.env.VERBOSE_LOGGING === 'true',
    logHeaders: process.env.LOG_HEADERS === 'true',
    logBody: process.env.LOG_BODY === 'true',
  },

  // Rate limiting settings
  rateLimit: {
    enabled: process.env.RATE_LIMIT_ENABLED !== 'false',
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 minutes
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  },

  // Token settings
  token: {
    scope: 'https://ai.azure.com/.default',
    cacheDuration: 3600000, // 1 hour in milliseconds
  },
};

// Validate required configuration
const validateConfig = () => {
  const required = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'BACKEND_API_KEY'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error('\n❌ FATAL: Missing required environment variables:');
    missing.forEach(key => console.error(`   - ${key}`));
    console.error('\nPlease set these variables in your .env file and restart the server.\n');
    process.exit(1);
  }
};

// Log configuration on startup
const logConfig = () => {
  console.log('\n🚀 Loading configuration...');
  console.log(`   Environment: ${config.server.environment}`);
  console.log(`   Port: ${config.server.port}`);
  console.log(`   CORS Origin: ${config.security.corsOrigin}`);
  console.log(`   API Key Required: ${config.security.requireApiKey}`);
  console.log(`   Azure Agent: ${config.agent.agentName}`);
  console.log(`   Verbose Logging: ${config.logging.verbose}`);
  console.log(`   Rate Limiting: ${config.rateLimit.enabled ? `Enabled (${config.rateLimit.maxRequests} requests per ${config.rateLimit.windowMs}ms)` : 'Disabled'}`);
  console.log('   Azure Credentials:');
  console.log(`     AZURE_TENANT_ID: ${config.azure.tenant ? '✓' : '✗'}`);
  console.log(`     AZURE_CLIENT_ID: ${config.azure.clientId ? '✓' : '✗'}`);
  console.log(`     AZURE_CLIENT_SECRET: ${config.azure.clientSecret ? '✓' : '✗'}`);
  console.log(`   Backend API Key: ${process.env.BACKEND_API_KEY ? '✓ Set' : '✗ Using default'}\n`);
};

validateConfig();
logConfig();

const app = express();

// CORS configuration
app.use(cors({
  origin: config.security.corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

app.use(express.json());

// Rate limiting middleware
if (config.rateLimit.enabled) {
  const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: config.rateLimit.maxRequests,
    message: 'Too many requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      // Skip rate limiting for health check
      return req.path === '/health' || req.path === '/';
    },
  });
  
  app.use(limiter);
  
  if (config.logging.verbose) {
    console.log(`✅ Rate limiting enabled: ${config.rateLimit.maxRequests} requests per ${config.rateLimit.windowMs}ms`);
  }
}

// API Key validation middleware
app.use((req, res, next) => {
  // Skip validation for health check and root
  if (req.path === '/health' || req.path === '/') {
    return next();
  }

  if (!config.security.requireApiKey) {
    return next();
  }

  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== config.security.apiKey) {
    if (config.logging.verbose) {
      console.log('❌ Unauthorized request - Invalid API key');
    }
    return res.status(401).json({ error: 'Unauthorized - Invalid API key' });
  }

  next();
});

// Request logging middleware
app.use((req, res, next) => {
  if (config.logging.verbose) {
    const timestamp = new Date().toISOString();
    console.log(`\n📨 [${timestamp}] ${req.method} ${req.path}`);
    
    if (config.logging.logHeaders && req.headers) {
      console.log('   Headers:', JSON.stringify(req.headers, null, 2));
    }
    
    if (config.logging.logBody && req.body && Object.keys(req.body).length > 0) {
      console.log('   Body:', JSON.stringify(req.body, null, 2));
    }
  }
  
  res.on('finish', () => {
    if (config.logging.verbose) {
      console.log(`   ✅ Response Status: ${res.statusCode}`);
    }
  });
  
  next();
});

// Initialize Azure credential
const credential = new ClientSecretCredential(
  config.azure.tenant,
  config.azure.clientId,
  config.azure.clientSecret
);

// Routes
app.post('/api/generate', async (req, res) => {
  try {
    const { input } = req.body;

    if (!input || !input.trim()) {
      return res.status(400).json({ error: 'Input is required' });
    }

    if (config.logging.verbose) {
      console.log('\n🤖 Generating content...');
      console.log(`   Input length: ${input.length}`);
    }

    // Get token server-side
    if (config.logging.verbose) {
      console.log('\n🔐 Acquiring Azure token...');
    }
    const token = await credential.getToken(config.token.scope);
    if (config.logging.verbose) {
      console.log('   ✅ Token acquired');
    }

    // Build Azure endpoint
    const azureEndpoint = `${config.agent.projectEndpoint}/api/projects/${config.agent.projectName}/openai/responses?api-version=${config.agent.apiVersion}`;
    
    if (config.logging.verbose) {
      console.log('\n📡 Calling Azure Agent API...');
      console.log(`   Endpoint: ${azureEndpoint}`);
      console.log(`   Agent: ${config.agent.agentName}`);
    }
    
    const response = await fetch(azureEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.token}`,
      },
      body: JSON.stringify({
        agent: {
          type: 'agent_reference',
          name: config.agent.agentName,
        },
        input: input,
      }),
    });

    if (config.logging.verbose) {
      console.log(`   Response status: ${response.status}`);
    }

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`❌ Azure API Error: ${response.status}`, errorText);
      return res.status(response.status).json({ error: errorText });
    }

    const data = await response.json();
    if (config.logging.verbose) {
      console.log('   ✅ Response received from Azure');
    }
    
    res.json(data);
  } catch (error) {
    console.error('❌ Error:', error.message);
    if (config.logging.verbose) {
      console.error('   Stack:', error.stack);
    }
    res.status(500).json({ error: error.message });
  }
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'Backend server is running',
    environment: config.server.environment,
    version: '1.0.0'
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(config.server.port, () => {
  console.log(`\n🎉 Backend running on http://localhost:${config.server.port}`);
  console.log('   GET / - Server status');
  console.log('   GET /health - Health check');
  console.log(`   POST /api/generate - Generate content${config.security.requireApiKey ? ' (requires X-API-Key header)' : ''}\n`);
});