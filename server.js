require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { ClientSecretCredential } = require("@azure/identity");
const rateLimit = require('express-rate-limit');

// Configuration object
const config = {
  // Server settings
  server: {
    port: process.env.PORT || 8080,
    environment: process.env.NODE_ENV || 'development',
  },

  // Security settings
  security: {
    apiKey: process.env.BACKEND_API_KEY,
    corsOrigins: (process.env.CORS_ORIGIN).split(',').map(origin => origin.trim()),
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
    projectEndpoint: process.env.AZURE_PROJECT_ENDPOINT,
    projectName: process.env.AZURE_PROJECT_NAME,
    agentName: process.env.AZURE_AGENT_NAME,
    apiVersion: '2025-11-15-preview',
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

  // Chat session settings
  chat: {
    sessionTimeout: parseInt(process.env.CHAT_SESSION_TIMEOUT || '1800000'), // 30 minutes in milliseconds
    cleanupInterval: parseInt(process.env.CHAT_CLEANUP_INTERVAL || '60000'), // 1 minute in milliseconds
  },
};

// Validate required configuration
const validateConfig = () => {
  const required = [
    'AZURE_TENANT_ID',
    'AZURE_CLIENT_ID',
    'AZURE_CLIENT_SECRET',
    'BACKEND_API_KEY',
    'AZURE_PROJECT_ENDPOINT',
    'AZURE_PROJECT_NAME',
    'AZURE_AGENT_NAME',
    'CORS_ORIGIN',
  ];
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
  console.log(`   CORS Origins: ${config.security.corsOrigins.join(', ')}`);
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
  origin: config.security.corsOrigins,
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

// Chat session storage
const chatSessions = new Map();

// Helper function to generate session ID
const generateSessionId = () => {
  return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

// Helper function to update session activity
const updateSessionActivity = (sessionId) => {
  const session = chatSessions.get(sessionId);
  if (session) {
    session.lastActivity = Date.now();
  }
};

// Cleanup inactive sessions
const cleanupSessions = () => {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [sessionId, session] of chatSessions.entries()) {
    if (now - session.lastActivity > config.chat.sessionTimeout) {
      chatSessions.delete(sessionId);
      cleaned++;
      if (config.logging.verbose) {
        console.log(`🧹 Cleaned up inactive session: ${sessionId}`);
      }
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned up ${cleaned} inactive session(s)`);
  }
};

// Start cleanup interval
setInterval(cleanupSessions, config.chat.cleanupInterval);

if (config.logging.verbose) {
  console.log(`✅ Session cleanup enabled: ${config.chat.sessionTimeout}ms timeout, ${config.chat.cleanupInterval}ms interval`);
}

// Routes

// Chat endpoint - supports new and existing sessions
app.post('/api/chat', async (req, res) => {
  try {
    const { sessionId, messages, model } = req.body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Messages array is required' });
    }

    // Validate message format
    for (const msg of messages) {
      if (!msg.role || !msg.content) {
        return res.status(400).json({ error: 'Each message must have role and content' });
      }
      if (!['system', 'user', 'assistant'].includes(msg.role)) {
        return res.status(400).json({ error: 'Message role must be system, user, or assistant' });
      }
    }

    let session;
    let newSessionId = sessionId;

    // Check if session exists or create new one
    if (sessionId) {
      session = chatSessions.get(sessionId);
      if (!session) {
        return res.status(404).json({ error: 'Session not found or expired' });
      }
      updateSessionActivity(sessionId);
      // Add new messages to session history
      session.messages.push(...messages);
    } else {
      // Create new session
      newSessionId = generateSessionId();
      session = {
        id: newSessionId,
        messages: [...messages],
        createdAt: Date.now(),
        lastActivity: Date.now(),
      };
      chatSessions.set(newSessionId, session);
      
      if (config.logging.verbose) {
        console.log(`\n🆕 New chat session created: ${newSessionId}`);
      }
    }

    if (config.logging.verbose) {
      console.log(`\n💬 Processing chat request...`);
      console.log(`   Session: ${newSessionId}`);
      console.log(`   Messages in session: ${session.messages.length}`);
      console.log(`   New messages: ${messages.length}`);
    }

    // Get token
    if (config.logging.verbose) {
      console.log('\n🔐 Acquiring Azure token...');
    }
    const token = await credential.getToken(config.token.scope);
    if (config.logging.verbose) {
      console.log('   ✅ Token acquired');
    }

    // Build Azure AI Foundry agent endpoint (same as /api/generate)
    const azureEndpoint = `${config.agent.projectEndpoint}/api/projects/${config.agent.projectName}/openai/responses?api-version=${config.agent.apiVersion}`;
    
    if (config.logging.verbose) {
      console.log('\n📡 Calling Azure Agent API...');
      console.log(`   Endpoint: ${azureEndpoint}`);
      console.log(`   Agent: ${config.agent.agentName}`);
    }

    // Prepare request body for agent
    // Extract the last user message as input
    const lastUserMessage = [...session.messages].reverse().find(m => m.role === 'user');
    const input = lastUserMessage ? lastUserMessage.content : '';

    if (!input) {
      return res.status(400).json({ error: 'No user message found in messages array' });
    }

    const requestBody = {
      agent: {
        type: 'agent_reference',
        name: config.agent.agentName,
      },
      input: input,
    };

    if (config.logging.verbose) {
      console.log(`   Request body: ${JSON.stringify(requestBody).substring(0, 200)}...`);
    }
    
    let response;
    try {
      response = await fetch(azureEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token.token}`,
        },
        body: JSON.stringify(requestBody),
        timeout: 30000, // 30 second timeout
      });
    } catch (fetchError) {
      console.error(`❌ Fetch Error: ${fetchError.message}`);
      return res.status(503).json({ error: `Azure connection failed: ${fetchError.message}` });
    }

    if (config.logging.verbose) {
      console.log(`   Response status: ${response.status}`);
    }

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`❌ Azure API Error: ${response.status}`, errorText);
      return res.status(response.status).json({ error: `Azure API Error: ${errorText}` });
    }

    const data = await response.json();
    
    // Add assistant's response to session history
    // Handle both agent response format and standard chat format
    if (data.choices && data.choices[0] && data.choices[0].message) {
      session.messages.push(data.choices[0].message);
    } else if (data.output) {
      // Agent response format - extract output text
      session.messages.push({
        role: 'assistant',
        content: data.output
      });
    }
    
    if (config.logging.verbose) {
      console.log('   ✅ Response received from Azure');
    }
    
    // Add session ID to response
    const responseData = {
      ...data,
      sessionId: newSessionId,
    };
    
    res.json(responseData);
  } catch (error) {
    console.error('❌ Error:', error.message);
    if (config.logging.verbose) {
      console.error('   Stack:', error.stack);
    }
    res.status(500).json({ error: error.message });
  }
});

// List all active sessions
app.get('/api/chat/sessions', async (req, res) => {
  try {
    const sessions = [];
    
    for (const [sessionId, session] of chatSessions.entries()) {
      sessions.push({
        id: session.id,
        messageCount: session.messages.length,
        createdAt: new Date(session.createdAt).toISOString(),
        lastActivity: new Date(session.lastActivity).toISOString(),
        inactiveDuration: Date.now() - session.lastActivity,
        timeUntilExpiry: Math.max(0, config.chat.sessionTimeout - (Date.now() - session.lastActivity)),
      });
    }
    
    res.json({
      totalSessions: sessions.length,
      sessions: sessions,
      sessionTimeout: config.chat.sessionTimeout,
    });
  } catch (error) {
    console.error('❌ Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Delete a specific session
app.delete('/api/chat/sessions/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required' });
    }
    
    const session = chatSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    chatSessions.delete(sessionId);
    
    if (config.logging.verbose) {
      console.log(`🗑️ Session deleted: ${sessionId}`);
    }
    
    res.json({ 
      message: 'Session deleted successfully',
      sessionId: sessionId,
    });
  } catch (error) {
    console.error('❌ Error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

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
      console.log(`   Token type: ${token.token ? 'Bearer' : 'MISSING'}`);
    }

    // Validate endpoint URL
    try {
      new URL(azureEndpoint);
    } catch (urlError) {
      console.error(`❌ Invalid Azure endpoint URL: ${azureEndpoint}`, urlError.message);
      return res.status(400).json({ error: 'Invalid Azure endpoint configuration' });
    }

    const requestBody = JSON.stringify({
      agent: {
        type: 'agent_reference',
        name: config.agent.agentName,
      },
      input: input,
    });

    if (config.logging.verbose) {
      console.log(`   Request body: ${requestBody.substring(0, 200)}...`);
    }
    
    let response;
    try {
      response = await fetch(azureEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token.token}`,
        },
        body: requestBody,
        timeout: 30000, // 30 second timeout
      });
    } catch (fetchError) {
      console.error(`❌ Fetch Error: ${fetchError.message}`);
      console.error(`   Endpoint: ${azureEndpoint}`);
      console.error(`   Cause: ${fetchError.cause || 'Unknown'}`);
      
      // Provide more specific error message
      if (fetchError.code === 'ENOTFOUND') {
        return res.status(503).json({ error: 'Cannot reach Azure endpoint - DNS resolution failed' });
      } else if (fetchError.code === 'ECONNREFUSED') {
        return res.status(503).json({ error: 'Azure endpoint refused connection' });
      } else if (fetchError.message.includes('timeout')) {
        return res.status(504).json({ error: 'Request timeout - Azure endpoint not responding' });
      }
      
      return res.status(503).json({ error: `Azure connection failed: ${fetchError.message}` });
    }

    if (config.logging.verbose) {
      console.log(`   Response status: ${response.status}`);
    }

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`❌ Azure API Error: ${response.status}`, errorText);
      return res.status(response.status).json({ error: `Azure API Error: ${errorText}` });
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
app.listen(config.server.port, '0.0.0.0', () => {
  console.log(`\n🎉 Backend running on http://0.0.0.0:${config.server.port}`);
  console.log('   GET / - Server status');
  console.log('   GET /health - Health check');
  console.log(`   POST /api/generate - Generate content${config.security.requireApiKey ? ' (requires X-API-Key header)' : ''}`);
  console.log(`   POST /api/chat - Chat with session management${config.security.requireApiKey ? ' (requires X-API-Key header)' : ''}`);
  console.log(`   GET /api/chat/sessions - List all active sessions${config.security.requireApiKey ? ' (requires X-API-Key header)' : ''}`);
  console.log(`   DELETE /api/chat/sessions/:sessionId - Delete a session${config.security.requireApiKey ? ' (requires X-API-Key header)' : ''}\n`);
});