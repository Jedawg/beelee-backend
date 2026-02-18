// server.js - Beelee Backend with Secure Authentication
// Run with: node server.js

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Secret key for JWT (CHANGE THIS!)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// ==================== USER DATABASE ====================
// In production, use a real database (PostgreSQL, MongoDB, etc.)
// For now, storing in memory with file persistence

const USERS_FILE = 'users.json';
const SESSIONS_FILE = 'sessions.json';

// Load or create users
let users = {};
if (fs.existsSync(USERS_FILE)) {
  users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
} else {
  // Default users (passwords are hashed!)
  users = {
    'admin': {
      id: 'admin',
      passwordHash: bcrypt.hashSync('beelee2024', 10),
      name: 'Admin User'
    },
    'thomas': {
      id: 'thomas',
      passwordHash: bcrypt.hashSync('shopping123', 10),
      name: 'Thomas'
    },
    'maria': {
      id: 'maria',
      passwordHash: bcrypt.hashSync('maria2024', 10),
      name: 'Maria'
    },
    'family': {
      id: 'family',
      passwordHash: bcrypt.hashSync('family2024', 10),
      name: 'Family Account'
    }
  };
  saveUsers();
}

// Load or create sessions (recipes + baskets per user)
let sessions = {};
if (fs.existsSync(SESSIONS_FILE)) {
  sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
} else {
  sessions = {};
  saveSessions();
}

function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function saveSessions() {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2));
}

function getUserSession(userId) {
  if (!sessions[userId]) {
    sessions[userId] = {
      recipes: [],
      basket: []
    };
    saveSessions();
  }
  return sessions[userId];
}

// ==================== MIDDLEWARE ====================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = users[username.toLowerCase()];
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const validPassword = bcrypt.compareSync(password, user.passwordHash);
  
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign(
    { userId: user.id, username: user.id },
    JWT_SECRET,
    { expiresIn: '7d' } // Token valid for 7 days
  );

  res.json({
    token,
    user: {
      id: user.id,
      name: user.name
    }
  });
});

// Verify token (check if user is logged in)
app.get('/api/verify', authenticateToken, (req, res) => {
  const user = users[req.user.userId];
  res.json({
    user: {
      id: user.id,
      name: user.name
    }
  });
});

// ==================== SESSION ROUTES ====================

// Get user's recipes
app.get('/api/recipes', authenticateToken, (req, res) => {
  const session = getUserSession(req.user.userId);
  res.json(session.recipes);
});

// Save a recipe
app.post('/api/recipes', authenticateToken, (req, res) => {
  const session = getUserSession(req.user.userId);
  const recipe = req.body;
  
  // Update or add recipe
  const existingIndex = session.recipes.findIndex(r => r.id === recipe.id);
  if (existingIndex >= 0) {
    session.recipes[existingIndex] = recipe;
  } else {
    session.recipes.push(recipe);
  }
  
  saveSessions();
  res.json({ success: true, recipe });
});

// Delete a recipe
app.delete('/api/recipes/:id', authenticateToken, (req, res) => {
  const session = getUserSession(req.user.userId);
  session.recipes = session.recipes.filter(r => r.id !== req.params.id);
  saveSessions();
  res.json({ success: true });
});

// Get user's basket
app.get('/api/basket', authenticateToken, (req, res) => {
  const session = getUserSession(req.user.userId);
  res.json(session.basket);
});

// Update basket
app.post('/api/basket', authenticateToken, (req, res) => {
  const session = getUserSession(req.user.userId);
  session.basket = req.body.basket;
  saveSessions();
  res.json({ success: true });
});

// Clear basket
app.delete('/api/basket', authenticateToken, (req, res) => {
  const session = getUserSession(req.user.userId);
  session.basket = [];
  saveSessions();
  res.json({ success: true });
});

// ==================== ADMIN ROUTES ====================

// Add new user (admin only - you can add auth check)
app.post('/api/admin/users', (req, res) => {
  const { username, password, name } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  if (users[username.toLowerCase()]) {
    return res.status(400).json({ error: 'User already exists' });
  }
  
  users[username.toLowerCase()] = {
    id: username.toLowerCase(),
    passwordHash: bcrypt.hashSync(password, 10),
    name: name || username
  };
  
  saveUsers();
  res.json({ success: true, userId: username.toLowerCase() });
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok',
    users: Object.keys(users).length,
    sessions: Object.keys(sessions).length
  });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
  console.log(`
🐝 Beelee Backend Server Running!
================================
Port: ${PORT}
Users: ${Object.keys(users).length}
Sessions: ${Object.keys(sessions).length}

API Endpoints:
  POST   /api/login          - Login
  GET    /api/verify         - Verify token
  GET    /api/recipes        - Get recipes
  POST   /api/recipes        - Save recipe
  DELETE /api/recipes/:id    - Delete recipe
  GET    /api/basket         - Get basket
  POST   /api/basket         - Update basket
  DELETE /api/basket         - Clear basket
  POST   /api/admin/users    - Add user
  GET    /api/health         - Health check

Current Users:
${Object.values(users).map(u => `  - ${u.id} (${u.name})`).join('\n')}
  `);
});
