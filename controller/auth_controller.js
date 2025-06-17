
const jwt = require('jsonwebtoken');
const { users, User } = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRATION_TIME = process.env.JWT_EXPIRATION_TIME || '10m';
const tokenBlacklist = new Set();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Missing or malformed token' });
  }

  const token = parts[1];
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ message: 'Token has been revoked' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      return res.status(401).json({ message: err.message });
    }
    req.userId = payload.userId;
    next();
  });
}

// POST /signup
function signup(req, res) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  if (users.find(u => u.email === email)) {
    return res.status(409).json({ message: 'Email already registered' });
  }

  const newUser = new User(email, password);
  users.push(newUser);
  return res.status(201).json({ message: 'User created successfully' });
}

// POST /login
function login(req, res) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  const user = users.find(u => u.email === email);
  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { userId: user.id },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRATION_TIME }
  );

  return res.json({ token });
}

// POST /logout
function logout(req, res) {
  const authHeader = req.headers['authorization'] || '';
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Missing or malformed token' });
  }
  const token = parts[1];

  try {
    jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ message: err.message });
  }

  tokenBlacklist.add(token);
  return res.json({ message: 'Logged out successfully' });
}

// GET /profile
function profile(req, res) {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  return res.json({ id: user.id, email: user.email });
}

module.exports = {
  authenticateToken,
  signup,
  login,
  logout,
  profile
};