const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

const JWT_SECRET = 'ba3b191897c5828298d371c0ab75bf005d6de2ab6fb15230ddb1cbd871fb9c35'; //generated using node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const JWT_EXPIRATION_TIME = "10m" //

app.use(express.json()); 
    
const users = [];
const token_blacklist = new Set();

function authenticate_token(req, res, next) {
    const authenticate_header = req.headers['authorization'] || '';
    const parts = authenticate_header.split(' ');

    if (parts.length !== 2 || parts[0] !== 'Bearer'){
        return res.status(401).json({message: 'Missing or incorrect formed token'});
    }

    const token = parts[1];

     if (token_blacklist.has(token)) {
        return res.status(401).json({ message: 'Token has been revoked' });
    }

    // Verify signature & expiry
    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) {
        // err.name === 'TokenExpiredError' or 'JsonWebTokenError'
            return res.status(401).json({ message: err.message });
        }
        // payload is { userId, iat, exp }
        req.userId = payload.userId;
        next();
    });
}

app.post('/signup', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  const exists = users.find(u => u.email === email);
  if (exists) {
    return res.status(409).json({ message: 'Email already registered' });
  }

  const newUser = { id: users.length + 1, email, password };
  users.push(newUser);
  return res.status(201).json({ message: 'User created successfully' });
});

/**
 * POST /login
 * Body: { email, password }
 *
 * If credentials match, generate a JWT and return it.
 */
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  // Find user
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
});

/**
 * POST /logout
 * Expects header: “Authorization: Bearer <token>”
 *
 * Add the token to blacklist
 */
app.post('/logout', (req, res) => {
  const authenticate_header = req.headers['authorization'] || '';
  const parts = authenticate_header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Missing or incorrect formed token' });
  }
  const token = parts[1];

  try {
    jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ message: err.message });
  }

  token_blacklist.add(token);
  return res.json({ message: 'Logged out successfully' });
});

/**
 * GET /profile
 * Header: “Authorization: Bearer <token>”
 *
 * Protected route. Only works if the token is valid and not blacklisted.
 * Returns { id, email } of the logged-in user.
 */
app.get('/profile', authenticate_token, (req, res) => {
  // req.userId was already set in authenticate_token()
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  // not sending back password
  return res.json({ id: user.id, email: user.email }); 
});

// Fallback for any other route -> 404
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

//start server 
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});