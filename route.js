const express = require('express');
const router = express.Router();
const {
  authenticateToken,
  signup,
  login,
  logout,
  profile
} = require('./controller/auth_controller');

router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);
router.get('/profile', authenticateToken, profile);