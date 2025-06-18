const express = require('express');   
const authRoutes = require('./route');

const app = express();
const PORT = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());

// not yet finished (TODO)
const rateLimit = require('express-rate-limit');
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                // limit each IP to 100 requests per windowMs
  // TODO: fine‑tune windowMs and max values based on expected traffic
});
app.use(apiLimiter);

// Leave simple
app.use('/', authRoutes);

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});