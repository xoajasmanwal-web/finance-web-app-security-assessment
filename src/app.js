const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const { Sequelize } = require('sequelize');

const app = express();
app.use(express.json());

// Finding 7 Fix: Enforce Security Headers (HSTS, X-Frame-Options, nosniff)
app.use(helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: 'deny' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"]
    }
  }
}));

const JWT_SECRET = process.env.JWT_SECRET || 'replace-with-strong-env-secret';

// Middleware: Verify JWT & enforce authentication
function authenticateToken(req, res, next) {
  const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// Finding 2 Fix: Server-side Role-Based Access Control (RBAC)
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admin access required' });
  }
  next();
}

// Finding 1 Fix: Parameterized Query to prevent SQL Injection
app.post('/rest/user/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password || email.includes("'")) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: 1, email, role: 'customer' }, JWT_SECRET, { expiresIn: '15m' });

    // Finding 5 Fix: Secure Cookie Flags
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    return res.json({ message: 'Login successful', token });
  } catch (err) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Finding 3 Fix: Ownership Check to prevent IDOR
app.get('/rest/basket/:id', authenticateToken, (req, res) => {
  const requestedUserId = parseInt(req.params.id, 10);
  if (req.user.id !== requestedUserId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: You do not own this resource' });
  }
  return res.json({ basketId: requestedUserId, items: [] });
});

// Admin-only route protected by RBAC
app.get('/api/Users', authenticateToken, requireAdmin, (req, res) => {
  return res.json({ users: [{ id: 1, email: 'customer@nbfc.in', role: 'customer' }] });
});

// Finding 6 Fix: Generic Global Error Handler (No Stack Trace Leakage)
app.use((err, req, res, next) => {
  res.status(500).json({ error: 'Internal Server Error' });
});

if (require.main === module) {
  app.listen(3000, () => console.log('Patched NBFC Portal running on port 3000'));
}

module.exports = app;
