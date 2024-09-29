// index.js

require('dotenv').config(); // Load environment variables

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();

// Middleware
app.use(cors()); // Enable CORS for all origins. Adjust as needed.
app.use(express.json()); // Parse JSON bodies

// PostgreSQL Pool Setup
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Routes

// 1. Health Check
app.get('/', (req, res) => {
  res.send('Question Puzzle Backend is running.');
});

// 2. User Registration (Optional)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if username already exists
    const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user
    const newUser = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );

    res.status(201).json({ message: 'User registered successfully.', user: newUser.rows[0] });
  } catch (error) {
    console.error('Error in /register:', error);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

// 3. User Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Fetch user by username
    const userQuery = 'SELECT * FROM users WHERE username = $1';
    const result = await pool.query(userQuery, [username]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found.' });
    }

    const user = result.rows[0];

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid password.' });
    }

    // Create JWT token
    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful.', token });
  } catch (error) {
    console.error('Error in /login:', error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// 4. Generate Question/Puzzle (Protected Route)
app.get('/generate', authenticateToken, async (req, res) => {
  try {
    // Fetch a random question or puzzle
    const query = 'SELECT * FROM questions ORDER BY RANDOM() LIMIT 1';
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No questions or puzzles available.' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error in /generate:', error);
    res.status(500).json({ message: 'Server error during question/puzzle generation.' });
  }
});

// Middleware to Authenticate JWT Tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  // Token format: "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided. Access denied.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ message: 'Invalid or expired token. Access forbidden.' });
    }

    req.user = user; // Attach user info to request
    next();
  });
}

// 5. (Optional) Add More Endpoints as Needed

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend server is running on port ${PORT}`);
});
