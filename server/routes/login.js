const express = require('express');
const mysql = require('mysql2');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'pritiag23092004',
  database: 'securebank',
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set secure to true if you're using HTTPS
  })
);

// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  // Query the database to find the user
  db.query(
    'SELECT * FROM login WHERE username = ?',
    [username],
    async (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }

      const user = results[0];
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Compare password using bcrypt
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Store the user ID in session
      req.session.userId = user.id;
      res.cookie('user_id', user.id, { httpOnly: true, maxAge: 3600000 }); // 1 hour
      return res.status(200).json({ message: 'Login successful' });
    }
  );
});

// Me route (retrieve current user info)
app.get('/api/me', (req, res) => {
  const userId = req.session.userId;

  if (!userId) {
    return res.status(401).json({ message: 'Not authenticated' });
  }

  // Query user info from the database
  db.query('SELECT id, username FROM login WHERE id = ?', [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }

    const user = results[0];
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.json(user);
  });
});

// Logout route
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Failed to log out' });
    }
    res.clearCookie('user_id');
    return res.status(200).json({ message: 'Logged out successfully' });
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }
  
    try {
      // Hash the password before storing it
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert the new user into the database
      db.query(
        'INSERT INTO login (username, password) VALUES (?, ?)',
        [username, hashedPassword],
        (err, results) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Database error' });
          }
          res.status(201).json({ message: 'User registered successfully' });
        }
      );
    } catch (error) {
      res.status(500).json({ message: 'Error hashing password' });
    }
  });
  