import dotenv from 'dotenv';
dotenv.config();
import express, { json } from 'express';
import { createConnection } from 'mysql2';
import { hash, compare } from 'bcrypt';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import cors from 'cors';

const app = express();

/// Middleware
app.use(json());
app.use(cors());
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET, // This uses the session secret from .env
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true },  // Set to true when using HTTPS
  })
);

// Connect to MySQL
const db = createConnection({
  host: "localhost",
  user: "root", 
  password: "pritiag23092004", 
  database: "securebank",
});

db.connect((err) => {
  if (err) console.error('Database connection failed:', err);
  else console.log('Connected to MySQL');
});

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
      const isPasswordValid = await compare(password, user.password);
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

// Register route
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    // Hash the password before storing it
    const hashedPassword = await hash(password, 10);

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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
