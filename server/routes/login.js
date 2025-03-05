import express from 'express';
import { createConnection } from 'mysql2';
import { hash, compare } from 'bcrypt';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const SESSION_SECRET = 'fc8b779b127ef4c71de20b211af689d4225d7e9a7603e5e4b9a68dbb6c1b44fe0eafb702b097f778ec4ea3153ee1fa6175f8f56fdb905496cfb9b2d36f21a12b';

// Middleware
app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // set to true if using HTTPS
  })
);

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html on the root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  db.query('SELECT * FROM login WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    const user = results[0];
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isPasswordValid = await compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid credentials' });

    req.session.userId = user.id;
    res.cookie('user_id', user.id, { httpOnly: true, maxAge: 3600000 }); // 1 hour

    return res.status(200).json({ message: 'Log in successful' });
  });
});

// Additional routes (me, logout, register) can go here...

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
