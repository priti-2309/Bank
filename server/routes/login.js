import express from 'express';
import mysql from 'mysql2';
import bcrypt from 'bcrypt';
import session from 'express-session';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const SESSION_SECRET = 'fc8b779b127ef4c71de20b211af689d4225d7e9a7603e5e4b9a68dbb6c1b44fe0eafb702b097f778ec4ea3153ee1fa6175f8f56fdb905496cfb9b2d36f21a12b';
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 3600000 } // Set expiry
}));

// Prevent caching of authenticated pages
app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    next();
});

// Serve static files from "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// ✅ Load `index.html` as the first page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ✅ MySQL Database Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "pritiag23092004",
    database: "securebank"
});

db.connect(err => {
    if (err) console.error('Database connection failed:', err);
    else console.log('Connected to MySQL');
});

// ✅ Login Route
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password required' });
    }

    db.query('SELECT * FROM login WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (results.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        req.session.userId = user.id;
        res.cookie('user_id', user.id, { httpOnly: true, maxAge: 3600000 }); // 1 hour

        return res.status(200).json({ success: true, redirect: '/userboard.html' });
    });
});

// ✅ Logout Route (Destroy session completely)
app.get('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ message: "Logout failed" });

        res.clearCookie('connect.sid'); // Clear session cookie
        res.clearCookie('user_id'); // Clear user ID cookie

        return res.json({ success: true, redirect: '/index.html' });
    });
});

// ✅ Route to check if user is logged in
app.get('/api/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ loggedIn: false, message: 'Not authenticated' });
    }

    db.query('SELECT id, email FROM login WHERE id = ?', [req.session.userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(500).json({ loggedIn: false, message: 'Error retrieving user' });
        }
        return res.json({ loggedIn: true, user: results[0] });
    });
});

// ✅ Protect the user dashboard route
app.get('/userboard.html', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/userLG.html'); // Redirect to login page if not authenticated
    }
    res.sendFile(path.join(__dirname, 'public', 'userboard.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
