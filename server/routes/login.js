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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//Database Connection
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

// Register route
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  try {
    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    db.query(
      'INSERT INTO login (email, password) VALUES (?, ?)',
      [email, hashedPassword],
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

//Login Route
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

//Logout Route (Destroy session completely)
app.get('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ message: "Logout failed" });

        res.clearCookie('connect.sid'); // Clear session cookie
        res.clearCookie('user_id'); // Clear user ID cookie

        return res.json({ success: true, redirect: '/index.html' });
    });
});

//Route to check if user is logged in
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

//Protect the user dashboard route
app.get('/userboard.html', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/userLG.html'); // Redirect to login page if not authenticated
    }
    res.sendFile(path.join(__dirname, 'public', 'userboard.html'));
});

//Admin login route
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;

    // Hardcoded Admin Credentials
    const ADMIN_EMAIL = "admin@gmail.com";
    const ADMIN_PASSWORD = "admin#123"; // Store hashed password in real applications

    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
        // Store admin session
        req.session.adminId = "admin";
        res.cookie('admin_id', "admin", { httpOnly: true, maxAge: 3600000 });

        return res.status(200).json({ success: true, redirect: '/adminboard.html' });
    } else {
        return res.status(401).json({ message: 'Invalid admin credentials' });
    }
});

//Admin logout route
app.get('/api/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ message: "Logout failed" });

        res.clearCookie('admin_id'); // Clear session
        return res.json({ success: true, redirect: '/index.html' });
    });
});

//to protect admin dashboard
app.get('/adminboard.html', (req, res) => {
    if (!req.session.adminId) {
        return res.redirect('/AdminLG.html'); // Redirect to login if not authenticated
    }
    res.sendFile(path.join(__dirname, 'public', 'adminboard.html'));
});

// User Details Route [USER]
app.get('/user-details', (req, res) => {
    const user_id = req.session.userId; // Get user_id from session

    db.query(
        `SELECT user_id, first_name, last_name, email, phone_number, 
                date_of_birth, address, date_joined 
         FROM users 
         WHERE user_id = ?`, 
        [user_id], 
        (err, results) => {
            if (err) {
                console.error("Error fetching user details:", err);
                return res.status(500).send("Internal Server Error");
            }

            if (results.length === 0) {
                return res.status(404).send("User not found");
            }

            res.render("userdata", { user: results[0] });
        }
    );
});

//Account details [USER]
app.get('/account-details', (req, res) => {
    const user_id = req.session.userId; // Get user_id from session

    db.query(
        `SELECT acc_id, account_type, balance, account_status, 
                created_at, last_updated, branch_code 
         FROM account 
         WHERE user_id = ?`, 
        [user_id], 
        (err, results) => {
            if (err) {
                console.error("Error fetching account details:", err);
                return res.status(500).send("Internal Server Error");
            }

            if (results.length === 0) {
                return res.status(404).send("No account found for this user");
            }

            res.render("accdata", { account: results[0] });
        }
    );
});

//Transaction history [USER]
app.get('/transactions', (req, res) => {
    const user_id = req.session.userId; // Get user ID from session

    const sql = `
        SELECT t.transaction_id, t.acc_id, t.transaction_type, 
               t.transaction_date, t.amount, t.balance_after, t.transaction_status
        FROM transaction_history t
        JOIN account a ON t.acc_id = a.acc_id  -- Link transactions to accounts
        WHERE a.user_id = ?  -- Filter by logged-in user
        ORDER BY t.transaction_date DESC`;

    db.query(sql, [user_id], (err, results) => {
        if (err) {
            console.error('Error fetching transaction history:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.render('transaction', { transactions: results });
    });
});





//EJS route for employee data [ADMIN]
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Ensure your 'views' folder is correctly placed

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));


// Route to render user data in EJS [ADMIN]
app.get('/allusers', (req, res) => {
    const sql = 'SELECT * FROM users';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching user data:', err.message);
            return res.status(500).send('Internal Server Error');
        }
        res.render('admin-userdata', { users: results });
    });
});

// Route to render all account data in EJS [ADMIN]
app.get('/allaccounts', (req, res) => {
    const sql = 'SELECT * FROM account';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching account data: ' + err.message);
            return res.status(500).send('Internal Server Error');
        }
        res.render('admin-accountdata', { accounts: results });
    });
});


// Route to render employee data in EJS [ADMIN]
app.get('/employees', (req, res) => {
    const sql = 'SELECT * FROM employee';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching employees: ' + err.message);
            return res.status(500).send('Internal Server Error');
        }
        res.render('employees', { employees: results });
    });
});

//Transaction history [ADMIN]
app.get('/all-transactions', (req, res) => {
    const sql = `SELECT t.transaction_id, t.acc_id, t.transaction_type, t.transaction_date, 
                        t.amount, t.balance_after, t.transaction_status, 
                        u.first_name, u.last_name 
                 FROM transaction_history t
                 JOIN account a ON t.acc_id = a.acc_id
                 JOIN users u ON a.user_id = u.user_id
                 ORDER BY t.transaction_date DESC`;

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching transaction history: ' + err.message);
            return res.status(500).send('Internal Server Error');
        }
        res.render('admin-transactions', { transactions: results });
    });
});


//Deleting employee from table [ADMIN]
app.delete("/delete-employee/:id", (req, res) => {
    const empId = req.params.id;
    db.query("DELETE FROM employee WHERE emp_id = ?", [empId], (err, result) => {
        if (err) {
            console.error(err);
            return res.json({ success: false });
        }
        res.json({ success: true });
    });
});


// Start server on port 3000
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
