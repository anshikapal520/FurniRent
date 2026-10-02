const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const frontendPath = __dirname;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
    secret: "furnirent-secret-key",
    resave: false,
    saveUninitialized: false
}));

// Frontend files
app.use(express.static(frontendPath, { index: false }));

app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.sendFile(path.join(frontendPath, "index.html"));
    }

    res.sendFile(path.join(frontendPath, "login.html"));
});

// Database
const db = new Database(path.join(__dirname, "furnirent.db"));

// Users table
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

// Orders table
db.prepare(`
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    furniture TEXT NOT NULL,
    address TEXT NOT NULL,
    status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
`).run();

// Home page
app.get("/", (req, res) => {
    res.sendFile(path.join(frontendPath, "index.html"));
});


// =========================
// SIGN UP
// =========================

app.post("/api/signup", async (req, res) => {

    const {
        name,
        email,
        phone,
        address,
        password
    } = req.body;

    if (!name || !email || !phone || !address || !password) {
        return res.status(400).json({
            message: "Please fill all fields."
        });
    }

    try {

        const existingUser = db.prepare(`
            SELECT id FROM users WHERE email = ?
        `).get(email);

        if (existingUser) {
            return res.status(400).json({
                message: "Email already registered."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = db.prepare(`
            INSERT INTO users
            (name, email, phone, address, password)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            name,
            email,
            phone,
            address,
            hashedPassword
        );

        req.session.userId = result.lastInsertRowid;

        res.json({
            message: "Account created successfully!",
            userId: result.lastInsertRowid
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Unable to create account."
        });
    }
});


// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {

    const {
        email,
        password
    } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Please enter email and password."
        });
    }

    try {

        const user = db.prepare(`
            SELECT * FROM users
            WHERE email = ?
        `).get(email);

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        req.session.userId = user.id;

        res.json({
            message: "Login successful!",
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                address: user.address
            }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Unable to login."
        });
    }
});


// =========================
// CHECK LOGIN
// =========================

app.get("/api/me", (req, res) => {

    if (!req.session.userId) {
        return res.json({
            loggedIn: false
        });
    }

    const user = db.prepare(`
        SELECT id, name, email, phone, address
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user) {
        return res.json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        user: user
    });
});


// =========================
// LOGOUT
// =========================

app.post("/api/logout", (req, res) => {

    req.session.destroy(() => {

        res.json({
            message: "Logged out successfully."
        });

    });
});


// =========================
// PLACE ORDER
// =========================

app.post("/api/orders", (req, res) => {

    const {
        customer_name,
        email,
        phone,
        furniture,
        address
    } = req.body;

    if (!customer_name || !email || !phone || !furniture || !address) {
        return res.status(400).json({
            message: "Please fill all required fields."
        });
    }

    const result = db.prepare(`
        INSERT INTO orders
        (customer_name, email, phone, furniture, address)
        VALUES (?, ?, ?, ?, ?)
    `).run(
        customer_name,
        email,
        phone,
        furniture,
        address
    );

    res.json({
        message: "Order placed successfully!",
        orderId: result.lastInsertRowid
    });
});


// =========================
// GET ORDERS
// =========================

app.get("/api/orders", (req, res) => {

    const orders = db.prepare(`
        SELECT * FROM orders
        ORDER BY id DESC
    `).all();

    res.json(orders);
});


// =========================
// CANCEL ORDER
// =========================

app.put("/api/orders/:id/cancel", (req, res) => {

    const result = db.prepare(`
        UPDATE orders
        SET status = 'Cancelled'
        WHERE id = ?
    `).run(req.params.id);

    if (result.changes === 0) {
        return res.status(404).json({
            message: "Order not found."
        });
    }

    res.json({
        message: "Order cancelled successfully."
    });
});


// =========================
// UPDATE ORDER STATUS
// =========================

app.put("/api/orders/:id/status", (req, res) => {

    const allowedStatuses = [
        "Pending",
        "Confirmed",
        "Delivered",
        "Completed",
        "Cancelled"
    ];

    const { status } = req.body;

    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
            message: "Invalid status."
        });
    }

    db.prepare(`
        UPDATE orders
        SET status = ?
        WHERE id = ?
    `).run(status, req.params.id);

    res.json({
        message: "Order status updated."
    });
});


// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
    console.log(`FurniRent running at http://localhost:${PORT}`);
});