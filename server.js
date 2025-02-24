const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

db.connect(err => {
  if (err) throw err;
  console.log("MySQL Connected...");
});

// User Registration
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
  db.query(sql, [name, email, hashedPassword], (err, result) => {
    if (err) return res.status(500).send(err);
    res.send({ message: "User Registered!" });
  });
});

// User Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length === 0) return res.status(401).send({ message: "User not found" });

    const isValid = await bcrypt.compare(password, results[0].password);
    if (!isValid) return res.status(401).send({ message: "Invalid password" });

    const token = jwt.sign({ id: results[0].id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.send({ message: "Login Successful", token });
  });
});

// Get Products
app.get("/products", (req, res) => {
  db.query("SELECT * FROM products", (err, results) => {
    if (err) return res.status(500).send(err);
    res.send(results);
  });
});

// Add Product (Admin)
app.post("/products", (req, res) => {
  const { name, price, category, image_url } = req.body;
  const sql = "INSERT INTO products (name, price, category, image_url) VALUES (?, ?, ?, ?)";
  db.query(sql, [name, price, category, image_url], (err, result) => {
    if (err) return res.status(500).send(err);
    res.send({ message: "Product Added!" });
  });
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
