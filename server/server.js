import dotenv from 'dotenv';
dotenv.config();
import express, { json } from "express";
import { createConnection } from "mysql2";
import { hash, compare } from "bcrypt";
import jwt from 'jsonwebtoken';
const { sign } = jwt;
import cors from "cors";

const app = express();
app.use(json());
app.use(cors());

// Connect to MySQL
const db = createConnection({
  host: "localhost",
  user: "root", 
  password: "pritiag23092004", 
  database: "securebank",
});

db.connect((err) => {
  if (err) console.error("Database connection failed:", err);
  else console.log("Connected to MySQL");
});

//express server
app.listen(3000, ()=>{
  console.log("Server is running on port 3000");
})