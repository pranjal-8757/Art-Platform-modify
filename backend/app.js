require("dotenv").config();  // ✅ MUST BE FIRST

const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");

const authRoutes = require("./routes/authRoutes");

const app = express();

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

// ✅ DB CONNECT (MUST BE BEFORE ROUTES)
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error("Connection error:", err));

// ROUTES
app.use("/", authRoutes);

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
