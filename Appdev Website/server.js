import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import cors from "cors";

import Student from "./models/Student.js";
import Instructor from "./models/Instructor.js";
import Admin from "./models/Admin.js";

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/eduvault", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection failed:", err));

app.post("/signup/student", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existing = await Student.findOne({ email });
    if (existing) return res.status(400).json({ message: "Student already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const student = new Student({ name, email, password: hashed });
    await student.save();

    res.json({ message: "Student signup successful!" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/signup/instructor", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existing = await Instructor.findOne({ email });
    if (existing) return res.status(400).json({ message: "Instructor already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const instructor = new Instructor({ name, email, password: hashed });
    await instructor.save();

    res.json({ message: "Instructor signup successful!" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/signup/admin", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existing = await Admin.findOne({ email });
    if (existing) return res.status(400).json({ message: "Admin already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const admin = new Admin({ name, email, password: hashed });
    await admin.save();

    res.json({ message: "Admin signup successful!" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/login/student", async (req, res) => {
  const { email, password } = req.body;
  const user = await Student.findOne({ email });
  if (!user) return res.status(400).json({ message: "Student not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid password" });

  res.json({ message: "Login successful!", redirect: "StudentHomePage.html" });
});

app.post("/login/instructor", async (req, res) => {
  const { email, password } = req.body;
  const user = await Instructor.findOne({ email });
  if (!user) return res.status(400).json({ message: "Instructor not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid password" });

  res.json({ message: "Login successful!", redirect: "InstructorHomePage.html" });
});

app.post("/login/admin", async (req, res) => {
  const { email, password } = req.body;
  const user = await Admin.findOne({ email });
  if (!user) return res.status(400).json({ message: "Admin not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: "Invalid password" });

  res.json({ message: "Login successful!", redirect: "AdminHomePage.html" });
});


app.listen(5000, () => console.log("Server running at http://localhost:5000"));
